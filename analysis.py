"""Contract reconciliation and evidence-linked questions about the supplied records."""
from collections import defaultdict
import hashlib
import json
import re
from artifacts import Invalid, SECRET, address, need, stamp

TAGS=("account","role","tenant","auth_state","ownership")
STATES=("Unreviewed","In review","Needs evidence","Documented","Dismissed")
EXPORTS=("API_ENDPOINTS.md","API_AUTHORIZATION_MATRIX.md","API_ATTACK_SURFACES.md","API_HYPOTHESES.md","API_WORKFLOWS.md","api-inventory.json")

def id_for(*v):
    return hashlib.sha256(json.dumps(v,separators=(",",":"),ensure_ascii=True).encode()).hexdigest()[:28]

def scope_rules(obj,key):
    need(isinstance(obj,dict) and obj.get("schema_version")==1 and isinstance(obj.get("rules"),list) and len(obj["rules"])<=100,"Expected scope schema v1 with up to 100 rules.")
    result=[]
    for r in obj["rules"]:
        need(isinstance(r,dict) and r.get("effect") in ("include","exclude") and isinstance(r.get("url"),str),"Invalid scope rule.")
        org,_,u=address(r["url"])
        need(not u.query and not u.fragment and not re.search(r"[%*{}]|(?:^|/)\.{1,2}(?:/|$)",u.path),"Scope rules require an exact origin and a literal path prefix.")
        result.append(dict(effect=r["effect"],origin=org,prefix=[stamp(key,p) for p in u.path.rstrip("/").split("/")[1:]],url=r["url"]))
    return result

def classify(r,rules):
    seg=r["segments"][1:]
    effects=[s["effect"] for s in rules if r["origin"]==s["origin"] and seg[:len(s["prefix"])]==s["prefix"]]
    # A template with a variable could span excluded subpaths: classify individual captures instead.
    if "exclude" in effects:return "Out-of-scope"
    if r["kind"]=="specified" and None in seg and any(s["effect"]=="exclude" and r["origin"]==s["origin"] for s in rules):return "Unknown / requires review"
    return "In-scope" if "include" in effects else "Unknown / requires review"

def reconcile(rows):
    specs=[r for r in rows if r["kind"]=="specified"]
    buckets=defaultdict(list)
    for s in specs:buckets[(s["origin"],len(s["segments"]))].append(s)
    diffs=[];seen=set()
    def discrepancy(label,detail,*refs):
        diffs.append(dict(type=label,detail=detail,evidence=[r["id"] for r in refs],status="Requires review"))
    for r in rows:
        r["route"]=r["path"];r["spec_ids"]=[]
        if r["kind"]!="observed":continue
        candidates=[]
        for s in buckets[r["origin"],len(r["segments"])]:
            if all(x==y or (x is None and v!="") for x,y,v in zip(s["segments"],r["segments"],r["path"].split("/"))):
                candidates.append(s)
        if not candidates:
            discrepancy("Observed only","No matching documented path in the imported definitions.",r);continue
        fixed=max(sum(v is not None for v in s["segments"]) for s in candidates)
        candidates=[s for s in candidates if sum(v is not None for v in s["segments"])==fixed]
        if len({s["path"] for s in candidates})>1:
            discrepancy("Ambiguous template","Several equally specific paths match; observation kept separate.",r,*candidates[:8]);continue
        r["route"]=candidates[0]["path"]
        compatible=[s for s in candidates if s["method"]==r["method"]]
        if not compatible:
            discrepancy("Method difference",r["method"]+" was recorded; specification lists "+", ".join(sorted({s["method"] for s in candidates})),r,*candidates[:8]);continue
        if len(compatible)>1:
            discrepancy("Multiple definitions","Overlapping specification versions. Compare one version per project.",r,*compatible[:8]);continue
        s=compatible[0];seen.add(s["id"]);r["spec_ids"]=[s["id"]]
        def diff(label,detail):discrepancy(label,detail,r,s)
        extra=set(r["query"])-set(s["query"]);missing=set(s["required_query"])-set(r["query"])
        if extra or missing:
            diff("Parameter difference","Extra query names: "+(", ".join(sorted(extra)) or "none")+"; required names not recorded: "+(", ".join(sorted(missing)) or "none"))
        for category,required,observed in (("header","required_headers","headers"),("cookie","required_cookies","cookie_names")):
            absent=set(s.get(required,[]))-set(r.get(observed,[]))
            if absent:diff("Parameter difference","Required "+category+" names absent from capture: "+", ".join(sorted(absent)))
        for status in r["statuses"]:
            if not any(x in s["statuses"] for x in (status,status[0]+"XX","default")):diff("Response status difference","Recorded "+status+" is absent from the response declarations.")
        def evidenced(token):
            if token.startswith("header:"):return token[7:] in r["headers"]
            if token.startswith("query:"):return token[6:] in [q.lower() for q in r["query"]]
            if token.startswith("cookie:"):return token[7:] in [c.lower() for c in r.get("cookie_names",[])]
            return token in r["auth"]
        if s["groups"] and not any(all(evidenced(t) for t in group) for group in s["groups"]):
            diff("Authentication declaration difference","Capture does not evidence a declared alternative. Capture sanitization or gateway authentication may explain this.")
        elif not s["groups"] and r["auth"]:
            diff("Authentication declaration difference","Capture contains credential metadata; operation has no declared requirement.")
    for s in specs:
        if s["id"] not in seen:discrepancy("Documented only","No uniquely aligned capture for this operation.",s)
    for r in rows:
        fields=sorted({f.split(":")[0] for f in r["fields"] if SECRET.search(f.split(":")[0])})
        if fields:discrepancy("Sensitive schema fields","Review classification of: "+", ".join(fields[:16]),r)
    return diffs

def matrix(rows):
    groups=defaultdict(list)
    for r in rows:
        if r["kind"]=="observed":groups[(r["origin"],r["method"],r["route"])].append(r)
    result=[]
    for (origin,method,path),rs in groups.items():
        outcomes=defaultdict(set)
        for r in rs:
            if any(r["labels"].values()) and r["statuses"]:
                context=tuple(r["labels"].get(k,"") for k in TAGS)
                outcomes[context].update(r["statuses"])
        result.append(dict(operation=method+" "+origin+path,evidence=[r["id"] for r in rs],
                           different=len({frozenset(s) for s in outcomes.values()})>1))
    return result

def questions(rows,diffs,flows):
    byid={r["id"]:r for r in rows};questions=[]
    def add(category,description,ids,missing,alternate,subject=""):
        ids=list(dict.fromkeys(ids));ops=sorted({r["method"]+" "+r["origin"]+r["route"] for i in ids if (r:=byid.get(i))})
        questions.append(dict(id=id_for(category,subject,ids),category=category,description=description,operations=ops,evidence=ids,
          contradictions="",assumptions=alternate,missing=missing,validation="Which policy, specification revision, or existing audit record resolves this question?",
          status="Unreviewed",notes=""))
    for m in matrix(rows):
        rs=[byid[i] for i in m["evidence"]]
        def labeled(k):return {r["labels"].get(k) for r in rs if r["labels"].get(k)}
        if labeled("ownership") and any(r["identifiers"] or r["spec_ids"] and byid[r["spec_ids"][0]]["identifiers"] for r in rs):
            add("Object-level authorization","Which documented ownership rule applies to these recorded objects?",m["evidence"],"Authoritative object ownership policy.","Object labels are supplied by the reviewer.")
        if len(labeled("role"))>1:
            add("Function-level authorization","Does the role policy explain the recorded outcomes?",m["evidence"],"Approved role-to-operation mapping.","Different request states may account for different outcomes.")
        if len(labeled("tenant"))>1:
            add("Multi-tenant isolation","Which tenant boundary does each recorded context represent?",m["evidence"],"Tenant policy and audit records.","Labels alone do not establish access across tenants.")
        if len(labeled("role"))>1 and len({tuple(sorted(r["fields"])) for r in rs})>1:
            add("Property-level authorization","Are the different recorded response shapes documented for these roles?",m["evidence"],"Field visibility contract.","Optional fields or data differences may explain the shapes.")
    for d in diffs:
        if d["type"]=="Sensitive schema fields":
            add("Sensitive data exposure","What disclosure policy applies to these field names?",d["evidence"],d["detail"],"A field name is not evidence that a sensitive value was disclosed.")
        if d["type"]=="Authentication declaration difference":
            add("Authentication consistency","Which authentication contract applies to this capture?",d["evidence"],d["detail"],"Imported specifications or redacted captures may be incomplete.")
    for flow in flows:
        prev=None
        for step in flow["steps"]:
            keys=step["evidence"]
            if not step["role"] or not keys:
                add("Workflow authorization",flow["title"]+" / "+step["title"]+": which role and evidence document this step?",keys,"Role or captured operation is missing.","The documented workflow may be incomplete.",step["id"])
            if prev and prev["after"] and step["before"] and prev["after"]!=step["before"]:
                add("State transition consistency",flow["title"]+": is there an intermediate documented state?",prev["evidence"]+keys,
                    prev["after"]+" → "+step["before"],"Other workflow steps may exist.",step["id"])
            prev=step
    return questions

def portable(project,artifacts,rows,diffs,mat,flows,hyp):
    return dict(schema_version=1,project=project,sources=artifacts,observations=rows,comparison=diffs,authorization_matrix=mat,workflows=flows,hypotheses=hyp)

def markdown(filename,data):
    rows={r["id"]:r for r in data["observations"]}
    def anchor(i):
        r=rows[i];return f"{i} · {r['file']} {r['ref']} · {r['timestamp']}"
    out=["# "+filename[:-3].replace("_"," ").title(),data["project"]["name"],"Exported "+data["exported_at"],"Offline records. Scope classifications reflect the imported policy only."]
    if filename in (EXPORTS[0],EXPORTS[2]):
        for r in rows.values():
            out+=[r["method"]+" "+r["origin"]+r["route"],r["kind"]+" · "+r["scope"]+" · "+anchor(r["id"])]
            if filename==EXPORTS[0]:
                for k in ("query","headers","content_types","statuses","fields","auth","warnings"):
                    if r[k]:out.append(k.replace("_"," ").capitalize()+": "+", ".join(r[k]))
            if filename==EXPORTS[2]:
                out+=["Resource names: "+", ".join(r["resources"]),"Identifiers: "+", ".join(r["identifiers"]),"Authentication metadata: "+", ".join(r["auth"])]
        if filename==EXPORTS[2]:
            out.extend(d["type"]+" · "+d["detail"]+" · "+", ".join(d["evidence"]) for d in data["comparison"])
    elif filename==EXPORTS[1]:
        for m in data["authorization_matrix"]:
            out.append(m["operation"])
            for i in m["evidence"]:
                r=rows[i];out+=[" · ".join(r["labels"].get(k,"") or "Unlabeled" for k in TAGS)+" · "+", ".join(r["statuses"])+" · "+anchor(i)]
    elif filename==EXPORTS[3]:
        for q in data["hypotheses"]:
            out.extend([q["category"]+" · "+q["id"],q["description"],"Operations: "+", ".join(q["operations"]),
                *[k.title()+": "+(q[k] or "Not recorded") for k in ("status","contradictions","assumptions","missing","validation","notes")],
                *[anchor(i) for i in q["evidence"]]])
    elif filename==EXPORTS[4]:
        for w in data["workflows"]:
            out.append(w["title"]+" · "+w["id"]+" · "+w["updated"])
            for i,s in enumerate(w["steps"],1):
                out.extend([f"{i}. "+s["title"]+" · "+s["role"]+" · "+s["before"]+" → "+s["after"],*[anchor(j) for j in s["evidence"]]])
    out.append("Source register")
    for a in data["sources"]:
        out.append(f"{a['file']} · {a['format']} · {a['timestamp']} · SHA-256 {a['sha256']}"+(" · "+a["response_file"]+" · response SHA-256 "+a["response_hash"] if a["response_hash"] else ""))
    # Treat operator notes and imported strings as literal text even in Markdown readers.
    return out[0]+"\n\n"+"\n\n".join("\n".join("    "+line for line in v.splitlines()) for v in out[1:])+"\n"
