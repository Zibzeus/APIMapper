"""Offline readers. Only allowlisted metadata crosses the parser process boundary."""
import hashlib
import hmac
import json
import re
from urllib.parse import urlsplit, unquote_plus

class Invalid(ValueError): pass
def need(ok,msg):
    if not ok: raise Invalid(msg)

METHODS=set("GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT".split())
SECRET=re.compile(r"password|passwd|secret|token|cookie|authorization|api.?key|session|ssn|email|phone|address|salary",re.I)
PUBLIC=set("api rest graphql v1 v2 v3 health status accounts users orders invoices reports documents files items projects tasks profile roles permissions payments refunds approvals login logout register recovery cancel share delete admin search me list audit events catalog exports archive".split())

def name(v):
    return v if isinstance(v,str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.\[\]-]{0,79}",v) and not re.search(r"(?:sk-|ghp_|eyJ|AKIA)[A-Za-z0-9_-]{8,}",v) else "[masked-name]"

def pointer(v):
    return v.replace("~","~0").replace("/","~1")

def stamp(key,s):
    return hmac.new(key.encode(),s.encode(),hashlib.sha256).hexdigest()[:24]

def json_doc(raw):
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,"Duplicate mapping key.")
            d[k]=v
        return d
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,"Non-finite JSON number."))

def yaml_doc(raw):
    import yaml
    class Safe(yaml.SafeLoader):
        count=depth=0
        def compose_node(self,parent,index):
            self.count+=1; self.depth+=1
            need(self.count<60000 and self.depth<=64,"YAML size or nesting limit exceeded.")
            need(not self.check_event(yaml.AliasEvent) and not getattr(self.peek_event(),"anchor",None),"YAML anchors and aliases are unsupported.")
            try:return super().compose_node(parent,index)
            finally:self.depth-=1
        def construct_mapping(self,node,deep=False):
            out={}
            for k,v in node.value:
                need(isinstance(k,yaml.ScalarNode) and k.value not in out and k.value!="<<","Duplicate, complex or merged YAML key.")
                out[k.value]=self.construct_object(v,deep=deep)
            return out
    return yaml.load(raw,Loader=Safe)

def declared_route(path):
    need(isinstance(path,str) and path.startswith("/") and len(path)<=1024 and not any(x in path for x in "?#\r\n"),"Invalid specified path.")
    parts=path.split("/")
    need(all(re.fullmatch(r"[\w.~%:@+-]{0,128}|\{[\w.-]{1,64}\}",p,re.ASCII) for p in parts),"Unsupported path template. Use whole-segment path variables.")
    return parts

def address(url):
    u=urlsplit(url)
    need(u.scheme in ("http","https") and u.hostname and not u.username and not u.password,"Expected an absolute HTTP(S) URL without user information.")
    host=u.hostname.lower().rstrip(".")
    need(re.fullmatch(r"[a-z0-9.:-]{1,253}",host) and (not u.port or u.port<=65535),"Invalid hostname or port.")
    authority=("["+host+"]" if ":" in host else host)
    if u.port and (u.scheme,u.port) not in (("https",443),("http",80)):authority+=":"+str(u.port)
    return u.scheme+"://"+authority,host,u

def mime(v):
    t=str(v or "").partition(";")[0].strip().lower()
    return t if re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+",t) and len(t)<96 else ""

def header_map(rows,field="name"):
    need(isinstance(rows,list) and len(rows)<=512,"Invalid headers.")
    return {name(h.get(field,h.get("name"))).lower():str(h.get("value","")) for h in rows if isinstance(h,dict) and h.get("disabled")!=True and isinstance(h.get(field,h.get("name")),str)}

def shape(value,depth=0):
    if depth>4:return []
    if isinstance(value,dict):
        need(len(value)<=160,"Response schema has too many fields.")
        result=[]
        for k,v in value.items():
            n=name(k); typ=("null" if v is None else "boolean" if isinstance(v,bool) else "number" if isinstance(v,(int,float)) else "object" if isinstance(v,dict) else "array" if isinstance(v,list) else "string")
            result.append(n+":"+typ)
            if isinstance(v,(dict,list)):result.extend(n+"."+s for s in shape(v,depth+1))
        need(len(result)<=512,"Response schema exceeds field limit.")
        return result
    if isinstance(value,list):
        return sorted({"[]."+s for v in value[:4] for s in shape(v,depth+1)})
    return []

def traffic(key,method,url,headers,status,body,ctype,ref,kind="observed",response_ref="",bodytype=""):
    origin,host,u=address(url); method=method.upper()
    need(method in METHODS and len(u.path)<=2048,"Unsupported method or oversized path.")
    pieces=(u.path or "/").split("/")
    need(len(pieces)<=64,"Too many path segments.")
    displayed=[p if not p or p in PUBLIC or re.fullmatch("v[0-9]{1,2}",p) else "{segment:"+stamp(key,p)+"}" for p in pieces]
    query=sorted({name(unquote_plus(x.partition("=")[0])) for x in u.query.split("&") if x})
    fields=[];warnings=[]
    if body and ("json" in bodytype or body.lstrip().startswith(("{","["))):
        try:fields=shape(json_doc(body))
        except (ValueError,RecursionError):warnings.append("Response shape unavailable.")
    auth=[]
    for k in headers:
        if k=="authorization":
            scheme=headers[k].split(" ",1)[0].lower()
            auth.append(scheme if scheme in ("bearer","basic","digest") else "authorization")
        elif k=="cookie":auth.append("cookie")
        elif SECRET.search(k):auth.append("header:"+k)
    need(status is None or type(status)==int and (status==0 or 100<=status<=599),"Invalid response status.")
    candidates=[f"path segment {i} (identifier-shaped)" for i,p in enumerate(pieces) if p.isdecimal() or re.fullmatch(r"[0-9a-fA-F-]{36}",p)]
    cookies=[name(v.partition("=")[0].strip()) for v in headers.get("cookie","").split(";") if "=" in v]
    return dict(kind=kind,method=method,origin=origin,host=host,path="/".join(displayed),segments=[stamp(key,p) for p in pieces],cookie_names=cookies,
                scope_ambiguous=any(p in (".","..") or "%" in p or "\\" in p for p in pieces),
                query=query,headers=sorted(headers),content_types=[mime(ctype)] if mime(ctype) else [],statuses=[str(status)] if status else [],
                fields=fields,auth=sorted(auth),ref=ref,response_ref=response_ref or ref,identifiers=candidates+sorted(n for n in query+[f.split(":")[0] for f in fields] if re.search(r"(^id$|_id$|Id$|\.id$)",n)),
                resources=[s for s in displayed if s in PUBLIC],warnings=warnings)

def parse_artifact(fmt,raw,second,key,origin_hint,limit):
    rows=[]; warnings=[]
    def add(x):
        need(len(rows)<limit,"Artifact exceeds the record limit.")
        rows.append(x)
    if fmt=="HTTP pair":
        def message(data):
            s=data.decode("utf8").replace("\r\n","\n");head,_,body=s.partition("\n\n")
            first,*lines=head.split("\n")
            need(len(lines)<=512 and all(":" in l for l in lines),"Malformed HTTP headers.")
            return first,{name(l.split(":",1)[0]).lower():l.split(":",1)[1].strip() for l in lines},body
        req,h,_=message(raw);res,rh,b=message(second)
        m=re.fullmatch(r"([A-Z]+) (\S+) HTTP/[0-9.]+",req);n=re.fullmatch(r"HTTP/[0-9.]+ (\d{3})(?: .*)?",res)
        need(m and n,"Expected a raw HTTP request and corresponding HTTP response.")
        url=m[2]
        if url.startswith("/"):
            need(origin_hint,"A relative HTTP target requires the capture origin.")
            org,_,u=address(origin_hint)
            need(not u.query and u.path in ("","/"),"Enter an origin without a base path.")
            if h.get("host"):need(address(u.scheme+"://"+h["host"])[0]==org,"Host header conflicts with capture origin.")
            url=org+url
        rec=traffic(key,m[1],url,h,int(n[1]),b,h.get("content-type"),"request:line 1",response_ref="response:line 1",bodytype=rh.get("content-type",""))
        rec["locations"]={"target":"request:line 1","request headers":"request:header block","status":"response:line 1","schema":"response:body"}
        add(rec)
        return rows,warnings
    data=yaml_doc(raw.decode("utf8")) if fmt=="OpenAPI YAML" else json_doc(raw)
    need(isinstance(data,dict),"Expected a document mapping.")
    if fmt=="HAR 1.2":
        log=data.get("log",{})
        need(log.get("version")=="1.2" and isinstance(log.get("entries"),list),"Expected HAR 1.2.")
        for i,e in enumerate(log["entries"]):
            req=e["request"];res=e["response"];h=header_map(req.get("headers",[]));body=res.get("content",{})
            ptr=f"/log/entries/{i}"
            rec=traffic(key,req["method"],req["url"],h,res["status"],body.get("text","") if not body.get("encoding") else "",
                req.get("postData",{}).get("mimeType") or h.get("content-type"),ptr+"/request",response_ref=ptr+"/response",bodytype=body.get("mimeType",""))
            rec["query"]=sorted(set(rec["query"])|{name(x["name"]) for x in req.get("queryString",[])})
            rec["cookie_names"]=sorted(set(rec["cookie_names"])|{name(c["name"]) for c in req.get("cookies",[])})
            if rec["cookie_names"] and "cookie" not in rec["auth"]:rec["auth"].append("cookie")
            rec["locations"]={k:ptr+"/"+v for k,v in {"target":"request/url","query":"request/queryString","headers":"request/headers","status":"response/status","schema":"response/content"}.items()}
            if e.get("startedDateTime"):
                from datetime import datetime
                try:rec["captured_at"]=datetime.fromisoformat(e["startedDateTime"]).isoformat()
                except (ValueError,TypeError):rec["warnings"].append("Invalid capture timestamp.")
            if body.get("encoding"):rec["warnings"].append("Encoded response body omitted.")
            add(rec)
    elif fmt.startswith("OpenAPI"):
        need(re.fullmatch(r"3\.(0|1)\.\d+",str(data.get("openapi",""))) and isinstance(data.get("paths"),dict),"Expected OpenAPI 3.0.x or 3.1.x with paths.")
        used_refs=set()
        def resolve(obj,seen=()):
            if not isinstance(obj,dict) or "$ref" not in obj:return obj
            ref=obj["$ref"]
            if not isinstance(ref,str) or not ref.startswith("#/") or ref in seen or len(seen)>=12:
                warnings.append("External, cyclic or deep reference omitted.");return {}
            cur=data
            for tok in ref[2:].split("/"):
                if not isinstance(cur,dict) or tok.replace("~1","/").replace("~0","~") not in cur:
                    warnings.append("Unresolved local reference.");return {}
                cur=cur[tok.replace("~1","/").replace("~0","~")]
            used_refs.add(ref)
            return resolve(cur,seen+(ref,))
        schemes={k:resolve(s) for k,s in data.get("components",{}).get("securitySchemes",{}).items()}
        def schema_fields(obj,prefix="",depth=0):
            if depth>4:return []
            obj=resolve(obj);out=[]
            for k,v in obj.get("properties",{}).items():
                k=name(k);v=resolve(v); t=v.get("type","unspecified")
                types=t if isinstance(t,list) else [t]
                normalized="|".join(x for x in types if x in ("string","number","integer","boolean","object","array","null"))
                out.append(prefix+k+":"+(normalized or "unspecified"));out.extend(schema_fields(v,prefix+k+".",depth+1))
                need(len(out)<=512,"Response schema exceeds field limit.")
            if "items" in obj:out.extend(schema_fields(obj["items"],prefix+"[].",depth+1))
            return out
        for path,raw_item in data["paths"].items():
            used_refs.clear()
            declared_route(path);item=resolve(raw_item)
            item_ptr=raw_item.get("$ref","#/paths/"+pointer(path)).removeprefix("#")
            for method,op in item.items():
                if method.upper() not in METHODS:continue
                ref=item_ptr+"/"+method
                servers=op.get("servers",item.get("servers",data.get("servers",[{"url":"/"}])))
                for si,server in enumerate(servers or [{"url":"/"}]):
                    used_refs.clear()
                    s=server["url"]
                    for k,var in server.get("variables",{}).items():s=s.replace("{"+k+"}",str(var["default"]))
                    if not s.startswith(("http://","https://")):
                        need(s.startswith("/") and not s.startswith("//") and origin_hint,"Relative server URL needs an explicit capture origin.")
                        s=address(origin_hint)[0]+s
                    org,host,u=address(s);full=u.path.rstrip("/")+path;parts=declared_route(full)
                    params=[resolve(x) for x in item.get("parameters",[])+op.get("parameters",[])]
                    params=list({(x.get("in"),x.get("name")):x for x in params if x}.values())
                    query=sorted({name(x["name"]) for x in params if x.get("in")=="query"})
                    required=sorted({name(x["name"]) for x in params if x.get("in")=="query" and x.get("required")})
                    fields=set();responses=op.get("responses",{})
                    codes=[]
                    for code,resp in responses.items():
                        if str(code).startswith("x-"):continue
                        need(re.fullmatch(r"[1-5](?:[0-9]{2}|XX)|default",str(code)),"Unsupported response status declaration.")
                        codes.append(str(code))
                        for media in resolve(resp).get("content",{}).values():fields.update(schema_fields(media.get("schema",{})))
                    groups=[];auth=[]
                    for group in op.get("security",data.get("security",[])):
                        tokens=[]
                        for sn in group:
                            desc=schemes.get(sn,{});t=desc.get("type")
                            token=(str(desc.get("scheme","authorization")).lower() if t=="http" else "bearer" if t in ("oauth2","openIdConnect") else
                                   str(desc.get("in","unknown"))+":"+name(desc.get("name","")).lower() if t=="apiKey" else "unspecified")
                            if t=="http" and token not in ("bearer","basic","digest","negotiate"):token="unspecified"
                            tokens.append(token);auth.append(name(sn)+"="+token)
                        groups.append(tokens)
                    add(dict(kind="specified",origin=org,host=host,path=full,method=method.upper(),segments=[None if p.startswith("{") else stamp(key,p) for p in parts],
                        query=query,required_query=required,headers=sorted({name(x["name"]).lower() for x in params if x.get("in")=="header"}),
                        required_headers=sorted({name(x["name"]).lower() for x in params if x.get("in")=="header" and x.get("required")}),
                        required_cookies=sorted({name(x["name"]) for x in params if x.get("in")=="cookie" and x.get("required")}),
                        content_types=sorted(mime(x) for x in resolve(op.get("requestBody",{})).get("content",{})),statuses=sorted(codes),
                        auth=sorted(set(auth)),groups=groups,fields=sorted(fields),identifiers=[name(p[1:-1]) for p in parts if p.startswith("{")],
                        locations=dict(operation=ref,parameters=[s for s,cond in [(item_ptr+"/parameters","parameters" in item),(ref+"/parameters","parameters" in op)] if cond],
                            server=((ref if "servers" in op else item_ptr if "servers" in item else "")+f"/servers/{si}") if servers and ("servers" in op or "servers" in item or "servers" in data) else "operator origin",
                            security=ref+"/security" if "security" in op else "/security" if "security" in data else "undeclared",
                            referenced_definitions=sorted(used_refs)),
                        resources=[p for p in parts if p and not p.startswith("{")],ref=ref,response_ref=ref+"/responses",warnings=[]))
    elif fmt=="Postman 2.1":
        need(data.get("info",{}).get("schema") in ("https://schema.getpostman.com/json/collection/v2.1.0/collection.json","https://schema.getpostman.com/json/collection/v2.1.0/collection.json#"),"Expected Postman Collection v2.1.")
        variables={v["key"]:str(v.get("value","")) for v in data.get("variable",[]) if isinstance(v,dict) and "key" in v}
        def walk(items,ref,depth,parent_auth):
            need(isinstance(items,list) and depth<=20,"Invalid or deep collection.")
            for i,item in enumerate(items):
                ptr=ref+"/"+str(i);auth=item.get("auth",parent_auth)
                if "item" in item:walk(item["item"],ptr+"/item",depth+1,auth);continue
                req=item["request"]
                if isinstance(req,str):req={"url":req,"method":"GET"}
                u=req["url"];url=u.get("raw","") if isinstance(u,dict) else u
                if isinstance(u,dict) and not url:
                    host=u.get("host","");host=".".join(host) if isinstance(host,list) else host
                    path=u.get("path",[]);path="/".join(path) if isinstance(path,list) else path
                    url=str(u.get("protocol","https"))+"://"+host+("/"+path.lstrip("/") if path else "")
                url=re.sub(r"\{\{(\w+)\}\}",lambda m:variables.get(m[1],m[0]),url)
                if "{{" in url:warnings.append(f"{ptr}: unresolved collection variable; item skipped.");continue
                h=header_map(req.get("header",[]),"key");rec=traffic(key,req["method"],url,h,None,"",h.get("content-type"),ptr+"/request",kind="collection")
                if isinstance(u,dict):rec["query"]=sorted(set(rec["query"])|{name(q.get("key","")) for q in u.get("query",[]) if not q.get("disabled")})
                a=req.get("auth",auth)
                if isinstance(a,dict) and a.get("type")!="noauth":rec["auth"].append(name(a.get("type","")))
                add(rec)
                for j,resp in enumerate(item.get("response",[])):
                    rh=header_map(resp.get("header",[]),"key")
                    if resp.get("originalRequest") and resp["originalRequest"]!=req:
                        warnings.append(f"{ptr}/response/{j}: saved request differs from the collection request; example omitted.");continue
                    ex={**rec,"kind":"example","ref":ptr+f"/response/{j}","response_ref":ptr+f"/response/{j}","statuses":[str(int(resp["code"]))] if resp.get("code") else [],"fields":[]}
                    if resp.get("body") and "json" in rh.get("content-type",""):
                        try:ex["fields"]=shape(json_doc(resp["body"]))
                        except ValueError:ex["warnings"]=["Example body shape unavailable."]
                    add(ex)
        walk(data["item"],"/item",0,data.get("auth"))
    else:raise Invalid("Unsupported artifact format. ARTEX native import requires a verified traffic schema.")
    return rows,sorted(set(warnings))
