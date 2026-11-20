import base64
from contextlib import contextmanager
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
from uuid import uuid4
from fastapi import FastAPI,Request
from fastapi.responses import RedirectResponse,PlainTextResponse,Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.concurrency import run_in_threadpool
from artifacts import Invalid,need,json_doc
from analysis import TAGS,STATES,EXPORTS,classify,scope_rules,reconcile,matrix,questions,portable,markdown,id_for

BASE=Path(__file__).resolve().parent
DATA=Path(os.getenv("APIMAPPER_DATA") or Path(os.getenv("LOCALAPPDATA") or os.getenv("XDG_DATA_HOME") or Path.home()/".local/share")/"apimapper-lite")
DATA.mkdir(exist_ok=True,parents=True,mode=0o700)
def setting(k,default,low,high):
    val=int(os.getenv("APIMAPPER_"+k,default));need(low<=val<=high,f"Invalid APIMAPPER_{k}.");return val
SIZE=setting("FILE_MIB",2,1,16)<<20
MEM=setting("MEMORY_MIB",192,64,512)<<20
TIME=setting("SECONDS",12,1,90)
LIMIT=setting("RECORDS",1000,1,4000)
IMPORT=threading.BoundedSemaphore(1)
TOKEN=secrets.token_urlsafe(32)
FORMATS=("HAR 1.2","OpenAPI JSON","OpenAPI YAML","Postman 2.1","HTTP pair")
TABS=("Import","Endpoint explorer","Spec comparison","Authorization matrix","Workflow mapping","Hypothesis review","Export")
def uid():return uuid4().hex
def now():return datetime.now(timezone.utc).isoformat(timespec="seconds")
@contextmanager
def db(write=False):
    c=sqlite3.connect(DATA/"inventory.sqlite3");c.row_factory=sqlite3.Row
    try:
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        with c:yield c
    finally:c.close()
with db(True) as c:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,name TEXT,created TEXT,salt TEXT,scope TEXT);
    CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,p TEXT REFERENCES projects,file TEXT,format TEXT,sha256 TEXT,response_hash TEXT,response_file TEXT,timestamp TEXT,warnings TEXT);
    CREATE TABLE IF NOT EXISTS obs(id TEXT PRIMARY KEY,s TEXT REFERENCES sources,data TEXT,labels TEXT);
    CREATE INDEX IF NOT EXISTS obs_source ON obs(s);
    CREATE INDEX IF NOT EXISTS source_project ON sources(p);
    CREATE TABLE IF NOT EXISTS flows(id TEXT PRIMARY KEY,p TEXT REFERENCES projects,data TEXT);
    CREATE TABLE IF NOT EXISTS triage(p TEXT REFERENCES projects,id TEXT,data TEXT,PRIMARY KEY(p,id));
    """)
app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
app.add_middleware(TrustedHostMiddleware,allowed_hosts=["localhost","127.0.0.1"])
app.mount("/assets",StaticFiles(directory=BASE/"assets"),name="assets")
tpl=Jinja2Templates(directory=BASE/"templates")
tpl.env.globals.update(csrf=TOKEN,tabs=TABS,formats=FORMATS,tags=TAGS,states=STATES,exports=EXPORTS,size=SIZE>>20,field_keys=("host","route","method","status","context","source"))
@app.middleware("http")
async def guard(req,call_next):
    if req.method=="POST":
        n=req.headers.get("content-length","")
        cap=2*SIZE+65536 if req.url.path.endswith("/import") else 131072
        if not n.isdecimal() or len(n)>10 or int(n)>cap or "transfer-encoding" in req.headers:
            return PlainTextResponse("Fixed-length request exceeds upload budget.",413)
        if req.headers.get("sec-fetch-site")=="cross-site":return PlainTextResponse("Cross-site request refused.",403)
    res=await call_next(req)
    res.headers.update({"Content-Security-Policy":"default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"})
    return res
@app.exception_handler(Invalid)
async def error(req,exc):return tpl.TemplateResponse(req,"error.html",dict(message=str(exc)),status_code=400)

def token(form):need(form.get("csrf")==TOKEN,"Expired or invalid form. Reload the page.")
def text(form,k,limit=200):
    v=form.get(k,"");need(isinstance(v,str) and len(v)<=limit,"Invalid or oversized "+k)
    v=re.sub(r"(?i)\b(?:bearer|basic)\s+\S+","[masked]",v.strip())
    v=re.sub(r"(?im)\b(authorization|cookie|password|token|api[-_]?key|secret)\s*[:=][^\r\n]*",r"\1: [masked]",v)
    return re.sub(r"\b[\w.+-]+@[\w.-]+\.[\w-]+\b","[masked-email]",v)
def project(c,p):
    r=c.execute("SELECT * FROM projects WHERE id=?",(p,)).fetchone();need(r,"Project not found.");return dict(r)
def back(p,t):return RedirectResponse(f"/p/{p}?tab={t}",303)
def sources(c,p):return [{**dict(x),"warnings":json.loads(x["warnings"])} for x in c.execute("SELECT * FROM sources WHERE p=? ORDER BY rowid",(p,))]
def snapshot(c,p):
    pr=project(c,p);pr.pop("salt");scope=json.loads(pr.pop("scope"));pr["scope"]=scope
    arts=sources(c,p);rows=[]
    for a in arts:
        for x in c.execute("SELECT * FROM obs WHERE s=? ORDER BY rowid",(a["id"],)):
            r=dict(json.loads(x["data"]),id=x["id"],source=a["id"],format=a["format"],file=a["file"],timestamp=a["timestamp"],labels=json.loads(x["labels"]))
            r["scope"]=classify(r,scope["rules"]) if not r.get("scope_ambiguous") else "Unknown / requires review"
            rows.append(r)
    diffs=reconcile(rows);mat=matrix(rows)
    flows=[json.loads(x[0]) for x in c.execute("SELECT data FROM flows WHERE p=? ORDER BY rowid",(p,))]
    pending=questions(rows,diffs,flows)
    saved={x["id"]:json.loads(x["data"]) for x in c.execute("SELECT * FROM triage WHERE p=?",(p,))}
    # Keep triaged questions and their evidence even if later labels change the trigger.
    for q in pending:
        prior=saved.pop(q["id"],None)
        if prior:q.update({k:prior[k] for k in ("status","notes","contradictions","updated")})
    for q in saved.values():q["trigger"]="Historical; no longer suggested by current records";pending.append(q)
    return portable(pr,arts,rows,diffs,mat,flows,pending)

@app.get("/")
def home(request:Request):
    with db() as c:return tpl.TemplateResponse(request,"home.html",dict(projects=c.execute("SELECT id,name,created FROM projects ORDER BY rowid DESC").fetchall()))
@app.post("/projects")
async def create(req:Request):
    async with req.form(max_files=0,max_fields=3) as f:token(f);name=text(f,"name",180)
    need(name,"Enter a project name.");p=uid()
    with db(True) as c:c.execute("INSERT INTO projects VALUES(?,?,?,?,?)",(p,name,now(),secrets.token_hex(32),json.dumps({"rules":[],"reference":"","updated":""})))
    return back(p,0)

def readfile(form,k):
    item=form.get(k);need(hasattr(item,"file") and item.filename,"Choose the required file.")
    name=item.filename;need(re.fullmatch(r"[\w .()-]{1,160}",name) and name not in (".",".."),"Use a plain filename.")
    raw=item.file.read(SIZE+1);need(0<len(raw)<=SIZE,"Artifact is empty or exceeds the file limit.")
    return name,raw
def ingest(p,form):
    fmt=form.get("format");need(fmt in FORMATS,"Unsupported format; native ARTEX traffic schema is not verified.")
    name,raw=readfile(form,"file");second_name,second=readfile(form,"response") if fmt=="HTTP pair" else ("",b"")
    with db() as c:pr=project(c,p)
    job=dict(fmt=fmt,raw=base64.b64encode(raw).decode(),second=base64.b64encode(second).decode(),key=pr["salt"],origin=text(form,"origin"),limit=LIMIT)
    try:
        proc=subprocess.run([sys.executable,str(BASE/"parse_worker.py"),str(MEM)],input=json.dumps(job).encode(),capture_output=True,timeout=TIME)
    except subprocess.TimeoutExpired as e:raise Invalid("Parsing time limit reached; nothing was saved.") from e
    need(proc.returncode==0 and proc.stdout,"Parser stopped or exceeded the memory budget.")
    result=json.loads(proc.stdout)
    if "error" in result:raise Invalid(result["error"])
    rows=result["rows"];sha=hashlib.sha256(raw).hexdigest();rh=hashlib.sha256(second).hexdigest() if second else ""
    sid=id_for(p,fmt,sha,rh,job["origin"])
    with db(True) as c:
        if c.execute("SELECT 1 FROM sources WHERE id=?",(sid,)).fetchone():return
        count=c.execute("SELECT count(*) FROM obs JOIN sources ON s=sources.id WHERE p=?",(p,)).fetchone()[0]
        need(count+len(rows)<=LIMIT and len(sources(c,p))<120,"Project record or source limit exceeded.")
        stored=c.execute("SELECT coalesce(sum(length(data)),0) FROM obs JOIN sources ON s=sources.id WHERE p=?",(p,)).fetchone()[0]
        need(stored+sum(len(json.dumps(r)) for r in rows)<=8*1024**2,"Project metadata exceeds 8 MiB. Use a separate project.")
        c.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)",(sid,p,name,fmt,sha,rh,second_name,now(),json.dumps(result["warnings"])))
        for i,r in enumerate(rows):c.execute("INSERT INTO obs VALUES(?,?,?,?)",(id_for(sid,i),sid,json.dumps(r),"{}"))

@app.post("/p/{p}/import")
async def upload(req:Request,p:str):
    need(IMPORT.acquire(False),"Another import is running.")
    try:
        async with req.form(max_files=2,max_fields=5,max_part_size=SIZE) as f:
            token(f);await run_in_threadpool(ingest,p,f)
    finally:IMPORT.release()
    return back(p,1)

@app.post("/p/{p}/scope")
async def scope(req:Request,p:str):
    async with req.form(max_files=1,max_fields=5) as f:
        token(f);file,raw=readfile(f,"file");ref=text(f,"reference")
        need(ref and f.get("approved")=="yes","Record an approved scope reference.")
        try:obj=json_doc(raw)
        except (ValueError,RecursionError):raise Invalid("Invalid scope JSON.")
        with db(True) as c:
            pr=project(c,p)
            c.execute("UPDATE projects SET scope=? WHERE id=?",(json.dumps(dict(rules=scope_rules(obj,pr["salt"]),reference=ref,file=file,sha256=hashlib.sha256(raw).hexdigest(),updated=now())),p))
    return back(p,0)

@app.get("/p/{p}")
def dashboard(request:Request,p:str,tab:int=0,page:int=1):
    need(tab in range(len(TABS)) and page>=1,"Unknown view or page.")
    with db() as c:d=snapshot(c,p)
    flt={k:request.query_params.get(k,"").casefold() for k in ("host","route","method","status","context","source")}
    def matches(r):
        vals=[r["origin"],r["route"]+" "+r["path"],r["method"]," ".join(r["statuses"])," ".join([*r["auth"],*r["labels"].values()]),r["format"]+" "+r["file"]]
        return all(q in v.casefold() for q,v in zip(flt.values(),vals))
    allrows=d["observations"];shown=[r for r in allrows if matches(r)]
    from urllib.parse import urlencode
    return tpl.TemplateResponse(request,"dashboard.html",dict(d=d,p=d["project"],tab=tab,rows=shown[(page-1)*50:page*50],rowcount=len(shown),page=page,
        flt=flt,query=urlencode(dict(tab=tab,**flt)),lookup={r["id"]:r for r in allrows}))

@app.get("/p/{p}/o/{oid}")
def detail(request:Request,p:str,oid:str):
    with db() as c:d=snapshot(c,p)
    r=next((r for r in d["observations"] if r["id"]==oid),None);need(r,"Observation not found in this project.")
    a=next(a for a in d["sources"] if a["id"]==r["source"])
    return tpl.TemplateResponse(request,"detail.html",dict(p=d["project"],r=r,a=a))

@app.post("/p/{p}/o/{oid}/labels")
async def labels(req:Request,p:str,oid:str):
    async with req.form(max_files=0,max_fields=8) as f:
        token(f);v={k:text(f,k,80) for k in TAGS}
    with db(True) as c:
        need(c.execute("UPDATE obs SET labels=? WHERE id=? AND s IN (SELECT id FROM sources WHERE p=?) AND json_extract(data,'$.kind')='observed'",(json.dumps(v),oid,p)).rowcount,"Select recorded traffic in this project.")
    return back(p,3)

@app.post("/p/{p}/workflow")
async def workflow(req:Request,p:str):
    async with req.form(max_files=0,max_fields=24) as f:
        token(f);flowid=text(f,"flow_id");title=text(f,"title")
        with db(True) as c:
            project(c,p)
            if not flowid:
                need(title and c.execute("SELECT count(*) FROM flows WHERE p=?",(p,)).fetchone()[0]<40,"Enter a workflow title; maximum 40 workflows.")
                flow=dict(id=uid(),title=title,steps=[],updated=now())
                c.execute("INSERT INTO flows VALUES(?,?,?)",(flow["id"],p,json.dumps(flow)))
            else:
                record=c.execute("SELECT data FROM flows WHERE p=? AND id=?",(p,flowid)).fetchone();need(record,"Unknown workflow.")
                flow=json.loads(record[0]);ids=list(dict.fromkeys(f.getlist("evidence")))
                need(title and len(ids)<=16 and len(flow["steps"])<80,"Enter a step; maximum 16 references and 80 steps.")
                for oid in ids:need(c.execute("SELECT 1 FROM obs JOIN sources ON obs.s=sources.id WHERE p=? AND obs.id=?",(p,oid)).fetchone(),"Foreign evidence reference.")
                flow["updated"]=now();flow["steps"].append(dict(id=uid(),title=title,role=text(f,"role"),before=text(f,"before"),after=text(f,"after"),evidence=ids))
                c.execute("UPDATE flows SET data=? WHERE p=? AND id=?",(json.dumps(flow),p,flowid))
    return back(p,4)

@app.post("/p/{p}/q/{qid}")
async def triage(req:Request,p:str,qid:str):
    async with req.form(max_files=0,max_fields=5) as f:
        token(f);status=f.get("status");need(status in STATES,"Invalid research status.")
        with db(True) as c:
            q=next((q for q in snapshot(c,p)["hypotheses"] if q["id"]==qid),None);need(q,"Unknown research question.")
            q.update(status=status,notes=text(f,"notes",2000),contradictions=text(f,"contradictions",2000),updated=now())
            c.execute("INSERT OR REPLACE INTO triage VALUES(?,?,?)",(p,qid,json.dumps(q)))
    return back(p,5)

@app.get("/p/{p}/export/{filename}")
def export(p:str,filename:str):
    need(filename in EXPORTS,"Unknown export format.")
    with db() as c:d=snapshot(c,p)
    for r in d["observations"]:r.pop("segments",None)
    for rule in d["project"]["scope"]["rules"]:rule.pop("prefix",None)
    isjson=filename==EXPORTS[-1]
    d["exported_at"]=now()
    body=json.dumps(d,indent=2,ensure_ascii=False) if isjson else markdown(filename,d)
    return Response(body,media_type="application/json" if isjson else "text/markdown",headers={"Content-Disposition":f'attachment; filename="{filename}"'})
