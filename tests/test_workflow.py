"""Acceptance tests with real SQLite, multipart uploads, parser subprocesses and exports."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from artifacts import Invalid, parse_artifact
from analysis import matrix, reconcile

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


class Workspace(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        with patch.dict(os.environ, APIMAPPER_DATA=cls.temp.name):
            import app
        cls.module = app
        cls.client = TestClient(app.app, base_url="http://localhost", follow_redirects=False)
        cls.addClassCleanup(cls.client.close)
        page = cls.client.get("/")
        cls.token = re.search(r'name="csrf" value="([^"]+)"', page.text)[1]

    def post(self, path, **fields):
        return self.client.post(path, data={"csrf": self.token, **fields})

    def setUp(self):
        a = self.post("/projects", name="Contract review")
        self.assertEqual(a.status_code, 303, a.text)
        self.project = a.headers["location"].split("?")[0]

    def upload(self, fmt, file, *, response=None, content=None, origin=""):
        files = {"file": (file, (EXAMPLES / file).read_bytes() if content is None else content)}
        if response:
            files["response"] = (response, (EXAMPLES / response).read_bytes())
        return self.client.post(self.project+"/import", data={"csrf":self.token,"format":fmt,"origin":origin}, files=files)

    def inventory(self):
        res = self.client.get(self.project+"/export/api-inventory.json")
        self.assertEqual(res.status_code, 200, res.text[:300])
        return res.json()

    def okay(self, res):
        self.assertEqual(res.status_code, 303, res.text)

    def test_review_from_upload_to_portable_export(self):
        self.okay(self.upload("OpenAPI JSON", "archive.openapi.json"))
        self.okay(self.upload("HAR 1.2", "archive.har"))
        self.okay(self.upload("HAR 1.2", "archive.har"))
        d = self.inventory()
        self.assertEqual((len(d["sources"]),len(d["observations"])), (2,8))
        self.assertTrue(all(r["scope"].startswith("Unknown") for r in d["observations"]))
        har = next(a for a in d["sources"] if a["format"] == "HAR 1.2")
        self.assertEqual(har["sha256"], hashlib.sha256((EXAMPLES/"archive.har").read_bytes()).hexdigest())
        self.okay(self.client.post(self.project+"/scope", data={"csrf":self.token,"approved":"yes","reference":"Approved fixture v1"},
                                   files={"file":("scope.json",(EXAMPLES/"approved-scope.json").read_bytes())}))
        d = self.inventory()
        rs = [r for r in d["observations"] if r["kind"]=="observed"]
        self.assertEqual([r["route"] for r in rs], ["/v1/reports/{id}"]*2+["/v1/reports/me","/v1/reports/{id}","/v1/health"])
        self.assertEqual((rs[0]["scope"],rs[-1]["scope"]), ("In-scope","Out-of-scope"))
        self.assertEqual(rs[0]["locations"]["status"],"/log/entries/0/response/status")
        self.assertTrue(rs[0]["captured_at"].startswith("2026-01-12"))
        self.assertEqual(rs[0]["fields"],["id:number","email:string"])
        self.assertEqual({x["type"] for x in d["comparison"]},
                         {"Parameter difference","Documented only","Observed only","Method difference",
                          "Response status difference","Authentication declaration difference","Sensitive schema fields"})
        for row, labels in zip(rs, [("A","Owner","North","Signed in","Own"),("B","Reader","South","Anonymous","Shared")]):
            self.okay(self.post(self.project+"/o/"+row["id"]+"/labels",**dict(zip(self.module.TAGS,labels))))
        self.okay(self.post(self.project+"/workflow",title="Receipt approval"))
        flow = self.inventory()["workflows"][0]["id"]
        for fields in [dict(title="Submit",role="Owner",before="Draft",after="Submitted",evidence=rs[0]["id"]),
                       dict(title="Close",before="Approved",after="Closed")]:
            self.okay(self.post(self.project+"/workflow",flow_id=flow,**fields))
        d=self.inventory()
        self.assertTrue(any(m["different"] for m in d["authorization_matrix"]))
        self.assertEqual(len({q["category"] for q in d["hypotheses"]}),8)
        q=next(q for q in d["hypotheses"] if q["category"]=="Function-level authorization")
        self.assertEqual(set(q["evidence"]),{rs[0]["id"],rs[1]["id"]})
        self.okay(self.post(self.project+"/q/"+q["id"],status="In review",notes="Check fixture policy",contradictions="Different request states"))
        saved=next(q for q in self.inventory()["hypotheses"] if q["status"]=="In review")
        self.assertEqual(saved["contradictions"],"Different request states")
        self.assertTrue(saved["updated"])
        for tab in range(7):
            self.assertEqual(self.client.get(self.project,params={"tab":tab}).status_code,200)
        detail=self.client.get(self.project+"/o/"+rs[0]["id"])
        self.assertIn("/log/entries/0/request",detail.text)
        filtered=self.client.get(self.project,params={"tab":1,"host":"example.invalid","route":"reports","method":"GET","status":"403","context":"Reader","source":"archive.har"})
        self.assertIn("1 matches",filtered.text)
        secret_values=["synthetic-token-not-for-storage","fixture-person@example.invalid","sample-private-value","fixture-secret-441"]
        for filename in self.module.EXPORTS:
            res=self.client.get(self.project+"/export/"+filename)
            self.assertEqual(res.status_code,200)
            self.assertIn(filename,res.headers["content-disposition"])
            self.assertIn("archive.har",res.text)
            for secret in secret_values:
                self.assertNotIn(secret,res.text)
        for secret in secret_values:
            self.assertNotIn(secret.encode(), (Path(self.temp.name)/"inventory.sqlite3").read_bytes())

    def test_other_artifacts_and_project_isolation(self):
        self.okay(self.upload("HTTP pair","request.http",response="response.http",origin="https://api.example.invalid"))
        self.okay(self.upload("Postman 2.1","archive.postman.json"))
        yaml=b"openapi: 3.0.3\npaths:\n  /status:\n    get:\n      responses:\n        '200': {description: OK}\n"
        self.okay(self.upload("OpenAPI YAML","contract.yaml",content=yaml,origin="https://api.example.invalid"))
        d=self.inventory()
        self.assertEqual([r["kind"] for r in d["observations"]],["observed","collection","example","specified"])
        row=d["observations"][0]
        self.assertEqual(row["auth"],["header:x-api-key"])
        self.assertEqual(row["response_ref"],"response:line 1")
        self.assertNotIn("local-fixture-key",json.dumps(d))
        src=d["sources"][0]
        self.assertEqual(src["response_hash"],hashlib.sha256((EXAMPLES/"response.http").read_bytes()).hexdigest())
        other=self.post("/projects",name="Other").headers["location"].split("?")[0]
        self.assertEqual(self.post(other+"/o/"+row["id"]+"/labels",role="X").status_code,400)
        self.assertEqual(self.client.get(other+"/o/"+row["id"]).status_code,400)
        self.assertEqual(self.client.post("/projects",data={"name":"bad","csrf":"no"}).status_code,400)

    def test_unsupported_and_resource_limits_are_atomic(self):
        for fmt,body in [("OpenAPI JSON",b'{"swagger":"2.0"}'),("ARTEX",b"{}"),("HAR 1.2",b"{"),("OpenAPI YAML",b"test: &k [1]\nrepeat: *k")]:
            self.assertEqual(self.upload(fmt,"input.txt",content=body).status_code,400)
        with patch.object(self.module,"LIMIT",2):
            self.assertEqual(self.upload("HAR 1.2","archive.har").status_code,400)
        self.assertEqual(self.upload("HAR 1.2","large.har",content=b"a"*(self.module.SIZE+1)).status_code,400)
        self.assertEqual(self.inventory()["sources"],[])


class Readers(unittest.TestCase):
    def parse(self,fmt,raw):
        return parse_artifact(fmt,raw,b"","fixture-key","https://api.example.invalid",100)

    def test_ambiguous_routes_and_foreign_hosts(self):
        spec=json.loads((EXAMPLES/"archive.openapi.json").read_text())
        spec["paths"]={path:{"get":{"responses":{"200":{}}}} for path in ("/reports/{x}","/reports/{y}")}
        rows,_=self.parse("OpenAPI JSON",json.dumps(spec))
        har=json.loads((EXAMPLES/"archive.har").read_text())
        har["log"]["entries"][1]["request"]["url"]="https://other.invalid/v1/reports/42"
        captures,_=self.parse("HAR 1.2",json.dumps(har))
        for i,r in enumerate(rows+captures):r["id"]=str(i)
        ds=reconcile(rows+captures)
        self.assertTrue(any(d["type"]=="Ambiguous template" for d in ds))
        self.assertTrue(any(d["type"]=="Observed only" and captures[1]["id"] in d["evidence"] for d in ds))
        self.assertFalse(captures[0]["spec_ids"])

    def test_equal_context_outcomes(self):
        rows=[dict(kind="observed",origin="https://example.invalid",method="GET",route="/",id=str(i),
                   labels={"role":role},statuses=[str(status)]) for i,(role,status) in enumerate([("A",200),("B",200),("",403)])]
        self.assertFalse(matrix(rows)[0]["different"])

    def test_parser_memory_ceiling(self):
        probe="from parse_worker import memory_limit\nmemory_limit(96*2**20)\ntry: bytearray(160*2**20)\nexcept MemoryError: pass\nelse: raise AssertionError('allocation exceeded limit')"
        subprocess.run([sys.executable,"-c",probe],cwd=EXAMPLES.parent,check=True,timeout=15)

    def test_untrusted_refs_and_duplicate_keys(self):
        doc=json.loads((EXAMPLES/"archive.openapi.json").read_text())
        for ref in ("https://example.invalid/remote.json","#/components/schemas/Receipt"):
            doc["components"]["schemas"]["Receipt"]={"$ref":ref}
            _,warnings=self.parse("OpenAPI JSON",json.dumps(doc))
            self.assertTrue(any("reference omitted" in w for w in warnings))
        with self.assertRaises(Invalid):
            self.parse("HAR 1.2",b'{"log":{},"log":{}}')
