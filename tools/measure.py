"""Run the local fixture workflow, sample process-tree RSS, then verify persistence."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time

import httpx
import psutil

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def run(entries):
    with tempfile.TemporaryDirectory() as temp:
        log = Path(temp) / "server.log"
        with log.open("w", encoding="utf8") as stream:
            server = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "0"],
                cwd=ROOT, env={**os.environ, "APIMAPPER_DATA":temp},
                stdout=stream, stderr=subprocess.STDOUT,
            )
            try:
                process = psutil.Process(server.pid)
                cpus = None
                if hasattr(process,"cpu_affinity"):
                    ids = process.cpu_affinity()[:2]
                    process.cpu_affinity(ids)
                    cpus = len(ids)
                for _ in range(200):
                    match = re.search(r"http://127\.0\.0\.1:\d+",log.read_text(encoding="utf8"))
                    if match or server.poll() is not None:
                        break
                    time.sleep(0.05)
                if not match:
                    raise RuntimeError(log.read_text(encoding="utf8"))
                with httpx.Client(base_url=match[0], trust_env=False, timeout=60) as client:
                    page = client.get("/")
                    page.raise_for_status()
                    token = re.search(r'name="csrf" value="([^"]+)"',page.text)[1]
                    reply = client.post("/projects",data={"csrf":token,"name":"Benchmark"})
                    assert reply.status_code == 303, reply.text
                    project = reply.headers["location"].split("?")[0]
                    base = process.memory_info().rss
                    samples = [base]
                    stop = threading.Event()

                    def sample():
                        while not stop.is_set():
                            size = 0
                            for p in [process,*process.children(recursive=True)]:
                                try:
                                    size += p.memory_info().rss
                                except psutil.NoSuchProcess:
                                    pass
                            samples.append(size)
                            stop.wait(0.01)

                    monitor = threading.Thread(target=sample)
                    monitor.start()
                    try:
                        har = json.loads((EXAMPLES/"archive.har").read_bytes())
                        original = har["log"]["entries"]
                        har["log"]["entries"] = [original[i%len(original)] for i in range(entries)]
                        start = time.perf_counter()
                        for fmt,name,data in [("OpenAPI JSON","archive.openapi.json",(EXAMPLES/"archive.openapi.json").read_bytes()),
                                              ("HAR 1.2","benchmark.har",json.dumps(har).encode())]:
                            reply = client.post(project+"/import",data={"format":fmt,"csrf":token},files={"file":(name,data)})
                            assert reply.status_code == 303, reply.text
                        for tab in (1,2,3,5):
                            client.get(project,params={"tab":tab}).raise_for_status()
                        export = client.get(project+"/export/api-inventory.json")
                        export.raise_for_status()
                        inventory = export.json()
                        assert len(inventory["observations"]) == entries+3
                        row = next(r for r in inventory["observations"] if r["kind"]=="observed")
                        reply = client.post(project+"/o/"+row["id"]+"/labels",data={"csrf":token,"role":"Fixture role"})
                        assert reply.status_code == 303, reply.text
                        elapsed = time.perf_counter()-start
                    finally:
                        stop.set()
                        monitor.join()
            finally:
                server.terminate()
                server.wait(timeout=15)
        # A fresh interpreter opens the same database and regenerates the inventory.
        check = "from app import db,snapshot\nimport sys\nwith db() as c: d=snapshot(c,sys.argv[1])\nassert any(r['labels'].get('role')=='Fixture role' for r in d['observations'])"
        subprocess.run([sys.executable,"-c",check,project.split("/")[-1]],cwd=ROOT,
                       env={**os.environ,"APIMAPPER_DATA":temp},check=True)
        return dict(platform=platform.system(),python=platform.python_version(),affinity_cpus=cpus,
                    captures=entries,records=entries+3,idle_rss_mib=round(base/2**20,1),
                    sampled_peak_tree_rss_mib=round(max(samples)/2**20,1),samples=len(samples),
                    elapsed_seconds=round(elapsed,2),sqlite_kib=round((Path(temp)/"inventory.sqlite3").stat().st_size/1024,1),
                    reopened_label=True)


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--entries",type=int,default=250,choices=range(1,998),metavar="1..997")
    print(json.dumps(run(cli.parse_args().entries),indent=2))
