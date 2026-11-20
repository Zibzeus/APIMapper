"""One bounded process per import. No networking or input-controlled commands."""
import sys
import os
def memory_limit(size):
    if sys.platform.startswith("linux"):
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(size,size))
    elif os.name=="nt":
        import ctypes as c
        from ctypes import wintypes as w
        class Basic(c.Structure):
            _fields_=[("process_time",c.c_int64),("job_time",c.c_int64),("flags",w.DWORD),("min_ws",c.c_size_t),("max_ws",c.c_size_t),("active",w.DWORD),("affinity",c.c_size_t),("priority",w.DWORD),("schedule",w.DWORD)]
        class Extended(c.Structure):
            _fields_=[("basic",Basic),("io",c.c_uint64*6),("process_memory",c.c_size_t),("job_memory",c.c_size_t),("peak_process",c.c_size_t),("peak_job",c.c_size_t)]
        k=c.WinDLL("kernel32",use_last_error=True)
        k.CreateJobObjectW.restype=w.HANDLE
        k.SetInformationJobObject.argtypes=(w.HANDLE,c.c_int,c.c_void_p,w.DWORD)
        k.AssignProcessToJobObject.argtypes=(w.HANDLE,w.HANDLE)
        job=k.CreateJobObjectW(None,None);info=Extended();info.basic.flags=0x100;info.process_memory=size
        if not job or not k.SetInformationJobObject(job,9,c.byref(info),c.sizeof(info)) or not k.AssignProcessToJobObject(job,w.HANDLE(-1)):
            raise RuntimeError("Cannot enforce parser memory limit.")
    else:raise RuntimeError("A supported memory limiter requires Linux or Windows.")

if __name__=="__main__":
    import json,base64
    try:
        memory_limit(int(sys.argv[1]))
        def offline(event,args):
            if event.startswith("socket."):
                raise PermissionError("Network unavailable in the artifact parser.")
        sys.addaudithook(offline)
        from artifacts import parse_artifact, Invalid,need
        job=json.load(sys.stdin.buffer)
        rows,warnings=parse_artifact(job["fmt"],base64.b64decode(job["raw"]),base64.b64decode(job["second"]),job["key"],job["origin"],job["limit"])
        body=json.dumps(dict(rows=rows,warnings=warnings),allow_nan=False)
        need(len(body)<8*1024**2,"Normalized metadata exceeds output limit.")
        print(body)
    except Exception as e:
        print(json.dumps({"error":str(e) if type(e).__name__=="Invalid" else "Malformed or unsupported artifact, or parser resource limit reached."}))
