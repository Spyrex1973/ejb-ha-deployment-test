import json, os, re, time
from pathlib import Path

def unescape(value):
    return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)

def mounts(lines):
    for line in lines:
        f=line.split()
        if len(f)<10 or "-" not in f: continue
        sep=f.index("-")
        if sep+3>=len(f): continue
        yield {"device":f[2],"root":unescape(f[3]),"mount":unescape(f[4]),"rw":"rw" in f[5].split(",") and "rw" in f[sep+3].split(",")}

def related(a,b):
    if a["device"]!=b["device"]: return False
    x,y=Path(a["root"]),Path(b["root"])
    return x.is_relative_to(y) or y.is_relative_to(x)

def inspect():
    report={"schema":2,"timestamp":time.time(),"complete":False,"processes":0,"denied":0,"media_mounts":[],"samba_processes":[],"uid":os.getuid()}
    all_mounts=[]
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal(): continue
        try:
            status=dict(line.split(":",1) for line in (p/"status").read_text().splitlines() if ":" in line)
            credentials={k:status.get(k,"").strip() for k in ("Uid","Gid","Groups","CapEff")}
            name=status.get("Name","").strip()
            if name in ("smbd","samba"): report["samba_processes"].append(int(p.name))
            for m in mounts((p/"mountinfo").read_text().splitlines()):
                all_mounts.append(dict(m,pid=int(p.name),credentials=credentials))
            report["processes"]+=1
        except (OSError,UnicodeError): report["denied"]+=1
    seeds=[m for m in all_mounts if any(re.search(r"(^|/)media(/|$)",m[k]) for k in ("root","mount"))]
    report["media_mounts"]=[m for m in all_mounts if any(related(m,s) for s in seeds)]
    report["limitations"]=["Host namespace identity not independently established","Alias candidates require host inode confirmation","SMB sessions and ACLs not established","Credentials and mount flags do not prove effective write access"]
    return report

if __name__=="__main__":
    print(json.dumps(inspect()),flush=True)
