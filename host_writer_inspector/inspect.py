import json, os, re, time
from pathlib import Path

def inspect():
    report={"schema":1,"timestamp":time.time(),"complete":False,"processes":0,"denied":0,"media_mounts":[]}
    for p in Path("/proc").iterdir():
        if not p.name.isdecimal(): continue
        try:
            lines=(p/"mountinfo").read_text().splitlines()
            report["processes"]+=1
            for line in lines:
                fields=line.split()
                if len(fields)<10 or "-" not in fields: continue
                root,mount,options=fields[3:6]
                if re.search(r"(^|/)media(/|$)",root) or re.search(r"(^|/)media(/|$)",mount):
                    report["media_mounts"].append({"pid":int(p.name),"device":fields[2],"root":root,"mount":mount,"rw":"rw" in options.split(",")})
        except (OSError,UnicodeError): report["denied"]+=1
    report["limitations"]=["Host namespace identity not independently established","Mount visibility does not prove effective write access","Alias and SMB coverage not established"]
    return report

if __name__=="__main__":
    print(json.dumps(inspect()),flush=True)
