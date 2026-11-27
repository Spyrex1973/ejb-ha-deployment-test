import urllib.request
import base64, hashlib, io, json, pathlib, stat, zipfile, os, sys
root=pathlib.Path('/share/ejb_music_reports/deployment_manager')
opts=json.loads(pathlib.Path('/data/options.json').read_text())
pin=opts['sha256']
policy=json.loads((root/'staging/distribution_policy.json').read_text())
if policy.get('production_activation') is not False or policy.get('probe_recovery') is not False: raise SystemExit('policy denied')
p=root/'staging/manager.zip.b64'
if p.stat().st_size>2000000: raise SystemExit('size limit')
b=base64.b64decode(p.read_bytes(),validate=True)
if hashlib.sha256(b).hexdigest()!=pin or len(pin)!=64: raise SystemExit('digest mismatch')
dest=pathlib.Path('/tmp/verified_manager')
dest.mkdir(exist_ok=False)
with zipfile.ZipFile(io.BytesIO(b)) as z:
    seen=set(); total=0
    for i in z.infolist():
        path=pathlib.PurePosixPath(i.filename)
        if path.is_absolute() or '..' in path.parts or '\\' in i.filename or i.filename in seen or stat.S_ISLNK(i.external_attr>>16): raise SystemExit('unsafe archive')
        seen.add(i.filename); total+=i.file_size
        if total>5000000 or len(seen)>200: raise SystemExit('archive limit')
        if len(path.parts)==2 and path.parts[0]=='ejb_deployment_manager' and path.suffix=='.py' and not path.name.startswith('test_'):
            (dest/path.name).write_bytes(z.read(i))
    if z.testzip() is not None: raise SystemExit('CRC failure')
# No source mount or API privileges. Only manager's status loop and stage validation are enabled.
if opts.get('enable_transfer') is not False or opts.get('enable_probe_recovery') is not False: raise SystemExit('activation denied')
print('Verified restricted manager package '+pin,flush=True)
# Read-only authentication acceptance; never print token or response body.
token=os.environ.get('SUPERVISOR_TOKEN','')
if not token: raise SystemExit('API token absent')
req=urllib.request.Request('http://supervisor/core/api/',headers={'Authorization':'Bearer '+token})
with urllib.request.urlopen(req,timeout=10) as response:
    if response.status!=200: raise SystemExit('Core API authentication failed')
print('Authenticated Core API GET passed',flush=True)
# Fixed read-only Supervisor metadata probe.
for endpoint, label in [('/addons/d255f66c_rollback_probe/info','probe'),('/backups/ad107ff0/info','backup')]:
    req=urllib.request.Request('http://supervisor'+endpoint,headers={'Authorization':'Bearer '+token})
    with urllib.request.urlopen(req,timeout=15) as response:
        data=json.load(response)
    if data.get('result')!='ok': raise SystemExit('Supervisor metadata rejected')
    d=data['data']
    if label=='probe':
        print('Supervisor probe metadata: '+json.dumps({k:d.get(k) for k in ('slug','version','state')}),flush=True)
    else:
        print('Supervisor backup metadata: '+json.dumps({k:d.get(k) for k in ('slug','type','addons','folders','homeassistant','protected')}),flush=True)
# Fail closed: recovery remains disabled until broker acceptance.
# Run the ordinary controller without privileged environment or inherited groups.
import subprocess
os.chdir(dest)
if os.geteuid() != 0:
    raise SystemExit('launcher requires root for privilege separation')
# Candidate uses a dedicated non-root numeric identity; report permissions
# must be validated in the installed container before release.
for entry in dest.iterdir():
    entry.chmod(0o444)
dest.chmod(0o555)
child = subprocess.Popen(
    [sys.executable, '-u', str(dest/'manager.py')],
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'},
    user=65532, group=65532, extra_groups=[], close_fds=True,
    umask=0o077)
raise SystemExit(child.wait())

