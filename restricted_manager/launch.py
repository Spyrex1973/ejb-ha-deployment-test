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
os.chdir(dest)
os.execv(sys.executable,[sys.executable,'-u',str(dest/'manager.py')])
