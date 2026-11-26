import hashlib, json, pathlib, zipfile, io, base64, stat, time
ROOT=pathlib.Path('/share/ejb_music_reports/deployment_manager/staging')
def validate():
    p=json.loads((ROOT/'distribution_policy.json').read_text())
    if p.get('production_activation') is not False or p.get('probe_recovery') is not False: raise ValueError('activation prohibited')
    pin=json.loads(pathlib.Path('/data/options.json').read_text())['sha256']
    if len(pin)!=64 or any(c not in '0123456789abcdef' for c in pin): raise ValueError('trusted pin missing')
    f=ROOT/'manager.zip.b64'
    if f.stat().st_size>2000000: raise ValueError('size limit')
    b=base64.b64decode(f.read_bytes(),validate=True)
    if hashlib.sha256(b).hexdigest()!=pin: raise ValueError('digest mismatch')
    with zipfile.ZipFile(io.BytesIO(b)) as z:
        seen=set(); total=0
        for i in z.infolist():
            path=pathlib.PurePosixPath(i.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in i.filename or i.filename in seen or stat.S_ISLNK(i.external_attr>>16): raise ValueError('unsafe member')
            seen.add(i.filename); total+=i.file_size
            if total>5000000 or len(seen)>200: raise ValueError('archive limit')
        if 'ejb_deployment_manager/manager.py' not in seen: raise ValueError('manager missing')
        if z.testzip() is not None: raise ValueError('CRC failure')
    print('VALIDATED private package SHA256 '+pin,flush=True)
while True:
    try: validate()
    except Exception as e: print('HOLD '+type(e).__name__+': '+str(e),flush=True)
    time.sleep(60)
