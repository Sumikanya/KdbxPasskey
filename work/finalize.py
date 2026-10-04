from pathlib import Path
import hashlib
import shutil
import zipfile

root=Path(__file__).resolve().parents[1]
dist=root/'dist'
for name in ['README.md','VALIDATION.md','OPTIMIZATION.md']:
    shutil.copy2(root/name,dist/name)
source_zip=dist/'KdbxPasskey-source.zip'
with zipfile.ZipFile(source_zip,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for path in (root/'source').rglob('*'):
        relative=path.relative_to(root)
        if not path.is_file() or any(p in {'build','bin','obj','.git','__pycache__'} for p in relative.parts):
            continue
        z.write(path,str(relative).replace('\\','/'))
    for name in ['README.md','VALIDATION.md','Build.ps1','NuGet.Config','OPTIMIZATION.md','LICENSE','NOTICE.md','BUILDING.md','CONTRIBUTING.md','SECURITY.md','.gitignore','.gitattributes']:
        z.write(root/name,name)
    for path in (root/'docs').rglob('*'):
        if path.is_file(): z.write(path,str(path.relative_to(root)).replace('\\','/'))
    for name in ['assemble.py','collect_notices.py','create_certificate.py','sign_ephemeral.py','verify_package.py','download_sdk.py','check_frozen_backend.py','check_desktop.py','finalize.py']:
        z.write(root/'work'/name,'work/'+name)
hashes=[]
for path in sorted(dist.iterdir()):
    if path.is_file() and path.name!='SHA256SUMS.txt':
        hashes.append(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name)
(dist/'SHA256SUMS.txt').write_text('\n'.join(hashes)+'\n',encoding='utf-8')
with zipfile.ZipFile(source_zip) as z:
    assert not any(name.endswith('.pfx') or '/obj/' in name or '/build/' in name for name in z.namelist())
print('Source kit, instructions, validation and SHA-256 checksums written')
for path in sorted(dist.iterdir()):
    if path.is_file():
        print(f'{path.name}: {path.stat().st_size:,} bytes')
