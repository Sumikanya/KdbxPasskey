from pathlib import Path
import importlib.metadata as metadata
import shutil
import zipfile
import xml.etree.ElementTree as ET

root=Path(__file__).resolve().parents[1]
out=root/'work/package-native/ThirdPartyLicenses'
out.mkdir(parents=True,exist_ok=True)
notices=['KDBX Passkey 0.2.7 - Third-party notices\n',
         'Windows provider: KeePassPasskey, Copyright 2026 Uwe Koegel, GPL-3.0-or-later.\n',
         'Source: https://github.com/yusei36/KeePassPasskey\n']
for dist in metadata.distributions():
    name=dist.metadata.get('Name','unknown')
    notices.append(f'Python distribution: {name} {dist.version}; License: {dist.metadata.get("License-Expression", dist.metadata.get("License", "see included license"))}\n')
    for file in dist.files or []:
        basename=Path(str(file)).name.lower()
        if basename.startswith(('license','licence','copying')) or '/licenses/' in str(file):
            src=Path(dist.locate_file(file))
            if src.is_file():
                dest=out/'Python'/name/Path(str(file)).name
                dest.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(src,dest)
ns={'n':'http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd'}
for package in (root/'work/nuget-packages').rglob('*.nupkg'):
    with zipfile.ZipFile(package) as z:
        nuspec=next((n for n in z.namelist() if n.endswith('.nuspec')),None)
        if not nuspec: continue
        doc=ET.fromstring(z.read(nuspec))
        # NuSpec schema versions differ; match the local-name instead.
        values={e.tag.split('}')[-1]:e.text for e in doc.iter() if e.text and not list(e)}
        name=values.get('id',package.stem)
        notices.append(f'.NET package: {name} {values.get("version", "")}; License: {values.get("license",values.get("licenseUrl","see package"))}\n')
        for file in z.namelist():
            if Path(file).name.lower().startswith(('license','licence','copying','third-party','thirdparty')):
                dest=out/'DotNet'/name/Path(file).name
                dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes(z.read(file))
for name in ['LICENSE.txt','ThirdPartyNotices.txt']:
    path=root/'work/dotnet'/name
    if path.exists(): shutil.copy2(path,out/('DotNetRuntime-'+name))
python_license=Path(__import__('sys').base_prefix)/'LICENSE.txt'
if python_license.exists(): shutil.copy2(python_license,out/'PythonRuntime-LICENSE.txt')
shutil.copy2(root/'source/desktop/LICENSE-WPF-UI.txt',out/'WPF-UI-LICENSE.txt')
(root/'work/package-native/THIRD_PARTY_NOTICES.txt').write_text(''.join(notices),encoding='utf-8')
print('Third-party license notices collected')
