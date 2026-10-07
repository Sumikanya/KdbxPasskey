from pathlib import Path
import shutil
import xml.etree.ElementTree as ET

def assemble(root):
    package = root/'work'/'package-native'
    # Discard only the verified staging directory, never build outputs or signing keys.
    if package.is_symlink() or package.resolve() != root.resolve()/'work'/'package-native':
        raise RuntimeError('Unsafe package staging path')
    if package.exists():
        shutil.rmtree(package)
    package.mkdir()
    # Keep symbols in publish output for debugging; omit them from runtime payload.
    def runtime_only(folder, names):
        return [name for name in names if name.lower().endswith('.pdb')]
    shutil.copytree(root/'work'/'native-ui', package, dirs_exist_ok=True, ignore=runtime_only)
    shutil.copytree(root/'work'/'backend-python'/'KdbxBackend', package/'Backend', dirs_exist_ok=True, ignore=runtime_only)
    shutil.copytree(root/'work'/'package'/'Provider', package/'Provider', dirs_exist_ok=True, ignore=runtime_only)
    upstream = root/'source'/'upstream'
    assets = package/'Assets'
    shutil.copytree(upstream/'src'/'KeePassPasskeyProvider.Package'/'Assets', assets, dirs_exist_ok=True)
    manifest = '''<?xml version="1.0" encoding="utf-8"?>
    <Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
     xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
     xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
     xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
     IgnorableNamespaces="uap rescap com">
     <Identity Name="KdbxPasskey" Publisher="CN=KDBX Passkey Local" Version="0.2.8.0" ProcessorArchitecture="x64" />
     <Properties><DisplayName>KDBX Passkey</DisplayName><PublisherDisplayName>Local build</PublisherDisplayName><Logo>Assets\\StoreLogo.png</Logo></Properties>
     <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.26100.0" MaxVersionTested="10.0.26300.0" /></Dependencies>
     <Resources><Resource Language="zh-cn" /><Resource Language="en-us" /></Resources>
     <Applications>
      <Application Id="KdbxPasskey" Executable="KdbxPasskey.exe" EntryPoint="Windows.FullTrustApplication">
       <uap:VisualElements DisplayName="KDBX Passkey" Description="Independently unlock KDBX passkeys for Windows apps"
        BackgroundColor="transparent" Square150x150Logo="Assets\\Square150x150Logo.png" Square44x44Logo="Assets\\Square44x44Logo.png" />
       <Extensions><com:Extension Category="windows.comServer"><com:ComServer>
        <com:ExeServer Executable="Provider\\KeePassPasskeyProvider.exe" Arguments="-ActivateAuthenticator" DisplayName="KDBX Passkey Provider">
         <com:Class Id="5ed456a2-9c32-4c42-a5f8-8da4470a7745" DisplayName="KDBX Passkey Provider" />
        </com:ExeServer>
       </com:ComServer></com:Extension></Extensions>
      </Application>
     </Applications>
     <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
    </Package>
    '''
    ET.fromstring(manifest)
    (package/'AppxManifest.xml').write_text(manifest, encoding='utf-8')
    shutil.copy2(upstream/'LICENSE', package/'LICENSE.txt')
    (package/'SOURCE.txt').write_text('''KDBX Passkey 0.2.8 (local prototype)
    Windows provider derived from https://github.com/yusei36/KeePassPasskey (GPL-3.0-or-later), Copyright 2026 Uwe Koegel.
    Original project branding/assets remain licensed under that project's license.
    Native WPF UI, read-only KDBX store and IPC backend: GPL-3.0-or-later.
    Complete corresponding source is provided beside this installation package in KdbxPasskey-source.zip.
    ''', encoding='utf-8')
    print('Single-application MSIX layout assembled')

if __name__ == "__main__":
    assemble(Path(__file__).resolve().parents[1])
