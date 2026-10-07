import base64
import hashlib
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import quote
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

root = Path(__file__).resolve().parents[1]
package = root/'dist/KdbxPasskey-0.2.8-x64.msix'
with zipfile.ZipFile(package) as z:
    assert not any(name.lower().endswith('.pdb') for name in z.namelist()), 'Debug symbols must stay outside the installation package'
    for required in ('KdbxPasskey.exe', 'Provider/KeePassPasskeyProvider.exe', 'Backend/KdbxBackend.exe'):
        assert required in z.namelist(), 'Missing runtime entry point: ' + required
    blockmap = z.read('AppxBlockMap.xml')
    bm = ET.fromstring(blockmap)
    ns = {'b':'http://schemas.microsoft.com/appx/2010/blockmap'}
    count = 0
    for entry in bm.findall('b:File',ns):
        data = z.read(quote(entry.attrib['Name'].replace('\\','/'), safe='/'))
        assert len(data) == int(entry.attrib['Size'])
        for i, block in enumerate(entry.findall('b:Block',ns)):
            assert hashlib.sha256(data[i*65536:(i+1)*65536]).digest() == base64.b64decode(block.attrib['Hash'])
        count += 1
    signature = z.read('AppxSignature.p7x')
    assert signature[:4] == b'PKCX'
    sd = cms.ContentInfo.load(signature[4:])['content']
    signer = sd['signer_infos'][0]
    cert = x509.load_der_x509_certificate(sd['certificates'][0].chosen.dump())
    expected_cert = x509.load_der_x509_certificate((root/'dist/KdbxPasskey.cer').read_bytes())
    assert cert.fingerprint(hashes.SHA256()) == expected_cert.fingerprint(hashes.SHA256())
    attrs = signer['signed_attrs'].dump()
    assert attrs[0] == 0xA0
    cert.public_key().verify(signer['signature'].native, b'\x31'+attrs[1:], padding.PKCS1v15(), hashes.SHA256())
    content = sd['encap_content_info']['content']
    message_digest = next(a['values'][0].native for a in signer['signed_attrs'] if a['type'].native == 'message_digest')
    # Authenticode hashes the content of the SPC indirect-data sequence, not its ASN.1 header.
    indirect = content.contents
    if hashlib.sha256(indirect).digest() != message_digest:
        indirect = content.parsed.contents
    assert hashlib.sha256(indirect).digest() == message_digest
    assert b'AXBM'+hashlib.sha256(blockmap).digest() in indirect
    assert b'AXCT'+hashlib.sha256(z.read('[Content_Types].xml')).digest() in indirect
    manifest = ET.fromstring(z.read('AppxManifest.xml'))
    foundation = '{http://schemas.microsoft.com/appx/manifest/foundation/windows10}'
    identity = manifest.find(foundation+'Identity')
    assert identity.attrib['Publisher'] == cert.subject.rfc4514_string()
    assert identity.attrib['Name'] == 'KdbxPasskey'
print(f'PASS: {count} payloads verified against blockmap; RSA signature, signed-content digest, certificate and publisher match')
