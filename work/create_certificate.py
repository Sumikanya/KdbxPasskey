from pathlib import Path
import win32crypt
import hashlib
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

root = Path(__file__).resolve().parents[1]
protected = root/'work'/'signing-key.dpapi'
cer = root/'dist'/'KdbxPasskey.cer'
pfx = root/'work'/'signing.pfx'
if protected.exists():
    payload = win32crypt.CryptUnprotectData(protected.read_bytes(), None, None, None, 1)[1]
    _, cert, _ = pkcs12.load_key_and_certificates(payload, b'local-build-only')
    if cer.exists() and cer.read_bytes() != cert.public_bytes(serialization.Encoding.DER):
        raise RuntimeError('Certificate does not match preserved signing key')
    pfx.write_bytes(payload)
    cer.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    (root/'dist'/'certificate-sha256.txt').write_text(cert.fingerprint(hashes.SHA256()).hex().upper()+'\n', encoding='ascii')
    print('Reused signing certificate; private key protected by current-user Windows DPAPI')
    raise SystemExit(0)
key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'KDBX Passkey Local')])
now = datetime.now(timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1))
        .not_valid_after(now+timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False,
            key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .sign(key, hashes.SHA256()))
pfx = root/'work'/'signing.pfx'
pfx.write_bytes(pkcs12.serialize_key_and_certificates(b'KDBX Passkey Local',key,cert,None,serialization.BestAvailableEncryption(b'local-build-only')))
# Keep the project folder's inherited ACL. A sandbox token SID is not a safe
# substitute for the desktop user's permissions; never replace the file DACL.
cer = root/'dist'/'KdbxPasskey.cer'
cer.write_bytes(cert.public_bytes(serialization.Encoding.DER))
fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
(root/'dist'/'certificate-sha256.txt').write_text(fingerprint+'\n',encoding='ascii')
print('Local package-signing certificate generated; nothing added to Windows trust stores')

protected.write_bytes(win32crypt.CryptProtectData(pfx.read_bytes(), 'KDBX Passkey local build signing key', None, None, None, 1))
print('Persistent signing key saved with current-user DPAPI encryption and inherited folder permissions')
