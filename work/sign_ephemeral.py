"""Workspace-only package signing with an ephemeral PFX key (no trust changes).
Native layout follows Microsoft SignerSignEx2 / APPX_SIP_CLIENT_DATA documentation.
"""
import ctypes as c
from ctypes import wintypes as w
from pathlib import Path

class Blob(c.Structure):
    _fields_=[('cbData',w.DWORD),('pbData',c.c_void_p)]
class FileInfo(c.Structure):
    _fields_=[('cbSize',w.DWORD),('name',w.LPCWSTR),('handle',c.c_void_p)]
class Subject(c.Structure):
    _fields_=[('cbSize',w.DWORD),('index',c.c_void_p),('choice',w.DWORD),('file',c.c_void_p)]
class CertStore(c.Structure):
    _fields_=[('cbSize',w.DWORD),('context',c.c_void_p),('policy',w.DWORD),('store',c.c_void_p)]
class Cert(c.Structure):
    _fields_=[('cbSize',w.DWORD),('choice',w.DWORD),('info',c.c_void_p),('hwnd',c.c_void_p)]
class Signature(c.Structure):
    _fields_=[('cbSize',w.DWORD),('hash',w.DWORD),('choice',w.DWORD),('attrs',c.c_void_p),('authenticated',c.c_void_p),('unauthenticated',c.c_void_p)]
class Params(c.Structure):
    _fields_=[('flags',w.DWORD),('subject',c.c_void_p),('cert',c.c_void_p),('signature',c.c_void_p),('provider',c.c_void_p),('tsFlags',w.DWORD),('oid',c.c_void_p),('url',c.c_void_p),('attrs',c.c_void_p),('sip',c.c_void_p),('context',c.c_void_p),('policy',c.c_void_p),('reserved',c.c_void_p)]
class Sip(c.Structure):
    _fields_=[('params',c.c_void_p),('state',c.c_void_p)]

def ptr(value):
    return c.addressof(value)

root=Path(__file__).resolve().parents[1]
crypt=c.WinDLL('crypt32',use_last_error=True)
crypt.PFXImportCertStore.argtypes=[c.POINTER(Blob),w.LPCWSTR,w.DWORD]
crypt.PFXImportCertStore.restype=c.c_void_p
crypt.CertEnumCertificatesInStore.argtypes=[c.c_void_p,c.c_void_p]
crypt.CertEnumCertificatesInStore.restype=c.c_void_p
crypt.CertCloseStore.argtypes=[c.c_void_p,w.DWORD]
crypt.CertFreeCertificateContext.argtypes=[c.c_void_p]
payload=c.create_string_buffer((root/'work/signing.pfx').read_bytes())
blob=Blob(len(payload)-1,ptr(payload))
store=crypt.PFXImportCertStore(c.byref(blob),'local-build-only',0x8000|0x200)
if not store:
    raise c.WinError(c.get_last_error())
context=crypt.CertEnumCertificatesInStore(store,None)
if not context:
    raise c.WinError(c.get_last_error())
try:
    index=w.DWORD(0)
    file=FileInfo(c.sizeof(FileInfo),str(root/'dist/KdbxPasskey-0.2.7-x64.msix'),None)
    subject=Subject(c.sizeof(Subject),ptr(index),1,ptr(file))
    info=CertStore(c.sizeof(CertStore),context,8,store)
    cert=Cert(c.sizeof(Cert),2,ptr(info),None)
    sig=Signature(c.sizeof(Signature),0x800c,0,None,None,None)
    params=Params()
    params.subject=ptr(subject)
    params.cert=ptr(cert)
    params.signature=ptr(sig)
    sip=Sip(ptr(params),None)
    params.sip=ptr(sip)
    dll=c.WinDLL('mssign32',use_last_error=True)
    dll.SignerSignEx2.argtypes=[w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,w.DWORD,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p,c.c_void_p]
    dll.SignerSignEx2.restype=c.c_long
    hr=dll.SignerSignEx2(0,ptr(subject),ptr(cert),ptr(sig),None,0,None,None,None,ptr(sip),None,None,None)
    if sip.state:
        vtable=c.cast(sip.state,c.POINTER(c.POINTER(c.c_void_p))).contents
        release=c.WINFUNCTYPE(w.ULONG,c.c_void_p)(vtable[2])
        release(sip.state)
    if hr < 0:
        raise RuntimeError(f'Windows package signing failed HRESULT=0x{hr & 0xffffffff:08X}')
    print('MSIX signed using an ephemeral key; no certificate trust stores modified')
finally:
    crypt.CertFreeCertificateContext(context)
    crypt.CertCloseStore(store,0)
