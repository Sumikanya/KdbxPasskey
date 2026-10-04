# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only KDBX credential store. No database writes, logs or key export API."""
import base64
import hashlib
import io
import threading
import time
from pathlib import Path

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from pykeepass import PyKeePass


def decode(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise ValueError("Invalid credential encoding")
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


# Botan can encode P-256 using explicit parameters; cryptography accepts named
# curves. Only normalize after verifying every domain parameter against P-256.
P256_P = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
P256_B = int("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
P256_N = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
P256_G = bytes.fromhex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")

class KeyFormatError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def check_p256_parameters(params):
    if params.name == 'named':
        if params.chosen.dotted != '1.2.840.10045.3.1.7':
            raise KeyFormatError('EC_CURVE_NOT_P256')
        return
    if params.name != 'specified':
        raise KeyFormatError('EC_PARAMETERS_MISSING')
    d = params.chosen.native
    if not (d['field_id']['field_type'] == 'prime_field'
            and d['field_id']['parameters'] == P256_P
            and int.from_bytes(d['curve']['a'], 'big') == P256_P - 3
            and int.from_bytes(d['curve']['b'], 'big') == P256_B
            and d['base'] == P256_G and d['order'] == P256_N
            and d['cofactor'] in (None, 1)):
        raise KeyFormatError('EC_EXPLICIT_PARAMETERS_NOT_P256')


def load_passkey_pem(value):
    payload = value.encode()
    try:
        return serialization.load_pem_private_key(payload, password=None)
    except (ValueError, UnsupportedAlgorithm):
        from asn1crypto import keys, pem
        label, _, der = pem.unarmor(payload)
        if label != "PRIVATE KEY":
            raise ValueError("Unsupported PEM container")
        info = keys.PrivateKeyInfo.load(der, strict=True)
        if info['private_key_algorithm']['algorithm'].native != 'ec':
            raise ValueError("Unsupported explicit key")
        params = info['private_key_algorithm']['parameters']
        check_p256_parameters(params)
        try:
            private = info['private_key'].parsed
            inner = private['parameters']
            if inner.native is not None:
                check_p256_parameters(inner)
            scalar = private['private_key'].native
            if not isinstance(scalar, int) or not 1 <= scalar < P256_N:
                raise KeyFormatError('EC_SCALAR_OUT_OF_RANGE')
        except KeyFormatError:
            raise
        except (ValueError, TypeError, KeyError, IndexError):
            raise KeyFormatError('EC_PRIVATE_ASN1_FAILED') from None
        key = ec.derive_private_key(scalar, ec.SECP256R1())
        public = private['public_key'].native
        if public is not None:
            advertised = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
            if advertised.public_numbers() != key.public_key().public_numbers():
                raise KeyFormatError("EC_PUBLIC_PRIVATE_MISMATCH")
        return key


def private_key_diagnostic(value):
    """Return only fixed codes and public algorithm identifiers, never key bytes."""
    from asn1crypto import keys, pem
    import re
    def oid_text(oid):
        text = oid.dotted
        return text if len(text) <= 80 and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", text) else "unknown"
    try:
        payload = value.encode()
        if len(payload) > 65536:
            return "PEM_TOO_LARGE"
        label, _, der = pem.unarmor(payload)
        if label != "PRIVATE KEY":
            return "PEM_CONTAINER_UNSUPPORTED"
    except (ValueError, TypeError, UnicodeError):
        return "PEM_DECODE_FAILED"
    try:
        info = keys.PrivateKeyInfo.load(der, strict=True)
        algorithm = info['private_key_algorithm']['algorithm']
        oid = oid_text(algorithm)
        detail = "PKCS8 algOID=" + oid
        if algorithm.native == 'ec':
            parameters = info['private_key_algorithm']['parameters']
            if parameters.name == 'named':
                detail += " curveOID=" + oid_text(parameters.chosen)
            elif parameters.name == 'specified':
                detail += " curve=explicit"
            else:
                detail += " curve=implicit"
        try:
            serialization.load_pem_private_key(payload, password=None)
            code = "PRIMARY_OK"
        except UnsupportedAlgorithm:
            code = "PRIMARY_UNSUPPORTED_ALGORITHM"
        except (ValueError, TypeError):
            code = "PRIMARY_INVALID_ENCODING_OR_KEY"
        return detail + " " + code
    except (ValueError, TypeError, KeyError, IndexError):
        return "PKCS8_ASN1_FAILED"


class StoreError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class UnlockError(Exception):
    def __init__(self, stage, error):
        self.stage = stage
        self.kind = type(error).__name__
        hints = {"CredentialsError": "解密凭据不匹配；请确认是否还需要密钥文件或硬件密钥。", "PermissionError": "Windows 拒绝读取文件。", "FileNotFoundError": "找不到文件。", "HeaderChecksumError": "数据库文件头校验失败。", "PayloadChecksumError": "数据库内容校验失败。", "MemoryError": "密钥派生所需内存不足。"}
        super().__init__(f"{stage}失败 [{self.kind}]：" + hints.get(self.kind, "发生兼容性或解析错误，请反馈此错误代码。"))


class Store:
    def __init__(self):
        self.gate = threading.RLock()
        self.records = []
        self.by_rp = {}
        self.by_id = {}
        self.generation = 0
        self.unlocked = False
        self.last_use = 0
        self.skipped = 0
        self.skipped_details = []

    def open(self, filename, password, keyfile=None):
        # Read bytes rather than let the library retain a writable file path.
        path = Path(filename)
        try:
            if path.stat().st_size > 256 * 1024 * 1024:
                raise ValueError("Database exceeds size limit")
            blob = path.read_bytes()
        except Exception as ex:
            raise UnlockError("读取数据库文件", ex) from None
        try:
            key_stream = io.BytesIO(Path(keyfile).read_bytes()) if keyfile else None
        except Exception as ex:
            raise UnlockError("读取密钥文件", ex) from None
        try:
            kp = PyKeePass(io.BytesIO(blob), password=password, keyfile=key_stream)
        except Exception as ex:
            raise UnlockError("解密数据库", ex) from None
        records = []
        seen = set()
        self.skipped = 0
        self.skipped_details = []
        recycle = kp.recyclebin_group
        for entry in kp.entries:
            groups = list(entry._element.iterancestors("Group"))
            if recycle is not None and any(g.findtext("UUID") == recycle._element.findtext("UUID") for g in groups):
                continue
            # Nearest explicit search setting overrides inherited settings.
            search = next((g.findtext("EnableSearching") for g in groups
                           if g.findtext("EnableSearching") in ("True", "False")), "True")
            if search == "False":
                continue
            fields = entry.custom_properties
            prefix = "KPEX_PASSKEY_"
            if not all(fields.get(prefix + x) for x in ("CREDENTIAL_ID", "RELYING_PARTY", "PRIVATE_KEY_PEM")):
                continue
            stage = "凭据 ID 编码"
            try:
                credential_id = decode(fields[prefix + "CREDENTIAL_ID"])
                stage = "用户 ID 编码或长度"
                user_handle = decode(fields.get(prefix + "USER_HANDLE", ""))
                if not 1 <= len(credential_id) <= 1024 or len(user_handle) > 64:
                    raise ValueError("Invalid passkey identifiers")
                stage = "站点 ID"
                rp = fields[prefix + "RELYING_PARTY"]
                if not isinstance(rp, str) or not rp or len(rp) > 253 or any(c in rp for c in "/\\\x00\r\n"):
                    raise ValueError("Invalid relying-party ID")
                stage = "备份标记"
                be = fields.get(prefix + "FLAG_BE", "1") == "1"
                bs = fields.get(prefix + "FLAG_BS", "1") == "1"
                if bs and not be:
                    raise ValueError("Inconsistent passkey backup flags")
                # Metadata validation is independent of parsing the signing key.
                key = None
                key_error = None
                try:
                    stage = "私钥 PEM 格式"
                    key = load_passkey_pem(fields[prefix + "PRIVATE_KEY_PEM"])
                    stage = "密钥算法"
                    if isinstance(key, ec.EllipticCurvePrivateKey):
                        if not isinstance(key.curve, ec.SECP256R1):
                            raise ValueError("Only P-256 EC credentials are supported")
                    elif not isinstance(key, (ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
                        raise ValueError("Unsupported passkey algorithm")
                except (ValueError, TypeError, UnsupportedAlgorithm) as ex:
                    key = None
                    key_error = stage + " / " + private_key_diagnostic(fields[prefix + "PRIVATE_KEY_PEM"])
                    if isinstance(ex, KeyFormatError):
                        key_error += " fallback=" + ex.code
                    self.skipped += 1
                    self.skipped_details.append({"rpId": rp, "reason": key_error + "（元数据仍同步）"})
                record = dict(credentialId=encode(credential_id), rpId=rp,
                              userHandle=encode(user_handle), userName=fields.get(prefix + "USERNAME", entry.username or ""),
                              title=entry.title or "Passkey", databaseName=path.name,
                              key=key, key_error=key_error, be=be, bs=bs)
            except (ValueError, TypeError, UnsupportedAlgorithm):
                self.skipped += 1
                self.skipped_details.append({"rpId": fields.get(prefix + "RELYING_PARTY", "未知站点"), "reason": stage})
                continue
            identity = (rp, record["credentialId"])
            if identity in seen:
                continue
            seen.add(identity)
            records.append(record)
        # Do not retain the decrypted XML or the master password after loading keys.
        del kp, blob, password
        with self.gate:
            self.records = records
            self.by_id = {(r["rpId"], r["credentialId"]): r for r in records}
            self.by_rp = {}
            for record in records:
                self.by_rp.setdefault(record["rpId"], []).append(record)
            self.unlocked = True
            self.generation += 1
            self.last_use = time.monotonic()
        return len(records)

    def lock(self):
        with self.gate:
            self.records.clear()
            self.by_rp.clear()
            self.by_id.clear()
            self.skipped_details.clear()
            self.skipped = 0
            self.unlocked = False
            self.generation += 1

    def candidates(self, rp=None, allow=None):
        with self.gate:
            if not self.unlocked:
                raise StoreError("db_locked", "请先在 KDBX Passkey 中解锁数据库。")
            ids = {encode(decode(x)) for x in allow} if allow else None
            return [self.public(r) for r in (self.records if rp is None else self.by_rp.get(rp, ()))
                    if (rp is None or r["rpId"] == rp) and (ids is None or r["credentialId"] in ids)]

    @staticmethod
    def public(record):
        return {k: record[k] for k in ("credentialId", "rpId", "userHandle", "userName", "title", "databaseName")}

    def assert_credential(self, request, approve):
        rp = request.get("rpId")
        if not isinstance(rp, str) or not rp:
            raise StoreError("internal_error", "Missing relying-party ID")
        client_hash = decode(request.get("clientDataHash"))
        if len(client_hash) != 32:
            raise StoreError("internal_error", "Client data hash must be 32 bytes")
        with self.gate:
            generation = self.generation
            choices = self.candidates(rp, request.get("allowCredentials"))
        if not choices:
            raise StoreError("not_found", "数据库中没有匹配的通行密钥。")
        selected = approve(rp, choices)
        if selected not in {c["credentialId"] for c in choices}:
            raise StoreError("internal_error", "认证已取消或超时。")
        with self.gate:
            if not self.unlocked or generation != self.generation:
                raise StoreError("db_locked", "Database locked while awaiting approval")
            record = self.by_id[(rp, selected)]
            if record["key"] is None:
                raise StoreError("internal_error", "该凭据元数据已同步，但私钥尚无法解析，暂时不能完成认证。请查看凭据诊断。")
            # UP + UV: explicit per-operation approval; the upstream provider performs
            # Windows Hello before sending this request (our get_settings requires it).
            flags = 0x05 | (0x08 if record["be"] else 0) | (0x10 if record["bs"] else 0)
            auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + b"\x00" * 4
            signed = auth + client_hash
            key = record["key"]
            if isinstance(key, ec.EllipticCurvePrivateKey):
                signature = key.sign(signed, ec.ECDSA(hashes.SHA256()))
            elif isinstance(key, rsa.RSAPrivateKey):
                signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
            else:
                signature = key.sign(signed)
            self.last_use = time.monotonic()
            return dict(type="get_assertion", credentialId=record["credentialId"],
                        authenticatorData=base64.b64encode(auth).decode(),
                        signature=base64.b64encode(signature).decode(), userHandle=record["userHandle"],
                        userName=record["userName"], userDisplayName=record["userName"])


SETTINGS = dict(signInVerification="WindowsHello", registrationVerification="WindowsHello",
                syncCredentialsToWindows=True, logLevel="Off", checkForPluginUpdates=False,
                statusRefreshIntervalMilliseconds=30000, notificationVerificationTimeoutMilliseconds=60000,
                showErrorNotifications=True, saveToExistingEntry=False)


def handle(store, request, approve):
    kind = request.get("type")
    response = dict(type=kind)
    if kind == "ping":
        return dict(type=kind, protocolVersion=1, version="1.4.0",
                    status="ready" if store.unlocked else "no_database")
    if request.get("protocolVersion", 1) != 1:
        return dict(type=kind, errorCode="incompatible_version", errorMessage="Unsupported IPC version")
    try:
        if kind == "get_settings":
            response["settings"] = SETTINGS.copy()
        elif kind == "save_settings":
            raise StoreError("internal_error", "此版本的安全设置固定，请在 KDBX Passkey 中操作。")
        elif kind == "get_credentials":
            response["credentials"] = store.candidates(request.get("rpId"), request.get("allowCredentials"))
        elif kind == "get_databases":
            response["databases"] = []  # Read-only: never advertise a registration destination.
        elif kind == "find_matching_entries":
            response["entries"] = []
        elif kind == "make_credential":
            raise StoreError("unsupported_algorithm", "此版本只读。请使用 KeePassXC 创建通行密钥，然后重新解锁。")
        elif kind == "get_assertion":
            return store.assert_credential(request, approve)
        else:
            raise StoreError("internal_error", "Unsupported operation")
    except StoreError as ex:
        response.update(errorCode=ex.code, errorMessage=str(ex))
    except Exception:
        response.update(errorCode="internal_error", errorMessage="Invalid request or unsupported credential")
    return response
