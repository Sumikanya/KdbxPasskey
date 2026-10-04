# SPDX-License-Identifier: GPL-3.0-or-later
import base64
import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from pykeepass import create_database, PyKeePass

from core import Store, StoreError, UnlockError, decode, encode, handle


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'test.kdbx'
        self.keys = [ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate(),
                     rsa.generate_private_key(public_exponent=65537, key_size=2048)]
        kp = create_database(str(self.path), password='fixture-password')
        for i, key in enumerate(self.keys):
            entry = kp.add_entry(kp.root_group, f'Fixture {i}', f'user{i}', '')
            fields = dict(CREDENTIAL_ID=encode(bytes([i+1])*32), RELYING_PARTY='example.test',
                          PRIVATE_KEY_PEM=key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()).decode(),
                          USER_HANDLE=encode(bytes([i+1])*16), USERNAME=f'user{i}', FLAG_BE='1', FLAG_BS='1')
            for name, value in fields.items():
                entry.set_custom_property('KPEX_PASSKEY_'+name, value, protect=True)
        # Recycle-bin entries and history must never become active credentials.
        trash = kp.add_entry(kp.root_group, 'Trash', 'trash', '')
        for key, value in kp.entries[0].custom_properties.items():
            trash.set_custom_property(key, value, protect=True)
        kp.trash_entry(trash)
        kp.save()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.store = Store()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.assertEqual(self.store.open(self.path, 'fixture-password'), 3)

    def test_malformed_passkey_does_not_prevent_unlock(self):
        kp = PyKeePass(str(self.path), password='fixture-password')
        kp.entries[0].set_custom_property('KPEX_PASSKEY_PRIVATE_KEY_PEM', 'invalid fixture', protect=True)
        kp.save()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.assertEqual(self.store.open(self.path, 'fixture-password'), 3)
        self.assertEqual(self.store.skipped, 1)
        metadata = handle(self.store, {'type': 'get_credentials'}, None)['credentials']
        self.assertEqual(len(metadata), 3)
        self.assertFalse(any('key' in item or 'key_error' in item for item in metadata))
        result = handle(self.store, self.req(0), lambda rp, items: items[0]['credentialId'])
        self.assertEqual(result['errorCode'], 'internal_error')
        self.assertNotIn('signature', result)
        self.assertIn('私钥', result['errorMessage'])
        good = handle(self.store, self.req(1), lambda rp, items: items[0]['credentialId'])
        self.assertIn('signature', good)
        self.store.lock()
        self.assertEqual(handle(self.store, {'type': 'get_credentials'}, None)['errorCode'], 'db_locked')

    def test_failure_stage_does_not_expose_exception_text(self):
        with self.assertRaises(UnlockError) as caught:
            Store().open(self.path, 'wrong-secret-fixture')
        self.assertEqual(caught.exception.stage, '解密数据库')
        self.assertEqual(caught.exception.kind, 'CredentialsError')
        self.assertNotIn('wrong-secret-fixture', str(caught.exception))

    def test_explicit_p256_private_key(self):
        from asn1crypto import keys, pem
        from core import P256_P, P256_B, P256_N, P256_G, load_passkey_pem
        original = self.keys[0]
        info = keys.PrivateKeyInfo.load(original.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        domain = keys.SpecifiedECDomain({'version': 'ecdpVer1', 'field_id': {'field_type': 'prime_field', 'parameters': P256_P}, 'curve': {'a': (P256_P-3).to_bytes(32, 'big'), 'b': P256_B.to_bytes(32, 'big')}, 'base': P256_G, 'order': P256_N, 'cofactor': 1})
        info['private_key_algorithm']['parameters'] = keys.ECDomainParameters(name='specified', value=domain)
        encoded = pem.armor('PRIVATE KEY', info.dump()).decode()
        loaded = load_passkey_pem(encoded)
        self.assertEqual(loaded.public_key().public_numbers(), original.public_key().public_numbers())
        signature = loaded.sign(b'fixture', ec.ECDSA(hashes.SHA256()))
        original.public_key().verify(signature, b'fixture', ec.ECDSA(hashes.SHA256()))
        info['private_key_algorithm']['parameters'].chosen['order'] = 123
        with self.assertRaises(ValueError):
            load_passkey_pem(pem.armor('PRIVATE KEY', info.dump()).decode())

    def test_private_key_diagnostics_only_expose_algorithm_metadata(self):
        from core import private_key_diagnostic
        for key, oid in zip(self.keys, ['1.2.840.10045.2.1', '1.3.101.112', '1.2.840.113549.1.1.1']):
            encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
            report = private_key_diagnostic(encoded)
            self.assertIn('algOID=' + oid, report)
            self.assertIn('PRIMARY_OK', report)
            self.assertNotIn(encoded.splitlines()[1], report)
            self.assertNotIn('BEGIN', report)
        self.assertEqual(private_key_diagnostic('SECRET-FIXTURE'), 'PEM_DECODE_FAILED')
        self.assertEqual(private_key_diagnostic('-----BEGIN PRIVATE KEY-----\nYWJj\n-----END PRIVATE KEY-----'), 'PKCS8_ASN1_FAILED')

    def test_named_p256_fallback_checks_scalar_and_public_key(self):
        from asn1crypto import keys, pem
        from unittest.mock import patch
        from core import load_passkey_pem, KeyFormatError, P256_N
        original = self.keys[0]
        info = keys.PrivateKeyInfo.load(original.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        def encoded():
            return pem.armor('PRIVATE KEY', info.dump()).decode()
        with patch('core.serialization.load_pem_private_key', side_effect=ValueError('primary loader rejected fixture')):
            loaded = load_passkey_pem(encoded())
            original.public_key().verify(loaded.sign(b'fixture', ec.ECDSA(hashes.SHA256())), b'fixture', ec.ECDSA(hashes.SHA256()))
            private = info['private_key'].parsed
            private['public_key'] = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            info['private_key'] = private
            with self.assertRaises(KeyFormatError) as caught:
                load_passkey_pem(encoded())
            self.assertEqual(caught.exception.code, 'EC_PUBLIC_PRIVATE_MISMATCH')
            private['private_key'] = 0
            info['private_key'] = private
            with self.assertRaises(KeyFormatError) as caught:
                load_passkey_pem(encoded())
            self.assertEqual(caught.exception.code, 'EC_SCALAR_OUT_OF_RANGE')

    def tearDown(self):
        self.assertEqual(self.before, hashlib.sha256(self.path.read_bytes()).digest())
        self.store.lock()
        self.temp.cleanup()

    def req(self, i=0):
        return dict(type='get_assertion', protocolVersion=1, rpId='example.test',
                    clientDataHash=base64.b64encode(b'c'*32).decode(), allowCredentials=[encode(bytes([i+1])*32)])

    def test_all_three_signatures_and_flags(self):
        for i, key in enumerate(self.keys):
            r = self.store.assert_credential(self.req(i), lambda rp, candidates: candidates[0]['credentialId'])
            auth = base64.b64decode(r['authenticatorData'])
            self.assertEqual(auth[:32], hashlib.sha256(b'example.test').digest())
            self.assertEqual(auth[32], 0x1d)
            self.assertEqual(auth[33:], bytes(4))
            message = auth + b'c'*32
            sig = base64.b64decode(r['signature'])
            public = key.public_key()
            if i == 0:
                public.verify(sig, message, ec.ECDSA(hashes.SHA256()))
            elif i == 1:
                public.verify(sig, message)
            else:
                public.verify(sig, message, padding.PKCS1v15(), hashes.SHA256())

    def test_cancel_does_not_sign(self):
        r = handle(self.store, self.req(), lambda *_: None)
        self.assertIn('errorCode', r)
        self.assertNotIn('signature', r)

    def test_lock_during_approval(self):
        def approve(_, choices):
            self.store.lock()
            return choices[0]['credentialId']
        r = handle(self.store, self.req(), approve)
        self.assertEqual(r['errorCode'], 'db_locked')

    def test_rp_and_allow_list_binding(self):
        for change in (dict(rpId='attacker.test'), dict(allowCredentials=[encode(b'x'*32)])):
            req = self.req()
            req.update(change)
            r = handle(self.store, req, lambda *_: self.fail('Must not prompt'))
            self.assertEqual(r['errorCode'], 'not_found')

    def test_metadata_never_exports_key(self):
        r = handle(self.store, dict(type='get_credentials'), None)
        self.assertEqual(len(r['credentials']), 3)
        for item in r['credentials']:
            self.assertNotIn('key', item)
            self.assertNotIn('PRIVATE_KEY_PEM', repr(item))

    def test_bad_hash_and_protocol(self):
        req = self.req()
        req['clientDataHash'] = encode(b'x'*31)
        self.assertIn('errorCode', handle(self.store, req, None))
        req['protocolVersion'] = 99
        self.assertEqual(handle(self.store, req, None)['errorCode'], 'incompatible_version')

    def test_registration_disabled(self):
        self.assertEqual(handle(self.store, dict(type='make_credential'), None)['errorCode'], 'unsupported_algorithm')

    def test_wrong_password_and_keyfile(self):
        with self.assertRaises(Exception):
            Store().open(self.path, 'incorrect')
        keyed = Path(self.temp.name)/'keyed.kdbx'
        keyfile = Path(self.temp.name)/'key.bin'
        keyfile.write_bytes(bytes(range(32)))
        kp = create_database(str(keyed), password='fixture-password', keyfile=str(keyfile))
        kp.save()
        self.assertEqual(Store().open(keyed, 'fixture-password', keyfile), 0)
        with self.assertRaises(Exception):
            Store().open(keyed, 'fixture-password')

    def test_disabled_search_group(self):
        kp = PyKeePass(str(self.path), password='fixture-password')
        group = kp.add_group(kp.root_group, 'Hidden')
        from lxml import etree
        etree.SubElement(group._element, 'EnableSearching').text = 'False'
        kp.move_entry(kp.entries[0], group)
        kp.save()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.assertEqual(Store().open(self.path, 'fixture-password'), 2)

    def test_duplicate_identity_keeps_first_and_lock_clears_indexes(self):
        kp = PyKeePass(str(self.path), password='fixture-password')
        original = kp.entries[0]
        duplicate = kp.add_entry(kp.root_group, 'Duplicate', 'duplicate', '')
        for key, value in original.custom_properties.items():
            duplicate.set_custom_property(key, value, protect=True)
        kp.save()
        self.before = hashlib.sha256(self.path.read_bytes()).digest()
        self.assertEqual(self.store.open(self.path, 'fixture-password'), 3)
        self.assertEqual(len(self.store.candidates('example.test')), 3)
        self.assertEqual(self.store.candidates('missing.test'), [])
        self.assertEqual(len(self.store.candidates('example.test', [encode(bytes([1])*32)])), 1)
        self.store.lock()
        self.assertEqual(self.store.by_id, {})
        self.assertEqual(self.store.by_rp, {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
