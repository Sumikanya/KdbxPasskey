"""Exercise the shipped backend over inherited stdio using a temporary vault."""
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import tempfile
import threading
import time
from pykeepass import create_database
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def main():
    root = Path(__file__).resolve().parents[1]
    executable = root / 'work/backend-python/KdbxBackend/KdbxBackend.exe'
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'fixture.kdbx'
        secret = 'temporary-frozen-check-secret'
        vault = create_database(str(path), password=secret)
        entry = vault.add_entry(vault.root_group, 'Fixture', 'fixture', '')
        key = ec.generate_private_key(ec.SECP256R1())
        for name, value in dict(CREDENTIAL_ID='AQID', RELYING_PARTY='example.test',
                                USER_HANDLE='AQ', PRIVATE_KEY_PEM=key.private_bytes(
                                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()).decode()).items():
            entry.set_custom_property('KPEX_PASSKEY_' + name, value, protect=True)
        vault.save()
        before = hashlib.sha256(path.read_bytes()).digest()
        events = queue.Queue()
        transcript = []
        process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True, encoding='utf-8',
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        def read():
            for line in process.stdout:
                transcript.append(line)
                events.put(json.loads(line))
            events.put({'type': 'eof'})
        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        def expect(kind):
            deadline = time.monotonic() + 20
            while True:
                event = events.get(timeout=max(.01, deadline - time.monotonic()))
                if event['type'] in ('error', 'eof'):
                    raise AssertionError('Unexpected backend event: ' + event['type'])
                if event['type'] == kind:
                    return event
        def send(request):
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
        try:
            expect('locked')
            send(dict(type='unlock', path=str(path), password=secret))
            opened = expect('opened')
            assert opened['total'] == opened['signable'] == 1
            assert opened['sites'] == ['example.test']
            assert opened['credentials'][0]['userName'] == 'fixture'
            assert set(opened['credentials'][0]) == {'rpId', 'userName', 'title', 'signable', 'reason'}
            send(dict(type='lock'))
            expect('locked')
            process.stdin.close()
            assert process.wait(timeout=15) == 0
            reader.join(2)
            assert not reader.is_alive()
            assert secret not in ''.join(transcript)
            assert 'PRIVATE KEY' not in ''.join(transcript)
            assert hashlib.sha256(path.read_bytes()).digest() == before
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
        print('Frozen backend passed: unlock, metadata, lock, EOF, no secret output, unchanged vault')


if __name__ == '__main__':
    main()
