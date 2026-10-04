# SPDX-License-Identifier: GPL-3.0-or-later
import json
import struct
import time
import unittest
import uuid
from unittest.mock import patch

import win32con
import win32file
import win32pipe

import windows


def send(request):
    for _ in range(30):
        try:
            pipe = win32file.CreateFile(windows.PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                                        0, None, win32con.OPEN_EXISTING, 0, None)
            break
        except Exception:
            time.sleep(.05)
    else:
        raise RuntimeError('Listener unavailable')
    try:
        data = json.dumps(request).encode()
        win32file.WriteFile(pipe, struct.pack('<I', len(data)) + data)
        _, header = win32file.ReadFile(pipe, 4)
        length, = struct.unpack('<I', header)
        body = bytearray()
        while len(body) < length:
            _, chunk = win32file.ReadFile(pipe, length-len(body))
            body.extend(chunk)
        return json.loads(body)
    finally:
        pipe.Close()


class WindowsTests(unittest.TestCase):
    def setUp(self):
        # Isolate test pipes from the user's running installed application.
        self.pipe_patch = patch("windows.PIPE", windows.PIPE + "-test-" + uuid.uuid4().hex)
        self.pipe_patch.start()
        self.addCleanup(self.pipe_patch.stop)

    def test_secure_pipe_framing_roundtrip_and_name_claim(self):
        # Fixture replaces OS package verification only inside this test process.
        # No bypass or fixture code is imported by the production executable.
        with patch('windows.current_package', return_value='fixture'), patch('windows.verify_client', return_value=True):
            server = windows.Server(lambda q: dict(type=q['type'], protocolVersion=1, status='ready'), 'fixture.exe', self.fail)
            server.start()
            try:
                result = send(dict(type='ping', protocolVersion=1))
                self.assertEqual(result['status'], 'ready')
                other = windows.Server(lambda _: {}, 'fixture.exe', self.fail)
                with self.assertRaises(Exception):
                    other.start()
                for _ in range(5):
                    self.assertEqual(send(dict(type='ping'))['protocolVersion'], 1)
            finally:
                server.close()
                time.sleep(.5)

    def test_real_package_verification_rejects_unpackaged_process(self):
        pipe = windows.Server(None, '', None).create_pipe(True)
        client = win32file.CreateFile(windows.PIPE, win32con.GENERIC_READ | win32con.GENERIC_WRITE,
                                      0, None, win32con.OPEN_EXISTING, 0, None)
        try:
            self.assertFalse(windows.verify_client(pipe, 'fixture.exe', 'fixture'))
            self.assertFalse(windows.verify_client(pipe, 'fixture.exe', None))
        finally:
            client.Close()
            pipe.Close()

    def test_session_notifications_can_register(self):
        windows.watch_session(lambda: None)


if __name__ == '__main__':
    unittest.main(verbosity=2)
