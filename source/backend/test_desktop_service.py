import io, json, tempfile, time, threading, unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path
from pykeepass import create_database
from desktop_service import DesktopService

class DesktopServiceTests(unittest.TestCase):
    def test_login_unlock_waits_resumes_and_closes_prompt(self):
        output = io.StringIO()
        service = DesktopService(output)
        service.ready = True
        result = []
        request = dict(type='ensure_unlocked', protocolVersion=1, rpId='example.test')
        worker = threading.Thread(target=lambda: result.append(service.handle_request(request, timeout=2)))
        worker.start()
        deadline = time.monotonic() + 1
        while not service.unlock_waiters and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(service.unlock_waiters)
        self.assertEqual(result, [])
        service.lock(preserve_unlock=True)  # Password retries must preserve the login.
        self.assertFalse(next(iter(service.unlock_waiters.values())).is_set())
        service.store.unlocked = True
        worker.join(3)
        self.assertNotIn('errorCode', result[0])
        self.assertFalse(service.unlock_waiters)
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1])['type'], 'unlock_request_closed')

    def test_login_unlock_cancellation_disconnect_timeout_and_lock(self):
        for mode in ('cancel', 'disconnect', 'timeout', 'lock', 'close'):
            service = DesktopService(io.StringIO())
            service.ready = True
            result = []
            connected = threading.Event()
            connected.set()
            request = dict(type='ensure_unlocked', protocolVersion=1, rpId='example.test')
            worker = threading.Thread(target=lambda: result.append(service.handle_request(request, connected.is_set, timeout=.3)))
            worker.start()
            deadline = time.monotonic() + 1
            while not service.unlock_waiters and time.monotonic() < deadline:
                time.sleep(.001)
            if mode == 'cancel': service.command(dict(type='cancel_unlock_request', token=next(iter(service.unlock_waiters))))
            if mode == 'disconnect': connected.clear()
            if mode == 'lock': service.lock()
            if mode == 'close': service.close()
            worker.join(2)
            self.assertFalse(worker.is_alive(), mode)
            self.assertIn('errorCode', result[0], mode)
            self.assertFalse(service.unlock_waiters)

    def test_background_queries_do_not_prompt_unlock(self):
        output = io.StringIO()
        service = DesktopService(output)
        for kind in ('ping', 'get_credentials', 'get_settings'):
            service.handle_request(dict(type=kind))
        self.assertEqual(output.getvalue(), '')

    def test_sync_feedback_reports_unavailable_and_completion(self):
        output = io.StringIO()
        service = DesktopService(output)
        service.sync()
        event = json.loads(output.getvalue().splitlines()[-1])
        self.assertFalse(event['busy'])
        self.assertFalse(event['success'])
        service.server = SimpleNamespace(close=lambda: None)
        service.store.unlocked = True
        with patch('desktop_service.subprocess.run', return_value=SimpleNamespace(stdout='SYNC ok', returncode=0)):
            service.sync(wait=True)
        events = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(events[-2]['busy'])
        self.assertFalse(events[-1]['busy'])
        self.assertTrue(events[-1]['success'])
        service.server = None
        service.close()

    def test_security_preferences_apply_and_validate(self):
        service = DesktopService(io.StringIO())
        self.assertTrue(service.lock_on_session)
        self.assertTrue(service.require_confirmation)
        service.command(dict(type='configure', idleSeconds=300, lockOnSession=False, requireConfirmation=False))
        service.store.unlocked = True
        service.session_lock()
        self.assertTrue(service.store.unlocked)
        self.assertEqual(service.approve('example.test', [{'credentialId': 'fixture'}]), 'fixture')
        for invalid in ('false', 0, None):
            service.command(dict(type='configure', idleSeconds=600, lockOnSession=invalid, requireConfirmation=True))
            self.assertEqual(service.idle_seconds, 300)
            self.assertFalse(service.require_confirmation)
        service.command(dict(type='configure', idleSeconds=600, lockOnSession=True, requireConfirmation=True))
        service.session_lock()
        self.assertFalse(service.store.unlocked)
        self.assertIsNone(service.approve('example.test', [{'credentialId': 'fixture'}]))
        service.close()

    def test_multiple_accounts_still_require_selection(self):
        service = DesktopService(io.StringIO())
        service.store.unlocked = True
        service.require_confirmation = False
        result = []
        worker = threading.Thread(target=lambda: result.append(service.approve('example.test', [{'credentialId': 'one'}, {'credentialId': 'two'}])))
        worker.start()
        deadline = time.monotonic() + 3
        while not service.pending and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(service.pending)
        self.assertEqual(result, [])
        service.command(dict(type='approval', token=next(iter(service.pending)), credentialId='two'))
        worker.join(3)
        self.assertEqual(result, ['two'])
        service.close()

    def test_unlock_lock_and_no_secret_in_output(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'fixture.kdbx'
            create_database(str(path), password='fixture-native-secret')
            original = path.read_bytes()
            output = io.StringIO()
            service = DesktopService(output)
            service.ready = True
            request = {'type':'unlock','path':str(path),'password':'fixture-native-secret'}
            service.command(request)
            deadline = time.monotonic() + 20
            while service.busy and time.monotonic() < deadline:
                time.sleep(.02)
            self.assertTrue(service.store.unlocked)
            self.assertEqual(request, {})
            self.assertNotIn('fixture-native-secret', output.getvalue())
            self.assertIn('opened', [json.loads(line)['type'] for line in output.getvalue().splitlines()])
            service.command({'type':'lock'})
            self.assertFalse(service.store.unlocked)
            self.assertEqual(original, path.read_bytes())
            service.close()

    def test_lock_revokes_pending_approval(self):
        service = DesktopService(io.StringIO())
        service.store.unlocked = True
        result = []
        worker = threading.Thread(target=lambda: result.append(service.approve('example.test', [{'credentialId':'fixture'}])))
        worker.start()
        deadline = time.monotonic() + 3
        while not service.pending and time.monotonic() < deadline:
            time.sleep(.01)
        service.lock()
        worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [None])
        service.close()

    def test_auto_lock_setting_rejects_disable_and_invalid_values(self):
        service = DesktopService(io.StringIO())
        for valid in (300,600,900,1800):
            service.command({'type':'configure','idleSeconds':valid})
            self.assertEqual(service.idle_seconds, valid)
        for invalid in (0,-1,True,'600',999999):
            service.command({'type':'configure','idleSeconds':invalid})
            self.assertEqual(service.idle_seconds, 1800)
        service.close()

    def test_sync_burst_coalesces_and_close_clears_last(self):
        service = DesktopService(io.StringIO())
        service.server = SimpleNamespace(close=lambda: None)
        service.store.unlocked = True
        entered, release = threading.Event(), threading.Event()
        operations = []
        def run(args, **kwargs):
            operations.append(args[1])
            self.assertEqual(kwargs['timeout'], 5)
            if len(operations) == 1:
                entered.set()
                self.assertTrue(release.wait(3))
            return SimpleNamespace(stdout='', returncode=0)
        with patch('desktop_service.subprocess.run', side_effect=run):
            service.sync()
            self.assertTrue(entered.wait(3))
            for _ in range(100):
                service.sync()
            closer = threading.Thread(target=service.close)
            closer.start()
            deadline = time.monotonic() + 2
            while not service.closing and time.monotonic() < deadline:
                time.sleep(.01)
            release.set()
            closer.join(3)
            self.assertFalse(closer.is_alive())
        self.assertEqual(operations, ['/synccredential', '/clearcredentials'])
        self.assertFalse(service.store.unlocked)

    def test_sync_failure_does_not_prevent_final_clear(self):
        service = DesktopService(io.StringIO())
        service.server = SimpleNamespace(close=lambda: None)
        with patch('desktop_service.subprocess.run', side_effect=TimeoutError) as run:
            service.sync(wait=True)
            service.close()
            self.assertEqual(run.call_count, 2)
        self.assertFalse(service.store.unlocked)

    def test_unlock_transfers_credential_indexes(self):
        service = DesktopService(io.StringIO())
        service.ready = True
        record = dict(rpId='example.test', credentialId='fixture', userHandle='',
                      userName='fixture', title='fixture', databaseName='fixture.kdbx', key=None)
        def load(store, *args):
            store.records = [record]
            store.by_rp = {'example.test': [record]}
            store.by_id = {('example.test', 'fixture'): record}
        with patch('desktop_service.Store.open', load):
            service.unlock({'path': 'fixture'})
            deadline = time.monotonic() + 3
            while service.busy and time.monotonic() < deadline:
                time.sleep(.01)
        self.assertEqual(service.store.candidates('example.test')[0]['credentialId'], 'fixture')
        service.close()
        self.assertEqual(service.store.by_id, {})
        self.assertEqual(service.store.by_rp, {})
