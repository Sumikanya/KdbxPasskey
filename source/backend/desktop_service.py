# SPDX-License-Identifier: GPL-3.0-or-later
"""Headless backend for the native WPF UI. Inherited stdio, no password args/logs."""
import sys, json, threading, queue, time, subprocess
from pathlib import Path
from core import Store, UnlockError, handle
from windows import Server, current_package, watch_session

class DesktopService:
    def __init__(self, output):
        self.output = output
        self.write_gate = threading.Lock()
        self.state_gate = threading.RLock()
        self.sync_condition = threading.Condition()
        self.sync_requested = False
        self.sync_worker = None
        self.store = Store()
        self.epoch = 0
        self.idle_seconds = 600
        self.lock_on_session = True
        self.require_confirmation = True
        self.busy = False
        self.pending = {}
        self.unlock_waiters = {}
        self.sequence = 0
        self.closing = False
        self.server = None
        self.ready = False
        self.provider = Path(sys.executable).parent.parent / 'Provider' / 'KeePassPasskeyProvider.exe'

    def emit(self, kind, **values):
        with self.write_gate:
            self.output.write(json.dumps(dict(type=kind, **values), ensure_ascii=False) + '\n')
            self.output.flush()

    def start(self):
        try:
            watch_session(self.session_lock)
            self.ready = True
            if current_package():
                if not self.provider.is_file():
                    raise RuntimeError('provider missing')
                self.server = Server(self.handle_request, str(self.provider), lambda _: self.emit('error', message='系统认证通信异常。'), interactive=True)
                self.server.start()
                threading.Thread(target=self.register, daemon=True).start()
            else:
                self.emit('sync', message='开发模式：数据库可解锁，系统认证需安装 MSIX。')
        except Exception:
            self.ready = False
            self.emit('error', message='系统认证服务或会话锁定监测启动失败。')
        threading.Thread(target=self.idle, daemon=True).start()
        self.emit('locked', message='数据库已锁定')

    def handle_request(self, request, connected=lambda: True, timeout=120):
        if request.get('type') != 'ensure_unlocked':
            return handle(self.store, request, self.approve)
        failed = dict(type='ensure_unlocked', errorCode='db_locked', errorMessage='解锁已取消或超时。')
        rp = request.get('rpId')
        if request.get('protocolVersion') != 1 or not isinstance(rp, str) or not rp or len(rp) > 253:
            return failed
        with self.state_gate:
            if self.closing or not self.ready:
                return failed
            if self.store.unlocked:
                return dict(type='ensure_unlocked')
            # One foreground unlock at a time. A second login cannot replace its context.
            if self.unlock_waiters:
                return failed
            self.sequence += 1
            token = str(self.sequence)
            cancelled = threading.Event()
            self.unlock_waiters[token] = cancelled
            self.emit('unlock_required', token=token, rp=rp)
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and connected():
                with self.state_gate:
                    if cancelled.is_set() or self.closing:
                        return failed
                    if self.store.unlocked:
                        return dict(type='ensure_unlocked')
                cancelled.wait(.1)
            return failed
        finally:
            with self.state_gate:
                self.unlock_waiters.pop(token, None)
            self.emit('unlock_request_closed', token=token)

    def session_lock(self):
        with self.state_gate:
            if self.lock_on_session:
                self.lock('Windows 锁屏或休眠，数据库已锁定。')

    def register(self):
        try:
            result = subprocess.run([str(self.provider), '/ensure_registered'], creationflags=subprocess.CREATE_NO_WINDOW, timeout=30, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace')
            detail = result.stdout.strip()
            self.emit('sync', message=detail if detail.startswith('REGISTER ') else f'提供程序 exit=0x{result.returncode & 0xffffffff:08X}')
            if result.returncode == 0:
                self.sync()
        except Exception:
            self.emit('error', message='Windows 提供程序启动失败。')

    def sync(self, wait=False):
        if not self.server:
            self.emit('sync', message='系统同步不可用：请从已安装的 MSIX 启动。', busy=False, success=False)
            return
        with self.sync_condition:
            if self.closing and not wait:
                return
            self.sync_requested = True
            if self.sync_worker is None or not self.sync_worker.is_alive():
                self.sync_worker = threading.Thread(target=self._sync_loop, daemon=True)
                self.sync_worker.start()
            self.sync_condition.notify_all()
            worker = self.sync_worker
        if wait:
            # At most one active operation plus the final cache clear (5s each).
            worker.join(11)

    def _sync_loop(self):
        while True:
            with self.sync_condition:
                if not self.sync_requested:
                    self.sync_worker = None
                    return
                self.sync_requested = False
            try:
                operation = '/synccredential' if self.store.unlocked else '/clearcredentials'
                self.emit('sync', message='正在同步到 Windows…', busy=True)
                result = subprocess.run([str(self.provider), operation], creationflags=subprocess.CREATE_NO_WINDOW, timeout=5, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='replace')
                detail = result.stdout.strip()
                self.emit('sync', busy=False, success=result.returncode == 0, message=(detail if detail.startswith('SYNC ') else ('凭据缓存已清除' if result.returncode == 0 else f'同步失败 exit=0x{result.returncode & 0xffffffff:08X}')))
            except Exception:
                self.emit('sync', busy=False, success=False, message='Windows 凭据同步失败，请重试。')

    def lock(self, message='数据库已锁定', preserve_unlock=False):
        with self.state_gate:
            if not preserve_unlock:
                for cancelled in self.unlock_waiters.values():
                    cancelled.set()
            self.epoch += 1
            self.store.lock()
            for response in self.pending.values():
                if response.empty():
                    response.put_nowait(None)
            self.pending.clear()
        self.emit('locked', message=message)
        if not self.closing:
            self.sync()

    def unlock(self, request):
        with self.state_gate:
            if self.busy or not self.ready:
                self.emit('error', message='服务未就绪或正在解锁。')
                return
            self.lock(preserve_unlock=True)
            self.busy = True
            epoch = self.epoch
        self.emit('busy')
        def run():
            temp = Store()
            try:
                temp.open(request.get('path', ''), request.get('password') or None, request.get('keyfile') or None)
                request.clear()
                with self.state_gate:
                    if epoch != self.epoch or self.closing:
                        temp.lock()
                        self.emit('cancelled', message='解锁已取消，请重新解锁。')
                        return
                    with self.store.gate, temp.gate:
                        self.store.records = temp.records
                        self.store.by_rp = temp.by_rp
                        self.store.by_id = temp.by_id
                        temp.records = []
                        temp.by_rp = {}
                        temp.by_id = {}
                        self.store.skipped = temp.skipped
                        self.store.skipped_details = temp.skipped_details
                        temp.skipped_details = []
                        self.store.unlocked = True
                        self.store.generation += 1
                        self.store.last_use = time.monotonic()
                    records = self.store.records
                    self.emit('opened', total=len(records), signable=sum(r['key'] is not None for r in records), sites=sorted({r['rpId'] for r in records}), diagnostics=list(self.store.skipped_details), credentials=[dict(rpId=r['rpId'], userName=r['userName'], title=r['title'], signable=r['key'] is not None, reason=r.get('key_error') or '') for r in records])
                self.sync()
            except Exception as ex:
                request.clear()
                temp.lock()
                if epoch == self.epoch:
                    self.emit('error', message=str(ex) if isinstance(ex, UnlockError) else f'数据库解析失败 [{type(ex).__name__}]')
            finally:
                self.busy = False
                self.emit('idle')
        threading.Thread(target=run, daemon=True).start()

    def approve(self, rp, choices):
        with self.state_gate:
            if not self.store.unlocked or self.closing:
                return None
            if not self.require_confirmation and len(choices) == 1:
                return choices[0]['credentialId']
            self.sequence += 1
            token = str(self.sequence)
            response = queue.Queue(maxsize=1)
            self.pending[token] = response
            self.emit('approve', token=token, rp=rp, choices=choices)
        try:
            return response.get(timeout=60)
        except queue.Empty:
            return None
        finally:
            with self.state_gate:
                self.pending.pop(token, None)
            self.emit('approval_closed', token=token)

    def command(self, request):
        kind = request.get('type')
        if kind == 'unlock':
            self.unlock(request)
        elif kind == 'cancel_unlock_request':
            with self.state_gate:
                cancelled = self.unlock_waiters.get(request.get('token'))
                if cancelled is not None:
                    cancelled.set()
        elif kind == 'lock':
            self.lock()
        elif kind == 'approval':
            with self.state_gate:
                response = self.pending.get(request.get('token'))
                if response is not None and response.empty():
                    response.put_nowait(request.get('credentialId'))
        elif kind == 'sync':
            self.sync()
        elif kind == 'configure':
            seconds = request.get('idleSeconds')
            session = request.get('lockOnSession', self.lock_on_session)
            confirmation = request.get('requireConfirmation', self.require_confirmation)
            if type(seconds) is int and seconds in (300, 600, 900, 1800) and type(session) is bool and type(confirmation) is bool:
                with self.state_gate:
                    self.idle_seconds = seconds
                    self.lock_on_session = session
                    self.require_confirmation = confirmation
            else:
                self.emit('error', message='安全设置无效。')
        elif kind == 'quit':
            return False
        return True

    def idle(self):
        while not self.closing:
            if self.store.unlocked and time.monotonic() - self.store.last_use >= self.idle_seconds:
                self.lock(f'{self.idle_seconds // 60} 分钟未认证，数据库已锁定。')
            time.sleep(1)

    def close(self):
        self.closing = True
        self.lock()
        self.sync(wait=True)
        if self.server:
            self.server.close()

if __name__ == '__main__':
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8')
    service = DesktopService(sys.stdout)
    try:
        service.start()
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if not service.command(request):
                    break
            except Exception:
                service.emit('error', message='界面通信请求无效。')
    finally:
        service.close()
