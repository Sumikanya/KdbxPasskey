# SPDX-License-Identifier: GPL-3.0-or-later
"""Windows IPC with same-user ACL, package/executable checks and bounded I/O."""
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import struct
import threading

import pywintypes
import win32api
import win32con
import win32event
import win32file
import win32gui
import win32pipe
import win32security

PIPE = r"\\.\pipe\kdbx-passkey-v1"
MAX_MESSAGE = 1024 * 1024
kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.GetCurrentPackageFamilyName.argtypes = [ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
kernel.GetNamedPipeClientProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel.OpenProcess.restype = wintypes.HANDLE
kernel.GetPackageFamilyName.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.UINT), wintypes.LPWSTR]
kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
kernel.CloseHandle.argtypes = [wintypes.HANDLE]


def current_package():
    count = wintypes.UINT()
    if kernel.GetCurrentPackageFamilyName(ctypes.byref(count), None) != 122:
        return None
    buf = ctypes.create_unicode_buffer(count.value)
    return buf.value if kernel.GetCurrentPackageFamilyName(ctypes.byref(count), buf) == 0 else None


def verify_client(pipe, expected_exe, package):
    if not package:
        return False
    pid = wintypes.ULONG()
    if not kernel.GetNamedPipeClientProcessId(int(pipe), ctypes.byref(pid)):
        return False
    process = kernel.OpenProcess(0x1000, False, pid.value)
    if not process:
        return False
    try:
        count = wintypes.UINT()
        if kernel.GetPackageFamilyName(process, ctypes.byref(count), None) != 122:
            return False
        family = ctypes.create_unicode_buffer(count.value)
        if kernel.GetPackageFamilyName(process, ctypes.byref(count), family) != 0 or family.value != package:
            return False
        length = wintypes.DWORD(32768)
        path = ctypes.create_unicode_buffer(length.value)
        if not kernel.QueryFullProcessImageNameW(process, 0, path, ctypes.byref(length)):
            return False
        return os.path.normcase(os.path.abspath(path.value)) == os.path.normcase(os.path.abspath(expected_exe))
    finally:
        kernel.CloseHandle(process)


def security_attributes():
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    finally:
        token.Close()
    sa = pywintypes.SECURITY_ATTRIBUTES()
    sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f"D:(A;;GA;;;{sid})(A;;GA;;;SY)S:(ML;;NRNW;;;ME)", 1)
    return sa


def transfer(pipe, data_or_length, writing=False):
    event = win32event.CreateEvent(None, True, False, None)
    ov = pywintypes.OVERLAPPED()
    ov.hEvent = event
    try:
        if writing:
            status, _ = win32file.WriteFile(pipe, data_or_length, ov)
        else:
            status, buf = win32file.ReadFile(pipe, data_or_length, ov)
        if status == 997:
            if win32event.WaitForSingleObject(event, 10000) != win32con.WAIT_OBJECT_0:
                win32file.CancelIoEx(pipe, ov)
                # Wait until cancelled before allowing the OVERLAPPED buffer to be freed.
                win32event.WaitForSingleObject(event, win32event.INFINITE)
                raise TimeoutError("IPC timed out")
        count = win32file.GetOverlappedResult(pipe, ov, True)
        return count if writing else bytes(buf[:count])
    finally:
        event.Close()


def read_exact(pipe, count):
    parts = bytearray()
    while len(parts) < count:
        part = transfer(pipe, count - len(parts))
        if not part:
            raise EOFError()
        parts.extend(part)
    return bytes(parts)


def read_request(pipe):
    length, = struct.unpack("<I", read_exact(pipe, 4))
    if not 0 < length <= MAX_MESSAGE:
        raise ValueError("Invalid frame length")
    request = json.loads(read_exact(pipe, length).decode("utf-8"))
    if not isinstance(request, dict):
        raise ValueError("Request must be an object")
    return request


def write_response(pipe, response):
    body = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        body = b'{"errorCode":"internal_error","errorMessage":"Response exceeds limit"}'
    data = struct.pack("<I", len(body)) + body
    offset = 0
    while offset < len(data):
        count = transfer(pipe, data[offset:], writing=True)
        if count <= 0:
            raise EOFError()
        offset += count


class Server:
    def __init__(self, handler, provider_path, report, interactive=False):
        self.interactive = interactive
        self.handler = handler
        self.provider_path = provider_path
        self.report = report
        self.package = current_package()
        self.stopping = threading.Event()
        self.slots = threading.BoundedSemaphore(4)
        self.listener = None

    def create_pipe(self, first=False):
        return win32pipe.CreateNamedPipe(PIPE, 3 | 0x40000000 | (0x00080000 if first else 0),
                                        0, 8, 65536, 65536, 0, security_attributes())

    def start(self):
        if not self.package:
            raise RuntimeError("请通过安装后的开始菜单启动程序；便携运行不启用系统认证。")
        self.listener = self.create_pipe(True)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        pipe = self.listener
        try:
            while not self.stopping.is_set():
                if not self.slots.acquire(timeout=.2):
                    continue
                ov = pywintypes.OVERLAPPED()
                ov.hEvent = win32event.CreateEvent(None, True, False, None)
                try:
                    try:
                        result = win32pipe.ConnectNamedPipe(pipe, ov)
                        if result == 535:
                            win32event.SetEvent(ov.hEvent)
                    except pywintypes.error as ex:
                        if ex.winerror != 535:
                            raise
                        win32event.SetEvent(ov.hEvent)
                    while win32event.WaitForSingleObject(ov.hEvent, 200) != win32con.WAIT_OBJECT_0:
                        if self.stopping.is_set():
                            win32file.CancelIoEx(pipe, ov)
                            win32event.WaitForSingleObject(ov.hEvent, win32event.INFINITE)
                            return
                    # Reserve the next instance before the accepted connection can
                    # close, so the pipe name is continuously owned by this process.
                    next_pipe = self.create_pipe()
                    self.listener = next_pipe
                    threading.Thread(target=self.serve, args=(pipe,), daemon=True).start()
                    pipe = next_pipe
                finally:
                    ov.hEvent.Close()
        except Exception:
            if not self.stopping.is_set():
                self.report("系统认证服务停止，请重启程序。")
        finally:
            if pipe:
                pipe.Close()

    def serve(self, pipe):
        try:
            if not verify_client(pipe, self.provider_path, self.package):
                return
            request = read_request(pipe)
            def connected():
                try:
                    win32pipe.PeekNamedPipe(pipe, 0)
                    return not self.stopping.is_set()
                except pywintypes.error:
                    return False
            response = self.handler(request, connected) if self.interactive else self.handler(request)
            write_response(pipe, response)
        except Exception:
            pass  # Never log raw requests, usernames, hashes or keys.
        finally:
            pipe.Close()
            self.slots.release()

    def close(self):
        self.stopping.set()


def watch_session(on_lock):
    """Lock on workstation lock/disconnect and suspend, using native notifications."""
    ready = threading.Event()
    state = {}
    def run():
        def wndproc(hwnd, msg, wparam, lparam):
            if msg == 0x02B1 and wparam in (2, 4, 7):
                on_lock()
            elif msg == win32con.WM_POWERBROADCAST and wparam == 4:
                on_lock()
            return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)
        try:
            wc = win32gui.WNDCLASS()
            wc.lpfnWndProc = wndproc
            wc.lpszClassName = "KdbxPasskeySessionWatcher"
            wc.hInstance = win32api.GetModuleHandle(None)
            atom = win32gui.RegisterClass(wc)
            hwnd = win32gui.CreateWindow(atom, "", 0, 0, 0, 0, 0, 0, 0, wc.hInstance, None)
            wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
            wts.WTSRegisterSessionNotification.argtypes = [wintypes.HWND, wintypes.DWORD]
            if not wts.WTSRegisterSessionNotification(hwnd, 0):
                raise ctypes.WinError(ctypes.get_last_error())
            state["ok"] = True
            ready.set()
            win32gui.PumpMessages()
        except Exception:
            state["ok"] = False
            ready.set()
    threading.Thread(target=run, daemon=True).start()
    if not ready.wait(5) or not state.get("ok"):
        raise RuntimeError("无法启用会话锁定监测；为安全起见，不能解锁数据库。")
