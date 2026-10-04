# SPDX-License-Identifier: GPL-3.0-or-later
"""One installed application: KDBX unlock UI and bundled Windows provider."""
import gc
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import Store, UnlockError, handle
from windows import Server, current_package, watch_session


class App:
    def __init__(self, root):
        self.root = root
        self.store = Store()
        self.events = queue.Queue()
        self.pending = []
        self.closing = False
        self.open_epoch = 0
        self.session_ready = False
        self.busy = False
        self.sync_gate = threading.Lock()
        self.base = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
        self.provider = self.base / "Provider" / "KeePassPasskeyProvider.exe"
        self.server = None
        self.session_notice = ""
        root.title("KDBX Passkey 0.1.8")
        root.geometry("1040x820")
        root.minsize(920, 760)
        root.configure(bg="#202020")
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure(".", background="#292929", foreground="#f5f5f5", font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background="#292929")
        style.configure("Side.TFrame", background="#202020")
        style.configure("TLabel", background="#292929", foreground="#f5f5f5")
        style.configure("TButton", background="#3b3b3b", foreground="#f5f5f5", padding=(14, 9), borderwidth=0)
        style.map("TButton", background=[("active", "#51465d"), ("disabled", "#303030")], foreground=[("disabled", "#888888")])
        style.configure("Primary.TButton", background="#c6a7e2", foreground="#24192d")
        style.map("Primary.TButton", background=[("active", "#dbc1f0"), ("disabled", "#53465e")])
        style.configure("TEntry", fieldbackground="#383838", foreground="#ffffff", insertcolor="#ffffff", padding=8)
        style.configure("TRadiobutton", background="#333333", foreground="#ffffff", padding=10)
        style.map("TRadiobutton", background=[("active", "#45394f")], indicatorcolor=[("selected", "#c6a7e2"), ("!selected", "#646464")])
        side = ttk.Frame(root, style="Side.TFrame", width=210, padding=18)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="⬡  KDBX Passkey", bg="#202020", fg="#d2b4ee", font=("Microsoft YaHei UI", 13, "bold")).pack(anchor="w", pady=(5, 35))
        ttk.Button(side, text="状态 / 数据库", command=lambda: self.passbox.focus_set()).pack(fill="x", pady=5)
        ttk.Button(side, text="凭据诊断", command=self.show_details).pack(fill="x", pady=5)
        ttk.Button(side, text="Windows 设置", command=self.settings).pack(fill="x", pady=5)
        tk.Label(side, text="0.1.8  ·  本地数据库", bg="#202020", fg="#999999", font=("Microsoft YaHei UI", 9)).pack(side="bottom", anchor="w")
        canvas = ttk.Frame(root, padding=24)
        canvas.pack(side="left", fill="both", expand=True)
        body = ttk.Frame(canvas, padding=24)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="KDBX Passkey", font=("Microsoft YaHei UI", 22, "bold")).pack(anchor="w")
        ttk.Label(body, text="独立解锁数据库 · 在 Windows 应用中使用已有通行密钥").pack(anchor="w", pady=(4, 20))
        self.status = tk.StringVar(value="数据库已锁定")
        ttk.Label(body, textvariable=self.status, foreground="#c6a7e2", wraplength=690).pack(anchor="w", pady=(0, 15))
        self.dbpath = tk.StringVar()
        self.keypath = tk.StringVar()
        self.password = tk.StringVar()
        self.path_row(body, "数据库 (.kdbx)", self.dbpath, self.choose_db)
        self.path_row(body, "密钥文件（可选）", self.keypath, self.choose_key)
        ttk.Label(body, text="主密码（密钥文件单独解锁时可留空）").pack(anchor="w", pady=(10, 4))
        self.passbox = ttk.Entry(body, textvariable=self.password, show="●")
        self.passbox.pack(fill="x")
        self.passbox.bind("<Return>", lambda _: self.unlock())
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=16)
        self.unlock_btn = ttk.Button(buttons, text="解锁数据库", style="Primary.TButton", command=self.unlock)
        self.unlock_btn.pack(side="left")
        ttk.Button(buttons, text="立即锁定", command=self.lock).pack(side="left", padx=8)
        ttk.Button(buttons, text="Windows 通行密钥设置", command=self.settings).pack(side="right")
        self.count = tk.StringVar(value="解锁后显示可用通行密钥数量。")
        ttk.Label(body, textvariable=self.count).pack(anchor="w", pady=8)
        ttk.Button(body, text="查看凭据站点与跳过原因", command=self.show_details).pack(anchor="w")
        self.sync_status = tk.StringVar(value="Windows 凭据同步：尚未执行")
        ttk.Label(body, textvariable=self.sync_status, wraplength=740).pack(anchor="w", pady=5)
        ttk.Separator(body).pack(fill="x", pady=12)
        ttk.Label(body, text="使用方法：解锁后，在登录窗口选择 KDBX Passkey，完成 Windows Hello，\n再确认本次认证。保持此窗口运行即可。", wraplength=690).pack(anchor="w")
        ttk.Label(body, text="10 分钟未认证、Windows 锁屏或休眠时自动锁定。数据库以只读方式打开。\n新增通行密钥请在 KeePassXC 中完成，再在这里重新解锁。", foreground="#aaaaaa",
                  wraplength=690).pack(anchor="w", pady=12)
        root.protocol("WM_DELETE_WINDOW", self.quit)
        root.bind("<Control-l>", lambda _: self.lock())
        try:
            watch_session(self.session_lock)
            self.session_ready = True
            if current_package():
                if not self.provider.is_file():
                    raise RuntimeError("安装包缺少 Windows 提供程序。")
                self.server = Server(lambda req: handle(self.store, req, self.approve), str(self.provider),
                                     lambda msg: self.events.put(("error", msg)))
                self.server.start()
                threading.Thread(target=self.initialize_provider, daemon=True).start()
            else:
                self.status.set("开发模式：可验证 KDBX 解锁；系统认证需安装 MSIX 后启动。")
        except Exception as ex:
            self.session_ready = False
            self.session_notice = str(ex)
            self.status.set(self.session_notice)
        root.after(100, self.tick)

    def show_details(self):
        with self.store.gate:
            sites = sorted({r["rpId"] for r in self.store.records})
            skipped = list(self.store.skipped_details)
        text = "已加载元数据的站点：\n" + ("\n".join(sites) or "无")
        text += "\n\n无法签名或无法同步的凭据：\n" + ("\n".join(f"{r['rpId']}：{r['reason']}" for r in skipped) or "无")
        messagebox.showinfo("凭据诊断（不含私钥）", text)

    def path_row(self, body, label, variable, choose):
        ttk.Label(body, text=label).pack(anchor="w", pady=(5, 4))
        row = ttk.Frame(body)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="选择", command=choose).pack(side="right", padx=(8, 0))

    def choose_db(self):
        path = filedialog.askopenfilename(title="选择 KeePassXC 数据库", filetypes=[("KeePass 数据库", "*.kdbx")])
        if path:
            self.dbpath.set(path)

    def choose_key(self):
        path = filedialog.askopenfilename(title="选择密钥文件")
        if path:
            self.keypath.set(path)

    def initialize_provider(self):
        try:
            result = subprocess.run([str(self.provider), "/ensure_registered"], creationflags=subprocess.CREATE_NO_WINDOW,
                                    timeout=30, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
            detail = result.stdout.strip()
            if not detail.startswith("REGISTER "):
                detail = f"REGISTER exit=0x{result.returncode & 0xffffffff:08X}"
            self.events.put(("provider_status", detail))
            if result.returncode:
                self.events.put(("error", f"Windows 提供程序未就绪：{detail}"))
            else:
                self.sync()
        except Exception:
            self.events.put(("error", "Windows 提供程序启动失败。"))

    def sync(self):
        if not self.server or self.closing:
            return
        def run():
            with self.sync_gate:
                try:
                    operation = "/synccredential" if self.store.unlocked else "/clearcredentials"
                    result = subprocess.run([str(self.provider), operation],
                                            creationflags=subprocess.CREATE_NO_WINDOW, timeout=30,
                                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", errors="replace")
                    detail = result.stdout.strip()
                    if not detail.startswith("SYNC "):
                        detail = f"exit={result.returncode}"
                    self.events.put(("sync_status", (operation, result.returncode, detail)))
                    if result.returncode:
                        self.events.put(("error", "凭据列表同步失败，请确认 Windows 中已启用 KDBX Passkey。"))
                except Exception:
                    self.events.put(("error", "凭据列表同步失败，请重新解锁后重试。"))
        threading.Thread(target=run, daemon=True).start()

    def unlock(self):
        if self.busy:
            return
        if not self.session_ready:
            messagebox.showerror("无法解锁", self.session_notice or "会话锁定监测未启用。")
            return
        path = self.dbpath.get().strip()
        if not path:
            messagebox.showinfo("选择数据库", "请先选择 .kdbx 数据库文件。")
            return
        # Capture the input before lock() clears the password widget.
        password = self.password.get() or None
        self.lock()
        self.busy = True
        self.unlock_btn.configure(state="disabled")
        self.status.set("正在解锁数据库…")
        keyfile = self.keypath.get().strip() or None
        epoch = self.open_epoch
        def load():
            temp = Store()
            try:
                number = temp.open(path, password, keyfile)
                self.events.put(("opened", (epoch, temp, number)))
            except Exception as ex:
                temp.lock()
                message = str(ex) if isinstance(ex, UnlockError) else f"解密后解析失败 [{type(ex).__name__}]；请反馈此错误代码。"
                self.events.put(("open_failed", (epoch, message)))
        threading.Thread(target=load, daemon=True).start()

    def session_lock(self):
        # Invalidate in-flight unlock/signing immediately, without waiting for Tk.
        self.open_epoch += 1
        self.store.lock()
        self.events.put(("locked", "Windows 会话已锁定或休眠，数据库已锁定。"))

    def lock(self):
        self.open_epoch += 1
        self.store.lock()
        self.password.set("")
        self.status.set("数据库已锁定")
        self.count.set("可用通行密钥：0")
        self.cancel_prompts()
        self.sync()
        gc.collect()

    def cancel_prompts(self):
        for dialog, result in self.pending[:]:
            result.put_nowait(None)
            dialog.destroy()
        self.pending.clear()

    def approve(self, rp, choices):
        response = queue.Queue(maxsize=1)
        self.events.put(("approve", (rp, choices, response, self.store.generation)))
        try:
            return response.get(timeout=60)
        except queue.Empty:
            return None

    def prompt(self, rp, choices, response, generation):
        if not self.store.unlocked or generation != self.store.generation:
            response.put_nowait(None)
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("确认通行密钥认证")
        dialog.geometry(f"620x{min(650, 260 + len(choices) * 65)}")
        dialog.configure(bg="#292929")
        dialog.transient(self.root)
        dialog.attributes("-topmost", True)
        frame = ttk.Frame(dialog, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="确认登录以下站点", font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w")
        ttk.Label(frame, text=rp, foreground="#c6a7e2", wraplength=510).pack(anchor="w", pady=12)
        ttk.Label(frame, text="选择要使用的账户：").pack(anchor="w")
        selected = tk.StringVar(value=choices[0]["credentialId"])
        for candidate in choices:
            label = f'{candidate["userName"] or "（无用户名）"}  ·  {candidate["title"]}'
            ttk.Radiobutton(frame, text=label, variable=selected, value=candidate["credentialId"]).pack(fill="x", pady=4)
        self.pending.append((dialog, response))
        def finish(value=None):
            if (dialog, response) not in self.pending:
                return
            self.pending.remove((dialog, response))
            response.put_nowait(value)
            dialog.destroy()
        row = ttk.Frame(frame)
        row.pack(fill="x", pady=12)
        ttk.Button(row, text="取消", command=finish).pack(side="right")
        ttk.Button(row, text="允许本次认证", style="Primary.TButton", command=lambda: finish(selected.get())).pack(side="right", padx=8)
        dialog.protocol("WM_DELETE_WINDOW", finish)
        dialog.bind("<Escape>", lambda _: finish())
        # Never map Enter to approval; an unexpected dialog must not consume a login keystroke.
        dialog.after(55000, finish)
        dialog.lift()

    def settings(self):
        os.startfile("ms-settings:passkeys-advancedoptions")

    def tick(self):
        if self.closing:
            return
        while True:
            try:
                event, payload = self.events.get_nowait()
            except queue.Empty:
                break
            if event == "opened":
                epoch, temp, number = payload
                self.busy = False
                self.unlock_btn.configure(state="normal")
                if epoch != self.open_epoch:
                    temp.lock()
                    self.status.set("解锁已取消；请重新解锁。")
                    continue
                # Keep the Store object stable because IPC callbacks reference it.
                with self.store.gate, temp.gate:
                    self.store.records = temp.records
                    self.store.by_rp = temp.by_rp
                    self.store.by_id = temp.by_id
                    self.store.skipped = temp.skipped
                    self.store.skipped_details = temp.skipped_details
                    temp.skipped_details = []
                    temp.records = []
                    temp.by_rp = {}
                    temp.by_id = {}
                    self.store.unlocked = True
                    self.store.generation += 1
                    self.store.last_use = time.monotonic()
                self.status.set("数据库已解锁；请在 Windows 设置中启用 KDBX Passkey。")
                self.count.set(f"凭据元数据：{number}；可签名：{sum(r['key'] is not None for r in self.store.records)}；异常条目：{temp.skipped}")
                self.sync()
            elif event == "open_failed":
                epoch, message = payload
                if epoch != self.open_epoch:
                    continue
                self.busy = False
                self.unlock_btn.configure(state="normal")
                self.status.set(message)
            elif event == "approve":
                self.prompt(*payload)
            elif event == "locked":
                self.status.set(payload)
                self.count.set("可用通行密钥：0")
                self.cancel_prompts()
                self.sync()
            elif event == "provider_status":
                self.sync_status.set(f"Windows 提供程序：{payload}")
            elif event == "sync_status":
                operation, code, detail = payload
                self.sync_status.set(f"Windows 凭据同步：{detail}")
            elif event == "error":
                self.status.set(payload)
        if self.store.unlocked and time.monotonic() - self.store.last_use >= 600:
            self.lock()
            self.status.set("10 分钟未认证，数据库已自动锁定。")
        self.root.after(100, self.tick)

    def quit(self):
        self.lock()
        self.closing = True
        if self.server:
            self.server.close()
        self.root.destroy()


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--runtime-check":
        import ctypes
        root = tk.Tk()
        root.withdraw()
        root.update()
        watch_session(lambda: None)
        dll = ctypes.WinDLL("webauthn.dll")
        checks = dict(tk=True, sessionNotifications=True,
                      windowsPluginApi=bool(getattr(dll, "WebAuthNPluginAddAuthenticator", None)),
                      packageIdentity=bool(current_package()))
        import tempfile
        from pykeepass import create_database
        with tempfile.TemporaryDirectory() as folder:
            fixture = Path(folder) / "runtime-fixture.kdbx"
            fixture_db = create_database(str(fixture), password="runtime-fixture-password")
            from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids
            params = fixture_db.kdbx.header.value.dynamic_header.kdf_parameters.data.dict
            params["$UUID"].value = kdf_uuids["argon2"]
            params["I"].value = 30
            params["M"].value = 67108864
            params["P"].value = 2
            params["V"].value = 19
            fixture_db.save()
            probe = Store()
            probe.open(fixture, "runtime-fixture-password")
            checks["kdbxUnlock"] = probe.unlocked
            probe.lock()
        root.destroy()
        Path(sys.argv[2]).write_text(json.dumps(checks, indent=2), encoding="utf-8")
        return
    import win32api
    import win32event
    guard = win32event.CreateMutex(None, False, "Local\\KdbxPasskey-UI")
    if win32api.GetLastError() == 183:
        messagebox.showinfo("KDBX Passkey", "程序已运行，请使用已打开的窗口。")
        guard.Close()
        return
    root = tk.Tk()
    try:
        App(root)
        root.mainloop()
    finally:
        guard.Close()


if __name__ == "__main__":
    main()
