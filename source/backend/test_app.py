# SPDX-License-Identifier: GPL-3.0-or-later
import tempfile
import time
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch
from pykeepass import create_database
from app import App

class UnlockTests(unittest.TestCase):
    def test_ui_supplies_password_before_clearing_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.kdbx"
            create_database(str(path), password="fixture-password")
            before = path.read_bytes()
            root = tk.Tk()
            root.withdraw()
            try:
                with patch("app.watch_session"), patch("app.current_package", return_value=None):
                    app = App(root)
                app.dbpath.set(str(path))
                app.password.set("fixture-password")
                app.unlock()
                self.assertEqual(app.password.get(), "")
                deadline = time.monotonic() + 20
                while app.busy and time.monotonic() < deadline:
                    root.update()
                    time.sleep(.02)
                self.assertFalse(app.busy)
                self.assertTrue(app.store.unlocked, app.status.get())
                self.assertEqual(path.read_bytes(), before)
                app.lock()
                self.assertFalse(app.store.unlocked)
            finally:
                root.destroy()

    def test_confirmation_preselects_first_account_without_auto_approval(self):
        import queue
        from tkinter import ttk
        root = tk.Tk()
        root.withdraw()
        try:
            with patch("app.watch_session"), patch("app.current_package", return_value=None):
                app = App(root)
            app.store.unlocked = True
            response = queue.Queue()
            choices = [dict(credentialId='fixture-one', userName='account', title='OKX'), dict(credentialId='fixture-two', userName='second', title='OKX')]
            app.prompt('okx.com', choices, response, app.store.generation)
            dialog = app.pending[0][0]
            def widgets(parent):
                for widget in parent.winfo_children():
                    yield widget
                    yield from widgets(widget)
            radios = [w for w in widgets(dialog) if isinstance(w, ttk.Radiobutton)]
            self.assertEqual(root.getvar(radios[0].cget('variable')), 'fixture-one')
            self.assertTrue(response.empty())
            approve = next(w for w in widgets(dialog) if isinstance(w, ttk.Button) and w.cget('text') == '允许本次认证')
            approve.invoke()
            self.assertEqual(response.get_nowait(), 'fixture-one')
        finally:
            root.destroy()

if __name__ == "__main__":
    unittest.main()
