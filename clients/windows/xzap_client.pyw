"""
XZAP Client — Windows GUI (tkinter).
Standalone SOCKS5 proxy with XZAP tunnel.
"""

import asyncio
import base64
import json
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

CONFIG_FILE = Path(os.environ.get("APPDATA", Path.home())) / "xzap" / "config.json"


def load_config() -> dict:
    defaults = {
        "server": "",
        "port": 8443,
        "key": "",
        "socks_port": 1080,
        "use_tls": True,
        "autoconnect": False,
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, encoding="utf-8") as f:
                saved = json.load(f)
            defaults.update(saved)
        except Exception:
            pass
    return defaults


def save_config(cfg: dict):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


class XZAPClientApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("XZAP Client")
        self.root.geometry("420x340")
        self.root.resizable(False, False)

        self._connected = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

        self._build_ui()
        self._load_settings()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        cfg = load_config()
        if cfg.get("autoconnect") and cfg.get("server") and cfg.get("key"):
            self.root.after(500, self._toggle_connect)

    def _build_ui(self):
        pad = {"padx": 10, "pady": 4}

        # Server settings
        frame = ttk.LabelFrame(self.root, text="Server", padding=10)
        frame.pack(fill="x", **pad)

        ttk.Label(frame, text="Host:").grid(row=0, column=0, sticky="w")
        self.entry_host = ttk.Entry(frame, width=30)
        self.entry_host.grid(row=0, column=1, sticky="ew", padx=(5, 0))

        ttk.Label(frame, text="Port:").grid(row=1, column=0, sticky="w")
        self.entry_port = ttk.Entry(frame, width=10)
        self.entry_port.grid(row=1, column=1, sticky="w", padx=(5, 0))

        ttk.Label(frame, text="Key:").grid(row=2, column=0, sticky="w")
        self.entry_key = ttk.Entry(frame, width=30, show="*")
        self.entry_key.grid(row=2, column=1, sticky="ew", padx=(5, 0))

        frame.columnconfigure(1, weight=1)

        # Local proxy settings
        frame2 = ttk.LabelFrame(self.root, text="Local Proxy", padding=10)
        frame2.pack(fill="x", **pad)

        ttk.Label(frame2, text="SOCKS5 port:").grid(row=0, column=0, sticky="w")
        self.entry_socks = ttk.Entry(frame2, width=10)
        self.entry_socks.grid(row=0, column=1, sticky="w", padx=(5, 0))

        self.var_tls = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame2, text="TLS (anti-DPI)", variable=self.var_tls).grid(
            row=0, column=2, padx=(20, 0)
        )

        self.var_auto = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame2, text="Auto-connect", variable=self.var_auto).grid(
            row=1, column=0, columnspan=3, sticky="w", pady=(5, 0)
        )

        # Connect button
        self.btn_connect = ttk.Button(
            self.root, text="Connect", command=self._toggle_connect
        )
        self.btn_connect.pack(**pad)

        # Status
        self.status_var = tk.StringVar(value="Disconnected")
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill="x", **pad)

        self.status_dot = tk.Canvas(status_frame, width=12, height=12,
                                     highlightthickness=0)
        self.status_dot.pack(side="left")
        self._draw_dot("red")

        ttk.Label(status_frame, textvariable=self.status_var).pack(
            side="left", padx=(5, 0)
        )

        # Proxy info
        self.proxy_info = tk.StringVar(value="")
        ttk.Label(self.root, textvariable=self.proxy_info,
                  foreground="gray").pack(**pad)

    def _draw_dot(self, color: str):
        self.status_dot.delete("all")
        self.status_dot.create_oval(2, 2, 10, 10, fill=color, outline=color)

    def _load_settings(self):
        cfg = load_config()
        self.entry_host.insert(0, cfg["server"])
        self.entry_port.insert(0, str(cfg["port"]))
        self.entry_key.insert(0, cfg["key"])
        self.entry_socks.insert(0, str(cfg["socks_port"]))
        self.var_tls.set(cfg["use_tls"])
        self.var_auto.set(cfg.get("autoconnect", False))

    def _save_settings(self):
        save_config({
            "server": self.entry_host.get().strip(),
            "port": int(self.entry_port.get().strip() or 8443),
            "key": self.entry_key.get().strip(),
            "socks_port": int(self.entry_socks.get().strip() or 1080),
            "use_tls": self.var_tls.get(),
            "autoconnect": self.var_auto.get(),
        })

    def _toggle_connect(self):
        if self._connected:
            self._disconnect()
        else:
            self._connect()

    def _connect(self):
        host = self.entry_host.get().strip()
        key_b64 = self.entry_key.get().strip()

        if not host or not key_b64:
            messagebox.showerror("Error", "Server and Key are required")
            return

        try:
            key = base64.b64decode(key_b64)
        except Exception:
            messagebox.showerror("Error", "Invalid base64 key")
            return

        port = int(self.entry_port.get().strip() or 8443)
        socks_port = int(self.entry_socks.get().strip() or 1080)
        use_tls = self.var_tls.get()

        self._save_settings()

        self.status_var.set("Connecting...")
        self._draw_dot("yellow")
        self.btn_connect.config(state="disabled")

        self._thread = threading.Thread(
            target=self._run_proxy,
            args=(host, port, key, socks_port, use_tls),
            daemon=True,
        )
        self._thread.start()

    def _run_proxy(self, host, port, key, socks_port, use_tls):
        from xzap.client import XZAPClient

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        async def main():
            client = XZAPClient(
                server_host=host,
                server_port=port,
                key=key,
                use_tls=use_tls,
            )

            lists_dir = PROJECT_ROOT / "lists"
            await client.router.load_lists(
                bypass_file=str(lists_dir / "bypass.txt"),
                xzap_file=str(lists_dir / "xzap.txt"),
            )

            proxy = client.make_socks5("127.0.0.1", socks_port)
            await proxy.start()

            self.root.after(0, self._on_connected, socks_port)

            await proxy.serve_forever()

        try:
            self._loop.run_until_complete(main())
        except Exception as e:
            self.root.after(0, self._on_error, str(e))

    def _on_connected(self, socks_port: int):
        self._connected = True
        self.status_var.set("Connected")
        self._draw_dot("#00cc00")
        self.btn_connect.config(text="Disconnect", state="normal")
        self.proxy_info.set(
            f"SOCKS5 proxy: 127.0.0.1:{socks_port}\n"
            f"Configure browser to use this proxy"
        )
        for w in (self.entry_host, self.entry_port, self.entry_key,
                  self.entry_socks):
            w.config(state="disabled")

    def _on_error(self, msg: str):
        self._connected = False
        self.status_var.set(f"Error: {msg[:60]}")
        self._draw_dot("red")
        self.btn_connect.config(text="Connect", state="normal")
        self.proxy_info.set("")

    def _disconnect(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._connected = False
        self.status_var.set("Disconnected")
        self._draw_dot("red")
        self.btn_connect.config(text="Connect", state="normal")
        self.proxy_info.set("")
        for w in (self.entry_host, self.entry_port, self.entry_key,
                  self.entry_socks):
            w.config(state="normal")

    def _on_close(self):
        self._save_settings()
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = XZAPClientApp()
    app.run()
