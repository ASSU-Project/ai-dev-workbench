#!/usr/bin/env python3
"""Presidio Shield Desktop — Native Desktop Window Launcher.

Starts the embedded FastAPI Presidio server on a free localhost port and
opens a native OS WebView window (WebKit on macOS, WebView2 on Windows,
WebKitGTK on Linux) via `pywebview`.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

import uvicorn

from app.server import app


def find_free_port(preferred: int = 18765) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return int(s.getsockname()[1])


def wait_for_server(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def run_server(port: int) -> None:
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="warning",
        access_log=False,
    )
    server = uvicorn.Server(config)
    server.run()


def main() -> None:
    parser = argparse.ArgumentParser(description="Presidio Shield Desktop Application")
    parser.add_argument("--port", type=int, default=0, help="Port to bind local server")
    parser.add_argument(
        "--browser",
        action="store_true",
        help="Open in default web browser instead of native pywebview window",
    )
    args = parser.parse_args()

    port = args.port if args.port > 0 else find_free_port()
    url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()

    wait_for_server(f"{url}/api/info", timeout=20.0)

    if not args.browser:
        try:
            import webview

            webview.settings["ALLOW_DOWNLOADS"] = True
            webview.create_window(
                title="AI & Data Workbench",
                url=url,
                width=1420,
                height=900,
                min_size=(1024, 680),
                text_select=True,
            )
            webview.start()
            return
        except Exception as exc:
            print(f"[Info] Native webview fallback to browser ({exc})", file=sys.stderr)

    print(f"Presidio Shield Desktop running at {url}")
    webbrowser.open(url)
    try:
        while server_thread.is_alive():
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
