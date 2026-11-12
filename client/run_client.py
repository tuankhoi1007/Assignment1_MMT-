"""
CO3093 - Client Entry-Point Runner.
Starts the client engine and serves the Web UI dashboard via a raw TCP socket HTTP server.

Usage:
    python -m client.run_client Alice
    python -m client.run_client Bob
    python -m client.run_client Bob --host 192.168.1.15
    python -m client.run_client Alice --password secret123 --register
    python -m client.run_client Alice --password secret123
"""

import argparse
import sys
import os
import time
import webbrowser

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client.client import CollaborationClient
from client.web_server import RawSocketHTTPServer


def main():
    parser = argparse.ArgumentParser(description="CO3093 Collaboration Client")
    parser.add_argument("name", nargs="?", default="", help="Username to login with (e.g. Alice, Bob)")
    parser.add_argument("--username", default="", help="Username to login with")
    parser.add_argument("--host", default="127.0.0.1", help="Server Host IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Server TCP Port (default: 8888)")
    parser.add_argument("--ui-port", type=int, default=5001, help="Local Web UI HTTP Port (default: 5001)")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically open browser")
    parser.add_argument("--password", default=None, help="Account password (omit for guest login, if the server allows it)")
    parser.add_argument("--register", action="store_true", help="Create the account, then log in")
    parser.add_argument("--force-relay", action="store_true", help="Send files through the server UDP relay")
    parser.add_argument("--congestion", default="cubic", choices=("cubic", "bbr"),
                        help="UDP congestion controller (default: cubic)")
    args = parser.parse_args()

    username = (args.name or args.username).strip()
    client = CollaborationClient(server_host=args.host, server_tcp_port=args.port)
    client.force_relay = args.force_relay
    client.congestion = args.congestion

    # Start raw-socket HTTP Web UI server (auto-increments port if busy)
    web_server = RawSocketHTTPServer(client, host="127.0.0.1", port=args.ui_port)
    web_server.start()
    url = f"http://127.0.0.1:{web_server.port}"

    if username:
        ok, msg = client.connect_and_login(
            username, host=args.host, port=args.port,
            password=args.password or None, register=args.register,
        )
        status = f"Logged in as '{username}'" if ok else f"Login failed: {msg}"
        print(f"[+] {status} | Web UI: {url}", flush=True)
    else:
        print(f"[+] Client running | Web UI: {url}", flush=True)

    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[-] Client stopped.")
    finally:
        client.disconnect()
        web_server.stop()


if __name__ == "__main__":
    main()
