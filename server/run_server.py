"""
CO3093 - Server Entry-Point Runner.
Usage:
    python -m server.run_server [--host 0.0.0.0] [--tcp-port 8888] [--udp-port 8889]
                                [--user-db server/users.json] [--allow-guest]
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from server.server import CollaborationServer

def main():
    parser = argparse.ArgumentParser(description="CO3093 Collaboration Server")
    parser.add_argument("--host", default="0.0.0.0", help="Binding host IP (default: 0.0.0.0)")
    parser.add_argument("--tcp-port", type=int, default=8888, help="TCP listening port (default: 8888)")
    parser.add_argument("--udp-port", type=int, default=8889, help="UDP relay / heartbeat port (default: 8889)")
    parser.add_argument("--user-db", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json"),
                        help="JSON file of salted password hashes (default: server/users.json)")
    parser.add_argument("--allow-guest", action="store_true",
                        help="Allow unregistered names to log in without a password")
    args = parser.parse_args()

    server = CollaborationServer(
        host=args.host, tcp_port=args.tcp_port, udp_port=args.udp_port,
        require_password=not args.allow_guest, user_db=args.user_db,
    )
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    main()
