"""
CO3093 - Raw Socket HTTP 1.1 Web UI Server (Step 9).
Built purely using standard low-level TCP sockets (no Flask, Django, Tornado, or WebSockets).
Parses HTTP/1.1 requests, serves static HTML/CSS/JS, and provides REST JSON endpoints
complying with Assignment 1 and CO3094 specifications (login, get-list, broadcast-peer, send-peer, etc.).
"""

import socket
import threading
import json
import os
import urllib.parse
import mimetypes
import base64
import logging

logger = logging.getLogger("RawWebUIServer")


def parse_cookies(headers):
    """Extract key-value cookie pairs from HTTP Cookie header (RFC 6265)."""
    cookie_str = headers.get("cookie", "")
    cookies = {}
    if cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def parse_authorization(headers):
    """Extract username from HTTP Authorization Basic header (RFC 2617 / RFC 7235)."""
    auth_header = headers.get("authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            b64_val = auth_header[6:].strip()
            decoded = base64.b64decode(b64_val).decode('utf-8', errors='ignore')
            if ":" in decoded:
                user, _ = decoded.split(":", 1)
                return user.strip()
            return decoded.strip()
        except Exception:
            pass
    return None


class RawSocketHTTPServer:
    """Lightweight HTTP 1.1 server implemented directly over raw TCP sockets."""
    def __init__(self, client, host="127.0.0.1", port=8080):
        self.client = client
        self.host = host
        self.port = port
        self.server_sock = None
        self.running = False
        self.static_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "web"))

    def start(self):
        """Bind and listen on a free port, automatically incrementing if occupied."""
        for p in range(self.port, self.port + 50):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if hasattr(socket, 'SO_REUSEADDR'):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, p))
                self.server_sock = sock
                self.port = p
                break
            except OSError:
                sock.close()

        if not self.server_sock:
            raise RuntimeError(f"Could not bind to any port in range {self.port} to {self.port + 50}")

        self.server_sock.listen(20)
        self.running = True
        logger.debug(f"Client Web UI available at: http://{self.host}:{self.port}")
        threading.Thread(target=self._accept_loop, daemon=True, name="RawHTTP-Acceptor").start()

    def stop(self):
        """Stop the HTTP server and close socket."""
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass

    def _accept_loop(self):
        """Accept incoming HTTP client connections."""
        while self.running:
            try:
                conn, _ = self.server_sock.accept()
                threading.Thread(target=self._handle_http_request, args=(conn,), daemon=True).start()
            except OSError:
                break

    def _handle_http_request(self, conn):
        """Parse raw HTTP request and route to appropriate GET/POST/PUT handlers."""
        conn.settimeout(5.0)
        try:
            req_data = bytearray()
            while b"\r\n\r\n" not in req_data:
                chunk = conn.recv(2048)
                if not chunk:
                    break
                req_data.extend(chunk)

            if not req_data:
                conn.close()
                return

            header_part, _, body_start = req_data.partition(b"\r\n\r\n")
            lines = header_part.decode('utf-8', errors='ignore').split("\r\n")
            req_line = lines[0].split()
            if len(req_line) < 2:
                conn.close()
                return

            method = req_line[0].upper()
            parsed_url = urllib.parse.urlparse(req_line[1])
            path = parsed_url.path
            query_params = urllib.parse.parse_qs(parsed_url.query)
            headers = {k.strip().lower(): v.strip() for k, v in [line.split(":", 1) for line in lines[1:] if ":" in line]}
            content_length = int(headers.get("content-length", 0))

            body = bytearray(body_start)
            while len(body) < content_length:
                chunk = conn.recv(min(65536, content_length - len(body)))
                if not chunk:
                    break
                body.extend(chunk)

            if method == "GET":
                self._handle_get(conn, path, headers, query_params)
            elif method in ("POST", "PUT"):
                self._handle_post(conn, path, bytes(body), headers, query_params)
            elif method == "DELETE":
                self._handle_delete(conn, path)
            elif method == "OPTIONS":
                self._send_res(conn, 204, "No Content", b"")
            else:
                self._send_res(conn, 405, "Method Not Allowed", b"Method Not Allowed")
        except Exception as e:
            logger.warning(f"HTTP handler error: {e}")
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send_res(self, conn, code, msg, body, content_type="text/plain", extra_headers=None):
        """Send formatted HTTP response headers and body with optional extra headers (e.g. Set-Cookie)."""
        headers = [
            f"HTTP/1.1 {code} {msg}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Access-Control-Allow-Origin: *",
            "Access-Control-Allow-Methods: GET, POST, PUT, OPTIONS",
            "Access-Control-Allow-Headers: Content-Type, Authorization, Cookie",
            "Cache-Control: no-store",
            "Connection: close"
        ]
        if extra_headers:
            headers.extend(extra_headers)
        conn.sendall(("\r\n".join(headers) + "\r\n\r\n").encode('utf-8') + body)

    def _send_json(self, conn, data, code=200, extra_headers=None):
        """Helper to send JSON response."""
        body = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self._send_res(conn, code, "OK", body, content_type="application/json; charset=utf-8", extra_headers=extra_headers)

    def _handle_get(self, conn, path, headers=None, query_params=None):
        """Handle GET requests: state API, peer list, file download, and static assets."""
        normalized_path = path.rstrip("/")
        headers = headers or {}
        query_params = query_params or {}

        # RFC 2617 / RFC 7235: Challenge endpoint
        if normalized_path == "/auth":
            auth_user = parse_authorization(headers)
            if auth_user:
                self._send_json(conn, {"authenticated": True, "username": auth_user})
            else:
                self._send_res(conn, 401, "Unauthorized", b"Authentication required", extra_headers=['WWW-Authenticate: Basic realm="CO3094 Chat"'])
            return

        # State and peer discovery endpoints (CO3094 Section 2.3 & 2.4: get-list API, add-list API, login status)
        if normalized_path in ("/api/state", "/get-list", "/add-list", "/active-peers", "/login", "/connect-peer", "/submit-info"):
            with self.client.lock:
                state = {
                    "username": self.client.username,
                    "is_connected": self.client.is_connected,
                    "server_host": self.client.server_host,
                    "server_port": self.client.server_tcp_port,
                    "udp_port": self.client.udp_port,
                    "fingerprint": self.client.my_fingerprint(),
                    "guest": self.client.guest,
                    "active_users": self.client.active_users,
                    "users": self.client.active_users,
                    "peers": self.client.active_users,
                    "messages": self.client.messages[-100:],
                    "transfers": list(self.client.transfers.values())
                }
            self._send_json(conn, state)
            return

        # Download received files (with directory traversal guard)
        if path.startswith("/downloads/"):
            fname = urllib.parse.unquote(path[len("/downloads/"):])
            fpath = os.path.abspath(os.path.join(self.client.download_dir, fname))
            if fpath.startswith(self.client.download_dir) and os.path.exists(fpath) and os.path.isfile(fpath):
                ctype, _ = mimetypes.guess_type(fpath)
                with open(fpath, "rb") as f:
                    self._send_res(conn, 200, "OK", f.read(), content_type=ctype or "application/octet-stream")
                return
            self._send_res(conn, 404, "Not Found", b"File not found")
            return

        # Static assets (HTML, CSS, JS, Images)
        fname = "index.html" if path in ("/", "") else path.lstrip("/")
        fpath = os.path.abspath(os.path.join(self.static_dir, fname))
        if fpath.startswith(self.static_dir) and os.path.exists(fpath) and os.path.isfile(fpath):
            ctype, _ = mimetypes.guess_type(fpath)
            with open(fpath, "rb") as f:
                self._send_res(conn, 200, "OK", f.read(), content_type=ctype or "text/html; charset=utf-8")
        else:
            self._send_res(conn, 404, "Not Found", b"Not Found")

    def _handle_delete(self, conn, path):
        """Handle DELETE requests: disconnect and clear session cookies."""
        ep = path.rstrip("/")
        if ep in ("/api/disconnect", "/logout", "/session", "/login"):
            self.client.disconnect()
            extra = ["Set-Cookie: session_user=; Path=/; Max-Age=0"]
            self._send_json(conn, {"success": True, "message": "Disconnected"}, extra_headers=extra)
        else:
            self._send_res(conn, 404, "Not Found", b"Not Found")

    def _handle_post(self, conn, path, body, headers, query_params=None):
        """Handle POST/PUT requests: login, peer messaging, and file streaming transfer."""
        try:
            data = json.loads(body.decode('utf-8')) if body else {}
            ep = path.rstrip("/")
            query_params = query_params or {}

            # 1. Peer registration & login (CO3094 Section 2.2 & 2.4: login API, submit-info API, connect-peer API)
            if ep in ("/api/connect", "/login", "/connect-peer", "/submit-info", "/register"):
                cookies = parse_cookies(headers)
                basic_user = parse_authorization(headers)
                uname = (
                    data.get("username")
                    or data.get("user")
                    or data.get("name")
                    or (query_params.get("username", [None])[0])
                    or cookies.get("session_user")
                    or basic_user
                    or (self.client.username if self.client.is_connected else "")
                    or ""
                ).strip()
                host = data.get("host") or data.get("server_ip") or data.get("server_host") or (query_params.get("host", [None])[0]) or "127.0.0.1"
                port = int(data.get("port") or data.get("server_port") or (query_params.get("port", [None])[0]) or 8888)

                if not uname:
                    self._send_json(conn, {"success": False, "message": "Username cannot be empty"}, 400)
                    return

                password = data.get("password") or None
                register = bool(data.get("register")) or ep == "/register"
                ok, msg = self.client.connect_and_login(uname, host, port, password=password, register=register)
                extra = [f"Set-Cookie: session_user={uname}; Path=/; SameSite=Lax"] if ok else None
                self._send_json(conn, {"success": ok, "message": msg, "username": uname}, extra_headers=extra)

            # 2. Disconnect & logout
            elif ep in ("/api/disconnect", "/logout"):
                self.client.disconnect()
                extra = ["Set-Cookie: session_user=; Path=/; Max-Age=0"]
                self._send_json(conn, {"success": True, "message": "Disconnected"}, extra_headers=extra)

            # 3. Peer chatting: Broadcast and Unicast (CO3094 Section 2.3 & 2.4: broadcast-peer API, send-peer API)
            elif ep in ("/api/send_message", "/broadcast-peer", "/send-peer"):
                is_broadcast = (ep == "/broadcast-peer")
                target = "ALL" if is_broadcast else (data.get("target") or data.get("receiver") or data.get("peer") or (query_params.get("target", [None])[0]) or (query_params.get("peer", [None])[0]) or "")
                text = (data.get("text") or data.get("message") or data.get("body") or (query_params.get("text", [None])[0]) or (query_params.get("message", [None])[0]) or "").strip()

                if not is_broadcast and not target:
                    self._send_json(conn, {"success": False, "message": "Target peer is required for send-peer"}, 400)
                    return

                if not text:
                    self._send_json(conn, {"success": False, "message": "Empty message"}, 400)
                    return

                ok = self.client.send_broadcast_message(text) if target == "ALL" else self.client.send_unicast_message(target, text)
                self._send_json(conn, {"success": ok})

            # 4. Reliable UDP file transfer (CO3094 Section 2.4: send-file API, upload_and_send)
            elif ep in ("/api/upload_and_send", "/send-file"):
                target = data.get("target") or data.get("receiver") or data.get("peer")
                raw_filename = data.get("filename") or data.get("name") or "upload.bin"
                filename = os.path.basename(raw_filename) or "upload.bin"
                content_b64 = data.get("content_b64", "")
                file_bytes = base64.b64decode(content_b64) if content_b64 else None
                file_path = data.get("file_path")

                use_relay = bool(data.get("force_relay")) or self.client.force_relay
                previous = self.client.force_relay
                self.client.force_relay = use_relay
                try:
                    ok, msg = self.client.send_file(target, file_path=file_path, file_bytes=file_bytes, filename=filename)
                finally:
                    self.client.force_relay = previous
                self._send_json(conn, {"success": ok, "message": msg})

            # 5. Peer list management (CO3094 Section 2.4: add-list API, get-list API)
            elif ep in ("/add-list", "/get-list"):
                with self.client.lock:
                    users = self.client.active_users
                self._send_json(conn, {"success": True, "users": users})

            else:
                self._send_res(conn, 404, "Not Found", b"API endpoint not found")
        except Exception as e:
            self._send_json(conn, {"success": False, "error": str(e)}, 500)
