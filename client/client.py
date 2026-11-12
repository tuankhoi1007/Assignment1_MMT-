"""
CO3093 - Client core networking engine.

TCP carries signaling and chat. UDP carries selective-repeat file streams, FIN,
and heartbeats to the server. Chat and files are encrypted per peer pair
(X25519 + HKDF, then AES-256-GCM). The server only relays ciphertext.
"""

import hashlib
import json
import logging
import os
import socket
import threading
import time

from protocol.packet import Packet, MsgType, PacketFlags, send_packet, recv_packet
from protocol.crypto import KeyPair
from protocol.udp_stream import (
    UDPPacket, StreamSender, StreamReceiver, build_heartbeat,
    TYPE_DATA, TYPE_ACK, TYPE_FIN, TYPE_HEARTBEAT, TYPE_HEARTBEAT_ACK,
    FLAG_FIN, FLAG_ABORT, FLAG_ENCRYPTED,
)

HEARTBEAT_INTERVAL = 5.0
UDP_HEARTBEAT_MISSES = 2  # then also ping over TCP, so the 15s watchdog still has a path

logger = logging.getLogger("ClientEngine")


class CollaborationClient:
    """Connection, authentication, messaging, and UDP file transfer for one user."""

    def __init__(self, server_host="127.0.0.1", server_tcp_port=8888):
        self.server_host = server_host
        self.server_tcp_port = server_tcp_port
        self.server_udp_port = 8889

        self.username = ""
        self.is_connected = False
        self.guest = False
        self.tcp_sock = None
        self.udp_sock = None
        self.udp_port = 0

        self.keys = None
        self.channel = None
        self.heartbeat_key = None
        self.hb_counter = 0
        self.udp_token = None
        self._peer_cryptos = {}

        self.heartbeat_interval = HEARTBEAT_INTERVAL
        self.last_udp_pong = 0.0
        self.force_relay = False
        self.congestion = "cubic"

        self.active_users = []
        self.messages = []
        self.transfers = {}
        self.active_receivers = {}
        self.active_senders = {}

        self.running = False
        self.lock = threading.RLock()
        self.send_lock = threading.Lock()
        self.seq_counter = 0

        self.download_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "downloads"))
        os.makedirs(self.download_dir, exist_ok=True)

    def _next_seq(self):
        with self.lock:
            self.seq_counter += 1
            return self.seq_counter

    def _send_tcp(self, pkt):
        with self.send_lock:
            send_packet(self.tcp_sock, pkt)

    def _close_sockets(self):
        for sock in (self.tcp_sock, self.udp_sock):
            if sock is None:
                continue
            try:
                sock.close()
            except Exception:
                pass
        self.tcp_sock = None
        self.udp_sock = None

    def _decode_channel_json(self, pkt, aad):
        if pkt.flags & PacketFlags.ENCRYPTED:
            if self.channel is None:
                raise ValueError("Encrypted packet without a channel key")
            raw = self.channel.decrypt(pkt.payload, aad)
            return json.loads(raw.decode("utf-8"))
        return pkt.to_json()

    def connect_and_login(self, username, host=None, port=None, password=None, register=False):
        """
        Handshake (with X25519), then login or register.

        password=None is a guest login, accepted only when the server allows guests
        and the name is not registered. register=True creates the account first.
        """
        if host:
            self.server_host = host
        if port:
            self.server_tcp_port = port

        try:
            self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_sock.bind(("0.0.0.0", 0))
            self.udp_port = self.udp_sock.getsockname()[1]

            self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_sock.settimeout(5.0)
            self.tcp_sock.connect((self.server_host, self.server_tcp_port))

            self.keys = KeyPair()
            self._peer_cryptos = {}
            hello = {"hello": "CLIENT_HELLO", "pubkey": self.keys.public_b64}
            send_packet(self.tcp_sock, Packet.json_payload(MsgType.HANDSHAKE_REQ, hello))
            ack = recv_packet(self.tcp_sock)
            if ack.msg_type != MsgType.HANDSHAKE_ACK:
                self._close_sockets()
                return False, "Handshake failed"
            ack_data = ack.to_json()
            self.server_udp_port = int(ack_data.get("udp_port", 8889))
            server_pub = ack_data.get("pubkey")
            self.channel = self.keys.derive(server_pub, "client-server") if server_pub else None
            self.heartbeat_key = self.keys.derive(server_pub, "udp-heartbeat").key if server_pub else None
            self.hb_counter = 0

            auth_data = {"username": username, "udp_port": self.udp_port}
            if password is not None:
                auth_data["password"] = password
            mtype = MsgType.AUTH_REGISTER if register else MsgType.AUTH_LOGIN
            if self.channel is not None:
                body = self.channel.encrypt(json.dumps(auth_data).encode("utf-8"), b"auth")
                auth_pkt = Packet(mtype, payload=body, flags=PacketFlags.ENCRYPTED)
            elif password is None and not register:
                auth_pkt = Packet.json_payload(mtype, auth_data)
            else:
                self._close_sockets()
                return False, "Server does not support encrypted login; refusing to send password"
            send_packet(self.tcp_sock, auth_pkt)

            while True:
                resp = recv_packet(self.tcp_sock)
                if resp.msg_type == MsgType.AUTH_FAILURE:
                    reason = resp.to_json().get("reason", "Login failed")
                    self._close_sockets()
                    return False, reason
                if resp.msg_type == MsgType.AUTH_SUCCESS:
                    data = self._decode_channel_json(resp, b"auth-ok")
                    self.username = username
                    self.is_connected = True
                    self.running = True
                    self.active_users = data.get("users", [])
                    self.udp_token = data.get("udp_token")
                    self.guest = bool(data.get("guest", False))
                    self.last_udp_pong = time.time()

                    self.tcp_sock.settimeout(None)
                    threading.Thread(target=self._tcp_listen_loop, name=f"TCP-{username}", daemon=True).start()
                    threading.Thread(target=self._udp_listen_loop, name=f"UDP-{username}", daemon=True).start()
                    threading.Thread(target=self._heartbeat_loop, name=f"Heartbeat-{username}", daemon=True).start()
                    logger.debug(f"Client '{username}' authenticated successfully.")
                    return True, "Registered and logged in" if register else "Login successful"
                if resp.msg_type == MsgType.USER_JOINED:
                    continue
                self._close_sockets()
                return False, f"Unexpected response: {resp.msg_type.name}"
        except Exception as e:
            logger.error(f"Error connecting to server: {e}")
            self._close_sockets()
            return False, str(e)

    def _peer_pubkey(self, username):
        with self.lock:
            info = next((u for u in self.active_users if u.get("username") == username), None)
        return info.get("pubkey") if info else None

    def _wait_peer(self, username, timeout=1.0):
        """Return the peer record once it has a public key, or None."""
        deadline = time.time() + timeout
        while True:
            with self.lock:
                info = next((u for u in self.active_users if u.get("username") == username), None)
            if info and info.get("pubkey"):
                return info
            if time.time() >= deadline:
                return None
            time.sleep(0.02)

    def _peer_crypto(self, peer_pubkey, context):
        cache_key = (peer_pubkey, context)
        with self.lock:
            cached = self._peer_cryptos.get(cache_key)
            if cached is None:
                cached = self.keys.derive(peer_pubkey, context)
                self._peer_cryptos[cache_key] = cached
            return cached

    def my_fingerprint(self):
        return self.keys.fingerprint if self.keys else None

    def disconnect(self):
        """Send DISCONNECT and close sockets."""
        if not self.is_connected:
            return
        self.running = False
        self.is_connected = False
        old_name = self.username
        self.username = ""
        with self.lock:
            for sender in list(self.active_senders.values()):
                try:
                    sender.cancel()
                except Exception:
                    pass
            self.active_senders.clear()
            self.active_receivers.clear()
        try:
            if self.tcp_sock:
                self._send_tcp(Packet(MsgType.DISCONNECT, payload=b"BYE"))
        except Exception:
            pass
        self._close_sockets()
        logger.debug(f"Client '{old_name}' disconnected cleanly.")

    def _send_chat(self, target, text, is_broadcast):
        """
        End-to-end encrypted chat.
        Unicast uses the key shared with `target`.
        Broadcast carries one ciphertext per online peer, so the server can read none of them.
        """
        if not self.is_connected:
            return False
        mtype = MsgType.MSG_BROADCAST if is_broadcast else MsgType.MSG_UNICAST
        try:
            if is_broadcast:
                with self.lock:
                    peers = [u for u in self.active_users if u.get("username") != self.username and u.get("pubkey")]
                aad = f"chat|{self.username}|ALL".encode("utf-8")
                ciphers = {}
                for user in peers:
                    ciphers[user["username"]] = self._peer_crypto(user["pubkey"], "chat").encrypt_string(text, aad)
                payload = {"ciphers": ciphers}
            else:
                peer = self._wait_peer(target)
                if not peer:
                    with self.lock:
                        self.messages.append({
                            "id": self._next_seq(),
                            "sender": "SYSTEM",
                            "target": self.username,
                            "text": f"Cannot deliver message: user '{target}' is offline.",
                            "timestamp": time.time(),
                            "is_broadcast": False,
                            "is_mine": False,
                        })
                    return False
                aad = f"chat|{self.username}|{target}".encode("utf-8")
                payload = {"target": target, "text": self._peer_crypto(peer["pubkey"], "chat").encrypt_string(text, aad)}
            pkt = Packet.json_payload(mtype, payload, seq=self._next_seq(), flags=PacketFlags.ENCRYPTED)
            self._send_tcp(pkt)
            with self.lock:
                self.messages.append({
                    "id": self.seq_counter,
                    "sender": self.username,
                    "target": target,
                    "text": text,
                    "timestamp": time.time(),
                    "is_broadcast": is_broadcast,
                    "is_mine": True,
                })
            return True
        except Exception as e:
            logger.warning(f"Error sending message: {e}")
            return False

    def _decrypt_chat(self, data, is_broadcast):
        sender = data.get("sender", "")
        sender_pub = self._peer_pubkey(sender) or data.get("sender_pubkey")
        if not sender_pub or not self.keys:
            return "[Decryption Error: unknown sender key]"
        if is_broadcast:
            ct = (data.get("ciphers") or {}).get(self.username)
            aad = f"chat|{sender}|ALL".encode("utf-8")
        else:
            ct = data.get("text", "")
            aad = f"chat|{sender}|{self.username}".encode("utf-8")
        if not ct:
            return "[Decryption Error: no ciphertext for me]"
        try:
            return self._peer_crypto(sender_pub, "chat").decrypt_string(ct, aad)
        except Exception:
            return "[Decryption Error]"

    def send_broadcast_message(self, text):
        """Send an encrypted broadcast message to global chat."""
        return self._send_chat("ALL", text, True)

    def send_unicast_message(self, target_user, text):
        """Send an encrypted direct message to one peer."""
        return self._send_chat(target_user, text, False)

    def send_file(self, target_user, file_path=None, file_bytes=None, filename=None):
        """Stream a file over UDP (direct, or via the server relay)."""
        if not self.is_connected:
            return False, "Client is not connected"

        if file_bytes is None:
            if not file_path or not os.path.exists(file_path):
                return False, "File does not exist"
            filename = os.path.basename(filename or file_path)
            with open(file_path, "rb") as f:
                file_data = f.read()
        else:
            filename = os.path.basename(filename or "uploaded_file.bin") or "uploaded_file.bin"
            file_data = file_bytes

        file_size = len(file_data)
        file_hash = hashlib.sha256(file_data).hexdigest()
        stream_id = (int(time.time() * 1000) + self._next_seq()) % 1000000000 or 1

        target_info = self._wait_peer(target_user)
        if not target_info:
            return False, f"Target user '{target_user}' is not online"
        target_ip = target_info.get("ip", "127.0.0.1")
        if target_ip in ("127.0.0.1", "0.0.0.0", "localhost"):
            target_ip = self.server_host if self.server_host not in ("127.0.0.1", "localhost", "0.0.0.0") else "127.0.0.1"
        target_udp_port = target_info.get("udp_port", 0)
        if not target_udp_port or target_udp_port <= 0:
            return False, f"Target user '{target_user}' has invalid UDP port ({target_udp_port})"
        peer_pub = target_info.get("pubkey")
        if not peer_pub:
            return False, f"Target user '{target_user}' has no public key"

        relay_addr = (self.server_host, self.server_udp_port)
        with self.lock:
            self.transfers[stream_id] = {
                "stream_id": stream_id,
                "role": "sender",
                "filename": filename,
                "file_size": file_size,
                "target": target_user,
                "progress": 0.0,
                "status": "Starting",
                "sha256": file_hash,
                "path": "relay" if self.force_relay else "direct",
            }

        def on_prog(acked, total, pct):
            with self.lock:
                entry = self.transfers.get(stream_id)
                if entry is None:
                    return
                entry["progress"] = round(pct, 1)
                entry["status"] = "Completed" if pct >= 100.0 else "Transferring..."
                entry["cwnd"] = round(sender.cc.cwnd, 1)
                if sender.via_relay:
                    entry["path"] = "relay"

        def on_fallback():
            with self.lock:
                entry = self.transfers.get(stream_id)
                if entry is not None:
                    entry["path"] = "relay"
            logger.debug(f"Stream {stream_id}: direct path silent, switching to server relay")

        crypto = self._peer_crypto(peer_pub, f"file:{stream_id}")
        sender = StreamSender(
            self.udp_sock,
            relay_addr if self.force_relay else (target_ip, target_udp_port),
            stream_id,
            file_data,
            encrypt=True,
            on_progress=on_prog,
            crypto=crypto,
            fallback_addr=None if self.force_relay else relay_addr,
            on_fallback=on_fallback,
            congestion=self.congestion,
        )
        sender.via_relay = self.force_relay
        with self.lock:
            self.active_senders[stream_id] = sender

        announce = Packet.json_payload(MsgType.FILE_ANNOUNCE, {
            "target": target_user,
            "filename": filename,
            "file_size": file_size,
            "sha256": file_hash,
            "stream_id": stream_id,
            "total_chunks": sender.total_chunks,
            "sender_udp_port": self.udp_port,
        })
        self._send_tcp(announce)
        time.sleep(0.05)
        threading.Thread(target=self._run_sender, args=(stream_id, sender), name=f"Sender-{stream_id}", daemon=True).start()
        return True, f"Started sending file '{filename}' to {target_user}"

    def _run_sender(self, stream_id, sender):
        try:
            sender.send_loop()
        finally:
            with self.lock:
                entry = self.transfers.get(stream_id)
                if entry is not None:
                    entry["cc"] = sender.stats()
                    entry["closed"] = sender.closed
                    entry["path"] = "relay" if sender.via_relay else entry.get("path", "direct")
                    if sender.failed:
                        entry["status"] = "Failed"
                    elif sender.aborted and not sender.finished:
                        entry["status"] = "Cancelled"
                self.active_senders.pop(stream_id, None)

    def _tcp_listen_loop(self):
        """Control packets and incoming messages from the server."""
        while self.running:
            try:
                pkt = recv_packet(self.tcp_sock)
            except (ConnectionResetError, BrokenPipeError, EOFError, OSError):
                logger.debug("Connection lost to server.")
                self.is_connected = False
                self.running = False
                break
            except ValueError as e:
                logger.warning(f"TCP framing corruption: {e}. Closing connection.")
                self.is_connected = False
                self.running = False
                break
            except Exception:
                continue

            msg_type = pkt.msg_type
            if msg_type == MsgType.USER_JOINED:
                data = pkt.to_json()
                with self.lock:
                    self.active_users = [u for u in self.active_users if u.get("username") != data.get("username")]
                    self.active_users.append(data)
            elif msg_type == MsgType.USER_LEFT:
                uname = pkt.to_json().get("username")
                with self.lock:
                    self.active_users = [u for u in self.active_users if u.get("username") != uname]
            elif msg_type in (MsgType.MSG_BROADCAST, MsgType.MSG_UNICAST):
                data = pkt.to_json()
                text = data.get("text", "")
                if pkt.flags & PacketFlags.ENCRYPTED:
                    text = self._decrypt_chat(data, msg_type == MsgType.MSG_BROADCAST)
                with self.lock:
                    self.messages.append({
                        "id": pkt.seq,
                        "sender": data.get("sender"),
                        "target": "ALL" if data.get("is_broadcast") else self.username,
                        "text": text,
                        "timestamp": data.get("timestamp", time.time()),
                        "is_broadcast": data.get("is_broadcast", False),
                        "is_mine": False,
                    })
            elif msg_type == MsgType.MSG_DELIVERY_ACK:
                data = pkt.to_json()
                if data.get("status") == "USER_NOT_FOUND":
                    tgt = data.get("target", "unknown")
                    with self.lock:
                        self.messages.append({
                            "id": pkt.seq,
                            "sender": "SYSTEM",
                            "target": self.username,
                            "text": f"Cannot deliver message: user '{tgt}' is offline.",
                            "timestamp": time.time(),
                            "is_broadcast": False,
                            "is_mine": False,
                        })
            elif msg_type == MsgType.FILE_ANNOUNCE:
                self._on_file_announce(pkt.to_json())

    def _on_file_announce(self, data):
        stream_id = data.get("stream_id")
        filename = os.path.basename(data.get("filename", "file.bin")) or "file.bin"
        file_size = data.get("file_size", 0)
        total_chunks = data.get("total_chunks", max(1, (file_size + 1199) // 1200))
        sender_name = data.get("sender")
        sender_pub = self._peer_pubkey(sender_name) or data.get("sender_pubkey")
        with self.lock:
            self.transfers[stream_id] = {
                "stream_id": stream_id,
                "role": "receiver",
                "filename": filename,
                "file_size": file_size,
                "sender": sender_name,
                "progress": 0.0,
                "status": "Receiving" if sender_pub else "Failed (no sender key)",
                "sha256": data.get("sha256"),
                "path": "direct",
            }
        if not sender_pub:
            return

        def on_recv_prog(got, tot, pct):
            with self.lock:
                entry = self.transfers.get(stream_id)
                if entry is not None:
                    entry["progress"] = min(99.0, round(pct, 1))

        crypto = self._peer_crypto(sender_pub, f"file:{stream_id}")
        receiver = StreamReceiver(stream_id, total_chunks, on_progress=on_recv_prog, crypto=crypto)
        with self.lock:
            self.active_receivers[stream_id] = receiver

    def _udp_listen_loop(self):
        """DATA, ACK, FIN, and heartbeat pongs on the client's UDP socket."""
        while self.running:
            try:
                raw, addr = self.udp_sock.recvfrom(65535)
                pkt = UDPPacket.decode(raw)
                if not pkt:
                    continue
                if pkt.pkt_type == TYPE_DATA:
                    receiver = self.active_receivers.get(pkt.stream_id)
                    if receiver is None:
                        continue
                    is_enc = bool(pkt.flags & FLAG_ENCRYPTED)
                    receiver.put_chunk(pkt.chunk_idx, pkt.payload, is_enc)
                    if receiver.has_chunk(pkt.chunk_idx):
                        ack = UDPPacket(TYPE_ACK, pkt.stream_id, pkt.chunk_idx, pkt.total_chunks)
                        self.udp_sock.sendto(ack.encode(), addr)
                    if receiver.is_complete() and not getattr(receiver, "finalized", False):
                        receiver.finalized = True
                        self._finalize_received_file(pkt.stream_id, receiver)
                elif pkt.pkt_type == TYPE_ACK:
                    sender = self.active_senders.get(pkt.stream_id)
                    if sender:
                        sender.handle_ack(pkt.chunk_idx, pkt.flags)
                elif pkt.pkt_type == TYPE_FIN:
                    self._handle_fin(pkt, addr)
                elif pkt.pkt_type == TYPE_HEARTBEAT_ACK:
                    self.last_udp_pong = time.time()
                    challenge = self._challenge_from_ack(pkt.payload)
                    if challenge:
                        self._send_udp_heartbeat(challenge=challenge)
            except (ConnectionResetError, ConnectionRefusedError):
                continue
            except OSError:
                if not self.running:
                    break
                continue

    def _handle_fin(self, pkt, addr):
        """ACK every FIN. Abort tears the stream down; a normal FIN waits until the file is complete."""
        sid = pkt.stream_id
        with self.lock:
            receiver = self.active_receivers.get(sid)
            info = self.transfers.get(sid)
        if pkt.flags & FLAG_ABORT:
            with self.lock:
                receiver = self.active_receivers.pop(sid, None)
                if receiver is not None:
                    receiver.aborted = True
                info = self.transfers.get(sid)
                if info is not None:
                    if info.get("progress", 0) < 100.0:
                        info["status"] = "Cancelled by sender"
                    info["closed"] = True
            self._ack_fin(pkt, addr, abort=True)
            return
        if receiver is not None and not receiver.is_complete():
            return
        if receiver is not None and not getattr(receiver, "finalized", False):
            receiver.finalized = True
            self._finalize_received_file(sid, receiver)
        if receiver is None and (info is None or info.get("role") != "receiver"):
            return
        self._ack_fin(pkt, addr, abort=False)
        with self.lock:
            self.active_receivers.pop(sid, None)
            info = self.transfers.get(sid)
            if info is not None:
                info["closed"] = True

    def _ack_fin(self, pkt, addr, abort=False):
        """ACK a FIN. Abort ACKs carry FLAG_ABORT as well as FLAG_FIN."""
        flags = FLAG_FIN | (FLAG_ABORT if abort else 0)
        fin_ack = UDPPacket(TYPE_ACK, pkt.stream_id, pkt.chunk_idx, pkt.total_chunks, flags=flags)
        try:
            if self.udp_sock is not None:
                self.udp_sock.sendto(fin_ack.encode(), addr)
        except OSError:
            pass

    def _finalize_received_file(self, stream_id, receiver):
        """Reassemble, check the whole-file SHA-256, and write client/downloads/."""
        try:
            file_bytes = receiver.reassemble()
            info = self.transfers.get(stream_id, {})
            filename = os.path.basename(info.get("filename", f"file_{stream_id}.bin")) or f"file_{stream_id}.bin"
            actual_hash = hashlib.sha256(file_bytes).hexdigest()
            save_path = os.path.join(self.download_dir, filename)
            base, ext = os.path.splitext(save_path)
            n = 1
            while os.path.exists(save_path):
                save_path = f"{base}_{n}{ext}"
                n += 1
            with open(save_path, "wb") as f:
                f.write(file_bytes)
            with self.lock:
                entry = self.transfers.setdefault(stream_id, {})
                entry["saved_filename"] = os.path.basename(save_path)
                entry["saved_path"] = save_path
                entry["progress"] = 100.0
                entry["status"] = "Completed" if actual_hash == info.get("sha256") else "Corrupted"
            logger.debug(f"File '{filename}' received: {save_path}")
        except Exception as e:
            logger.error(f"Error finalizing received file: {e}")

    def _challenge_from_ack(self, payload):
        """Return the server's address-change challenge, or '' when this ACK is only a pong."""
        if not payload or payload == b"PONG":
            return ""
        try:
            data = json.loads(payload.decode("utf-8"))
        except Exception:
            return ""
        challenge = data.get("challenge") if isinstance(data, dict) else ""
        return challenge if isinstance(challenge, str) else ""

    def _send_udp_heartbeat(self, challenge=""):
        """
        Authenticated UDP heartbeat.

        The body is HMAC'd with the key derived from the login handshake. The login
        token is not included. `challenge` is set only when answering the server's
        proof for a new source address.
        """
        if not self.heartbeat_key or not self.udp_sock or not self.username:
            return
        with self.lock:
            self.hb_counter += 1
            counter = self.hb_counter
        body = build_heartbeat(self.heartbeat_key, self.username, counter, self.udp_port, challenge)
        ping = UDPPacket(TYPE_HEARTBEAT, 0, counter, 0, body)
        self.udp_sock.sendto(ping.encode(), (self.server_host, self.server_udp_port))

    def _heartbeat_loop(self):
        """
        Ping the server over UDP every heartbeat_interval seconds.
        If no pong arrives for UDP_HEARTBEAT_MISSES intervals, also send the TCP ping
        so a network that blocks UDP 8889 does not get the session killed by the watchdog.
        """
        while self.running:
            if self.is_connected:
                try:
                    if self.heartbeat_key and self.udp_sock:
                        self._send_udp_heartbeat()
                except OSError:
                    pass
                try:
                    silent = time.time() - self.last_udp_pong
                    need_tcp = (not self.heartbeat_key) or silent > UDP_HEARTBEAT_MISSES * self.heartbeat_interval
                    if need_tcp and self.tcp_sock and self.running:
                        self._send_tcp(Packet(MsgType.HEARTBEAT_PING, payload=b"PING"))
                except OSError:
                    if not self.running:
                        break
            time.sleep(self.heartbeat_interval)
