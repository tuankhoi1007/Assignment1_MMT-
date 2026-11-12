"""
CO3093 - Central multi-threaded collaboration server.

TCP 8888 carries signaling (handshake, login, chat relay, file announce, TCP heartbeat fallback).
UDP 8889 carries heartbeats (which also discover the client's UDP address) and relays file
chunks when the two peers cannot reach each other directly. Chat and file payloads stay
encrypted under the peers' own keys; this process only forwards them.
"""

import base64
import hmac
import json
import logging
import os
import secrets
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol.packet import Packet, MsgType, PacketFlags, send_packet, recv_packet
from protocol.crypto import KeyPair
from protocol.udp_stream import (
    UDPPacket, TYPE_DATA, TYPE_ACK, TYPE_FIN, TYPE_HEARTBEAT, TYPE_HEARTBEAT_ACK,
    verify_heartbeat,
)
from server.user_manager import UserManager
from server.credentials import CredentialStore

MAX_USERNAME_LEN = 32
RELAY_STREAM_IDLE_SEC = 120.0
HEARTBEAT_CHALLENGE_TTL = 2.0

logger = logging.getLogger("CollaborationServer")


def _parse_client_pubkey(payload):
    """Return the client's X25519 public key (base64) from a handshake body, or None."""
    try:
        data = json.loads(payload.decode("utf-8"))
    except Exception:
        return None
    pub = data.get("pubkey") if isinstance(data, dict) else None
    if not isinstance(pub, str):
        return None
    try:
        raw = base64.b64decode(pub, validate=True)
    except Exception:
        return None
    if len(raw) != 32:
        return None
    return pub


class CollaborationServer:
    """Central server managing client connections, authentication, and routing."""

    def __init__(self, host="0.0.0.0", tcp_port=8888, udp_port=8889, verbose=True,
                 require_password=False, user_db=None):
        """
        require_password=False keeps guest login for names that are NOT registered,
        which is what the original local tests use. A registered name always needs
        its password. `python -m server.run_server` turns require_password on
        unless --allow-guest is passed.
        """
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.verbose = verbose

        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if hasattr(socket, "SO_REUSEADDR"):
            self.udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.user_manager = UserManager()
        self.credentials = CredentialStore(user_db)
        self.require_password = require_password
        self.running = False

        self.relay_streams = {}
        self.relay_lock = threading.RLock()
        self.relayed_packets = 0
        # Idle limit for a socket that has not logged in. After AUTH_SUCCESS the
        # socket blocks with no recv timeout: liveness is the 15s watchdog, which
        # UDP heartbeats (or the TCP ping fallback) keep refreshed.
        self.pre_auth_timeout = 60.0

    def _log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def start(self):
        """Listen on TCP and UDP and accept clients until stop()."""
        self.running = True
        self.tcp_sock.bind((self.host, self.tcp_port))
        self.tcp_sock.listen(50)
        self.tcp_sock.settimeout(1.0)
        self.udp_sock.bind((self.host, self.udp_port))
        self.udp_sock.settimeout(1.0)

        threading.Thread(target=self._heartbeat_watchdog, name="Watchdog-Worker", daemon=True).start()
        threading.Thread(target=self._udp_loop, name="UDP-Relay-Worker", daemon=True).start()

        self._log(f"[Server] Listening on {self.host} (TCP: {self.tcp_port}, UDP: {self.udp_port})")
        try:
            while self.running:
                try:
                    client_sock, client_addr = self.tcp_sock.accept()
                    threading.Thread(
                        target=self._handle_client,
                        args=(client_sock, client_addr),
                        name=f"Client-{client_addr[0]}:{client_addr[1]}",
                        daemon=True,
                    ).start()
                except (socket.timeout, OSError):
                    if not self.running:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Shut down the server and close all open sockets."""
        if not self.running:
            return
        self.running = False
        for s in (self.tcp_sock, self.udp_sock):
            try:
                s.close()
            except Exception:
                pass
        for session in self.user_manager.get_all_sessions():
            try:
                session.tcp_sock.close()
            except Exception:
                pass
        self._log("[Server] Stopped.")

    def _broadcast_packet(self, packet, exclude_user=None):
        """Send a packet to all authenticated online clients."""
        for session in self.user_manager.get_all_sessions():
            if exclude_user and session.username == exclude_user:
                continue
            try:
                with session.lock:
                    send_packet(session.tcp_sock, packet)
            except Exception as e:
                logger.debug(f"Failed to send broadcast to {session.username}: {e}")

    def _send_to_user(self, username, packet):
        """Send a unicast packet to a specific user."""
        session = self.user_manager.get_user(username)
        if not session:
            return False
        try:
            with session.lock:
                send_packet(session.tcp_sock, packet)
            return True
        except Exception as e:
            logger.debug(f"Failed to unicast to {username}: {e}")
            return False

    def _handle_client(self, sock, addr):
        """Worker thread servicing one TCP client."""
        sock.settimeout(self.pre_auth_timeout)
        current_user = None
        channel = None
        heartbeat_key = None
        client_pub = None

        try:
            while self.running:
                try:
                    packet = recv_packet(sock)
                except (socket.timeout, ConnectionResetError, BrokenPipeError, EOFError, OSError):
                    break
                except ValueError as e:
                    logger.warning(f"Framing corruption from {addr}: {e}. Terminating client connection.")
                    break

                msg_type = packet.msg_type

                if msg_type == MsgType.HANDSHAKE_REQ:
                    ack_data = {"server": "CO3093-RelayServer", "udp_port": self.udp_port}
                    client_pub = _parse_client_pubkey(packet.payload)
                    channel = None
                    heartbeat_key = None
                    if client_pub:
                        server_keys = KeyPair()
                        channel = server_keys.derive(client_pub, "client-server")
                        heartbeat_key = server_keys.derive(client_pub, "udp-heartbeat").key
                        ack_data["pubkey"] = server_keys.public_b64
                    send_packet(sock, Packet.json_payload(MsgType.HANDSHAKE_ACK, ack_data))

                elif msg_type in (MsgType.AUTH_LOGIN, MsgType.AUTH_REGISTER):
                    if current_user:
                        continue
                    ok, info = self._authenticate(packet, channel)
                    if not ok:
                        send_packet(sock, Packet.json_payload(MsgType.AUTH_FAILURE, {"reason": info}))
                        continue
                    username, udp_port, guest = info
                    session = self.user_manager.add_user(username, sock, addr, udp_port, pubkey=client_pub)
                    if not session:
                        send_packet(sock, Packet.json_payload(MsgType.AUTH_FAILURE, {"reason": "Username already taken"}))
                        continue
                    current_user = username
                    session.authenticated = True
                    session.guest = guest
                    session.heartbeat_key = heartbeat_key
                    # UDP heartbeats do not touch this socket. A recv timeout here
                    # would drop a live session that never needs to send TCP.
                    sock.settimeout(None)
                    self._log(f"[+] '{username}' joined" + (" (guest)" if guest else ""))
                    success = {
                        "username": username,
                        "users": self.user_manager.get_all_users(),
                        "udp_token": session.udp_token,
                        "guest": guest,
                    }
                    if channel:
                        body = channel.encrypt(json.dumps(success).encode("utf-8"), b"auth-ok")
                        send_packet(sock, Packet(MsgType.AUTH_SUCCESS, payload=body, flags=PacketFlags.ENCRYPTED))
                    else:
                        send_packet(sock, Packet.json_payload(MsgType.AUTH_SUCCESS, success))
                    joined = session.to_dict()
                    self._broadcast_packet(Packet.json_payload(MsgType.USER_JOINED, {
                        "username": username,
                        "ip": addr[0],
                        "udp_port": udp_port,
                        "pubkey": joined["pubkey"],
                        "fingerprint": joined["fingerprint"],
                    }), exclude_user=username)

                elif msg_type == MsgType.MSG_BROADCAST:
                    if not current_user:
                        continue
                    data = packet.to_json()
                    self._log(f"[Chat] {current_user} (Broadcast)")
                    data["sender"] = current_user
                    data["sender_pubkey"] = client_pub
                    data["timestamp"] = time.time()
                    data["is_broadcast"] = True
                    relay_pkt = Packet.json_payload(MsgType.MSG_BROADCAST, data, flags=packet.flags)
                    self._broadcast_packet(relay_pkt, exclude_user=current_user)
                    send_packet(sock, Packet.json_payload(MsgType.MSG_DELIVERY_ACK, {"status": "DELIVERED", "msg_id": packet.seq}))

                elif msg_type == MsgType.MSG_UNICAST:
                    if not current_user:
                        continue
                    data = packet.to_json()
                    target_user = data.get("target")
                    self._log(f"[Direct] {current_user} -> {target_user}")
                    data["sender"] = current_user
                    data["sender_pubkey"] = client_pub
                    data["timestamp"] = time.time()
                    data["is_broadcast"] = False
                    relay_pkt = Packet.json_payload(MsgType.MSG_UNICAST, data, flags=packet.flags)
                    success = self._send_to_user(target_user, relay_pkt)
                    ack_status = "DELIVERED" if success else "USER_NOT_FOUND"
                    send_packet(sock, Packet.json_payload(MsgType.MSG_DELIVERY_ACK, {"status": ack_status, "target": target_user}))

                elif msg_type == MsgType.FILE_ANNOUNCE:
                    if not current_user:
                        continue
                    data = packet.to_json()
                    target_user = data.get("target")
                    data["sender"] = current_user
                    data["sender_pubkey"] = client_pub
                    stream_id = data.get("stream_id")
                    if isinstance(stream_id, int) and target_user:
                        sender_session = self.user_manager.get_user(current_user)
                        target_session = self.user_manager.get_user(target_user)
                        with self.relay_lock:
                            self.relay_streams[stream_id] = {
                                "sender": current_user,
                                "target": target_user,
                                "sender_pin": self._login_endpoint(sender_session),
                                "target_pin": self._login_endpoint(target_session),
                                "last": time.time(),
                            }
                    self._log(f"[File] {current_user} -> {target_user}: {data.get('filename', '')}")
                    self._send_to_user(target_user, Packet.json_payload(MsgType.FILE_ANNOUNCE, data))

                elif msg_type == MsgType.HEARTBEAT_PING:
                    if current_user:
                        self.user_manager.update_heartbeat(current_user)
                    send_packet(sock, Packet(MsgType.HEARTBEAT_PONG, payload=b"PONG"))

                elif msg_type == MsgType.DISCONNECT:
                    break

        except Exception:
            pass
        finally:
            if current_user:
                removed = self.user_manager.remove_user(current_user)
                self._drop_routes_for(current_user)
                if removed:
                    self._log(f"[-] '{current_user}' left")
                    self._broadcast_packet(Packet.json_payload(MsgType.USER_LEFT, {"username": current_user}))
            try:
                sock.close()
            except Exception:
                pass

    def _authenticate(self, packet, channel):
        """
        Validate AUTH_LOGIN / AUTH_REGISTER.
        Returns (True, (username, udp_port, guest)) or (False, reason).

        A password is accepted only inside the handshake channel. Registered names
        need the matching password. Unknown names may log in as guests only when
        require_password is off.
        """
        try:
            if packet.flags & PacketFlags.ENCRYPTED:
                if channel is None:
                    return False, "Encrypted login without key exchange"
                data = json.loads(channel.decrypt(packet.payload, b"auth").decode("utf-8"))
            else:
                data = packet.to_json()
        except Exception:
            return False, "Malformed or undecryptable login payload"

        username = str(data.get("username", "")).strip()
        password = data.get("password", None)
        try:
            udp_port = int(data.get("udp_port", 0) or 0)
        except (TypeError, ValueError):
            udp_port = 0
        if not username:
            return False, "Username cannot be empty"
        if len(username) > MAX_USERNAME_LEN:
            return False, f"Username too long (max {MAX_USERNAME_LEN})"
        if password is not None and not (packet.flags & PacketFlags.ENCRYPTED):
            return False, "Password must be sent over the encrypted channel"

        if packet.msg_type == MsgType.AUTH_REGISTER:
            ok, reason = self.credentials.register(username, password)
            if not ok:
                return False, reason
            self._log(f"[Auth] registered '{username}'")
            return True, (username, udp_port, False)

        if self.credentials.is_registered(username):
            if not self.credentials.verify(username, password if isinstance(password, str) else ""):
                return False, "Invalid username or password"
            return True, (username, udp_port, False)
        if self.require_password:
            return False, "Unknown user: please register first"
        return True, (username, udp_port, True)

    def _udp_loop(self):
        """UDP 8889: heartbeats, and relay of DATA / ACK / FIN for announced streams."""
        while self.running:
            try:
                raw, addr = self.udp_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except (ConnectionResetError, ConnectionRefusedError):
                continue
            except OSError:
                if not self.running:
                    break
                continue
            pkt = UDPPacket.decode(raw)
            if not pkt:
                continue
            if pkt.pkt_type == TYPE_HEARTBEAT:
                self._handle_udp_heartbeat(pkt, addr)
            elif pkt.pkt_type in (TYPE_DATA, TYPE_ACK, TYPE_FIN):
                self._relay_udp(pkt, raw, addr)

    def _send_heartbeat_ack(self, addr, challenge):
        """Pong, or a challenge the client must echo from this same source address."""
        if challenge:
            payload = json.dumps({"challenge": challenge}).encode("utf-8")
        else:
            payload = b"PONG"
        try:
            self.udp_sock.sendto(UDPPacket(TYPE_HEARTBEAT_ACK, 0, 0, 0, payload).encode(), addr)
        except OSError:
            pass

    def _handle_udp_heartbeat(self, pkt, addr):
        """
        Refresh liveness from an HMAC'd heartbeat.

        A cleartext token is ignored. The source address becomes the relay address
        only after a challenge issued for that address is echoed in a later heartbeat.
        A repeat from the address already on file needs no challenge.
        """
        try:
            data = json.loads(pkt.payload.decode("utf-8"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        username = str(data.get("username", ""))
        session = self.user_manager.get_user(username)
        if not session or not session.heartbeat_key or not verify_heartbeat(session.heartbeat_key, data):
            return
        try:
            counter = int(data.get("counter", 0))
        except (TypeError, ValueError):
            return
        if counter <= session.hb_counter:
            return
        challenge = str(data.get("challenge") or "")
        now = time.time()
        pending = (
            session.pending_challenge
            and session.pending_challenge_addr == addr
            and now <= session.pending_challenge_until
        )
        answered = False
        if pending and challenge:
            answered = hmac.compare_digest(challenge, session.pending_challenge) if len(challenge) == len(session.pending_challenge) else False
        if answered:
            session.hb_counter = counter
            session.pending_challenge = None
            session.pending_challenge_addr = None
            self.user_manager.update_heartbeat(username, udp_addr=addr)
            self._send_heartbeat_ack(addr, None)
            return
        if session.udp_addr == addr:
            session.hb_counter = counter
            session.pending_challenge = None
            session.pending_challenge_addr = None
            self.user_manager.update_heartbeat(username)
            self._send_heartbeat_ack(addr, None)
            return
        # Authenticated, but from an address we have not confirmed. Do not move udp_addr.
        session.hb_counter = counter
        self.user_manager.update_heartbeat(username)
        if not pending:
            session.pending_challenge = secrets.token_hex(16)
            session.pending_challenge_addr = addr
            session.pending_challenge_until = now + HEARTBEAT_CHALLENGE_TTL
        self._send_heartbeat_ack(addr, session.pending_challenge)

    def _login_endpoint(self, session):
        """Address advertised at login, used only until a heartbeat confirms one."""
        if session is None or not session.udp_port:
            return None
        return (session.ip, int(session.udp_port))

    def _registered_endpoint(self, session, pin):
        """
        Where a registered stream endpoint may send from.
        Prefer the address proved by a heartbeat. Never the source of the file packet itself.
        """
        if session is not None and session.udp_addr:
            return (session.udp_addr[0], int(session.udp_addr[1]))
        if pin:
            return (pin[0], int(pin[1]))
        return None

    def _relay_udp(self, pkt, raw, src_addr):
        """
        Forward one file packet unchanged between the two users registered for this stream.

        DATA and FIN go sender -> target, ACK goes target -> sender. The source must be
        that user's authenticated UDP address. A packet from anywhere else is dropped,
        and this path does not learn a new address.
        """
        with self.relay_lock:
            route = self.relay_streams.get(pkt.stream_id)
            if not route:
                return
        forward_to_target = pkt.pkt_type in (TYPE_DATA, TYPE_FIN)
        source_name = route["sender"] if forward_to_target else route["target"]
        dest_name = route["target"] if forward_to_target else route["sender"]
        src_pin = route.get("sender_pin") if forward_to_target else route.get("target_pin")
        dst_pin = route.get("target_pin") if forward_to_target else route.get("sender_pin")
        src_session = self.user_manager.get_user(source_name)
        dst_session = self.user_manager.get_user(dest_name)
        if not src_session or not dst_session:
            return
        expected_src = self._registered_endpoint(src_session, src_pin)
        expected_dst = self._registered_endpoint(dst_session, dst_pin)
        if expected_src is None or expected_dst is None:
            return
        if (src_addr[0], int(src_addr[1])) != expected_src:
            return
        with self.relay_lock:
            current = self.relay_streams.get(pkt.stream_id)
            if current is not None:
                current["last"] = time.time()
        try:
            self.udp_sock.sendto(raw, expected_dst)
            self.relayed_packets += 1
        except OSError:
            pass

    def _drop_routes_for(self, username):
        with self.relay_lock:
            dead = [sid for sid, route in self.relay_streams.items()
                    if username in (route["sender"], route["target"])]
            for sid in dead:
                self.relay_streams.pop(sid, None)

    def _heartbeat_watchdog(self):
        """Drop sessions that have been silent (UDP or TCP) for 15 seconds."""
        while self.running:
            time.sleep(5.0)
            if not self.running:
                break
            now = time.time()
            with self.relay_lock:
                stale = [sid for sid, route in self.relay_streams.items()
                         if now - route["last"] > RELAY_STREAM_IDLE_SEC]
                for sid in stale:
                    self.relay_streams.pop(sid, None)
            for sess in self.user_manager.cleanup_inactive_users(timeout_sec=15.0):
                self._drop_routes_for(sess.username)
                self._log(f"[-] '{sess.username}' timed out")
                try:
                    sess.tcp_sock.close()
                except Exception:
                    pass
                self._broadcast_packet(Packet.json_payload(
                    MsgType.USER_LEFT, {"username": sess.username, "reason": "Timeout"}
                ))
