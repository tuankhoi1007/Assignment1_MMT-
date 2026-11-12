"""
Tests for congestion control, X25519 end-to-end keys, the UDP relay,
FIN, salted passwords, and UDP heartbeats.
"""

import hashlib
import json
import os
import queue
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography.exceptions import InvalidTag

import protocol.crypto as crypto_mod
from protocol.crypto import KeyPair, CryptoManager
from protocol.packet import Packet, MsgType, send_packet, recv_packet
import protocol.udp_stream as udp_mod
from protocol.udp_stream import (
    BbrLite, CongestionController, RttEstimator, StreamReceiver, StreamSender, UDPPacket,
    CUBIC_BETA, CUBIC_C, FLAG_ABORT, FLAG_FIN, INITIAL_CWND, MAX_RTO, MIN_RTO, MIN_SSTHRESH,
    TYPE_ACK, TYPE_DATA, TYPE_FIN, TYPE_HEARTBEAT,
    build_heartbeat, chunk_aad,
)
from server.credentials import CredentialStore
from server.server import CollaborationServer
from client.client import CollaborationClient


class QueuePipe:
    """Fake socket: sendto() enqueues the datagram unless drop() says otherwise."""

    def __init__(self, outbox, drop=None):
        self.q = outbox
        self.drop = drop or (lambda raw: False)

    def sendto(self, data, addr):
        if not self.drop(data):
            self.q.put((data, addr))


def run_pair(sender, receiver, answer_fin=True, timeout=10.0):
    """Drive a StreamSender against a StreamReceiver through in-memory queues."""
    data_q, ack_q = queue.Queue(), queue.Queue()
    sender.sock = QueuePipe(data_q)
    ack_pipe = QueuePipe(ack_q)
    seen = {"fin": 0, "abort": 0}
    stop = threading.Event()

    def recv_loop():
        while not stop.is_set():
            try:
                raw, addr = data_q.get(timeout=0.05)
            except queue.Empty:
                continue
            pkt = UDPPacket.decode(raw)
            if pkt is None:
                continue
            if pkt.pkt_type == TYPE_DATA:
                receiver.put_chunk(pkt.chunk_idx, pkt.payload, pkt.flags & 1)
                ack_pipe.sendto(
                    UDPPacket(TYPE_ACK, pkt.stream_id, pkt.chunk_idx, pkt.total_chunks).encode(),
                    addr,
                )
            elif pkt.pkt_type == TYPE_FIN:
                seen["fin"] += 1
                if pkt.flags & FLAG_ABORT:
                    seen["abort"] += 1
                elif answer_fin:
                    ack_pipe.sendto(
                        UDPPacket(TYPE_ACK, pkt.stream_id, pkt.chunk_idx, pkt.total_chunks, flags=FLAG_FIN).encode(),
                        addr,
                    )

    def ack_loop():
        while not stop.is_set():
            try:
                raw, _addr = ack_q.get(timeout=0.05)
            except queue.Empty:
                continue
            pkt = UDPPacket.decode(raw)
            if pkt is not None:
                sender.handle_ack(pkt.chunk_idx, pkt.flags)

    threads = [threading.Thread(target=fn, daemon=True) for fn in (recv_loop, ack_loop)]
    for thread in threads:
        thread.start()
    worker = threading.Thread(target=sender.send_loop, daemon=True)
    worker.start()
    worker.join(timeout)
    time.sleep(0.05)
    stop.set()
    return seen


class TestCongestionControl(unittest.TestCase):
    def test_rto_follows_rfc6298(self):
        est = RttEstimator()
        est.add_sample(0.1)  # SRTT=0.1, RTTVAR=0.05, RTO=0.3
        self.assertAlmostEqual(est.srtt, 0.1)
        self.assertAlmostEqual(est.rttvar, 0.05)
        self.assertAlmostEqual(est.rto, 0.3)
        est.add_sample(0.2)  # RTTVAR=0.0625, SRTT=0.1125, RTO=0.3625
        self.assertAlmostEqual(est.rttvar, 0.0625)
        self.assertAlmostEqual(est.srtt, 0.1125)
        self.assertAlmostEqual(est.rto, 0.3625)
        est.backoff()
        self.assertAlmostEqual(est.rto, 0.725)
        for _ in range(10):
            est.backoff()
        self.assertEqual(est.rto, MAX_RTO)
        tiny = RttEstimator()
        tiny.add_sample(0.0001)
        self.assertEqual(tiny.rto, MIN_RTO)

    def test_slow_start_then_additive_above_the_curve(self):
        cc = CongestionController()
        self.assertEqual(cc.cwnd, INITIAL_CWND)
        self.assertEqual(cc.state, "slow_start")
        cc.ssthresh = INITIAL_CWND + 2
        cc.on_new_ack()
        cc.on_new_ack()
        self.assertEqual(cc.cwnd, INITIAL_CWND + 2)
        self.assertEqual(cc.state, "congestion_avoidance")
        # Just after slow start the cubic target is still below cwnd, so the
        # TCP-friendly branch adds one chunk per RTT (1/cwnd per ACK).
        before = cc.cwnd
        cc.on_new_ack(now=5.0, rtt=1.0)
        self.assertAlmostEqual(cc.cwnd, before + 1.0 / before)

    def test_cubic_loss_reaction_and_curve(self):
        cc = CongestionController()
        cc.cwnd = 20
        cc.on_fast_retransmit(now=1000.0)
        self.assertAlmostEqual(cc.w_max, 20)
        self.assertAlmostEqual(cc.ssthresh, 20 * CUBIC_BETA)
        self.assertAlmostEqual(cc.cwnd, 20 * CUBIC_BETA)
        self.assertAlmostEqual(cc.k, (20 * (1 - CUBIC_BETA) / CUBIC_C) ** (1.0 / 3.0))
        self.assertEqual(cc.state, "congestion_avoidance")
        self.assertEqual(cc.fast_retransmits, 1)
        self.assertNotAlmostEqual(cc.cwnd, 10)  # beta is 0.7, not Reno's 1/2

        # t = K + 2s is past W_max: the cubic term, not +1/cwnd, moves the window.
        cc2 = CongestionController()
        cc2.cwnd = 20 * CUBIC_BETA
        cc2.w_max = 20
        cc2.k = (20 * (1.0 - CUBIC_BETA) / CUBIC_C) ** (1.0 / 3.0)
        cc2.ssthresh = cc2.cwnd
        cc2.epoch_start = 0.0
        before = cc2.cwnd
        t_past = 2.0
        rtt = 10.0
        w_cubic = CUBIC_C * (t_past ** 3) + cc2.w_max
        friendly = (3.0 * (1.0 - CUBIC_BETA)) / (1.0 + CUBIC_BETA)
        w_est = cc2.w_max * CUBIC_BETA + friendly * ((cc2.k + t_past) / rtt)
        target = max(w_cubic, w_est)
        self.assertGreater(w_cubic, cc2.w_max)
        cc2.on_new_ack(now=cc2.k + t_past, rtt=rtt)
        self.assertAlmostEqual(cc2.cwnd, before + min(1.0, (target - before) / before))
        self.assertGreater(cc2.cwnd - before, 1.0 / before)

    def test_timeout_returns_to_slow_start(self):
        cc = CongestionController()
        cc.cwnd = 20
        cc.on_fast_retransmit(now=10.0)
        reduced = cc.cwnd
        cc.on_timeout(now=20.0)
        self.assertAlmostEqual(cc.w_max, reduced * (1.0 + CUBIC_BETA) / 2.0)
        self.assertAlmostEqual(cc.ssthresh, max(reduced * CUBIC_BETA, MIN_SSTHRESH))
        self.assertEqual(cc.cwnd, 1.0)
        self.assertEqual(cc.state, "slow_start")
        self.assertEqual(cc.loss_events, 2)
        self.assertEqual(cc.timeouts, 1)

    def test_window_grows_on_clean_path(self):
        data = os.urandom(150 * 1200)
        sender = StreamSender(None, ("x", 1), 11, data)
        receiver = StreamReceiver(11, sender.total_chunks)
        run_pair(sender, receiver)
        self.assertTrue(sender.finished)
        self.assertEqual(receiver.reassemble(), data)
        self.assertGreater(sender.cc.max_cwnd_seen, 16)
        self.assertIsNotNone(sender.rtt.srtt)
        self.assertEqual(sender.cc.name, "cubic")

    def test_fast_retransmit_and_karn(self):
        sender = StreamSender(QueuePipe(queue.Queue()), ("x", 1), 12, os.urandom(10 * 1200))
        now = time.time()
        sender.next_seq = 6
        for i in range(6):
            sender.send_times[i] = now
        sender.cc.cwnd = 8
        for idx in (1, 2, 3):
            sender.handle_ack(idx)
        self.assertTrue(sender.fast_retx_pending)
        self.assertEqual(sender.cc.fast_retransmits, 1)
        self.assertLess(sender.cc.cwnd, 8)

        fresh = StreamSender(QueuePipe(queue.Queue()), ("x", 1), 13, os.urandom(1200))
        fresh.send_times[0] = time.time()
        fresh.retransmit_counts[0] = 1
        fresh.handle_ack(0)
        self.assertIsNone(fresh.rtt.srtt)

    def test_no_cwnd_growth_during_fast_recovery(self):
        """ACKs must not inflate cwnd while base is still at or below the recovery point."""
        sender = StreamSender(QueuePipe(queue.Queue()), ("x", 1), 14, os.urandom(10 * 1200))
        sender.next_seq = 6
        sender.cc.cwnd = 9.10
        # Slow start would add a whole chunk per ACK. Recovery must suppress that.
        sender.cc.ssthresh = 100.0
        sender.cc.w_max = 9.10
        sender.cc.epoch_start = time.time()
        sender.recovery_point = 5
        sender.base = 0
        before = sender.cc.cwnd
        for idx in (1, 2, 3, 4, 5):
            sender.handle_ack(idx)
            self.assertEqual(sender.cc.cwnd, before)
            self.assertEqual(sender.recovery_point, 5)
        # Acknowledging the recovery point while an earlier hole remains is still recovery.
        self.assertIn(5, sender.acked)
        self.assertEqual(sender.base, 0)
        sender.handle_ack(0)
        self.assertGreater(sender.base, 5)
        self.assertEqual(sender.recovery_point, -1)
        self.assertEqual(sender.cc.cwnd, before)
        sender.handle_ack(6)
        self.assertAlmostEqual(sender.cc.cwnd, before + 1.0)

    def test_bbr_lite_follows_bdp_and_ignores_aimd(self):
        bbr = BbrLite()
        t0 = 1000.0
        for i in range(40):
            bbr.on_new_ack(now=t0 + i * 0.002, rtt=0.02)
        self.assertGreater(bbr.cwnd, INITIAL_CWND)
        self.assertEqual(bbr.state, "startup")
        held = bbr.cwnd
        bbr.on_fast_retransmit(now=t0 + 1)
        self.assertEqual(bbr.cwnd, held)
        bbr.on_timeout(now=t0 + 2)
        self.assertEqual(bbr.cwnd, INITIAL_CWND)
        self.assertEqual(bbr.state, "probe_bw")

        data = os.urandom(3000)
        sender = StreamSender(None, ("x", 1), 31, data, congestion="bbr")
        receiver = StreamReceiver(31, sender.total_chunks)
        run_pair(sender, receiver)
        self.assertTrue(sender.finished)
        self.assertEqual(receiver.reassemble(), data)
        self.assertEqual(sender.stats()["algorithm"], "bbr")


class TestKeyExchange(unittest.TestCase):
    def test_no_hard_coded_key(self):
        self.assertFalse(hasattr(crypto_mod, "SHARED_KEY_32_BYTES"))
        self.assertNotEqual(CryptoManager().key, CryptoManager().key)

    def test_ecdh_hkdf_pairwise_keys(self):
        alice, bob, eve = KeyPair(), KeyPair(), KeyPair()
        shared_ab = alice.derive(bob.public_b64, "chat")
        shared_ba = bob.derive(alice.public_b64, "chat")
        self.assertEqual(shared_ab.key, shared_ba.key)
        self.assertNotEqual(shared_ab.key, alice.derive(bob.public_b64, "file:1").key)
        token = shared_ab.encrypt_string("hello bob", b"chat|alice|bob")
        self.assertEqual(shared_ba.decrypt_string(token, b"chat|alice|bob"), "hello bob")
        with self.assertRaises(InvalidTag):
            eve.derive(alice.public_b64, "chat").decrypt_string(token, b"chat|alice|bob")
        with self.assertRaises(InvalidTag):
            shared_ba.decrypt_string(token, b"chat|alice|eve")

    def test_chunk_position_is_authenticated(self):
        key = CryptoManager()
        receiver = StreamReceiver(5, 3, crypto=key)
        moved = key.encrypt(b"chunk-0", chunk_aad(5, 0, 3))
        self.assertFalse(receiver.put_chunk(1, moved, True))
        self.assertTrue(receiver.put_chunk(0, moved, True))


class TestFin(unittest.TestCase):
    def test_fin_closes_stream(self):
        data = os.urandom(5000)
        sender = StreamSender(None, ("x", 1), 21, data)
        receiver = StreamReceiver(21, sender.total_chunks)
        seen = run_pair(sender, receiver)
        self.assertTrue(sender.finished)
        self.assertTrue(sender.closed)
        self.assertGreaterEqual(seen["fin"], 1)

    def test_cancel_sends_abort_fin(self):
        outbox = queue.Queue()
        sender = StreamSender(QueuePipe(outbox), ("x", 1), 22, os.urandom(5000))
        sender.cancel()
        pkt = UDPPacket.decode(outbox.get(timeout=1)[0])
        self.assertEqual(pkt.pkt_type, TYPE_FIN)
        self.assertTrue(pkt.flags & FLAG_ABORT)
        self.assertTrue(sender.aborted)
        if sender._fin_thread is not None:
            sender.closed = True
            sender._fin_thread.join(timeout=1)

    def test_abort_fin_retries_with_backoff_until_acked(self):
        """A lost abort FIN is retransmitted with exponential backoff, and stops once ACK'd."""
        packets = []
        clock = {"t": 1000.0}
        sender_holder = {}

        class Pipe:
            def sendto(self, data, addr):
                packets.append((clock["t"], data))
                if len(packets) == 2:
                    sender_holder["sender"].handle_ack(0, FLAG_FIN)

        sender = StreamSender(Pipe(), ("x", 1), 23, os.urandom(100), encrypt=False)
        sender_holder["sender"] = sender
        sender.rtt.rto = 0.2
        sender.fin_retries = 4
        old_time, old_sleep = udp_mod.time.time, udp_mod.time.sleep
        udp_mod.time.time = lambda: clock["t"]
        udp_mod.time.sleep = lambda dt: clock.__setitem__("t", clock["t"] + dt)
        try:
            sender.cancel()
            self.assertIsNotNone(sender._fin_thread)
            sender._fin_thread.join(timeout=2)
        finally:
            udp_mod.time.time = old_time
            udp_mod.time.sleep = old_sleep
        self.assertTrue(sender.closed)
        self.assertEqual(len(packets), 2)
        gaps = packets[1][0] - packets[0][0]
        self.assertAlmostEqual(gaps, 0.2, delta=0.01)
        for _stamp, raw in packets:
            pkt = UDPPacket.decode(raw)
            self.assertEqual(pkt.pkt_type, TYPE_FIN)
            self.assertTrue(pkt.flags & FLAG_ABORT)

        packets.clear()
        clock["t"] = 2000.0
        lone = StreamSender(Pipe(), ("x", 1), 24, os.urandom(100), encrypt=False)
        lone.rtt.rto = 0.2
        lone.fin_retries = 4
        udp_mod.time.time = lambda: clock["t"]
        udp_mod.time.sleep = lambda dt: clock.__setitem__("t", clock["t"] + dt)
        try:
            lone._fin_handshake(FLAG_ABORT)
        finally:
            udp_mod.time.time = old_time
            udp_mod.time.sleep = old_sleep
        self.assertEqual(len(packets), 4)
        gaps = [packets[i + 1][0] - packets[i][0] for i in range(3)]
        self.assertAlmostEqual(gaps[0], 0.2, delta=0.01)
        self.assertAlmostEqual(gaps[1], 0.4, delta=0.01)
        self.assertAlmostEqual(gaps[2], 0.8, delta=0.01)

    def test_failed_send_uses_abort_handshake(self):
        sender = StreamSender(QueuePipe(queue.Queue()), ("x", 1), 25, os.urandom(100))
        sender.failed = True
        sender.running = False
        seen = {}

        def fake_fin(flags=0):
            seen["flags"] = flags

        sender._fin_handshake = fake_fin
        sender.send_loop()
        self.assertEqual(seen["flags"], FLAG_ABORT)

    def test_receiver_acks_abort_fin_and_tears_down(self):
        client = CollaborationClient()
        sent = []

        class Sock:
            def sendto(self, data, addr):
                sent.append((data, addr))

        client.udp_sock = Sock()
        receiver = StreamReceiver(7, 4)
        receiver.put_chunk(0, b"partial", False)
        client.active_receivers[7] = receiver
        client.transfers[7] = {"role": "receiver", "progress": 25.0, "status": "Receiving"}
        abort = UDPPacket(TYPE_FIN, 7, 4, 4, flags=FLAG_ABORT)
        client._handle_fin(abort, ("127.0.0.1", 9))
        self.assertNotIn(7, client.active_receivers)
        self.assertTrue(receiver.aborted)
        self.assertTrue(client.transfers[7]["closed"])
        self.assertEqual(client.transfers[7]["status"], "Cancelled by sender")
        ack = UDPPacket.decode(sent[-1][0])
        self.assertEqual(ack.pkt_type, TYPE_ACK)
        self.assertTrue(ack.flags & FLAG_FIN)
        self.assertTrue(ack.flags & FLAG_ABORT)
        self.assertEqual(sent[-1][1], ("127.0.0.1", 9))

        sent.clear()
        client._handle_fin(abort, ("127.0.0.1", 9))
        self.assertEqual(len(sent), 1, "a repeated abort FIN is still acknowledged")

        sent.clear()
        client.active_receivers[8] = StreamReceiver(8, 2)
        client.transfers[8] = {"role": "receiver", "progress": 0.0, "status": "Receiving"}
        early = UDPPacket(TYPE_FIN, 8, 2, 2)
        client._handle_fin(early, ("127.0.0.1", 9))
        self.assertIn(8, client.active_receivers)
        self.assertEqual(sent, [])


class TestCredentials(unittest.TestCase):
    def test_salted_hash_and_persistence(self):
        path = os.path.join(tempfile.mkdtemp(), "users.json")
        store = CredentialStore(path)
        self.assertTrue(store.register("alice", "pass1234")[0])
        self.assertTrue(store.register("bob", "pass1234")[0])
        self.assertFalse(store.register("alice", "other123")[0])
        self.assertFalse(store.register("carol", "ab")[0])
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
        self.assertNotIn("pass1234", raw)
        db = json.loads(raw)
        self.assertNotEqual(db["alice"]["hash"], db["bob"]["hash"])
        self.assertNotEqual(db["alice"]["salt"], db["bob"]["salt"])
        reloaded = CredentialStore(path)
        self.assertTrue(reloaded.verify("alice", "pass1234"))
        self.assertFalse(reloaded.verify("alice", "wrong"))
        self.assertFalse(reloaded.verify("nobody", "pass1234"))


class TestSpecGapsIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tcp_port, cls.udp_port = 19888, 19889
        cls.db = os.path.join(tempfile.mkdtemp(), "users.json")
        cls.server = CollaborationServer(
            host="127.0.0.1", tcp_port=cls.tcp_port, udp_port=cls.udp_port,
            verbose=False, require_password=True, user_db=cls.db,
        )
        threading.Thread(target=cls.server.start, daemon=True).start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        time.sleep(0.2)

    def _client(self, name, password="secret123", register=True, hb=None):
        client = CollaborationClient(server_host="127.0.0.1", server_tcp_port=self.tcp_port)
        if hb:
            client.heartbeat_interval = hb
        ok, msg = client.connect_and_login(name, password=password, register=register)
        self.assertTrue(ok, msg)
        self.addCleanup(client.disconnect)
        return client

    def _wait(self, cond, timeout=8.0):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.05)
        return False

    def test_register_login_and_rejections(self):
        client = CollaborationClient(server_host="127.0.0.1", server_tcp_port=self.tcp_port)
        ok, _msg = client.connect_and_login("Pat", password="hunter22", register=True)
        self.assertTrue(ok)
        self.assertFalse(client.guest)
        client.disconnect()
        time.sleep(0.2)

        bad = CollaborationClient(server_host="127.0.0.1", server_tcp_port=self.tcp_port)
        ok, msg = bad.connect_and_login("Pat", password="wrongpass")
        self.assertFalse(ok)
        self.assertIn("Invalid", msg)
        ok, _msg = bad.connect_and_login("Pat", password="hunter22", register=True)
        self.assertFalse(ok)
        ok, _msg = bad.connect_and_login("Nobody")
        self.assertFalse(ok)

        good = CollaborationClient(server_host="127.0.0.1", server_tcp_port=self.tcp_port)
        ok, msg = good.connect_and_login("Pat", password="hunter22")
        self.assertTrue(ok, msg)
        good.disconnect()

    def test_plaintext_password_is_rejected(self):
        raw = socket.create_connection(("127.0.0.1", self.tcp_port), timeout=3)
        try:
            send_packet(raw, Packet(MsgType.HANDSHAKE_REQ, payload=b"HELLO"))
            recv_packet(raw)
            send_packet(raw, Packet.json_payload(MsgType.AUTH_LOGIN, {"username": "Sniffed", "password": "abcd1234"}))
            resp = recv_packet(raw)
            self.assertEqual(resp.msg_type, MsgType.AUTH_FAILURE)
            self.assertIn("encrypted", resp.to_json()["reason"])
        finally:
            raw.close()

    def test_chat_is_end_to_end_encrypted(self):
        relayed = []
        orig_unicast, orig_bcast = self.server._send_to_user, self.server._broadcast_packet

        def spy_unicast(user, pkt):
            relayed.append(pkt.payload)
            return orig_unicast(user, pkt)

        def spy_bcast(pkt, exclude_user=None):
            relayed.append(pkt.payload)
            return orig_bcast(pkt, exclude_user)

        self.server._send_to_user = spy_unicast
        self.server._broadcast_packet = spy_bcast
        self.addCleanup(setattr, self.server, "_send_to_user", orig_unicast)
        self.addCleanup(setattr, self.server, "_broadcast_packet", orig_bcast)

        alice = self._client("E2E_Alice")
        bob = self._client("E2E_Bob")
        carol = self._client("E2E_Carol")
        self.assertTrue(self._wait(lambda: len([u for u in alice.active_users if u["username"].startswith("E2E_")]) == 3))

        alice.send_unicast_message("E2E_Bob", "private plan 42")
        alice.send_broadcast_message("hello everyone 77")
        self.assertTrue(self._wait(lambda: any(m["text"] == "private plan 42" for m in bob.messages)))
        self.assertTrue(self._wait(lambda: any(m["text"] == "hello everyone 77" for m in carol.messages)))
        self.assertTrue(any(m["text"] == "hello everyone 77" for m in bob.messages))
        self.assertFalse(any(m["text"] == "private plan 42" for m in carol.messages))

        blob = b"".join(relayed)
        self.assertNotIn(b"private plan 42", blob)
        self.assertNotIn(b"hello everyone 77", blob)
        unicast = next(json.loads(p) for p in relayed if b'"target": "E2E_Bob"' in p)
        self.assertTrue(carol._decrypt_chat(unicast, False).startswith("[Decryption Error"))

    def _send_and_wait(self, src, dst, name, size=60 * 1024):
        path = os.path.join(tempfile.mkdtemp(), name)
        data = os.urandom(size)
        with open(path, "wb") as handle:
            handle.write(data)
        ok, msg = src.send_file(dst.username, path)
        self.assertTrue(ok, msg)
        self.assertTrue(self._wait(
            lambda: any(t.get("filename") == name and t.get("saved_path") for t in dst.transfers.values()),
            15,
        ))
        info = next(t for t in dst.transfers.values() if t.get("filename") == name)
        with open(info["saved_path"], "rb") as handle:
            self.assertEqual(hashlib.sha256(handle.read()).hexdigest(), hashlib.sha256(data).hexdigest())
        self.addCleanup(os.remove, info["saved_path"])
        sent = next(t for t in src.transfers.values() if t.get("filename") == name)
        return sent, info

    def test_direct_file_stays_off_the_relay(self):
        alice = self._client("Direct_A", hb=0.3)
        bob = self._client("Direct_B", hb=0.3)
        self.assertTrue(self._wait(lambda: any(u["username"] == "Direct_B" and u.get("pubkey") for u in alice.active_users)))
        before = self.server.relayed_packets
        sent, _info = self._send_and_wait(alice, bob, "direct_file.bin", size=8 * 1024)
        self.assertEqual(sent["path"], "direct")
        self.assertEqual(self.server.relayed_packets, before)
        self.assertTrue(self._wait(lambda: sent.get("closed") is True))

    def test_file_through_forced_relay_with_fin(self):
        alice = self._client("Relay_A", hb=0.3)
        bob = self._client("Relay_B", hb=0.3)
        self.assertTrue(self._wait(lambda: any(u["username"] == "Relay_B" for u in alice.active_users)))
        alice.force_relay = True
        before = self.server.relayed_packets
        sent, received = self._send_and_wait(alice, bob, "relay_file.bin")
        self.assertGreater(self.server.relayed_packets, before)
        self.assertEqual(sent["path"], "relay")
        self.assertTrue(self._wait(lambda: sent.get("closed") is True))
        self.assertTrue(self._wait(lambda: received.get("closed") is True))
        self.assertEqual(bob.active_receivers, {})
        self.assertTrue(self._wait(lambda: alice.active_senders == {}))

    def test_relay_fallback_when_direct_path_fails(self):
        alice = self._client("NAT_A", hb=0.3)
        bob = self._client("NAT_B", hb=0.3)
        self.assertTrue(self._wait(lambda: any(u["username"] == "NAT_B" for u in alice.active_users)))
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        dead_port = dead.getsockname()[1]
        dead.close()
        with alice.lock:
            for user in alice.active_users:
                if user["username"] == "NAT_B":
                    user["udp_port"] = dead_port
        sent, _info = self._send_and_wait(alice, bob, "nat_file.bin", size=20 * 1024)
        self.assertEqual(sent["path"], "relay")

    def test_udp_heartbeat_registers_address(self):
        client = self._client("HB_User", hb=0.2)
        session = self.server.user_manager.get_user("HB_User")
        self.assertTrue(self._wait(lambda: session.udp_addr is not None, 3))
        self.assertEqual(session.udp_addr[1], client.udp_port)
        self.assertLess(time.time() - client.last_udp_pong, 1.0)
        self.assertLess(time.time() - session.last_heartbeat, 1.0)

    def test_udp_heartbeat_keeps_session_past_tcp_idle_timeout(self):
        """UDP liveness must keep the session up when the TCP socket stays quiet.

        The recv timeout applies only until login. Afterwards the 15s watchdog is
        the thing that drops a silent client, and UDP heartbeats refresh it.
        """
        previous = self.server.pre_auth_timeout
        self.server.pre_auth_timeout = 0.3
        try:
            client = self._client("IdleTCP", hb=0.2)
            session = self.server.user_manager.get_user("IdleTCP")
            self.assertTrue(self._wait(lambda: session.udp_addr is not None, 3))
            time.sleep(1.0)
            self.assertIs(self.server.user_manager.get_user("IdleTCP"), session)
            self.assertTrue(client.is_connected)
            self.assertTrue(any(u["username"] == "IdleTCP" for u in client.active_users))
        finally:
            self.server.pre_auth_timeout = previous

    def test_heartbeat_packet_does_not_carry_the_token(self):
        client = CollaborationClient()
        client.username = "alice"
        client.heartbeat_key = b"k" * 32
        client.udp_port = 5
        client.server_host = "127.0.0.1"
        client.server_udp_port = 9
        client.udp_token = "secret-token-value"
        sent = []

        class Sock:
            def sendto(self, data, addr):
                sent.append(data)

        client.udp_sock = Sock()
        client._send_udp_heartbeat()
        self.assertEqual(len(sent), 1)
        self.assertNotIn(b"secret-token-value", sent[0])
        self.assertNotIn(b"token", sent[0])
        body = json.loads(UDPPacket.decode(sent[0]).payload.decode("utf-8"))
        self.assertIn("mac", body)
        self.assertNotIn("token", body)

    def test_forged_udp_heartbeat_is_ignored(self):
        self._client("HB_Victim", hb=30)
        session = self.server.user_manager.get_user("HB_Victim")
        self.assertTrue(self._wait(lambda: session.udp_addr is not None, 3))
        real_addr = session.udp_addr
        forger = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            body = json.dumps({"username": "HB_Victim", "token": "not-the-token"}).encode()
            forger.sendto(UDPPacket(TYPE_HEARTBEAT, 0, 1, 0, body).encode(), ("127.0.0.1", self.udp_port))
            time.sleep(0.3)
            self.assertEqual(session.udp_addr, real_addr)
        finally:
            forger.close()

    def test_stolen_token_cannot_take_over_relay_address(self):
        """A heartbeat that only knows the old cleartext token must not move udp_addr."""
        client = self._client("HB_Owner", hb=0.2)
        session = self.server.user_manager.get_user("HB_Owner")
        self.assertTrue(self._wait(lambda: session.udp_addr is not None, 3))
        real_addr = session.udp_addr
        stolen = session.udp_token
        self.assertTrue(stolen)

        attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(attacker.close)
        legacy = json.dumps({
            "username": "HB_Owner", "token": stolen, "udp_port": 9,
        }).encode("utf-8")
        attacker.sendto(UDPPacket(TYPE_HEARTBEAT, 0, 1, 0, legacy).encode(), ("127.0.0.1", self.udp_port))
        time.sleep(0.3)
        self.assertEqual(session.udp_addr, real_addr)

        replay = build_heartbeat(session.heartbeat_key, "HB_Owner", 1, 9, "")
        attacker.sendto(UDPPacket(TYPE_HEARTBEAT, 0, 1, 0, replay).encode(), ("127.0.0.1", self.udp_port))
        fresh = build_heartbeat(session.heartbeat_key, "HB_Owner", session.hb_counter + 5, 9, "")
        attacker.sendto(UDPPacket(TYPE_HEARTBEAT, 0, 99, 0, fresh).encode(), ("127.0.0.1", self.udp_port))
        time.sleep(0.3)
        self.assertEqual(session.udp_addr, real_addr)
        self.assertNotEqual(attacker.getsockname(), real_addr)

    def test_relay_drops_packets_that_are_not_from_a_registered_endpoint(self):
        server = CollaborationServer(host="127.0.0.1", tcp_port=0, udp_port=0, verbose=False)
        self.addCleanup(server.udp_sock.close)
        alice_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(alice_tcp.close)
        self.addCleanup(bob_tcp.close)
        self.addCleanup(server.tcp_sock.close)
        alice = server.user_manager.add_user("RelA", alice_tcp, ("127.0.0.1", 1), udp_port=41001)
        bob = server.user_manager.add_user("RelB", bob_tcp, ("127.0.0.1", 2), udp_port=41002)
        alice.authenticated = True
        bob.authenticated = True
        alice.udp_addr = ("127.0.0.1", 41001)
        bob.udp_addr = ("127.0.0.1", 41002)
        server.relay_streams[5] = {
            "sender": "RelA",
            "target": "RelB",
            "sender_pin": ("127.0.0.1", 41001),
            "target_pin": ("127.0.0.1", 41002),
            "last": time.time(),
        }
        raw = UDPPacket(TYPE_DATA, 5, 0, 1, b"x").encode()
        pkt = UDPPacket.decode(raw)
        server._relay_udp(pkt, raw, ("127.0.0.1", 9))
        self.assertEqual(server.relayed_packets, 0)
        self.assertEqual(alice.udp_addr, ("127.0.0.1", 41001))
        server._relay_udp(pkt, raw, ("127.0.0.1", 41001))
        self.assertEqual(server.relayed_packets, 1)

    def test_web_ui_has_password_and_relay_controls(self):
        from client.web_server import RawSocketHTTPServer
        import urllib.request

        web = RawSocketHTTPServer(CollaborationClient(), host="127.0.0.1", port=15111)
        web.start()
        self.addCleanup(web.stop)
        time.sleep(0.2)
        with urllib.request.urlopen(f"http://127.0.0.1:{web.port}/api/state") as resp:
            self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
        with urllib.request.urlopen(f"http://127.0.0.1:{web.port}/") as resp:
            html = resp.read().decode("utf-8")
        self.assertIn('id="input-password"', html)
        self.assertIn('id="input-register"', html)
        self.assertIn('id="force-relay"', html)
        with urllib.request.urlopen(f"http://127.0.0.1:{web.port}/app.js") as resp:
            script = resp.read().decode("utf-8")
        self.assertIn("force_relay", script)
        self.assertIn("password", script)

    def test_web_login_registers_with_password(self):
        """The raw HTTP UI posts the password through to the collaboration server."""
        from client.web_server import RawSocketHTTPServer
        import urllib.request

        engine = CollaborationClient(server_host="127.0.0.1", server_tcp_port=self.tcp_port)
        web = RawSocketHTTPServer(engine, host="127.0.0.1", port=15121)
        web.start()
        self.addCleanup(engine.disconnect)
        self.addCleanup(web.stop)
        time.sleep(0.2)
        payload = json.dumps({
            "username": "WebPat",
            "password": "webpass1",
            "register": True,
            "host": "127.0.0.1",
            "port": self.tcp_port,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{web.port}/api/connect",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 200)
            self.assertTrue(body.get("success"), body)
            self.assertIn("session_user=WebPat", resp.headers.get("Set-Cookie", ""))
        self.assertTrue(engine.is_connected)
        self.assertFalse(engine.guest)
        self.assertTrue(self.server.credentials.verify("WebPat", "webpass1"))
        self.assertFalse(self.server.credentials.verify("WebPat", "nope"))


if __name__ == "__main__":
    unittest.main()
