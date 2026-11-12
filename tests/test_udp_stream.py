"""
Unit Tests for Reliable UDP Streaming Engine (Selective Repeat Sliding Window).
"""

import unittest
import os
import sys
import socket
import threading
import hashlib
import queue
import random

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from protocol.udp_stream import StreamSender, StreamReceiver, UDPPacket, TYPE_DATA, TYPE_ACK


class TestUDPStream(unittest.TestCase):
    def test_selective_repeat_with_simulated_loss(self):
        """Test Selective Repeat ARQ under 20% simulated packet loss."""
        class LossyPipe:
            def __init__(self, target_queue, loss_rate=0.2):
                self.q = target_queue
                self.loss_rate = loss_rate
            def sendto(self, data, addr):
                if random.random() > self.loss_rate:
                    self.q.put((data, addr))

        q_to_recv = queue.Queue()
        q_to_send = queue.Queue()

        sender_pipe = LossyPipe(q_to_recv, loss_rate=0.2)
        receiver_pipe = LossyPipe(q_to_send, loss_rate=0.2)

        test_data = os.urandom(40 * 1024)
        stream_id = 701

        sender = StreamSender(sender_pipe, ('sim', 1), stream_id, test_data, encrypt=True)
        receiver = StreamReceiver(stream_id, sender.total_chunks)

        stop = False
        def recv_loop():
            while not stop:
                try:
                    raw, addr = q_to_recv.get(timeout=0.05)
                    pkt = UDPPacket.decode(raw)
                    if pkt and pkt.stream_id == stream_id:
                        if pkt.pkt_type == TYPE_DATA:
                            receiver.put_chunk(pkt.chunk_idx, pkt.payload, pkt.flags & 1)
                            ack = UDPPacket(TYPE_ACK, stream_id, pkt.chunk_idx, pkt.total_chunks)
                            receiver_pipe.sendto(ack.encode(), addr)
                except queue.Empty:
                    continue

        def ack_loop():
            while not stop:
                try:
                    raw, _ = q_to_send.get(timeout=0.05)
                    pkt = UDPPacket.decode(raw)
                    if pkt and pkt.pkt_type == TYPE_ACK:
                        sender.handle_ack(pkt.chunk_idx)
                except queue.Empty:
                    continue

        t_recv = threading.Thread(target=recv_loop, daemon=True)
        t_ack = threading.Thread(target=ack_loop, daemon=True)
        t_send = threading.Thread(target=sender.send_loop, daemon=True)

        t_recv.start()
        t_ack.start()
        t_send.start()

        t_send.join(timeout=10.0)
        stop = True
        t_recv.join(timeout=0.5)
        t_ack.join(timeout=0.5)

        self.assertTrue(sender.finished, "Sender did not finish transmission despite retransmissions")
        self.assertTrue(receiver.is_complete(), "Receiver did not receive all chunks")
        reassembled = receiver.reassemble()
        self.assertEqual(hashlib.sha256(reassembled).hexdigest(), hashlib.sha256(test_data).hexdigest())

    def test_reliable_stream_transfer_no_loss(self):
        """Test sending 50KB binary data over live UDP socket with Selective Repeat and AES-GCM."""
        try:
            sender_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender_sock.bind(("127.0.0.1", 0))
            receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receiver_sock.bind(("127.0.0.1", 0))
            recv_port = receiver_sock.getsockname()[1]
        except Exception as e:
            self.skipTest(f"Socket binding restricted by OS: {e}")

        test_data = os.urandom(50 * 1024)
        stream_id = 101

        sender = StreamSender(sender_sock, ("127.0.0.1", recv_port), stream_id, test_data, encrypt=True)
        receiver = StreamReceiver(stream_id, sender.total_chunks)

        received_any = threading.Event()
        stop_recv = False
        def recv_loop():
            while not stop_recv:
                try:
                    receiver_sock.settimeout(0.1)
                    raw, addr = receiver_sock.recvfrom(65535)
                    received_any.set()
                    pkt = UDPPacket.decode(raw)
                    if pkt and pkt.stream_id == stream_id:
                        if pkt.pkt_type == TYPE_DATA:
                            receiver.put_chunk(pkt.chunk_idx, pkt.payload, pkt.flags & 1)
                            ack = UDPPacket(TYPE_ACK, stream_id, pkt.chunk_idx, pkt.total_chunks)
                            receiver_sock.sendto(ack.encode(), addr)
                except socket.timeout:
                    continue
                except Exception:
                    break

        recv_thread = threading.Thread(target=recv_loop, daemon=True)
        recv_thread.start()

        def ack_loop():
            while not stop_recv:
                try:
                    sender_sock.settimeout(0.1)
                    raw, _ = sender_sock.recvfrom(65535)
                    pkt = UDPPacket.decode(raw)
                    if pkt and pkt.pkt_type == TYPE_ACK:
                        sender.handle_ack(pkt.chunk_idx)
                except socket.timeout:
                    continue
                except Exception:
                    break

        ack_thread = threading.Thread(target=ack_loop, daemon=True)
        ack_thread.start()

        send_thread = threading.Thread(target=sender.send_loop, daemon=True)
        send_thread.start()

        try:
            # Wait up to 1 second to check if OS network sandbox drops loopback UDP
            if not received_any.wait(timeout=1.0):
                self.skipTest("Loopback UDP is restricted by OS sandbox/firewall policy")

            send_thread.join(timeout=10.0)
            self.assertTrue(sender.finished, "Sender did not finish transmission in time")
            self.assertTrue(receiver.is_complete(), "Receiver did not receive all chunks")

            reassembled = receiver.reassemble()
            self.assertEqual(hashlib.sha256(reassembled).hexdigest(), hashlib.sha256(test_data).hexdigest())
        finally:
            stop_recv = True
            recv_thread.join(timeout=0.3)
            ack_thread.join(timeout=0.3)
            try: sender_sock.close()
            except Exception: pass
            try: receiver_sock.close()
            except Exception: pass


if __name__ == '__main__':
    unittest.main()
