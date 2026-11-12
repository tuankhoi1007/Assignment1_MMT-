"""
CO3093 - Reliable UDP streaming.

Selective Repeat ARQ, plus:
  * RFC 6298 retransmission timeout (SRTT / RTTVAR, exponential back-off)
  * CUBIC congestion control (RFC 8312): slow start, cubic avoidance, loss reaction
  * optional BBR-lite controller (bandwidth-delay product, no AIMD cut)
  * FIN (type 3) to close a stream, ACK'd with FLAG_FIN
  * HEARTBEAT (type 4) / HEARTBEAT_ACK (type 5) for the server UDP port

Fixed 24-byte header:
  Magic (2B) | Type (1B) | Flags (1B) | StreamID (4B) | ChunkIdx (4B) |
  TotalChunks (4B) | Len (2B) | Reserved (2B) | CRC32 (4B)
"""

import math
import struct
import threading
import time
import zlib

from protocol.crypto import default_crypto

UDP_MAGIC = 0x5546  # 'UF'
CHUNK_PAYLOAD_SIZE = 1200  # stays under the 1500-byte Ethernet MTU after IP+UDP+AES-GCM
WINDOW_SIZE = 64            # flow-control cap, in chunks. The send window is min(cwnd, this).
MAX_CHUNK_RETRANSMITS = 30

# Congestion window (chunks).
INITIAL_CWND = 2.0
INITIAL_SSTHRESH = 32.0
MIN_SSTHRESH = 2.0
DUP_ACK_THRESHOLD = 3

# CUBIC (RFC 8312). beta is the multiplicative decrease factor.
CUBIC_C = 0.4
CUBIC_BETA = 0.7

# RFC 6298. MIN/MAX are tighter than the RFC's 1s/60s because this is a LAN app.
INITIAL_RTO = 0.25
MIN_RTO = 0.05
MAX_RTO = 3.0
RTO_ALPHA = 1 / 8
RTO_BETA = 1 / 4
RTO_K = 4
CLOCK_GRANULARITY = 0.005
RETRANSMIT_TIMEOUT = INITIAL_RTO  # old name: now only the RTO before the first sample

# If the direct peer does not ACK within this long, resend via the server relay.
DIRECT_PROBE_TIMEOUT = 1.0

FIN_MAX_RETRIES = 5

UDP_HEADER_FORMAT = "!HBBIIIH2sI"
UDP_HEADER_SIZE = struct.calcsize(UDP_HEADER_FORMAT)
assert UDP_HEADER_SIZE == 24

TYPE_DATA = 1
TYPE_ACK = 2
TYPE_FIN = 3             # end of stream; FLAG_ABORT means the sender cancelled
TYPE_HEARTBEAT = 4       # client -> server liveness, also registers the UDP source address
TYPE_HEARTBEAT_ACK = 5   # server -> client

FLAG_NONE = 0x00
FLAG_ENCRYPTED = 0x01
FLAG_FIN = 0x02          # on an ACK: this ACK acknowledges a FIN
FLAG_ABORT = 0x04        # on a FIN: transfer cancelled, discard partial data


def chunk_aad(stream_id, chunk_idx, total_chunks):
    """AES-GCM associated data. Binds a ciphertext to its position so chunks cannot be swapped."""
    return struct.pack("!III", int(stream_id) & 0xFFFFFFFF, int(chunk_idx) & 0xFFFFFFFF, int(total_chunks) & 0xFFFFFFFF)


class UDPPacket:
    """Binary UDP packet with a fixed 24-byte header and a CRC32 over the payload."""

    def __init__(self, pkt_type, stream_id, chunk_idx, total_chunks, payload=b"", flags=FLAG_NONE):
        self.magic = UDP_MAGIC
        self.pkt_type = pkt_type
        self.flags = flags
        self.stream_id = stream_id
        self.chunk_idx = chunk_idx
        self.total_chunks = total_chunks
        self.payload = payload
        self.data_len = len(payload)
        self.checksum = zlib.crc32(payload) & 0xFFFFFFFF

    def encode(self):
        hdr = struct.pack(
            UDP_HEADER_FORMAT,
            self.magic,
            self.pkt_type,
            self.flags,
            self.stream_id,
            self.chunk_idx,
            self.total_chunks,
            self.data_len,
            b"\x00\x00",
            self.checksum,
        )
        return hdr + self.payload

    @classmethod
    def decode(cls, raw):
        if len(raw) < UDP_HEADER_SIZE:
            return None
        magic, p_type, flags, s_id, c_idx, tot, d_len, _, checksum = struct.unpack(
            UDP_HEADER_FORMAT, raw[:UDP_HEADER_SIZE]
        )
        if magic != UDP_MAGIC:
            return None
        payload = raw[UDP_HEADER_SIZE:UDP_HEADER_SIZE + d_len]
        if len(payload) != d_len or (zlib.crc32(payload) & 0xFFFFFFFF) != checksum:
            return None
        return cls(p_type, s_id, c_idx, tot, payload, flags)


class RttEstimator:
    """
    Adaptive retransmission timeout, RFC 6298.

    First sample R:   SRTT = R, RTTVAR = R/2
    Later samples:    RTTVAR = (1-beta)*RTTVAR + beta*|SRTT-R|
                      SRTT   = (1-alpha)*SRTT + alpha*R
    RTO = SRTT + max(G, K*RTTVAR), clamped to [MIN_RTO, MAX_RTO].

    backoff() doubles the RTO (exponential back-off on timeout). The caller applies
    Karn's rule: do not feed samples from a segment that was retransmitted.
    """

    def __init__(self):
        self.srtt = None
        self.rttvar = None
        self.rto = INITIAL_RTO

    def add_sample(self, r):
        if r < 0:
            return
        if self.srtt is None:
            self.srtt = r
            self.rttvar = r / 2.0
        else:
            self.rttvar = (1 - RTO_BETA) * self.rttvar + RTO_BETA * abs(self.srtt - r)
            self.srtt = (1 - RTO_ALPHA) * self.srtt + RTO_ALPHA * r
        varied = self.srtt + max(CLOCK_GRANULARITY, RTO_K * self.rttvar)
        self.rto = min(MAX_RTO, max(MIN_RTO, varied))

    def backoff(self):
        self.rto = min(MAX_RTO, self.rto * 2.0)


class CongestionController:
    """
    CUBIC (RFC 8312), counted in chunks rather than bytes.

    Slow start (cwnd < ssthresh): cwnd += 1 per new ACK.
    Congestion avoidance: W_cubic(t) = C*(t-K)^3 + W_max, with
        K = cbrt(W_max * (1-beta) / C).
    Each ACK moves cwnd toward max(W_cubic, W_est) by (target-cwnd)/cwnd,
    i.e. one full step per RTT. While cwnd sits above the curve the increase
    is the Reno-style 1/cwnd (TCP-friendly region, RFC 8312 §4.2).
    W_est(t) = W_max*beta + [3*(1-beta)/(1+beta)] * (t/RTT).

    Loss:
      * fast retransmit: ssthresh = cwnd*beta, cwnd = ssthresh (multiplicative decrease)
      * timeout:         ssthresh = cwnd*beta, cwnd = 1 (back to slow start)
    Fast convergence (RFC 8312 §4.6): if cwnd was still below the previous
    W_max, the new W_max is cwnd*(1+beta)/2 so a flow that overshot releases
    the extra bandwidth.
    """

    name = "cubic"

    def __init__(self):
        self.cwnd = INITIAL_CWND
        self.ssthresh = INITIAL_SSTHRESH
        self.w_max = 0.0
        self.k = 0.0
        self.epoch_start = None
        self.max_cwnd_seen = self.cwnd
        self.loss_events = 0
        self.timeouts = 0
        self.fast_retransmits = 0

    @property
    def state(self):
        if self.cwnd < self.ssthresh:
            return "slow_start"
        return "congestion_avoidance"

    def on_new_ack(self, now=None, rtt=None):
        now = time.time() if now is None else now
        if self.cwnd < self.ssthresh:
            self.cwnd += 1.0
        else:
            self._congestion_avoidance(now, rtt)
        if self.cwnd > WINDOW_SIZE:
            self.cwnd = float(WINDOW_SIZE)
        self.max_cwnd_seen = max(self.max_cwnd_seen, self.cwnd)

    def _ensure_epoch(self, now):
        if self.epoch_start is not None:
            return
        self.epoch_start = now
        if self.w_max <= 0:
            self.w_max = self.cwnd
            self.k = math.cbrt(self.w_max * (1.0 - CUBIC_BETA) / CUBIC_C)

    def _congestion_avoidance(self, now, rtt):
        self._ensure_epoch(now)
        t = max(0.0, now - self.epoch_start)
        w_cubic = CUBIC_C * ((t - self.k) ** 3) + self.w_max
        rtt = rtt if rtt and rtt > 0 else 0.1
        friendly = (3.0 * (1.0 - CUBIC_BETA)) / (1.0 + CUBIC_BETA)
        w_est = self.w_max * CUBIC_BETA + friendly * (t / rtt)
        target = max(w_cubic, w_est)
        if target > self.cwnd:
            self.cwnd += min(1.0, (target - self.cwnd) / self.cwnd)
        else:
            self.cwnd += 1.0 / self.cwnd

    def on_fast_retransmit(self, now=None):
        self._react_to_loss(time.time() if now is None else now, timeout=False)

    def on_timeout(self, now=None):
        self._react_to_loss(time.time() if now is None else now, timeout=True)

    def _react_to_loss(self, now, timeout):
        if self.w_max > 0 and self.cwnd < self.w_max:
            self.w_max = self.cwnd * (1.0 + CUBIC_BETA) / 2.0
        else:
            self.w_max = self.cwnd
        self.ssthresh = max(self.cwnd * CUBIC_BETA, MIN_SSTHRESH)
        self.k = math.cbrt(max(self.w_max, 1e-9) * (1.0 - CUBIC_BETA) / CUBIC_C)
        self.epoch_start = now
        if timeout:
            self.cwnd = 1.0
            self.timeouts += 1
        else:
            self.cwnd = self.ssthresh
            self.fast_retransmits += 1
        self.loss_events += 1
        self.max_cwnd_seen = max(self.max_cwnd_seen, self.cwnd)

    def window(self):
        """Chunks allowed in flight: min(floor(cwnd), flow-control cap), at least 1."""
        return max(1, min(int(self.cwnd), WINDOW_SIZE))


class BbrLite:
    """
    Optional BBR-style controller. Not full BBR (no pacing-gain cycle, no ProbeRTT).

    The window tracks the measured bandwidth-delay product instead of AIMD:
        BDP  = delivery_rate * min_rtt          (chunks)
        cwnd = gain * BDP
    Startup uses gain 2 until the delivery rate stops climbing, then gain 1.
    A fast retransmit does not multiply the window down (that is the point of
    BBR relative to CUBIC). A timeout drops the window back to the initial
    value because the rate estimate is no longer believable.
    """

    name = "bbr"
    STARTUP_GAIN = 2.0
    CRUISE_GAIN = 1.0

    def __init__(self):
        self.cwnd = float(INITIAL_CWND)
        self.ssthresh = None
        self.min_rtt = None
        self.max_bw = 0.0
        self.mode = "startup"
        self.max_cwnd_seen = self.cwnd
        self.loss_events = 0
        self.timeouts = 0
        self.fast_retransmits = 0
        self._delivered = 0
        self._window_start = None
        self._plateau = 0

    @property
    def state(self):
        return self.mode

    def on_new_ack(self, now=None, rtt=None):
        now = time.time() if now is None else now
        self._delivered += 1
        if rtt is not None and rtt > 0:
            self.min_rtt = rtt if self.min_rtt is None else min(self.min_rtt, rtt)
        if self._window_start is None:
            self._window_start = now
        elapsed = now - self._window_start
        if elapsed >= 0.05 and self.min_rtt:
            bw = self._delivered / elapsed
            if bw > self.max_bw * 1.25:
                self.max_bw = bw
                self._plateau = 0
            elif bw > self.max_bw:
                self.max_bw = bw
            else:
                self._plateau += 1
                if self.mode == "startup" and self._plateau >= 3:
                    self.mode = "probe_bw"
            self._delivered = 0
            self._window_start = now
        if self.max_bw > 0 and self.min_rtt:
            gain = self.STARTUP_GAIN if self.mode == "startup" else self.CRUISE_GAIN
            self.cwnd = max(float(INITIAL_CWND), gain * self.max_bw * self.min_rtt)
        if self.cwnd > WINDOW_SIZE:
            self.cwnd = float(WINDOW_SIZE)
        self.max_cwnd_seen = max(self.max_cwnd_seen, self.cwnd)

    def on_fast_retransmit(self, now=None):
        self.loss_events += 1
        self.fast_retransmits += 1
        self.mode = "probe_bw"

    def on_timeout(self, now=None):
        self.loss_events += 1
        self.timeouts += 1
        self.mode = "probe_bw"
        self.cwnd = float(INITIAL_CWND)
        self.max_bw = 0.0

    def window(self):
        return max(1, min(int(self.cwnd), WINDOW_SIZE))


def make_controller(name):
    if name in (None, "", "cubic"):
        return CongestionController()
    if name == "bbr":
        return BbrLite()
    raise ValueError(f"Unknown congestion controller '{name}'")


class StreamSender:
    """Selective Repeat sender with an adaptive RTO and a congestion window."""

    def __init__(self, sock, target_addr, stream_id, raw_data, encrypt=True, on_progress=None,
                 crypto=None, fallback_addr=None, on_fallback=None, congestion="cubic"):
        self.sock = sock
        self.target_addr = target_addr
        self.stream_id = stream_id
        self.on_progress = on_progress
        self.crypto = crypto or default_crypto
        self.fallback_addr = fallback_addr
        self.on_fallback = on_fallback
        self.via_relay = False

        parts = [raw_data[i:i + CHUNK_PAYLOAD_SIZE] for i in range(0, max(1, len(raw_data)), CHUNK_PAYLOAD_SIZE)]
        self.total_chunks = len(parts)
        self.chunks = []
        for idx, part in enumerate(parts):
            if encrypt:
                aad = chunk_aad(stream_id, idx, self.total_chunks)
                self.chunks.append((self.crypto.encrypt(part, aad), FLAG_ENCRYPTED))
            else:
                self.chunks.append((part, FLAG_NONE))

        self.base = 0
        self.next_seq = 0
        self.acked = set()
        self.send_times = {}
        self.retransmit_counts = {}
        self.lock = threading.RLock()
        self.running = True
        self.finished = False
        self.failed = False
        self.closed = False
        self.aborted = False

        self.rtt = RttEstimator()
        self.cc = make_controller(congestion)
        self.dup_acks = 0
        self.recovery_point = -1
        self.fast_retx_pending = False
        self.start_time = None
        self.first_ack_time = None

    def cancel(self):
        """Stop sending and tell the peer to drop partial data (FIN + ABORT)."""
        with self.lock:
            if self.finished or self.aborted:
                self.running = False
                return
            self.running = False
            self.aborted = True
        self._send_raw(UDPPacket(TYPE_FIN, self.stream_id, self.total_chunks, self.total_chunks, flags=FLAG_ABORT))

    def handle_ack(self, ack_idx, flags=FLAG_NONE):
        """Record an ACK: RTT sample (Karn), congestion window, advance base."""
        progress = None
        with self.lock:
            if flags & FLAG_FIN:
                self.closed = True
                return
            if self.first_ack_time is None:
                self.first_ack_time = time.time()
            if ack_idx in self.acked or not (0 <= ack_idx < self.total_chunks):
                return
            self.acked.add(ack_idx)

            sample = None
            if self.retransmit_counts.get(ack_idx, 0) == 0 and ack_idx in self.send_times:
                sample = time.time() - self.send_times[ack_idx]
                self.rtt.add_sample(sample)
            self.cc.on_new_ack(rtt=sample if sample is not None else self.rtt.srtt)

            if ack_idx > self.base and self.base not in self.acked:
                # Later data arrived while `base` is still missing: same signal as a dup ACK.
                self.dup_acks += 1
                if self.dup_acks == DUP_ACK_THRESHOLD and self.base > self.recovery_point:
                    self.cc.on_fast_retransmit()
                    self.recovery_point = self.next_seq - 1
                    self.fast_retx_pending = True

            old_base = self.base
            while self.base in self.acked and self.base < self.total_chunks:
                self.base += 1
            if self.base != old_base:
                self.dup_acks = 0

            if len(self.acked) >= self.total_chunks:
                self.finished = True
            if self.on_progress:
                pct = (len(self.acked) / self.total_chunks) * 100.0
                progress = (len(self.acked), self.total_chunks, pct)
        if progress and self.on_progress:
            try:
                self.on_progress(*progress)
            except Exception:
                pass

    def _send_raw(self, pkt):
        try:
            self.sock.sendto(pkt.encode(), self.target_addr)
        except Exception:
            pass

    def _switch_to_relay_locked(self):
        """Direct path produced no ACK (NAT, firewall). Resend through the server."""
        self.target_addr = self.fallback_addr
        self.via_relay = True
        self.next_seq = self.base
        self.retransmit_counts.clear()
        self.send_times.clear()
        self.dup_acks = 0
        self.fast_retx_pending = False
        self.recovery_point = -1
        self.rtt = RttEstimator()
        self.cc = make_controller(self.cc.name)
        self.start_time = time.time()

    def send_loop(self):
        """Send within the congestion window, retransmit losses, then close with FIN."""
        self.start_time = time.time()
        while self.running and not self.finished and not self.failed:
            now = time.time()
            to_send = []
            switched = False
            with self.lock:
                if (self.fallback_addr and not self.via_relay and self.first_ack_time is None
                        and self.start_time is not None and now - self.start_time > DIRECT_PROBE_TIMEOUT):
                    self._switch_to_relay_locked()
                    switched = True

                if self.fast_retx_pending:
                    self.fast_retx_pending = False
                    if self.base < self.total_chunks and self.base not in self.acked:
                        self._mark_retransmit(self.base, now, to_send)

                timed_out = []
                rto = self.rtt.rto
                for idx in range(self.base, min(self.next_seq, self.total_chunks)):
                    if idx not in self.acked and idx not in to_send and (now - self.send_times.get(idx, 0) > rto):
                        timed_out.append(idx)
                if timed_out:
                    if self.base > self.recovery_point:
                        self.cc.on_timeout(now)
                        self.rtt.backoff()
                        self.recovery_point = self.next_seq - 1
                    allowed = self.cc.window()
                    for idx in timed_out[:allowed]:
                        if not self._mark_retransmit(idx, now, to_send):
                            break
                    for idx in timed_out[allowed:]:
                        # Not sent this round; become eligible again in half an RTO.
                        self.send_times[idx] = now - self.rtt.rto / 2.0

                in_flight = sum(1 for i in range(self.base, self.next_seq) if i not in self.acked)
                while (self.next_seq < self.total_chunks and in_flight < self.cc.window()
                       and self.next_seq < self.base + WINDOW_SIZE):
                    to_send.append(self.next_seq)
                    self.send_times[self.next_seq] = now
                    self.next_seq += 1
                    in_flight += 1

            if switched and self.on_fallback:
                try:
                    self.on_fallback()
                except Exception:
                    pass
            for idx in to_send:
                payload, flags = self.chunks[idx]
                self._send_raw(UDPPacket(TYPE_DATA, self.stream_id, idx, self.total_chunks, payload, flags))
            time.sleep(0.001 if to_send else 0.005)

        if self.failed and not self.aborted:
            self.aborted = True
            self._send_raw(UDPPacket(TYPE_FIN, self.stream_id, self.total_chunks, self.total_chunks, flags=FLAG_ABORT))
        elif self.finished and not self.aborted:
            self._fin_handshake()
        self.running = False

    def _mark_retransmit(self, idx, now, to_send):
        retries = self.retransmit_counts.get(idx, 0) + 1
        if retries > MAX_CHUNK_RETRANSMITS:
            self.failed = True
            self.running = False
            return False
        self.retransmit_counts[idx] = retries
        self.send_times[idx] = now
        to_send.append(idx)
        return True

    def _fin_handshake(self):
        """Send FIN (type 3) until the receiver answers with ACK+FLAG_FIN."""
        interval = max(MIN_RTO, min(self.rtt.rto, 0.3))
        for _ in range(FIN_MAX_RETRIES):
            if self.closed or self.aborted or not self.running:
                break
            self._send_raw(UDPPacket(TYPE_FIN, self.stream_id, self.total_chunks, self.total_chunks))
            deadline = time.time() + interval
            while time.time() < deadline and not self.closed and self.running:
                time.sleep(0.005)

    def stats(self):
        with self.lock:
            ssthresh = getattr(self.cc, "ssthresh", None)
            if ssthresh is None or ssthresh == float("inf"):
                ssthresh_out = None
            else:
                ssthresh_out = round(ssthresh, 2)
            return {
                "algorithm": self.cc.name,
                "cwnd": round(self.cc.cwnd, 2),
                "ssthresh": ssthresh_out,
                "state": self.cc.state,
                "rto_ms": round(self.rtt.rto * 1000, 1),
                "srtt_ms": None if self.rtt.srtt is None else round(self.rtt.srtt * 1000, 2),
                "loss_events": self.cc.loss_events,
                "via_relay": self.via_relay,
            }


class StreamReceiver:
    """Buffers out-of-order chunks, checks the GCM tag, and reassembles the file."""

    def __init__(self, stream_id, total_chunks, on_progress=None, crypto=None):
        self.stream_id = stream_id
        self.total_chunks = total_chunks
        self.received_chunks = {}
        self.on_progress = on_progress
        self.crypto = crypto or default_crypto
        self.lock = threading.RLock()
        self.fin_received = False
        self.aborted = False

    def has_chunk(self, chunk_idx):
        with self.lock:
            return chunk_idx in self.received_chunks

    def put_chunk(self, chunk_idx, payload, is_encrypted):
        """Store one chunk. Returns False on duplicate, out-of-range, or bad tag."""
        with self.lock:
            if chunk_idx in self.received_chunks or not (0 <= chunk_idx < self.total_chunks):
                return False
            try:
                if is_encrypted:
                    data = self.crypto.decrypt(payload, chunk_aad(self.stream_id, chunk_idx, self.total_chunks))
                else:
                    data = payload
            except Exception:
                return False
            self.received_chunks[chunk_idx] = data
            progress = None
            if self.on_progress:
                pct = (len(self.received_chunks) / self.total_chunks) * 100.0
                progress = (len(self.received_chunks), self.total_chunks, pct)
        if progress and self.on_progress:
            try:
                self.on_progress(*progress)
            except Exception:
                pass
        return True

    def is_complete(self):
        with self.lock:
            return len(self.received_chunks) >= self.total_chunks

    def reassemble(self):
        with self.lock:
            if len(self.received_chunks) < self.total_chunks:
                raise ValueError("Stream incomplete: missing chunks")
            file_data = bytearray()
            for i in range(self.total_chunks):
                file_data.extend(self.received_chunks[i])
            return bytes(file_data)
