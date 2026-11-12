"""
CO3093 - Custom Binary TCP Application Framing Protocol.
Fixed 20-byte Header: Magic (2B) | Ver (1B) | Type (1B) | Flags (1B) | Reserved (3B) | Seq (4B) | Length (4B) | CRC32 (4B)
"""

import struct
import zlib
import enum
import json

MAGIC = 0x4353  # 'CS' (Collaboration Streaming)
PROTOCOL_VERSION = 1
MAX_PACKET_PAYLOAD = 10 * 1024 * 1024  # 10 MB maximum for TCP signaling

HEADER_FORMAT = "!HBBB3sIII"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
assert HEADER_SIZE == 20


class MsgType(enum.IntEnum):
    # Handshake & Authentication (Steps 2 & 3)
    HANDSHAKE_REQ = 1
    HANDSHAKE_ACK = 2
    AUTH_LOGIN = 3
    AUTH_SUCCESS = 4
    AUTH_FAILURE = 5
    DISCONNECT = 6
    AUTH_REGISTER = 7      # Create an account (username + password) and log in

    # State Management & Heartbeat (Steps 3 & 7)
    USER_JOINED = 12
    USER_LEFT = 13
    HEARTBEAT_PING = 14
    HEARTBEAT_PONG = 15

    # Streaming Messaging (Step 5)
    MSG_BROADCAST = 20
    MSG_UNICAST = 21
    MSG_DELIVERY_ACK = 22

    # UDP File Transfer Signaling (Step 6)
    FILE_ANNOUNCE = 30


class PacketFlags:
    NONE = 0x00
    ENCRYPTED = 0x01


class Packet:
    """Binary TCP packet with a fixed 20-byte header and payload."""
    def __init__(self, msg_type, payload=b"", seq=0, flags=PacketFlags.NONE):
        self.magic = MAGIC
        self.version = PROTOCOL_VERSION
        self.msg_type = MsgType(msg_type)
        self.flags = flags
        self.seq = seq
        self.payload = payload
        self.checksum = zlib.crc32(payload) & 0xFFFFFFFF

    def encode(self):
        """Serialize header and payload into bytes."""
        header_bytes = struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.version,
            int(self.msg_type),
            self.flags,
            b"\x00\x00\x00",
            self.seq,
            len(self.payload),
            self.checksum
        )
        return header_bytes + self.payload

    @classmethod
    def decode_header(cls, header_bytes):
        """Parse 20-byte header and validate protocol magic."""
        if len(header_bytes) < HEADER_SIZE:
            raise ValueError("Header bytes too short (< 20 bytes)")
        magic, ver, msg_type, flags, _, seq, length, checksum = struct.unpack(HEADER_FORMAT, header_bytes)
        if magic != MAGIC or ver != PROTOCOL_VERSION:
            raise ValueError(f"Invalid magic (0x{magic:04X}) or version ({ver})")
        if length > MAX_PACKET_PAYLOAD:
            raise ValueError(f"Payload length exceeds maximum allowed limit ({length} > {MAX_PACKET_PAYLOAD})")
        return {
            "magic": magic, "version": ver, "msg_type": MsgType(msg_type),
            "flags": flags, "seq": seq, "length": length, "checksum": checksum
        }

    @classmethod
    def from_bytes(cls, data):
        """Decode packet from raw bytes and verify CRC32."""
        h = cls.decode_header(data[:HEADER_SIZE])
        payload = data[HEADER_SIZE:HEADER_SIZE + h["length"]]
        if len(payload) != h["length"]:
            raise ValueError("Payload length mismatch")
        if (zlib.crc32(payload) & 0xFFFFFFFF) != h["checksum"]:
            raise ValueError("CRC32 checksum mismatch")
        return cls(h["msg_type"], payload=payload, seq=h["seq"], flags=h["flags"])

    @classmethod
    def json_payload(cls, msg_type, data_dict, seq=0, flags=PacketFlags.NONE):
        """Create a packet containing UTF-8 JSON payload."""
        json_bytes = json.dumps(data_dict, ensure_ascii=False).encode('utf-8')
        return cls(msg_type, payload=json_bytes, seq=seq, flags=flags)

    def to_json(self):
        """Deserialize payload bytes to dictionary."""
        return json.loads(self.payload.decode('utf-8'))


def recv_exact(sock, num_bytes):
    """Read exactly num_bytes from a TCP socket stream to prevent framing issues."""
    buffer = bytearray()
    while len(buffer) < num_bytes:
        chunk = sock.recv(num_bytes - len(buffer))
        if not chunk:
            raise ConnectionResetError("Remote socket connection closed unexpectedly")
        buffer.extend(chunk)
    return bytes(buffer)


def recv_packet(sock):
    """Read a complete packet: 20-byte header first, followed by payload with CRC32 check."""
    header_bytes = recv_exact(sock, HEADER_SIZE)
    h = Packet.decode_header(header_bytes)
    payload = recv_exact(sock, h["length"]) if h["length"] > 0 else b""
    if (zlib.crc32(payload) & 0xFFFFFFFF) != h["checksum"]:
        raise ValueError("CRC32 Checksum mismatch in received packet")
    return Packet(h["msg_type"], payload=payload, seq=h["seq"], flags=h["flags"])


def send_packet(sock, packet):
    """Send serialized packet over TCP socket."""
    sock.sendall(packet.encode())
