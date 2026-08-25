#!/usr/bin/env python3
"""Emit the packet BPF_PROG_TEST_RUN is fed.

    mkpkt.py <out|-> [total_len] [source_port]

The IPv4 checksum is computed rather than written down: a hand-typed constant
that happens to be wrong makes the kernel drop the frame in a way that looks
like a program bug for an hour.
"""

import struct
import sys

SRC_MAC = bytes.fromhex("020000000002")
DST_MAC = bytes.fromhex("020000000001")
SRC_IP = bytes([10, 90, 1, 2])
DST_IP = bytes([10, 90, 1, 1])
SRC_PORT = 12345
DST_PORT = 19000
TOTAL_LEN = 64


def checksum(header: bytes) -> int:
    total = sum(struct.unpack(f">{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp_frame(total_len: int, sport: int = SRC_PORT) -> bytes:
    """The source port is a parameter because the bucket bench indexes its bank by it:
    two frames differing only in source port are two frames aiming at two buckets, which
    is how a contention measurement chooses between one cache line and several."""
    payload_len = total_len - 14 - 20 - 8
    if payload_len < 0:
        raise SystemExit(f"{total_len} bytes cannot hold an Ethernet, IPv4 and UDP header")

    udp = struct.pack(">HHHH", sport, DST_PORT, 8 + payload_len, 0) + bytes(payload_len)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0) + SRC_IP + DST_IP
    ip = ip[:10] + struct.pack(">H", checksum(ip)) + ip[12:]
    frame = DST_MAC + SRC_MAC + struct.pack(">H", 0x0800) + ip + udp

    assert len(frame) == total_len, f"{len(frame)} bytes, expected {total_len}"
    assert checksum(ip) == 0 or checksum(frame[14:34]) == 0, "the header does not verify"
    return frame


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "-"
    size = int(sys.argv[2]) if len(sys.argv) > 2 else TOTAL_LEN
    sport = int(sys.argv[3]) if len(sys.argv) > 3 else SRC_PORT
    frame = udp_frame(size, sport)
    if out == "-":
        sys.stdout.buffer.write(frame)
    else:
        with open(out, "wb") as fh:
            fh.write(frame)
