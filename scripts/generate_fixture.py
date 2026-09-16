#!/usr/bin/env python3
"""Generate a deterministic, checksum-valid Ethernet/IPv4/TCP HTTP fixture."""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "pcaps" / "http_fixture.pcap"
CLIENT_IP = ipaddress.IPv4Address("10.10.1.2").packed
SERVER_IP = ipaddress.IPv4Address("10.10.1.3").packed
CLIENT_PORT = 45123
SERVER_PORT = 8080
NOISE_CLIENT_IP = ipaddress.IPv4Address("10.10.2.2").packed
NOISE_SERVER_IP = ipaddress.IPv4Address("10.10.2.3").packed
NOISE_CLIENT_PORT = 46123
NOISE_SERVER_PORT = 9999
LIVE_CLIENT_IP = ipaddress.IPv4Address("10.10.3.2").packed
LIVE_SERVER_IP = ipaddress.IPv4Address("10.10.3.3").packed
LIVE_CLIENT_PORT = 47123
LIVE_SERVER_PORT = 8080
SRC_MAC = bytes.fromhex("020000000001")
DST_MAC = bytes.fromhex("020000000002")


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_frame(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int,
              seq: int, ack: int, flags: int, payload: bytes, ident: int) -> bytes:
    tcp = struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port, seq, ack, 5 << 4, flags, 65535, 0, 0,
    ) + payload
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp))
    tcp_sum = checksum(pseudo + tcp)
    tcp = tcp[:16] + struct.pack("!H", tcp_sum) + tcp[18:]

    total_len = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len, ident, 0x4000, 64, 6, 0, src_ip, dst_ip,
    )
    ip_sum = checksum(ip)
    ip = ip[:10] + struct.pack("!H", ip_sum) + ip[12:]
    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + ip + tcp


def main() -> None:
    request = (
        b"POST /submit HTTP/1.1\r\n"
        b"Host: service.local\r\n"
        b"User-Agent: python-requests/2.32\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 13\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"FLAG{fixture}"
    )
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"OK"
    )

    # Split inside the User-Agent header to exercise TCP/HTTP streaming reassembly.
    split = request.index(b"User-Agent") + len(b"User-Ag")
    req_a, req_b = request[:split], request[split:]

    cseq = 1000
    sseq = 5000
    packets: list[bytes] = []
    packets.append(tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, cseq, 0, 0x02, b"", 1))
    packets.append(tcp_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, sseq, cseq + 1, 0x12, b"", 2))
    cseq += 1
    sseq += 1
    packets.append(tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x18, req_a, 3))
    cseq += len(req_a)
    packets.append(tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x18, req_b, 4))
    cseq += len(req_b)
    packets.append(tcp_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, sseq, cseq, 0x18, response, 5))
    sseq += len(response)
    packets.append(tcp_frame(CLIENT_IP, SERVER_IP, CLIENT_PORT, SERVER_PORT, cseq, sseq, 0x11, b"", 6))
    cseq += 1
    packets.append(tcp_frame(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, sseq, cseq, 0x11, b"", 7))

    # Unconfigured-port noise. The smoke test configures only 8080 and asserts
    # that this payload on 9999 never reaches flow/storage/UI.
    noise_seq = 9000
    noise_payload = b"GET /noise HTTP/1.1\r\nHost: noise.local\r\nUser-Agent: curl/9.0\r\n\r\n"
    packets.append(tcp_frame(NOISE_CLIENT_IP, NOISE_SERVER_IP, NOISE_CLIENT_PORT, NOISE_SERVER_PORT, noise_seq, 0, 0x02, b"", 8))
    noise_seq += 1
    packets.append(tcp_frame(NOISE_CLIENT_IP, NOISE_SERVER_IP, NOISE_CLIENT_PORT, NOISE_SERVER_PORT, noise_seq, 0, 0x1C, noise_payload, 9))

    # Long-lived configured-port flow: payload is present, but no FIN/RST is
    # emitted. It must become visible through live snapshots without waiting for
    # idle timeout or application shutdown.
    live_seq = 12000
    live_payload = b"GET /live HTTP/1.1\r\nHost: live.local\r\nUser-Agent: live-agent/1.0\r\n\r\n"
    packets.append(tcp_frame(LIVE_CLIENT_IP, LIVE_SERVER_IP, LIVE_CLIENT_PORT, LIVE_SERVER_PORT, live_seq, 0, 0x02, b"", 10))
    live_seq += 1
    packets.append(tcp_frame(LIVE_CLIENT_IP, LIVE_SERVER_IP, LIVE_CLIENT_PORT, LIVE_SERVER_PORT, live_seq, 0, 0x18, live_payload, 11))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    # Classic little-endian pcap, microsecond timestamps, Ethernet linktype.
    with OUT.open("wb") as f:
        f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        base = 1_700_000_000
        for i, packet in enumerate(packets):
            f.write(struct.pack("<IIII", base, i * 1_000, len(packet), len(packet)))
            f.write(packet)

    print(f"wrote {OUT} ({len(packets)} packets, {OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
