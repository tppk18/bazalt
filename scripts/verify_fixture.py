#!/usr/bin/env python3
"""Verify the bundled PCAP fixture without third-party dependencies."""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PCAP = ROOT / "pcaps" / "http_fixture.pcap"


def checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    words = struct.unpack(f"!{len(data)//2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse() -> list[dict]:
    data = PCAP.read_bytes()
    if len(data) < 24:
        raise AssertionError("pcap header truncated")
    magic = data[:4]
    if magic != b"\xd4\xc3\xb2\xa1":
        raise AssertionError(f"unexpected pcap magic {magic.hex()}")
    _, major, minor, _, _, snaplen, linktype = struct.unpack_from("<IHHIIII", data, 0)
    assert (major, minor, linktype) == (2, 4, 1)
    assert snaplen >= 1500

    packets: list[dict] = []
    off = 24
    while off < len(data):
        if off + 16 > len(data):
            raise AssertionError("truncated pcap packet header")
        ts_sec, ts_usec, caplen, wirelen = struct.unpack_from("<IIII", data, off)
        off += 16
        frame = data[off:off + caplen]
        off += caplen
        assert len(frame) == caplen == wirelen
        assert len(frame) >= 14 + 20 + 20
        assert frame[12:14] == b"\x08\x00"

        ip = frame[14:]
        ihl = (ip[0] & 0x0F) * 4
        total_len = struct.unpack_from("!H", ip, 2)[0]
        assert checksum(ip[:ihl]) == 0, "bad IPv4 checksum"
        assert ip[9] == 6
        src = ipaddress.IPv4Address(ip[12:16])
        dst = ipaddress.IPv4Address(ip[16:20])

        tcp = ip[ihl:total_len]
        sport, dport, seq, ack = struct.unpack_from("!HHII", tcp, 0)
        data_off = (tcp[12] >> 4) * 4
        flags = tcp[13]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        assert checksum(pseudo + tcp) == 0, "bad TCP checksum"
        payload = tcp[data_off:]
        packets.append({
            "ts": ts_sec * 1_000_000 + ts_usec,
            "src": str(src), "dst": str(dst),
            "sport": sport, "dport": dport,
            "seq": seq, "ack": ack, "flags": flags,
            "payload": payload,
        })
    assert off == len(data)
    return packets


def reassemble(packets: list[dict], src: str, dst: str) -> bytes:
    data_packets = [p for p in packets if p["src"] == src and p["dst"] == dst and p["payload"]]
    data_packets.sort(key=lambda p: p["seq"])
    out = bytearray()
    expected = None
    for p in data_packets:
        seq = p["seq"]
        payload = p["payload"]
        if expected is None:
            expected = seq
        if seq < expected:
            overlap = expected - seq
            payload = payload[overlap:]
            seq = expected
        assert seq == expected, f"gap in fixture stream: expected {expected}, got {seq}"
        out.extend(payload)
        expected += len(payload)
    return bytes(out)


def main() -> None:
    packets = parse()
    assert len(packets) == 11, len(packets)
    assert sum(bool(p["flags"] & 0x02) for p in packets) == 4

    client_payload_packets = [p for p in packets if p["src"] == "10.10.1.2" and p["payload"]]
    assert len(client_payload_packets) == 2, "request should span two TCP payloads"
    assert b"User-Ag" in client_payload_packets[0]["payload"]
    assert b"ent: python-requests/2.32" in client_payload_packets[1]["payload"]

    request = reassemble(packets, "10.10.1.2", "10.10.1.3")
    response = reassemble(packets, "10.10.1.3", "10.10.1.2")
    assert request.startswith(b"POST /submit HTTP/1.1\r\n")
    assert b"User-Agent: python-requests/2.32\r\n" in request
    assert request.endswith(b"FLAG{fixture}")
    assert b"Content-Length: 13\r\n" in request
    assert response.startswith(b"HTTP/1.1 200 OK\r\n") and response.endswith(b"OK")
    noise = reassemble(packets, "10.10.2.2", "10.10.2.3")
    assert b"Host: noise.local" in noise and any(p["dport"] == 9999 for p in packets)
    live = reassemble(packets, "10.10.3.2", "10.10.3.3")
    assert b"User-Agent: live-agent/1.0" in live
    live_packets = [p for p in packets if p["src"] == "10.10.3.2" and p["dst"] == "10.10.3.3"]
    assert all((p["flags"] & 0x05) == 0 for p in live_packets), "live fixture must not FIN/RST"
    print(f"FIXTURE PASS: {len(packets)} checksum-valid packets; split UA + historical flag + port-filter noise + open live flow verified")


if __name__ == "__main__":
    main()
