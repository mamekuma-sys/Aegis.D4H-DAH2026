from __future__ import annotations

import importlib.util
import struct
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TOOL_PATH = REPO_ROOT / "agents" / "defender" / "tools" / "replay_pcaps.py"
SPEC = importlib.util.spec_from_file_location("replay_pcaps", TOOL_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - repository failure
    raise RuntimeError("could not load PCAP replay tool")
replay_pcaps = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = replay_pcaps
SPEC.loader.exec_module(replay_pcaps)


def _tcp_packet(
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    sequence: int,
    payload: bytes,
) -> bytes:
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        sequence,
        0,
        5 << 4,
        0x18,
        65535,
        0,
        0,
    )
    total_length = 20 + len(tcp) + len(payload)
    ip = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        6,
        0,
        src_ip,
        dst_ip,
    )
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    return ethernet + ip + tcp + payload


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", index, 0, len(frame), len(frame)))
            handle.write(frame)


class TestPcapReplay(unittest.TestCase):
    def test_replays_real_policy_and_never_needs_a_committed_pcap(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        exploit = (
            b"GET /fetch?url=http://helper-box:8080/secret HTTP/1.1\r\n"
            b"Host: service\r\n\r\n"
        )
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n"
            + b"FLAG" + b"{synthetic-marker}"
        )
        normal = b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n"
        frames = [
            _tcp_packet(client, server, 40000, 8080, 100, exploit),
            _tcp_packet(server, client, 8080, 40000, 500, response),
            _tcp_packet(client, server, 40001, 8080, 1000, normal),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "synthetic.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-18T00:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(report["policy"]["drop_capable_rules"], 14)
        self.assertEqual(total["parsed_requests"], 2)
        self.assertEqual(total["exploit_shape_requests"], 1)
        self.assertEqual(total["blocked_exploit_shape_requests"], 1)
        self.assertEqual(total["passed_other_requests"], 1)
        self.assertEqual(total["unexpected_other_drops"], 0)
        self.assertEqual(total["flag_linked_requests"], 1)
        self.assertEqual(total["blocked_flag_linked_requests"], 1)
        self.assertEqual(report["layers"]["L1-HTTP-8080"]["exploit_shape_requests"], 1)
        self.assertEqual(report["layers"]["L2-HTTP-8082"]["parsed_requests"], 0)

    def test_reports_packet_coalescing_separately_from_unexpected_drops(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        payload = (
            b"GET /fetch?url=http://helper-box:8080/secret HTTP/1.1\r\n"
            b"Host: service\r\n\r\n"
            b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "coalesced.pcap"
            _write_pcap(pcap, [_tcp_packet(client, server, 40000, 8082, 100, payload)])
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-18T00:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["parsed_requests"], 2)
        self.assertEqual(total["coalesced_other_requests"], 1)
        self.assertEqual(total["unexpected_other_drops"], 0)

    def test_real_hot_policy_still_blocks_a_split_header(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        first = b"GET /fetch?url=http://helper-"
        second = b"box:8080/secret HTTP/1.1\r\nHost: service\r\n\r\n"
        frames = [
            _tcp_packet(client, server, 40000, 8082, 100, first),
            _tcp_packet(client, server, 40000, 8082, 100 + len(first), second),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "split.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-18T00:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["parsed_requests"], 1)
        self.assertEqual(total["blocked_exploit_shape_requests"], 1)
        self.assertEqual(total["dropped_packets"], 1)
        self.assertEqual(total["drops_without_complete_request"], 0)

    def test_links_a_split_graphql_body_drop_to_its_flag_response(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        body = b'{"query":"{ missionAudit { lastDeployment { notes } } }"}'
        header = (
            b"POST /graphql HTTP/1.1\r\n"
            b"Host: service\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        )
        first = header + body[:12]
        second = body[12:]
        response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n"
            + b"FLAG" + b"{synthetic-marker}"
        )
        frames = [
            _tcp_packet(client, server, 40000, 8082, 100, first),
            _tcp_packet(client, server, 40000, 8082, 100 + len(first), second),
            _tcp_packet(server, client, 8082, 40000, 500, response),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "split-graphql.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-18T00:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["exploit_shape_requests"], 1)
        self.assertEqual(total["blocked_exploit_shape_requests"], 1)
        self.assertEqual(total["flag_linked_requests"], 1)
        self.assertEqual(total["blocked_flag_linked_requests"], 1)

    def test_rejects_pcapng_and_unsafe_lengths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid = Path(temp_dir) / "invalid.pcap"
            invalid.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
            with self.assertRaises(replay_pcaps.PcapFormatError):
                tuple(replay_pcaps.iter_pcap_frames(invalid))


if __name__ == "__main__":
    unittest.main()
