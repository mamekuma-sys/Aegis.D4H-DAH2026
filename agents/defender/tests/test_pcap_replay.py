from __future__ import annotations

import gzip
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
    flags: int = 0x18,
) -> bytes:
    tcp = struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        sequence,
        0,
        5 << 4,
        flags,
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
    def test_replays_split_egress_flag_as_one_blocked_marker(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        request = b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n"
        first = b"HTTP/1.1 200 OK\r\n\r\nFLAG{f754c99511e9caa2"
        second = b"6226bc372215084b}"
        frames = [
            _tcp_packet(client, server, 40000, 8080, 100, request),
            _tcp_packet(server, client, 8080, 40000, 500, first),
            _tcp_packet(server, client, 8080, 40000, 500 + len(first), second),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "split-egress.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T07:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["egress_packets"], 2)
        self.assertEqual(total["egress_flag_packets"], 1)
        self.assertEqual(total["blocked_egress_flag_packets"], 1)
        self.assertEqual(total["unexpected_egress_drops"], 0)
        self.assertEqual(total["flag_linked_labels"], {"unclassified": 1})

    def test_replays_egress_flag_verdicts_without_dropping_normal_responses(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        normal_request = b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n"
        flag_response = (
            b"HTTP/1.1 200 OK\r\n\r\n"
            b"FLAG{f754c99511e9caa26226bc372215084b}"
        )
        normal_response = b"HTTP/1.1 200 OK\r\n\r\nhealthy"
        frames = [
            _tcp_packet(client, server, 40000, 8080, 100, normal_request),
            _tcp_packet(server, client, 8080, 40000, 500, flag_response),
            _tcp_packet(client, server, 40001, 8080, 1000, normal_request),
            _tcp_packet(server, client, 8080, 40001, 1500, normal_response),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "egress.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T07:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["egress_packets"], 2)
        self.assertEqual(total["egress_flag_packets"], 1)
        self.assertEqual(total["blocked_egress_flag_packets"], 1)
        self.assertEqual(total["unexpected_egress_drops"], 0)

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
        self.assertEqual(report["policy"]["drop_capable_rules"], 40)
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

    def test_portal_feedback_requires_observed_service_id_query(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        exploit = (
            b"GET /portal/feedback?service_id=vulncheck HTTP/1.1\r\n"
            b"Host: service\r\n\r\n"
        )
        normal = b"GET /portal/feedback HTTP/1.1\r\nHost: service\r\n\r\n"
        frames = [
            _tcp_packet(client, server, 40000, 8080, 100, exploit),
            _tcp_packet(client, server, 40001, 8080, 200, normal),
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "portal-feedback.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T02:50:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["exploit_shape_requests"], 1)
        self.assertEqual(total["blocked_exploit_shape_requests"], 1)
        self.assertEqual(total["passed_other_requests"], 1)
        self.assertEqual(total["unexpected_other_drops"], 0)

    def test_semantic_graphql_rsc_and_ws_are_labeled_as_observed_shapes(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        bodies = (
            (
                b"POST /%67%72%61%70%68%71%6C HTTP/1.1\r\n",
                b'{"query":"{ missionAudit { lastDeployment { notes } } }"}',
            ),
            (
                b"POST /api/rsc-action HTTP/1.1\r\n",
                b'{"ref":"cHJvY2Vzcy5lbnYuTUMyX0lOVEVSTkFMX0FQSV9UT0tFTg==","token":"fresh"}',
            ),
        )
        frames = []
        for index, (line, body) in enumerate(bodies):
            request = (
                line + b"Host: service\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
            )
            frames.append(_tcp_packet(
                client, server, 41000 + index, 8082, 100, request
            ))
        frames.append(_tcp_packet(
            client, server, 41002, 8082, 100,
            b"GET /ws/mission-feed HTTP/1.1\r\nHost: service\r\n"
            b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        ))
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "semantic-l2.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap], REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T05:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["exploit_shape_requests"], 3)
        self.assertEqual(total["blocked_exploit_shape_requests"], 3)
        self.assertEqual(total["unexpected_other_drops"], 0)

    def test_discovers_and_replays_gzip_compressed_pcap(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        frame = _tcp_packet(
            client,
            server,
            40000,
            8080,
            100,
            b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            plain = root / "capture.pcap"
            compressed = root / "capture.pcap.gz"
            _write_pcap(plain, [frame])
            with plain.open("rb") as source, gzip.open(compressed, "wb") as target:
                target.write(source.read())
            plain.unlink()

            paths = replay_pcaps.discover_pcaps([str(root)])
            report = replay_pcaps.replay_paths(
                paths,
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T02:50:00Z"),
            ).to_dict()

        self.assertEqual(paths, [compressed])
        self.assertEqual(report["files"], 1)
        self.assertEqual(report["total"]["parsed_requests"], 1)

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

    def test_early_segment_drop_is_attributed_to_completed_request(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        first = (
            b"GET /svc/flag-12345678-1234-1234-1234-123456789abc HTTP/1.1\r\n"
        )
        second = b"Host: service\r\n\r\n"
        frames = [
            _tcp_packet(client, server, 42000, 8080, 100, first),
            _tcp_packet(client, server, 42000, 8080, 100 + len(first), second),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "early-drop.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap], REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T07:00:00Z"),
            ).to_dict()

        total = report["total"]
        self.assertEqual(total["exploit_shape_requests"], 1)
        self.assertEqual(total["blocked_exploit_shape_requests"], 1)
        self.assertEqual(total["drops_without_complete_request"], 1)
        self.assertEqual(total["unexpected_other_drops"], 0)

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

    def test_new_syn_prevents_flag_link_across_reused_four_tuple(self):
        client = b"\x0a\x01\x00\x04"
        server = b"\x0a\x01\x01\x02"
        old_request = b"GET /health HTTP/1.1\r\nHost: service\r\n\r\n"
        unrelated_response = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 24\r\n\r\n"
            + b"FLAG" + b"{synthetic-marker}"
        )
        frames = [
            _tcp_packet(client, server, 40000, 8082, 100, old_request),
            _tcp_packet(client, server, 40000, 8082, 5000, b"", flags=0x02),
            _tcp_packet(server, client, 8082, 40000, 7000, unrelated_response),
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            pcap = Path(temp_dir) / "tuple-reuse.pcap"
            _write_pcap(pcap, frames)
            report = replay_pcaps.replay_paths(
                [pcap],
                REPO_ROOT / "agents" / "defender" / "policy",
                replay_pcaps.parse_as_of("2026-08-21T02:50:00Z"),
            ).to_dict()

        self.assertEqual(report["total"]["parsed_requests"], 1)
        self.assertEqual(report["total"]["flag_linked_requests"], 0)

    def test_rejects_pcapng_and_unsafe_lengths(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid = Path(temp_dir) / "invalid.pcap"
            invalid.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
            with self.assertRaises(replay_pcaps.PcapFormatError):
                tuple(replay_pcaps.iter_pcap_frames(invalid))


if __name__ == "__main__":
    unittest.main()
