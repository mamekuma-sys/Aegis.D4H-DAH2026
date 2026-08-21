#!/usr/bin/env python3
"""Replay raw Ethernet PCAPs through the real defender hot policy.

The report contains aggregate counters only. Packet payloads, addresses, cookies,
and flag values are never emitted. The observed-shape labels are deliberately kept
separate from policy rule IDs so that unexpected drops remain visible.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator


REPO_ROOT = Path(__file__).resolve().parents[3]
DEFENDER_SRC = REPO_ROOT / "agents" / "defender" / "src"
if str(DEFENDER_SRC) not in sys.path:
    sys.path.insert(0, str(DEFENDER_SRC))

from aegis_defender.http_semantics import HttpRequestView, parse_http_request  # noqa: E402
from aegis_defender.packet import IPPROTO_TCP, ParsedPacket, parse_ip  # noqa: E402
from aegis_defender.policy import HotPolicy  # noqa: E402
from aegis_defender.rules import CompiledPolicy, load_policy  # noqa: E402


SERVICE_PORTS = frozenset({8080, 8082, 9000, 9090})
PORT_LAYERS = {8080: "L1", 9000: "L1", 8082: "L2", 9090: "L3"}
QUERY_NAMES = (
    "url", "uri", "target", "u", "dest", "path", "host",
    "callback", "next", "fetch", "proxy", "resource",
)
HTTP_REQUEST_LINE = re.compile(
    rb"(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) [^\r\n]{1,1536} HTTP/1\.[01]\r\n"
)
HTTP_RESPONSE_LINE = re.compile(rb"HTTP/1\.[01] [0-9]{3}(?: [^\r\n]*)?\r\n")
FLAG_MARKER = re.compile(rb"FLAG\{[^}\r\n]{1,512}\}")
MAX_CAPTURED_FRAME = 16 * 1024 * 1024
ETHERNET_LINKTYPE = 1
ETHERTYPE_IPV4 = 0x0800
VLAN_ETHERTYPES = frozenset({0x8100, 0x88A8, 0x9100})


class PcapFormatError(ValueError):
    """The input is not a supported, bounded classic Ethernet PCAP."""


@dataclass(slots=True)
class RequestRecord:
    dropped: bool
    label: str | None
    flag_linked: bool = False


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    timestamp: float
    data: bytes


@dataclass(slots=True)
class ReplayClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


@dataclass(slots=True)
class LayerReport:
    ingress_packets: int = 0
    parsed_requests: int = 0
    exploit_shape_requests: int = 0
    blocked_exploit_shape_requests: int = 0
    missed_exploit_shape_requests: int = 0
    other_requests: int = 0
    passed_other_requests: int = 0
    coalesced_other_requests: int = 0
    unexpected_other_drops: int = 0
    dropped_packets: int = 0
    drops_without_complete_request: int = 0
    flag_linked_requests: int = 0
    blocked_flag_linked_requests: int = 0
    rules: Counter[str] = field(default_factory=Counter)
    labels: Counter[str] = field(default_factory=Counter)

    def add(self, other: "LayerReport") -> None:
        for name in (
            "ingress_packets", "parsed_requests", "exploit_shape_requests",
            "blocked_exploit_shape_requests", "missed_exploit_shape_requests",
            "other_requests", "passed_other_requests", "coalesced_other_requests",
            "unexpected_other_drops", "dropped_packets",
            "drops_without_complete_request", "flag_linked_requests",
            "blocked_flag_linked_requests",
        ):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.rules.update(other.rules)
        self.labels.update(other.labels)

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["rules"] = dict(sorted(self.rules.items()))
        result["labels"] = dict(sorted(self.labels.items()))
        positives = self.exploit_shape_requests
        others = self.other_requests
        result["exploit_shape_block_rate"] = (
            self.blocked_exploit_shape_requests / positives if positives else None
        )
        result["unexpected_other_drop_rate"] = (
            self.unexpected_other_drops / others if others else None
        )
        return result


@dataclass(slots=True)
class ReplayReport:
    files: int
    policy_source: str
    bundle_id: str
    policy_rules: int
    drop_capable_rules: int
    policy_demotions: tuple[str, ...]
    layers: dict[str, LayerReport]
    parse_statuses: Counter[str]

    def to_dict(self) -> dict[str, object]:
        total = LayerReport()
        for layer in self.layers.values():
            total.add(layer)
        return {
            "files": self.files,
            "policy": {
                "source": self.policy_source,
                "bundle_id": self.bundle_id,
                "rules": self.policy_rules,
                "drop_capable_rules": self.drop_capable_rules,
                "demotions": list(self.policy_demotions),
            },
            "total": total.to_dict(),
            "layers": {
                name: report.to_dict()
                for name, report in sorted(self.layers.items())
            },
            "parse_statuses": dict(sorted(self.parse_statuses.items())),
            "interpretation": {
                "unexpected_other_drop_rate": (
                    "관측된 공격 형태가 없는 기타 요청 기준 오탐 대리값이며, "
                    "공식 정상 라벨 또는 SLA 오탐률이 아니다."
                ),
                "flag_linked_requests": (
                    "PCAP 응답에서 FLAG{...} 존재만 확인해 연결한 요청 수이며 "
                    "플래그 값은 저장하거나 출력하지 않는다."
                ),
                "parsed_requests": (
                    "현재 패킷에 완전한 HTTP 헤더가 있는 요청만 세며, 실제 HotPolicy의 "
                    "bounded TCP stitcher 판정은 별도로 그대로 실행한다."
                ),
            },
        }


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise PcapFormatError("truncated PCAP record")
    return data


def iter_pcap_frames(path: Path) -> Iterator[CapturedFrame]:
    """Yield bounded frames from a classic Ethernet PCAP."""
    with path.open("rb") as handle:
        header = _read_exact(handle, 24)
        magic = header[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = ">"
        else:
            raise PcapFormatError("unsupported PCAP magic (pcapng is not accepted)")
        timestamp_divisor = 1_000_000_000 if magic in (
            b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"
        ) else 1_000_000

        major, minor = struct.unpack_from(f"{endian}HH", header, 4)
        snaplen, linktype = struct.unpack_from(f"{endian}II", header, 16)
        if (major, minor) != (2, 4):
            raise PcapFormatError(f"unsupported PCAP version {major}.{minor}")
        if linktype != ETHERNET_LINKTYPE:
            raise PcapFormatError(f"unsupported PCAP linktype {linktype}; Ethernet is required")
        if snaplen <= 0 or snaplen > MAX_CAPTURED_FRAME:
            raise PcapFormatError("unsafe PCAP snaplen")

        record_struct = struct.Struct(f"{endian}IIII")
        while True:
            record_header = handle.read(record_struct.size)
            if not record_header:
                return
            if len(record_header) != record_struct.size:
                raise PcapFormatError("truncated PCAP record header")
            seconds, fraction, captured_length, _original_length = record_struct.unpack(
                record_header
            )
            if captured_length > snaplen or captured_length > MAX_CAPTURED_FRAME:
                raise PcapFormatError("unsafe PCAP frame length")
            yield CapturedFrame(
                timestamp=seconds + fraction / timestamp_divisor,
                data=_read_exact(handle, captured_length),
            )


def ethernet_ipv4(frame: bytes) -> bytes | None:
    if len(frame) < 14:
        return None
    offset = 14
    ethertype = struct.unpack_from(">H", frame, 12)[0]
    vlan_depth = 0
    while ethertype in VLAN_ETHERTYPES:
        if vlan_depth >= 2 or len(frame) < offset + 4:
            return None
        ethertype = struct.unpack_from(">H", frame, offset + 2)[0]
        offset += 4
        vlan_depth += 1
    if ethertype != ETHERTYPE_IPV4 or len(frame) <= offset:
        return None
    return frame[offset:]


def extract_http_requests(payload: bytes) -> tuple[HttpRequestView, ...]:
    """Extract complete bounded request headers without retaining raw values."""
    requests: list[HttpRequestView] = []
    for match in HTTP_REQUEST_LINE.finditer(payload):
        start = match.start()
        if start and payload[start - 2 : start] != b"\r\n":
            continue
        header_end = payload.find(b"\r\n\r\n", match.end())
        if header_end < 0 or header_end + 4 - start > 4096:
            continue
        view = parse_http_request(payload[start : header_end + 4])
        if view is not None:
            requests.append(view)
    return tuple(requests)


def classify_observed_shape(port: int, request: HttpRequestView) -> str | None:
    """Independent labels derived from documented TEAM1 observed exploit shapes."""
    if port == 8082:
        if request.ssrf_target_matches(
            QUERY_NAMES,
            ("helper-box", "172.18.0.2", "0xac120002", "2886860802", "::ffff:ac12:2"),
            (8080,),
            "/secret",
        ):
            return "l1-helper-secret-ssrf"
        if request.path == "/config":
            for name, value in request.query_pairs:
                normalized = value.lower().replace("\\", "/")
                if name == "file" and re.fullmatch(r"(?:\.\./){1,8}flag", normalized):
                    return "l1-config-flag-traversal"

    if port == 8082:
        if request.path == "/admin" and request.cookie_claim_matches(
            "session", "role", ("admin",)
        ):
            return "l2-forged-admin-session"
        if request.path in ("/fetch", "/proxy"):
            if request.ssrf_target_matches(
                QUERY_NAMES, ("127.0.0.1", "localhost", "::1"), (8082,), "/secret"
            ):
                return "l2-loopback-secret-ssrf"
            if request.ssrf_target_matches(
                QUERY_NAMES, ("127.0.0.1", "127.1"), (8082,), "/registry"
            ):
                return "l2-loopback-registry-ssrf"

    if (
        port == 9090
        and request.path == "/product"
        and request.sql_source_matches(("id",), "app_meta")
    ):
        return "l3-app-meta-union-sqli"
    return None


def _flow_key(parsed: ParsedPacket, reverse: bool = False) -> tuple[bytes, int, bytes, int]:
    if reverse:
        return parsed.dst_ip, parsed.dst_port, parsed.src_ip, parsed.src_port
    return parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port


def replay_file(path: Path, policy: CompiledPolicy) -> tuple[dict[str, LayerReport], Counter[str]]:
    layers = {name: LayerReport() for name in PORT_LAYERS.values()}
    statuses: Counter[str] = Counter()
    clock = ReplayClock()
    hot_policy = HotPolicy(policy=policy, clock=clock)
    pending: dict[tuple[bytes, int, bytes, int], list[RequestRecord]] = {}
    current_response: dict[tuple[bytes, int, bytes, int], RequestRecord] = {}
    records: list[tuple[str, RequestRecord]] = []
    packet_id = 0

    for captured in iter_pcap_frames(path):
        clock.now = captured.timestamp
        raw_ip = ethernet_ipv4(captured.data)
        if raw_ip is None:
            continue
        parsed = parse_ip(raw_ip)
        statuses[parsed.status.value] += 1
        if not parsed.ok or parsed.protocol != IPPROTO_TCP:
            continue

        if parsed.dst_port in SERVICE_PORTS:
            packet_id += 1
            layer_name = PORT_LAYERS[parsed.dst_port]
            layer = layers[layer_name]
            layer.ingress_packets += 1
            decision = hot_policy.decide(packet_id, parsed, received_at=clock.now)
            if decision.is_drop:
                layer.dropped_packets += 1
                layer.rules[decision.rule_id] += 1

            requests = list(extract_http_requests(parsed.payload))

            if decision.is_drop and not requests:
                layer.drops_without_complete_request += 1
            packet_has_exploit = any(
                classify_observed_shape(parsed.dst_port, request) is not None
                for request in requests
            )
            flow_pending = pending.setdefault(_flow_key(parsed), [])
            for request in requests:
                label = classify_observed_shape(parsed.dst_port, request)
                record = RequestRecord(dropped=decision.is_drop, label=label)
                flow_pending.append(record)
                records.append((layer_name, record))
                layer.parsed_requests += 1
                if label is not None:
                    layer.labels[label] += 1
                    layer.exploit_shape_requests += 1
                    if decision.is_drop:
                        layer.blocked_exploit_shape_requests += 1
                    else:
                        layer.missed_exploit_shape_requests += 1
                else:
                    layer.other_requests += 1
                    if decision.is_drop and packet_has_exploit:
                        layer.coalesced_other_requests += 1
                    elif decision.is_drop:
                        layer.unexpected_other_drops += 1
                    else:
                        layer.passed_other_requests += 1

        elif parsed.src_port in SERVICE_PORTS and parsed.payload:
            flow = _flow_key(parsed, reverse=True)
            response_starts = len(HTTP_RESPONSE_LINE.findall(parsed.payload))
            if response_starts:
                queue = pending.get(flow, [])
                for _ in range(response_starts):
                    if queue:
                        current_response[flow] = queue.pop(0)
            if FLAG_MARKER.search(parsed.payload):
                record = current_response.get(flow)
                if record is None:
                    queue = pending.get(flow, [])
                    record = queue[-1] if queue else None
                if record is not None:
                    record.flag_linked = True

    for layer_name, record in records:
        if record.flag_linked:
            layers[layer_name].flag_linked_requests += 1
            if record.dropped:
                layers[layer_name].blocked_flag_linked_requests += 1
    return layers, statuses


def replay_paths(paths: list[Path], policy_dir: Path, as_of: float | None) -> ReplayReport:
    policy, policy_report = load_policy(
        str(policy_dir), now_epoch=as_of if as_of is not None else time.time()
    )
    layers = {name: LayerReport() for name in PORT_LAYERS.values()}
    statuses: Counter[str] = Counter()
    for path in paths:
        file_layers, file_statuses = replay_file(path, policy)
        for name, report in file_layers.items():
            layers[name].add(report)
        statuses.update(file_statuses)
    return ReplayReport(
        files=len(paths),
        policy_source=policy_report.source,
        bundle_id=policy_report.bundle_id,
        policy_rules=policy_report.rule_count,
        drop_capable_rules=policy_report.drop_capable_rules,
        policy_demotions=policy_report.demotions,
        layers=layers,
        parse_statuses=statuses,
    )


def discover_pcaps(inputs: list[str]) -> list[Path]:
    paths: set[Path] = set()
    for raw in inputs:
        path = Path(raw)
        if path.is_dir():
            paths.update(candidate for candidate in path.rglob("*.pcap") if candidate.is_file())
        elif path.is_file() and path.suffix.lower() == ".pcap":
            paths.add(path)
        else:
            raise FileNotFoundError(f"PCAP input not found: {path}")
    if not paths:
        raise FileNotFoundError("no .pcap files found")
    return sorted(paths)


def parse_as_of(value: str | None) -> float | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def format_text(document: dict[str, object]) -> str:
    policy = document["policy"]
    total = document["total"]
    assert isinstance(policy, dict) and isinstance(total, dict)
    block_rate = total["exploit_shape_block_rate"]
    other_rate = total["unexpected_other_drop_rate"]
    block_percent = "n/a" if block_rate is None else f"{100 * float(block_rate):.4f}%"
    other_percent = "n/a" if other_rate is None else f"{100 * float(other_rate):.6f}%"
    lines = [
        "Defender PCAP offline replay",
        f"- files: {document['files']}",
        (
            f"- policy: {policy['source']} / {policy['bundle_id']} / "
            f"drop-capable {policy['drop_capable_rules']}"
        ),
        f"- HTTP requests: {total['parsed_requests']}",
        (
            f"- observed exploit shapes: {total['blocked_exploit_shape_requests']} / "
            f"{total['exploit_shape_requests']} blocked ({block_percent})"
        ),
        (
            f"- packet verdicts: {total['dropped_packets']} dropped, "
            f"{total['drops_without_complete_request']} without a packet-local complete header"
        ),
        (
            f"- other requests: {total['passed_other_requests']} passed, "
            f"{total['coalesced_other_requests']} coalesced, "
            f"{total['unexpected_other_drops']} unexpected drops ({other_percent})"
        ),
        (
            f"- flag-linked requests: {total['blocked_flag_linked_requests']} / "
            f"{total['flag_linked_requests']} blocked"
        ),
        "- note: unexpected-other rate is an offline proxy, not an official SLA false-positive rate.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", help="PCAP file or directory")
    parser.add_argument(
        "--policy-dir",
        type=Path,
        default=REPO_ROOT / "agents" / "defender" / "policy",
    )
    parser.add_argument(
        "--as-of",
        help="policy evaluation time in ISO-8601 (default: current time)",
    )
    parser.add_argument("--json", action="store_true", help="emit aggregate JSON")
    parser.add_argument(
        "--require-drop-rules",
        type=int,
        help="exit non-zero unless this many drop-capable rules loaded",
    )
    parser.add_argument(
        "--require-files",
        type=int,
        help="exit non-zero unless this many PCAP files were replayed",
    )
    parser.add_argument(
        "--require-zero-unexpected-other-drops",
        action="store_true",
        help="exit non-zero if the observed-shape proxy finds an unexpected other drop",
    )
    parser.add_argument(
        "--min-exploit-block-rate",
        type=float,
        help="exit non-zero if observed exploit-shape block rate is below this 0..1 value",
    )
    args = parser.parse_args(argv)

    try:
        paths = discover_pcaps(args.inputs)
        report = replay_paths(paths, args.policy_dir, parse_as_of(args.as_of))
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    document = report.to_dict()
    if args.json:
        print(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(format_text(document))
    total = document["total"]
    assert isinstance(total, dict)
    failed = (
        args.require_drop_rules is not None
        and report.drop_capable_rules != args.require_drop_rules
    ) or (
        args.require_files is not None and report.files != args.require_files
    ) or (
        args.require_zero_unexpected_other_drops
        and int(total["unexpected_other_drops"]) != 0
    )
    if args.min_exploit_block_rate is not None:
        if not 0.0 <= args.min_exploit_block_rate <= 1.0:
            parser.error("--min-exploit-block-rate must be between 0 and 1")
        actual_rate = total["exploit_shape_block_rate"]
        failed = failed or actual_rate is None or float(actual_rate) < args.min_exploit_block_rate
    if failed:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
