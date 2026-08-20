"""Read raw evidence locally and emit only lossy, redacted summaries."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import shutil
import struct
import subprocess
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterable

from .redaction import safe_label, uri_shape


ALLOWED_SUFFIXES = (
    ".pcap",
    ".pcapng",
    ".pcap.gz",
    ".pcapng.gz",
    ".log",
    ".json",
    ".jsonl",
    ".txt",
    ".gz",
)
MAX_TEXT_BYTES = 4 * 1024 * 1024
MAX_EVENT_SAMPLES = 200
MAX_TSHARK_PACKETS = 50_000
MAX_EVIDENCE_FILES = 128


class IngestError(ValueError):
    pass


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_allowed(path: Path) -> bool:
    lowered = path.name.lower()
    return any(lowered.endswith(suffix) for suffix in ALLOWED_SUFFIXES)


def discover_inputs(raw_inputs: Iterable[str | Path]) -> list[Path]:
    discovered: set[Path] = set()
    for raw in raw_inputs:
        candidate = Path(raw).expanduser()
        if candidate.is_dir():
            discovered.update(path.resolve() for path in candidate.rglob("*") if path.is_file() and is_allowed(path))
        elif candidate.is_file() and is_allowed(candidate):
            discovered.add(candidate.resolve())
        else:
            raise IngestError(f"허용된 evidence 파일 또는 디렉터리가 아닙니다: {candidate}")
    if not discovered:
        raise IngestError("처리할 evidence 파일이 없습니다")
    if len(discovered) > MAX_EVIDENCE_FILES:
        raise IngestError(f"한 run에서 evidence 파일은 최대 {MAX_EVIDENCE_FILES}개입니다")
    return sorted(discovered)


def assert_stable(path: Path, stability_seconds: float) -> None:
    before = path.stat()
    if stability_seconds > 0:
        time.sleep(stability_seconds)
    after = path.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise IngestError(f"아직 기록 중인 파일입니다: {path.name}")


def _pcap_stream_metadata(handle: BinaryIO) -> dict[str, object]:
    header = handle.read(24)
    if len(header) != 24:
        raise IngestError("truncated pcap header")
    magic = header[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise IngestError("not classic pcap")
    endian, resolution = formats[magic]
    packet_count = 0
    first: float | None = None
    last: float | None = None
    captured_bytes = 0
    while True:
        packet_header = handle.read(16)
        if not packet_header:
            break
        if len(packet_header) != 16:
            raise IngestError("truncated pcap packet header")
        seconds, fraction, captured_length, _ = struct.unpack(f"{endian}IIII", packet_header)
        payload = handle.read(captured_length)
        if len(payload) != captured_length:
            raise IngestError("truncated pcap packet")
        timestamp = seconds + fraction / resolution
        first = timestamp if first is None else first
        last = timestamp
        packet_count += 1
        captured_bytes += captured_length
    return {
        "packet_count": packet_count,
        "captured_bytes": captured_bytes,
        "first_timestamp": first,
        "last_timestamp": last,
    }


def _tshark_summary(path: Path) -> dict[str, object] | None:
    executable = shutil.which("tshark")
    if not executable or path.name.lower().endswith(".gz"):
        return None
    command = [
        executable,
        "-r",
        str(path),
        "-c",
        str(MAX_TSHARK_PACKETS),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-e",
        "frame.time_epoch",
        "-e",
        "ip.proto",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "http.request.method",
        "-e",
        "http.request.uri",
        "-e",
        "http.response.code",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"parse_status": "tshark_failed"}
    if result.returncode != 0:
        return {"parse_status": "tshark_failed"}

    ports: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    route_shapes: Counter[str] = Counter()
    features: Counter[str] = Counter()
    first: float | None = None
    last: float | None = None
    frames = 0
    for line in result.stdout.splitlines():
        fields = (line.split("\t") + [""] * 7)[:7]
        timestamp, _protocol, source_port, destination_port, method, uri, status = fields
        frames += 1
        try:
            numeric_time = float(timestamp)
            first = numeric_time if first is None else first
            last = numeric_time
        except ValueError:
            pass
        for port in (source_port, destination_port):
            if port.isdigit():
                ports[port] += 1
        if method and method.isalpha():
            methods[method.upper()[:16]] += 1
        if status.isdigit():
            statuses[status] += 1
        if uri:
            shaped = uri_shape(uri)
            route_shapes[str(shaped["path_shape"])] += 1
            features.update(str(item) for item in shaped["features"])
    return {
        "parse_status": "tshark_structural",
        "frames_sampled": frames,
        "sample_truncated": frames >= MAX_TSHARK_PACKETS,
        "first_timestamp": first,
        "last_timestamp": last,
        "ports": dict(ports.most_common(32)),
        "methods": dict(methods),
        "http_statuses": dict(statuses),
        "route_shapes": dict(route_shapes.most_common(64)),
        "features": dict(features),
    }


def summarize_pcap(path: Path) -> dict[str, object]:
    tshark = _tshark_summary(path)
    if tshark is not None:
        return tshark
    try:
        opener = gzip.open if path.name.lower().endswith(".gz") else Path.open
        if opener is gzip.open:
            with gzip.open(path, "rb") as handle:
                metadata = _pcap_stream_metadata(handle)
        else:
            with path.open("rb") as handle:
                metadata = _pcap_stream_metadata(handle)
        return {"parse_status": "classic_pcap_metadata", **metadata}
    except (OSError, IngestError):
        return {"parse_status": "metadata_only", "size_bytes": path.stat().st_size}


_FIELD_GROUPS = {
    "timestamp": {"timestamp", "time", "ts", "created_at", "observed_at"},
    "level": {"level", "severity"},
    "event": {"event", "type", "name", "action", "decision", "verdict"},
    "method": {"method", "http_method"},
    "uri": {"uri", "url", "path", "request_uri"},
    "status": {"status", "status_code", "http_status", "code"},
    "port": {"port", "src_port", "dst_port", "source_port", "destination_port"},
    "duration": {"latency_ms", "duration_ms", "elapsed_ms"},
    "layer": {"layer", "profile"},
    "error": {"error", "exception", "reason"},
}


def _flatten_json(value: object, prefix: str = "") -> Iterable[tuple[str, object]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _flatten_json(item, child)
    elif isinstance(value, list):
        return
    else:
        yield prefix.rsplit(".", 1)[-1].lower(), value


def _safe_json_event(value: object) -> dict[str, object]:
    event: dict[str, object] = {}
    for raw_key, raw_value in _flatten_json(value):
        for group, keys in _FIELD_GROUPS.items():
            if raw_key not in keys or group in event:
                continue
            if group == "uri":
                event[group] = uri_shape(str(raw_value))
            elif group in {"status", "port", "duration"} and isinstance(raw_value, (int, float)):
                event[group] = raw_value
            elif group == "method":
                method = str(raw_value).upper()
                event[group] = method if method.isalpha() and len(method) <= 16 else safe_label(method)
            elif group == "timestamp":
                event[group] = safe_label(raw_value)
            else:
                event[group] = safe_label(raw_value)
    return event


def _keyword_counts(text: str) -> dict[str, int]:
    lowered = text.lower()
    keywords = (
        "error",
        "exception",
        "timeout",
        "heartbeat",
        "reconnect",
        "accept",
        "drop",
        "rate_limit",
        "oom",
    )
    return {keyword: lowered.count(keyword) for keyword in keywords if keyword in lowered}


def summarize_text(path: Path) -> dict[str, object]:
    opener = gzip.open if path.name.lower().endswith(".gz") else Path.open
    if opener is gzip.open:
        handle = gzip.open(path, "rt", encoding="utf-8", errors="replace")
    else:
        handle = path.open("rt", encoding="utf-8", errors="replace")
    events: list[dict[str, object]] = []
    counts: Counter[str] = Counter()
    lines = 0
    bytes_seen = 0
    truncated = False
    with handle:
        for line in handle:
            encoded_size = len(line.encode("utf-8", "replace"))
            if bytes_seen + encoded_size > MAX_TEXT_BYTES:
                truncated = True
                break
            bytes_seen += encoded_size
            lines += 1
            counts.update(_keyword_counts(line))
            if len(events) >= MAX_EVENT_SAMPLES:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            safe_event = _safe_json_event(parsed)
            if safe_event:
                events.append(safe_event)
    return {
        "parse_status": "sanitized_text",
        "line_count": lines,
        "bytes_sampled": bytes_seen,
        "sample_truncated": truncated,
        "keyword_counts": dict(counts),
        "structured_events": events,
    }


def safe_source_name(path: Path) -> str:
    suffixes = "".join(path.suffixes[-2:])[:24]
    stem = path.name[: -len(suffixes)] if suffixes else path.name
    return f"{safe_label(stem)}{suffixes.lower()}"


def ingest(
    inputs: Iterable[str | Path],
    *,
    side: str,
    artifact_root: Path,
    stability_seconds: float = 1.0,
    run_id: str | None = None,
) -> tuple[dict[str, object], Path]:
    if side not in {"attacker", "defender"}:
        raise IngestError("side는 attacker 또는 defender여야 합니다")
    files = discover_inputs(inputs)
    actual_run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", actual_run_id):
        raise IngestError("run-id는 1~64자의 안전한 label이어야 합니다")
    run_dir = artifact_root / actual_run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    evidence: list[dict[str, object]] = []
    for path in files:
        assert_stable(path, stability_seconds)
        digest = sha256_file(path)
        lowered = path.name.lower()
        kind = "pcap" if any(marker in lowered for marker in (".pcap", ".pcapng")) else "log"
        summary = summarize_pcap(path) if kind == "pcap" else summarize_text(path)
        evidence.append(
            {
                "evidence_id": f"E-{digest[:12]}",
                "sha256": digest,
                "source_name": safe_source_name(path),
                "kind": kind,
                "size_bytes": path.stat().st_size,
                "summary": summary,
            }
        )
    manifest: dict[str, object] = {
        "schema_version": 1,
        "run_id": actual_run_id,
        "created_at": utc_now(),
        "side": side,
        "raw_content_included": False,
        "evidence": evidence,
    }
    output = run_dir / "manifest.json"
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return manifest, output
