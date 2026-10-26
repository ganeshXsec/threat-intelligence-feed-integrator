#!/usr/bin/env python3
"""Aggregate IOC indicators from configured feeds or a local file."""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = ROOT / "config.json"
DEFAULT_OUTPUT = ROOT / "output"

HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\."
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$"
)
URL_RE = re.compile(r"^https?://", re.IGNORECASE)


def classify_indicator(value: str) -> tuple[str, str] | None:
    """Return (normalized_indicator, type), or None if the value is not supported."""
    value = value.strip().strip('"').strip("'").strip().rstrip(",;")
    if not value or value.startswith("#"):
        return None

    # Hashes are normalized to lowercase.
    if HASH_RE.fullmatch(value):
        return value.lower(), "hash"

    # IP addresses, including IPv4 and IPv6.
    try:
        return str(ipaddress.ip_address(value)), "ip"
    except ValueError:
        pass

    # URLs: retain the URL but normalize scheme/host casing.
    if URL_RE.match(value):
        try:
            parsed = urlsplit(value)
            if not parsed.hostname:
                return None
            host = parsed.hostname.lower()
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            port = f":{parsed.port}" if parsed.port else ""
            netloc = host + port
            if parsed.username or parsed.password:
                return None  # Avoid collecting credential-bearing URLs.
            normalized = parsed._replace(scheme=parsed.scheme.lower(), netloc=netloc).geturl()
            return normalized, "url"
        except (ValueError, TypeError):
            return None

    # Domains: strip a trailing dot and normalize case.
    candidate = value.lower().rstrip(".")
    if DOMAIN_RE.fullmatch(candidate):
        return candidate, "domain"
    return None


def extract_candidates(text: str, fmt: str = "auto") -> Iterable[str]:
    """Yield candidate values from plain text or CSV content."""
    if fmt == "csv":
        rows = csv.reader(text.splitlines())
        for row in rows:
            for cell in row:
                cell = cell.strip()
                if cell and not cell.startswith("#"):
                    yield cell
        return

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "//")):
            continue
        if fmt == "text":
            yield line
            continue
        # Auto mode: split common CSV/whitespace separators and let validation filter.
        for item in re.split(r"[\s,;]+", line):
            item = item.strip().strip('"').strip("'")
            if item:
                yield item


def read_local_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def fetch_url(url: str, timeout: int, max_bytes: int) -> str:
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("Only HTTP(S) feed URLs are supported")
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ThreatIntelFeedIntegrator/1.0 (defensive learning project)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        content = response.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError(f"Feed exceeded configured size limit ({max_bytes} bytes)")
    return content.decode("utf-8", errors="replace")


def aggregate_text(
    text: str, source: str, fmt: str, collected_at: str,
    indicators: dict[str, dict],
) -> int:
    accepted = 0
    for candidate in extract_candidates(text, fmt):
        parsed = classify_indicator(candidate)
        if not parsed:
            continue
        value, kind = parsed
        if value not in indicators:
            indicators[value] = {
                "indicator": value,
                "type": kind,
                "sources": set(),
                "first_seen_by_tool": collected_at,
            }
        indicators[value]["sources"].add(source)
        accepted += 1
    return accepted


def write_outputs(indicators: dict[str, dict], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for value in sorted(indicators):
        item = indicators[value]
        records.append({
            "indicator": item["indicator"],
            "type": item["type"],
            "sources": sorted(item["sources"]),
            "first_seen_by_tool": item["first_seen_by_tool"],
            "source_count": len(item["sources"]),
        })

    json_path = output_dir / "iocs.json"
    csv_path = output_dir / "iocs.csv"
    json_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "indicator", "type", "sources", "first_seen_by_tool", "source_count"
            ],
        )
        writer.writeheader()
        for record in records:
            row = record.copy()
            row["sources"] = ";".join(record["sources"])
            writer.writerow(row)
    return json_path, csv_path


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict) or not isinstance(config.get("feeds", []), list):
        raise ValueError("Config must be a JSON object with a 'feeds' list")
    return config


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect, normalize, deduplicate, and export threat-intelligence IOCs."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, help="JSON feed config")
    parser.add_argument("--input", type=Path, help="Use a local text/CSV file instead of remote feeds")
    parser.add_argument("--input-format", choices=["auto", "text", "csv"], default="auto")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    try:
        config = load_config(args.config) if args.config.exists() and not args.input else {}
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"[ERROR] Could not read config: {exc}", file=sys.stderr)
        return 2

    timeout = int(config.get("timeout_seconds", 15))
    max_bytes = int(config.get("max_bytes_per_feed", 5_000_000))
    collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    indicators: dict[str, dict] = defaultdict(dict)
    errors = []
    total_candidates = 0

    if args.input:
        try:
            content = read_local_file(args.input)
            count = aggregate_text(content, args.input.name, args.input_format, collected_at, indicators)
            total_candidates += count
            print(f"[OK] {args.input}: accepted {count} indicator occurrence(s)")
        except OSError as exc:
            print(f"[ERROR] Could not read input file: {exc}", file=sys.stderr)
            return 2
    else:
        feeds = config.get("feeds", [])
        if not feeds:
            print("[ERROR] No feeds configured. Add feeds to config.json or use --input.", file=sys.stderr)
            return 2
        for feed in feeds:
            name = str(feed.get("name") or feed.get("url") or "unnamed-feed")
            url = str(feed.get("url", ""))
            fmt = str(feed.get("format", "auto")).lower()
            try:
                content = fetch_url(url, timeout, max_bytes)
                count = aggregate_text(content, name, fmt, collected_at, indicators)
                total_candidates += count
                print(f"[OK] {name}: accepted {count} indicator occurrence(s)")
            except (OSError, ValueError, urllib.error.URLError) as exc:
                message = f"{name}: {exc}"
                errors.append(message)
                print(f"[WARN] {message}", file=sys.stderr)

    json_path, csv_path = write_outputs(indicators, args.output_dir)
    print(f"\nUnique indicators: {len(indicators)}")
    print(f"JSON report: {json_path}")
    print(f"CSV report:  {csv_path}")
    if errors:
        print(f"Feeds with errors: {len(errors)} (see warnings above)")
    return 0 if indicators or not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
