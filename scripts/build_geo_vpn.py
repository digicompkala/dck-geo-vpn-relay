#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
CONFIG = ROOT / "config" / "protected-networks.txt"

UA = "DCK-Geo-VPN-Relay/1.1 (+https://digicompkala.com/)"
TIMEOUT = 45
MAX_DOWNLOAD = 12 * 1024 * 1024

URLS = {
    "ripe": "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest",
    "x4bnet": "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt",
    "tor": "https://check.torproject.org/torbulkexitlist",
    "proxio": "https://raw.githubusercontent.com/proxio-io/proxy-list/main/all.txt",
    "google": "https://raw.githubusercontent.com/digicompkala/dck-google-ipranges-relay/main/dist/google-ipranges.json",
}

PROVIDERS = [
    "airvpn",
    "ivpn",
    "mullvad",
    "nordvpn",
    "ovpn",
    "pia",
    "protonvpn",
    "riseupvpn",
    "surfshark",
    "windscribe",
]

PROVIDER_BASE = (
    "https://raw.githubusercontent.com/"
    "Joe12387/open-source-vpn-ip-lists/master/{name}.txt"
)


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        status = getattr(resp, "status", 200)
        if status != 200:
            raise RuntimeError(f"HTTP {status}: {url}")
        data = resp.read(MAX_DOWNLOAD + 1)
    if not data:
        raise RuntimeError(f"empty download: {url}")
    if len(data) > MAX_DOWNLOAD:
        raise RuntimeError(f"download too large: {url}")
    return data


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_network(value: str):
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except Exception:
        return None


def parse_ip(value: str):
    try:
        return ipaddress.ip_address(value.strip())
    except Exception:
        return None


def global_network(net) -> bool:
    return bool(net and net.network_address.is_global)


def collapse(networks):
    v4 = sorted(set(n for n in networks if n.version == 4))
    v6 = sorted(set(n for n in networks if n.version == 6))
    out = []
    if v4:
        out.extend(ipaddress.collapse_addresses(v4))
    if v6:
        out.extend(ipaddress.collapse_addresses(v6))
    return list(out)


def subtract_one(net, blocked):
    if net.version != blocked.version or not net.overlaps(blocked):
        return [net]
    if net.subnet_of(blocked):
        return []
    if blocked.subnet_of(net):
        return list(net.address_exclude(blocked))
    return [net]


def subtract_many(networks, blocked):
    current = collapse(networks)
    blockers = collapse(blocked)
    for b in blockers:
        next_items = []
        for n in current:
            next_items.extend(subtract_one(n, b))
        current = next_items
    return collapse(current)


def read_static_protected():
    nets = []
    for raw in CONFIG.read_text(encoding="utf-8").splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        n = parse_network(value)
        if n is None:
            raise RuntimeError(f"invalid protected network: {value}")
        nets.append(n)
    return collapse(nets)


def parse_ripe(data: bytes):
    nets = []
    records = 0
    for raw in data.decode("utf-8", "replace").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("|")
        if len(fields) < 7:
            continue
        registry, cc, typ, start, value, _, status = fields[:7]
        if registry.lower() != "ripencc" or cc.upper() != "IR":
            continue
        if typ.lower() not in {"ipv4", "ipv6"}:
            continue
        if status.lower() in {"available", "reserved"}:
            continue
        try:
            if typ.lower() == "ipv4":
                first = ipaddress.IPv4Address(start)
                count = int(value)
                if count <= 0:
                    continue
                last = ipaddress.IPv4Address(int(first) + count - 1)
                nets.extend(ipaddress.summarize_address_range(first, last))
            else:
                nets.append(ipaddress.IPv6Network(f"{start}/{int(value)}", strict=False))
            records += 1
        except Exception:
            continue
    return collapse(nets), records


def parse_cidr_lines(data: bytes):
    nets = []
    for raw in data.decode("utf-8", "replace").splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        n = parse_network(value)
        if global_network(n):
            nets.append(n)
    return collapse(nets)


def parse_ip_lines(data: bytes):
    nets = []
    for raw in data.decode("utf-8", "replace").splitlines():
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        ip = parse_ip(value)
        if ip and ip.is_global:
            nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
    return collapse(nets)


def parse_proxy_lines(data: bytes):
    nets = []
    for raw in data.decode("utf-8", "replace").splitlines():
        value = raw.strip()
        if not value:
            continue
        value = re.sub(r"^[a-zA-Z0-9+.-]+://", "", value)
        host = None
        m6 = re.match(r"^\[([0-9a-fA-F:]+)\](?::\d+)?$", value)
        if m6:
            host = m6.group(1)
        else:
            m4 = re.match(r"^([0-9.]+)(?::\d+)?$", value)
            if m4:
                host = m4.group(1)
        if not host:
            continue
        ip = parse_ip(host)
        if ip and ip.is_global:
            nets.append(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
    return collapse(nets)


def parse_google(data: bytes):
    obj = json.loads(data.decode("utf-8"))
    ranges = obj.get("ranges")
    if not isinstance(ranges, list):
        raise RuntimeError("Google relay JSON missing ranges")
    nets = []
    for item in ranges:
        if not isinstance(item, dict):
            continue
        n = parse_network(str(item.get("cidr", "")))
        if global_network(n):
            nets.append(n)
    return collapse(nets), obj


def write_networks(path: Path, networks):
    text = "".join(f"{n}\n" for n in networks)
    path.write_text(text, encoding="utf-8")
    return hashlib.sha256(text.encode()).hexdigest()


def overlaps_any(left, right):
    for a in left:
        for b in right:
            if a.version == b.version and a.overlaps(b):
                return True, str(a), str(b)
    return False, None, None


def main():
    DIST.mkdir(parents=True, exist_ok=True)

    source_meta = {}

    ripe_raw = fetch(URLS["ripe"])
    source_meta["ripe"] = {"url": URLS["ripe"], "bytes": len(ripe_raw), "sha256": sha256_bytes(ripe_raw)}
    iran, ripe_records = parse_ripe(ripe_raw)

    x4_raw = fetch(URLS["x4bnet"])
    source_meta["x4bnet"] = {"url": URLS["x4bnet"], "bytes": len(x4_raw), "sha256": sha256_bytes(x4_raw)}
    x4 = parse_cidr_lines(x4_raw)

    tor_raw = fetch(URLS["tor"])
    source_meta["tor"] = {"url": URLS["tor"], "bytes": len(tor_raw), "sha256": sha256_bytes(tor_raw)}
    tor = parse_ip_lines(tor_raw)

    # Public working-proxy data is intentionally observation-only. It changes
    # quickly and is more prone to false positives than the curated VPN feeds,
    # so it must never be a warning signal by itself.
    proxies = []
    proxy_failure = None
    try:
        proxy_raw = fetch(URLS["proxio"])
        proxies = parse_proxy_lines(proxy_raw)
        source_meta["proxio"] = {
            "url": URLS["proxio"],
            "bytes": len(proxy_raw),
            "sha256": sha256_bytes(proxy_raw),
            "networks": len(proxies),
            "warning_signal": False,
        }
    except Exception as exc:
        proxy_failure = str(exc)
        source_meta["proxio"] = {
            "url": URLS["proxio"],
            "warning_signal": False,
            "status": "optional_source_failed",
            "error": proxy_failure,
        }

    google_raw = fetch(URLS["google"])
    source_meta["google_protection"] = {"url": URLS["google"], "bytes": len(google_raw), "sha256": sha256_bytes(google_raw)}
    google, google_obj = parse_google(google_raw)

    provider = []
    provider_success = 0
    provider_failures = []
    provider_counts = {}
    for name in PROVIDERS:
        url = PROVIDER_BASE.format(name=name)
        try:
            raw = fetch(url)
            nets = parse_ip_lines(raw)
            if not nets:
                raise RuntimeError("no valid global IPs")
            provider.extend(nets)
            provider_success += 1
            provider_counts[name] = len(nets)
            source_meta[f"provider_{name}"] = {"url": url, "bytes": len(raw), "sha256": sha256_bytes(raw), "networks": len(nets)}
        except Exception as exc:
            provider_failures.append({"provider": name, "error": str(exc)})
    provider = collapse(provider)

    static_protected = read_static_protected()
    protected = collapse(static_protected + google)

    iran4 = [n for n in iran if n.version == 4]
    iran6 = [n for n in iran if n.version == 6]

    # Sanity gates. A failed gate leaves the previous dist untouched because
    # the workflow only commits after this script exits successfully.
    if len(iran4) < 100:
        raise RuntimeError(f"Iran IPv4 prefix count too small: {len(iran4)}")
    if len(x4) < 1000:
        raise RuntimeError(f"X4BNet VPN count too small: {len(x4)}")
    if len(tor) < 100:
        raise RuntimeError(f"Tor exit count too small: {len(tor)}")
    if provider_success < 5:
        raise RuntimeError(f"too few VPN provider feeds succeeded: {provider_success}")
    if len(google) < 100:
        raise RuntimeError(f"Google protected range count too small: {len(google)}")

    # Conservative warning union: curated known-VPN networks, first-party VPN
    # provider egress/server lists, and Tor exits. Public working proxies are
    # recorded for observation only and are excluded from the warning union.
    candidate_raw = collapse(x4 + provider + tor)
    raw_count = len(candidate_raw)

    # Iran is always direct-allow. Protected crawler/partner/origin ranges are
    # also always excluded from the warning candidate list.
    candidate_no_ir = subtract_many(candidate_raw, iran)
    iran_adjustments = raw_count - len(candidate_no_ir)
    candidate = subtract_many(candidate_no_ir, protected)
    protected_adjustments = len(candidate_no_ir) - len(candidate)

    # Keep a Tor-only output too, with the same safety exclusions.
    tor_safe = subtract_many(subtract_many(tor, iran), protected)

    bad, a, b = overlaps_any(candidate, iran)
    if bad:
        raise RuntimeError(f"final candidate overlaps Iran: {a} <-> {b}")
    bad, a, b = overlaps_any(candidate, protected)
    if bad:
        raise RuntimeError(f"final candidate overlaps protected: {a} <-> {b}")

    cand4 = [n for n in candidate if n.version == 4]
    cand6 = [n for n in candidate if n.version == 6]
    tor4 = [n for n in tor_safe if n.version == 4]
    tor6 = [n for n in tor_safe if n.version == 6]

    if len(cand4) < 1000:
        raise RuntimeError(f"final VPN/proxy IPv4 count too small: {len(cand4)}")

    hashes = {
        "iran-v4.txt": write_networks(DIST / "iran-v4.txt", iran4),
        "iran-v6.txt": write_networks(DIST / "iran-v6.txt", iran6),
        "vpn-proxy-v4.txt": write_networks(DIST / "vpn-proxy-v4.txt", cand4),
        "vpn-proxy-v6.txt": write_networks(DIST / "vpn-proxy-v6.txt", cand6),
        "tor-v4.txt": write_networks(DIST / "tor-v4.txt", tor4),
        "tor-v6.txt": write_networks(DIST / "tor-v6.txt", tor6),
    }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy": {
            "iran": "allow_direct",
            "non_iran_unmatched": "allow_direct",
            "non_iran_known_vpn_or_tor": "warning_candidate",
            "public_working_proxy_feed": "observe_only_not_warning_signal",
            "warning_is_block": False,
            "visitor_may_continue": True,
            "hosting_provider_alone_is_signal": False,
        },
        "counts": {
            "ripe_ir_resource_records": ripe_records,
            "iran_ipv4_networks": len(iran4),
            "iran_ipv6_networks": len(iran6),
            "x4bnet_networks": len(x4),
            "provider_vpn_networks": len(provider),
            "provider_feeds_successful": provider_success,
            "provider_feeds_total": len(PROVIDERS),
            "tor_networks_raw": len(tor),
            "public_proxy_networks_observed": len(proxies),
            "public_proxy_feed_successful": proxy_failure is None,
            "candidate_raw_networks": raw_count,
            "candidate_ipv4_networks": len(cand4),
            "candidate_ipv6_networks": len(cand6),
            "tor_ipv4_networks": len(tor4),
            "tor_ipv6_networks": len(tor6),
            "static_protected_networks": len(static_protected),
            "google_protected_networks": len(google),
            "total_protected_networks": len(protected),
            "iran_subtraction_net_change": iran_adjustments,
            "protected_subtraction_net_change": protected_adjustments,
        },
        "provider_counts": provider_counts,
        "provider_failures": provider_failures,
        "optional_source_failures": ([{"source": "proxio", "error": proxy_failure}] if proxy_failure else []),
        "google_relay_generated_at": google_obj.get("generated_at"),
        "sources": source_meta,
        "output_sha256": hashes,
    }

    report_text = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    (DIST / "dck-geo-vpn-report.json").write_text(report_text, encoding="utf-8")

    print("BUILD=OK")
    for key, value in report["counts"].items():
        print(f"{key.upper()}={value}")
    print(f"REPORT_SHA256={hashlib.sha256(report_text.encode()).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"BUILD=FAILED ERROR={exc}", file=sys.stderr)
        sys.exit(1)
