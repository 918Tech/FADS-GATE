from __future__ import annotations

import hashlib
import platform
import socket
from pathlib import Path
from typing import Any, Iterable

import psutil

from .sensor import scan_workspace
from .waterplum import CURRENT_2026_DOMAINS, CURRENT_2026_IPS, CURRENT_2026_SHA256, FBI_COMMAND_MARKERS, HISTORICAL_PACKAGES

PROCESS_FAMILY_MARKERS = {
    "beavertail": "infostealer_behavior",
    "invisibleferret": "rat_persistence",
    "ottercookie": "rat_persistence",
    "ottercandy": "infostealer_behavior",
    "stoatwaffle": "infostealer_behavior",
}


def _safe_process_text(proc: psutil.Process) -> str:
    try:
        parts = [proc.name(), proc.exe(), *proc.cmdline()]
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return ""
    return " ".join(part for part in parts if part).lower()


def _network_matches() -> set[str]:
    matches: set[str] = set()
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return matches
    for conn in connections:
        if not conn.raddr:
            continue
        remote_ip = str(conn.raddr.ip)
        if remote_ip in CURRENT_2026_IPS:
            matches.add(remote_ip)
    return matches


def _process_observables() -> tuple[set[str], set[str], set[str], set[str], dict[str, bool]]:
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    packages: set[str] = set()
    signals: dict[str, bool] = {}
    for proc in psutil.process_iter():
        text = _safe_process_text(proc)
        if not text:
            continue
        for ip in CURRENT_2026_IPS:
            if ip in text:
                ips.add(ip)
        for domain in CURRENT_2026_DOMAINS:
            if domain in text:
                domains.add(domain)
        for digest in CURRENT_2026_SHA256:
            if digest in text:
                hashes.add(digest)
        for package in HISTORICAL_PACKAGES:
            if package in text:
                packages.add(package)
        for family, signal in PROCESS_FAMILY_MARKERS.items():
            if family in text:
                signals[signal] = True
        if any(marker in text for marker in FBI_COMMAND_MARKERS):
            signals["unexpected_child_process"] = True
    if ips or domains or hashes or packages:
        signals["unauthorized_network"] = True
    return ips, domains, hashes, packages, signals


def collect_endpoint_telemetry(scan_roots: Iterable[str | Path] = ()) -> dict[str, Any]:
    ips, domains, hashes, packages, signals = _process_observables()
    ips.update(_network_matches())
    file_paths: set[str] = set()
    command_markers: set[str] = set()

    for root in scan_roots:
        path = Path(root)
        if not path.exists():
            continue
        result = scan_workspace(path)
        observed = result["observables"]
        ips.update(observed["ips"])
        domains.update(observed["domains"])
        hashes.update(observed["sha256"])
        packages.update(observed["packages"])
        file_paths.update(observed["file_paths"])
        command_markers.update(observed["command_text"].split())
        signals.update({k: bool(v) for k, v in result["signals"].items() if v})

    if ips or domains or hashes or packages:
        signals["unauthorized_network"] = True

    host_fingerprint = hashlib.sha256(
        (socket.gethostname() + "|" + platform.platform()).encode("utf-8")
    ).hexdigest()[:24]

    return {
        "sensor": {
            "id": f"endpoint-{host_fingerprint}",
            "platform": platform.system().lower(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
        },
        "signals": signals,
        "observables": {
            "ips": sorted(ips),
            "domains": sorted(domains),
            "sha256": sorted(hashes),
            "packages": sorted(packages),
            "file_paths": sorted(file_paths),
            "command_text": " ".join(sorted(command_markers)),
        },
    }
