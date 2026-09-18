from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .waterplum import (
    CURRENT_2026_DOMAINS,
    CURRENT_2026_IPS,
    CURRENT_2026_SHA256,
    FBI_COMMAND_MARKERS,
    HISTORICAL_PACKAGES,
)

MAX_TEXT_BYTES = 2 * 1024 * 1024
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".next",
    ".cache",
}
ACTIVE_SUFFIXES = {
    ".cjs",
    ".js",
    ".json",
    ".jsx",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}
ACTIVE_FILENAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
}
PROFILE_SELF_EXCLUSIONS = {
    "src/fads_gate/waterplum.py",
    "src/fads_gate/sensor.py",
    "tests/test_waterplum.py",
    "tests/test_sensor.py",
    "docs/WATERPLUM.md",
}


def _eligible(path: Path, root: Path) -> bool:
    rel = path.relative_to(root).as_posix()
    if rel in PROFILE_SELF_EXCLUSIONS:
        return False
    if any(part in EXCLUDED_DIRS for part in path.relative_to(root).parts):
        return False
    if path.name in ACTIVE_FILENAMES:
        return True
    return path.suffix.lower() in ACTIVE_SUFFIXES


def _read_text(path: Path) -> str:
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size <= 0 or size > MAX_TEXT_BYTES:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _package_install_hook_signal(path: Path, text: str, matched_tokens: set[str]) -> bool:
    if path.name != "package.json":
        return False
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return False
    scripts = payload.get("scripts")
    if not isinstance(scripts, dict):
        return False
    for key in ("preinstall", "install", "postinstall"):
        value = scripts.get(key)
        if not isinstance(value, str):
            continue
        lowered = value.lower()
        if any(marker in lowered for marker in FBI_COMMAND_MARKERS):
            return True
        if any(token in lowered for token in matched_tokens):
            return True
    return False


def scan_workspace(root: str | Path) -> dict[str, Any]:
    root_path = Path(root).resolve()
    ips: set[str] = set()
    domains: set[str] = set()
    hashes: set[str] = set()
    packages: set[str] = set()
    marker_paths: set[str] = set()
    command_markers: set[str] = set()
    signals: dict[str, bool] = {}

    exact_tokens = set(CURRENT_2026_IPS) | set(CURRENT_2026_DOMAINS) | set(CURRENT_2026_SHA256)

    for path in root_path.rglob("*"):
        if not path.is_file() or not _eligible(path, root_path):
            continue
        rel = path.relative_to(root_path).as_posix()
        text = _read_text(path)
        if not text:
            continue
        lowered = text.lower()

        for ip in CURRENT_2026_IPS:
            if ip in text:
                ips.add(ip)
        for domain in CURRENT_2026_DOMAINS:
            if domain in lowered:
                domains.add(domain)
        for digest in CURRENT_2026_SHA256:
            if digest in lowered:
                hashes.add(digest)

        if path.name in ACTIVE_FILENAMES:
            for package in HISTORICAL_PACKAGES:
                if package in lowered:
                    packages.add(package)

        if rel.endswith(".vscode/tasks.json"):
            suspicious = [marker for marker in FBI_COMMAND_MARKERS if marker in lowered]
            if suspicious:
                marker_paths.add(rel)
                command_markers.update(suspicious)
                signals["vscode_task_autoexec"] = True
                signals["unexpected_child_process"] = True

        if "/.githooks/" in f"/{rel}" or rel.startswith(".githooks/"):
            suspicious = [marker for marker in FBI_COMMAND_MARKERS if marker in lowered]
            if suspicious:
                marker_paths.add(rel)
                command_markers.update(suspicious)
                signals["unexpected_child_process"] = True

        if rel.endswith("task/tokenlinux.sh") or rel.endswith("task/mac"):
            marker_paths.add(rel)
            signals["unknown_executable"] = True

        matched_tokens = exact_tokens | packages
        if _package_install_hook_signal(path, text, matched_tokens):
            marker_paths.add(rel)
            signals["install_hook"] = True
            command_markers.update(marker for marker in FBI_COMMAND_MARKERS if marker in lowered)

    if ips or domains or hashes or packages:
        signals["unauthorized_network"] = True

    return {
        "signals": signals,
        "observables": {
            "ips": sorted(ips),
            "domains": sorted(domains),
            "sha256": sorted(hashes),
            "packages": sorted(packages),
            "file_paths": sorted(marker_paths),
            "command_text": " ".join(sorted(command_markers)),
        },
    }


def remote_payload(scan: dict[str, Any]) -> dict[str, Any]:
    observables = scan["observables"]
    return {
        "id": "github-repository-telemetry",
        "capabilities": ["repo.read", "telemetry.read"],
        "signals": {
            "unknownExecutable": bool(scan["signals"].get("unknown_executable")),
            "installHook": bool(scan["signals"].get("install_hook")),
            "vscodeTaskAutoExec": bool(scan["signals"].get("vscode_task_autoexec")),
            "unexpectedChildProcess": bool(scan["signals"].get("unexpected_child_process")),
            "unauthorizedNetwork": bool(scan["signals"].get("unauthorized_network")),
        },
        "observables": {
            "ips": observables["ips"],
            "domains": observables["domains"],
            "sha256": observables["sha256"],
            "packages": observables["packages"],
            "filePaths": observables["file_paths"],
            "commandText": observables["command_text"],
        },
    }
