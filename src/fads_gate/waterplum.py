from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

PROFILE_ID = "WATERPLUM_CONTAGIOUS_INTERVIEW"
PROFILE_DATE = "2026-09-18"

# Public defensive indicators only. Matching is passive; this code never contacts them.
CURRENT_2026_IPS = frozenset(
    {
        # Jamf Threat Labs, 2026-09-03
        "162.0.239.85",
        "147.124.202.205",
        # NTT Security, StoatWaffle / WaterPlum, 2026-03-17
        "185.163.125.196",
        "147.124.202.208",
        "163.245.194.216",
        "66.235.168.136",
        "87.236.177.9",
    }
)

CURRENT_2026_DOMAINS = frozenset(
    {
        "w3pi.social",
        "miniapp.w3pi.social",
        "softcus.net",
        "pobelstudio.com",
        "pobel.studio",
        "kikaiverse.com",
        "lalitae.com",
    }
)

CURRENT_2026_SHA256 = frozenset(
    {
        "0882bb158878a1ca19320f5160dc93f4608c862f3ab652671bb92a82b2f1eb39",
        "815a41a0c0426ffec3c9ad08e1fb125a040cf0e41acce2a86b891aeb08648d61",
        "42620128470e26d473a128f354b77ca2c5fe9e5782e7addc1e3f863dbd0cd9b0",
        "4c025bda19d6b7b1f9cc209876099b20130a198c18ae22b7809470dde93c62db",
        "b07f46962c409cb854e34e06abcfc616edcc5a554a43cfac8f4f26cb818a340d",
    }
)

HISTORICAL_IPS = frozenset({"95.164.17.24"})
HISTORICAL_PACKAGES = frozenset({"passports-js", "bcrypts-js", "blockscan-api"})

FBI_COMMAND_MARKERS = (
    "curl",
    "base64",
    "-enc",
    "mshta",
    "invoke-webrequest",
    "iwr-uri",
    "hidden",
)

TTP_WEIGHTS = {
    "recruiter_coding_assignment": 15,
    "unknown_executable": 25,
    "install_hook": 20,
    "vscode_task_autoexec": 30,
    "unexpected_child_process": 20,
    "unauthorized_network": 30,
    "credential_access": 35,
    "wallet_access": 35,
    "infostealer_behavior": 35,
    "rat_persistence": 35,
    "canary_interaction": 40,
    "replay": 50,
    "policy_tamper": 80,
}


@dataclass(frozen=True)
class WaterPlumAssessment:
    profile: str
    score: int
    state: str
    route: str
    decision: str
    matches: tuple[str, ...]
    reasons: tuple[str, ...]


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return tuple(str(item).strip().lower() for item in value if str(item).strip())


def _normalize_domain(value: str) -> str:
    return value.removeprefix("https://").removeprefix("http://").split("/", 1)[0].split(":", 1)[0].rstrip(".")


def assess_waterplum(
    *,
    signals: Mapping[str, Any] | None = None,
    observables: Mapping[str, Any] | None = None,
) -> WaterPlumAssessment:
    signals = signals or {}
    observables = observables or {}
    score = 0
    matches: list[str] = []
    reasons: list[str] = []

    for name, weight in TTP_WEIGHTS.items():
        if signals.get(name) is True:
            score += weight
            reasons.append(f"TTP:{name}+{weight}")

    for ip in _strings(observables.get("ips")):
        if ip in CURRENT_2026_IPS:
            matches.append(f"published-2026-ip:{ip}")
        elif ip in HISTORICAL_IPS:
            matches.append(f"published-historical-ip:{ip}")

    for domain in _strings(observables.get("domains")):
        normalized = _normalize_domain(domain)
        if normalized in CURRENT_2026_DOMAINS:
            matches.append(f"published-2026-domain:{normalized}")

    for digest in _strings(observables.get("sha256")):
        if digest in CURRENT_2026_SHA256:
            matches.append(f"published-2026-sha256:{digest}")

    for package in _strings(observables.get("packages")):
        if package in HISTORICAL_PACKAGES:
            matches.append(f"published-historical-package:{package}")

    command_text = str(observables.get("command_text", "")).lower()
    for marker in FBI_COMMAND_MARKERS:
        if marker in command_text:
            matches.append(f"fbi-command-marker:{marker}")

    for path in _strings(observables.get("file_paths")):
        normalized = path.replace("\\", "/")
        if normalized.endswith(".vscode/tasks.json"):
            matches.append("fbi-vscode-task-path")
        if "/.githooks/" in normalized or "/.git/hooks/" in normalized:
            matches.append("contagious-interview-git-hook-path")
        if normalized.endswith("/task/tokenlinux.sh") or normalized.endswith("/task/mac"):
            matches.append("published-2026-stage-path")

    current_exact = any(item.startswith("published-2026-") for item in matches)
    historical_exact = any(item.startswith("published-historical-") for item in matches)

    if current_exact:
        score = max(score, 95)
        reasons.append("exact-published-2026-waterplum-indicator")
    elif historical_exact:
        score = max(score, 90)
        reasons.append("exact-published-contagious-interview-indicator")

    if any(item.startswith("fbi-") for item in matches):
        score += 15
        reasons.append("fbi-waterplum-defensive-marker")

    score = min(score, 100)

    if signals.get("policy_tamper") is True or signals.get("replay") is True:
        return WaterPlumAssessment(
            profile=PROFILE_ID,
            score=score,
            state="TERMINATED",
            route="NO_CAPABILITY",
            decision="TERMINATE_SESSION",
            matches=tuple(matches),
            reasons=tuple(reasons),
        )

    if current_exact or historical_exact or score >= 70:
        return WaterPlumAssessment(
            profile=PROFILE_ID,
            score=score,
            state="QUARANTINED",
            route="HOUSE_OF_MIRRORS_WATERPLUM",
            decision="DECEIVE_AND_CONTAIN",
            matches=tuple(matches),
            reasons=tuple(reasons),
        )

    if score >= 35:
        return WaterPlumAssessment(
            profile=PROFILE_ID,
            score=score,
            state="RESTRICTED",
            route="CLOAK_RESTRICTED",
            decision="RESTRICT",
            matches=tuple(matches),
            reasons=tuple(reasons),
        )

    return WaterPlumAssessment(
        profile=PROFILE_ID,
        score=score,
        state="TRUSTED",
        route="CLOAK_CANONICAL",
        decision="ALLOW_LIMITED",
        matches=tuple(matches),
        reasons=tuple(reasons),
    )
