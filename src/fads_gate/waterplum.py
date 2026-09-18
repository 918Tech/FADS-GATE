from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

PROFILE_ID = "WATERPLUM_CONTAGIOUS_INTERVIEW"
PROFILE_DATE = "2026-09-18"

# Exact public indicators used only for passive matching. No network contact is made.
PUBLISHED_IPS = frozenset({"95.164.17.24"})
PUBLISHED_PACKAGES = frozenset({"passports-js", "bcrypts-js", "blockscan-api"})
FBI_COMMAND_MARKERS = (
    "curl",
    "base64",
    "-enc",
    "mshta",
    "invoke-webrequest-uri",
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
        if ip in PUBLISHED_IPS:
            matches.append(f"published-ip:{ip}")

    for package in _strings(observables.get("packages")):
        if package in PUBLISHED_PACKAGES:
            matches.append(f"published-package:{package}")

    command_text = str(observables.get("command_text", "")).lower()
    for marker in FBI_COMMAND_MARKERS:
        if marker in command_text:
            matches.append(f"fbi-command-marker:{marker}")

    for path in _strings(observables.get("file_paths")):
        normalized = path.replace("\\", "/")
        if normalized.endswith(".vscode/tasks.json"):
            matches.append("fbi-vscode-task-path")

    if any(item.startswith("published-") for item in matches):
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

    if any(item.startswith("published-") for item in matches) or score >= 70:
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
