from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .audit import HashChainAuditLog
from .gateway import CapabilityGateway
from .models import CapabilityRequest
from .policy import CapabilityPolicy


def _json_file(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fads-gate")
    sub = parser.add_subparsers(dest="command", required=True)

    evaluate = sub.add_parser("evaluate", help="evaluate a capability request")
    evaluate.add_argument("--policy", required=True)
    evaluate.add_argument("--subject", required=True)
    evaluate.add_argument("--manifest", required=True)
    evaluate.add_argument("--audit-log")

    verify = sub.add_parser("verify-audit", help="verify an audit hash chain")
    verify.add_argument("path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "verify-audit":
        ok, count = HashChainAuditLog(args.path).verify()
        print(json.dumps({"ok": ok, "records": count}))
        return 0 if ok else 2

    manifest = _json_file(args.manifest)
    policy = CapabilityPolicy.from_json(args.policy)
    audit = HashChainAuditLog(args.audit_log) if args.audit_log else None
    result = CapabilityGateway(policy, audit_log=audit).authorize(
        CapabilityRequest(
            subject_id=args.subject,
            requested=tuple(map(str, manifest.get("capabilities", ()))),
            manifest=manifest,
        )
    )
    print(json.dumps(asdict(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
