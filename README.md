# FADS-GATE

**FADS Guardian + Capability Gateway** for defensive mediation of AI-agent tool access.

The repository started as "An AI Agent Detection An Capabilities Stripper." The implementation now combines deterministic agent evidence inspection, default-deny capability reduction, tamper-evident audit records, and a passive WaterPlum / Contagious Interview defense service.

## What exists now

- `FADSGuardian`: deterministic inspection of declared agent evidence.
- `CapabilityPolicy`: hard denies, ordered allow/deny rules, subject matching, declared-agent constraints, and per-capability risk ceilings.
- `CapabilityGateway`: reduces a requested capability set to the granted subset before downstream execution.
- `HashChainAuditLog`: append-only JSONL records chained with SHA-256 for tamper evidence.
- `WATERPLUM_CONTAGIOUS_INTERVIEW`: passive matching for current 2026 WaterPlum indicators and FBI-described behaviors, with Cloak / House-of-Mirrors routing decisions.
- CLI, HTTP service, examples, tests, architecture documentation, and GitHub Actions CI.

## Quick start

Requires Python 3.11+.

```bash
python -m pip install -e .

python -m fads_gate evaluate \
  --policy examples/policy.json \
  --subject agent:demo \
  --manifest examples/agent-manifest.json \
  --audit-log ./fads-audit.jsonl

python -m fads_gate verify-audit ./fads-audit.jsonl
python -m unittest discover -s tests -v
```

## WaterPlum defense service

```bash
fads-waterplum
```

The service listens on `$HOST:$PORT` (defaults to `0.0.0.0:8080`) and exposes:

- `GET /healthz`
- `POST /v1/evaluate`

It evaluates telemetry that has already been observed by an authorized defender. Exact WaterPlum IOC matches and high-confidence TTP combinations are routed to `HOUSE_OF_MIRRORS_WATERPLUM`; replay or policy-tamper signals collapse to `NO_CAPABILITY`.

The service never scans, probes, or connects to suspected WaterPlum infrastructure. House-of-Mirrors endpoints are synthetic and use documentation-reserved networks.

See [docs/WATERPLUM.md](docs/WATERPLUM.md) for the current 2026 indicator profile.

## Core invariant

**Protected executors must consume only the `granted` set returned by the gateway.** Detection alone is informational; the capability boundary is the enforcement point.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the trust boundaries and security model.
