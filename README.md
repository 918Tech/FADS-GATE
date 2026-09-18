# FADS-GATE

**FADS Guardian + Capability Gateway** for defensive mediation of AI-agent tool access.

The repository started as "An AI Agent Detection An Capabilities Stripper." The first implementation turns that idea into an enforceable boundary: inspect explicit agent evidence, evaluate each requested capability against policy, strip anything not permitted, and emit a tamper-evident audit event.

## What exists now

- `FADSGuardian`: deterministic inspection of declared agent evidence. It does **not** pretend to classify arbitrary humans as AI.
- `CapabilityPolicy`: hard denies, ordered allow/deny rules, subject matching, declared-agent constraints, and per-capability risk ceilings.
- `CapabilityGateway`: reduces a requested capability set to the granted subset before downstream execution.
- `HashChainAuditLog`: append-only JSONL records chained with SHA-256 for tamper evidence.
- CLI, example policy/manifest, unit tests, and GitHub Actions CI.

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

The example agent requests `repo.read`, `repo.push`, `process.exec`, and `secrets.read`. Under the supplied default-deny policy, only explicitly admitted capabilities survive. `secrets.*` and capability delegation are hard-denied.

## Core invariant

**Protected executors must consume only the `granted` set returned by the gateway.** Detection alone is informational; the capability boundary is the enforcement point.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the threat model, trust boundaries, and next interfaces.
