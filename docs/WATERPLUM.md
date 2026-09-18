# WaterPlum / Contagious Interview defense profile

This branch adds a passive detector and containment decision service for the WaterPlum / Contagious Interview threat described in the September 18, 2026 FBI/IC3 joint advisory.

## Scope

The service evaluates telemetry already observed by an authorized defender. It never probes, connects to, scans, redirects traffic toward, or otherwise interacts with a suspected third-party host.

Exact public indicators currently encoded:

- `95.164.17.24` — publicly associated with BeaverTail / Contagious Interview infrastructure.
- `passports-js`, `bcrypts-js`, `blockscan-api` — malicious npm package names publicly associated with BeaverTail.

The current FBI behavior profile includes recruiter coding assignments, malicious NPM, malicious VS Code `.vscode/tasks.json` auto-execution, loaders/RATs, credential and wallet access, infostealer behavior, unauthorized network activity, and command/script markers cited in the advisory.

## Decision path

```text
observed telemetry
      |
      v
WaterPlum profile
      |
      +-- low risk ----------> CLOAK_CANONICAL
      +-- suspicious --------> CLOAK_RESTRICTED
      +-- WaterPlum match ---> HOUSE_OF_MIRRORS_WATERPLUM
      +-- replay/tamper -----> NO_CAPABILITY
```

The House-of-Mirrors response uses only documentation-reserved addresses and synthetic services. Canonical 918 infrastructure and real credentials are never copied into the decoy namespace.

## HTTP service

```bash
python -m fads_gate.server
```

Health:

```text
GET /healthz
```

Evaluate already-observed telemetry:

```text
POST /v1/evaluate
Content-Type: application/json
```

Example request:

```json
{
  "capabilities": ["repo.read", "process.exec", "network.outbound", "secrets.read"],
  "signals": {
    "recruiter_coding_assignment": true,
    "install_hook": true,
    "credential_access": true
  },
  "observables": {
    "ips": ["95.164.17.24"],
    "file_paths": [".vscode/tasks.json"],
    "command_text": "curl ... | base64 ..."
  }
}
```

An exact IOC match is treated as a defensive indicator, not independent proof of actor identity.
