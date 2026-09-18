# WaterPlum / Contagious Interview defense profile

This branch adds a passive detector and containment decision service for the WaterPlum / Contagious Interview threat described in the September 18, 2026 FBI/IC3 joint advisory.

## Scope

The service evaluates telemetry already observed by an authorized defender. It never probes, connects to, scans, redirects traffic toward, or otherwise interacts with a suspected third-party host.

## Current 2026 indicators encoded

September 3, 2026 Jamf Threat Labs Contagious Interview cluster:

- Staging C2: `162.0.239.85`
- Operator C2: `147.124.202.205`
- Related domains: `w3pi.social`, `miniapp.w3pi.social`, `softcus.net`, `pobelstudio.com`, `pobel.studio`, `kikaiverse.com`, `lalitae.com`
- Published SHA-256 samples for `/task/tokenlinux.sh`, `/task/mac`, `parser.js`, `scdata`, and `ldata`

March 17, 2026 NTT Security StoatWaffle / WaterPlum indicators:

- `185.163.125.196`
- `147.124.202.208`
- `163.245.194.216`
- `66.235.168.136`
- `87.236.177.9`

Historical Contagious Interview indicators remain supported at lower recency weight, including `95.164.17.24` and the malicious npm packages `passports-js`, `bcrypts-js`, and `blockscan-api`.

The FBI behavior profile includes recruiter coding assignments, malicious NPM packages, malicious VS Code `.vscode/tasks.json` auto-execution, loaders and RATs, credential and cryptocurrency-wallet access, infostealer behavior, unauthorized network activity, and suspicious script markers such as `curl`, `base64`, `-enc`, `mshta`, `Invoke-WebRequest`, `iwr-uri`, and `hidden`.

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
python -m pip install -e .
fads-waterplum
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
    "ips": ["162.0.239.85"],
    "domains": ["w3pi.social"],
    "file_paths": [".vscode/tasks.json"],
    "command_text": "curl ... | base64 ..."
  }
}
```

An IOC match is treated as a defensive indicator, not independent proof of operator identity. The service performs no active contact with matched infrastructure.
