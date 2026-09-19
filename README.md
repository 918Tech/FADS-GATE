# 918 Technologies FADS-GATE

> **A globally distributed, attack-activated defensive control plane for AI agents, developer infrastructure, and enrolled endpoints.**

**FADS-GATE v1.3** is the current public release of the 918 Technologies **Foreign Agent Defense System / Capability Gateway**.

This repository contains a working defensive architecture that combines:

- default-deny capability mediation,
- WaterPlum / Contagious Interview detection,
- signed asset enrollment,
- independent geo attestation,
- autonomous restriction and quarantine,
- House of Mirrors deception,
- seven-continent defensive beacon routing,
- redundant global coordinators,
- passive RF proximity evidence,
- public threat-intelligence enrichment,
- cryptographically signed evidence,
- and a Postgres-backed tamper-evident evidence ledger.

The design goal is simple:

> **Detect suspicious behavior, reduce capability immediately, preserve evidence, and activate defensive controls without waiting for a human operator.**

---

## World announcement

918 Technologies is releasing FADS-GATE as a public reference implementation of an **attack-activated global defense mesh**.

The system is not a single scanner and it is not an attack-back platform. It is a layered defensive control plane.

When an enrolled sensor or protected workload crosses a FADS policy threshold, the system can automatically transition through:

```text
TRUSTED
   ↓
RESTRICTED
   ↓
QUARANTINED
   ↓
TERMINATED
```

Those states activate progressively stronger local controls:

```text
RESTRICTED
  → capability stripping
  → evidence capture
  → Cloak restriction

QUARANTINED
  → capability stripping
  → Cloak restriction
  → House of Mirrors containment
  → evidence capture

TERMINATED
  → session termination
  → zero capability
  → evidence capture
```

A signed defense event is then propagated to redundant coordinators so the rest of the mesh can move into a stronger defensive posture.

No attack-back behavior is required.

---

## Global defense mesh

FADS-GATE currently supports seven logical continent beacons:

| Beacon | Logical continent | Current hosting model |
|---|---|---|
| `918-beacon-north-america` | North America | In-continent |
| `918-beacon-south-america` | South America | Relay-hosted |
| `918-beacon-europe` | Europe | In-continent |
| `918-beacon-africa` | Africa | Relay-hosted |
| `918-beacon-asia` | Asia | In-continent |
| `918-beacon-oceania` | Oceania | Relay-hosted |
| `918-beacon-antarctica` | Antarctica | Relay-hosted |

Relay-hosted beacons are explicitly identified as relays. FADS does not pretend a cloud workload is physically located on a continent when it is not.

Two independent proximity/defense coordinators provide control-plane redundancy.

```text
North America ─┐
South America ─┤
Europe ────────┤
Africa ────────┤
Asia ──────────┤──> redundant global coordinators
Oceania ───────┤
Antarctica ────┘
```

---

## Attack-activated global posture

The mesh maintains a short-lived global posture derived from active defensive events:

```text
NORMAL
   ↓
HEIGHTENED
   ↓
CONTAINMENT
   ↓
CRITICAL
```

Severity is driven by local FADS verdicts:

| Local verdict | Global posture contribution |
|---|---|
| `RESTRICTED` | `HEIGHTENED` |
| `QUARANTINED` | `CONTAINMENT` |
| `TERMINATED` | `CRITICAL` |

Beacons poll redundant coordinators and use the strongest valid posture.

Global posture does **not** automatically quarantine unrelated assets. It tightens defensive policy while preserving local evidence requirements.

---

## WaterPlum / Contagious Interview defense

FADS-GATE includes a current WaterPlum profile for defensive detection of the DPRK-linked Contagious Interview software-development lure pattern.

The system evaluates already-observed telemetry such as:

- suspicious repository artifacts,
- install hooks,
- unexpected child processes,
- credential-access behavior,
- replay attempts,
- policy tampering,
- known WaterPlum IPs,
- known domains,
- known hashes,
- and related behavioral signals.

Exact IOC matches and strong TTP combinations can trigger quarantine or termination.

FADS does **not** contact suspected WaterPlum infrastructure.

See [docs/WATERPLUM.md](docs/WATERPLUM.md).

---

## Capability gateway

Detection is not the enforcement boundary.

The core FADS invariant is:

> **Protected executors consume only the capability set returned by the gateway.**

A workload can request:

```text
repo.read
network.outbound
secrets.read
capability.delegate
```

and receive only:

```text
repo.read
```

if policy strips the rest.

The capability layer supports hard denies, ordered allow/deny rules, subject matching, declared-agent constraints, per-capability risk ceilings, one-way degradation, and zero-capability termination.

---

## House of Mirrors

Suspicious or quarantined sessions can be routed away from canonical infrastructure and into a synthetic defensive environment.

House of Mirrors uses synthetic services, documentation-reserved IP ranges, inert credentials, decoy project/data graphs, canary markers, and `918-IPCTX` provenance.

Canonical 918 data and deceptive state are kept in separate namespaces.

House of Mirrors is defensive deception. It does not contain functional malware, exploit payloads, destructive commands, or attack-back logic.

---

## Signed enrollment and geo attestation

Protected endpoints can enroll into the mesh and receive signed short-lived asset tokens.

Tokens bind asset identity, platform, region, independently attested country, issuance and expiration, attestation-provider identities, salted source-IP hash, token epoch, and deployment scope.

The current geo-attestation design requires independent provider consensus and re-attests authenticated requests.

A global token epoch provides emergency revocation.

---

## Passive RF proximity layer

FADS-GATE includes a passive proximity model for enrolled sensors.

Captive-portal Wi-Fi networks may be used only as passive RF landmarks:

```text
association      NO
authentication   NO
portal traffic   NO
probe traffic    NO
Internet use     NO
```

Raw SSIDs/BSSIDs are pseudonymized locally before entering the mesh.

The global proximity graph can use HMAC-pseudonymized landmark IDs, RSSI, channel, timestamp, Echo score, enrolled asset identity, and beacon metadata.

A “jump” means the location hypothesis/control path moves between enrolled 918 anchors. It does not mean the system joins or traverses third-party Wi-Fi networks.

---

## Public threat arrays

FADS-GATE can enrich already-observed indicators with public threat intelligence.

Supported integrations include GreyNoise community/Internet-observation context, ThreatFox IOC intelligence when configured, WaterPlum-specific indicators, and internal FADS evidence.

The output distinguishes:

```text
device / IP
   ↓
infrastructure
   ↓
malware family
   ↓
operational cluster
   ↓
public alias
```

It does **not** automatically turn an IP address into a named human identity.

Autonomous quarantine requires stronger corroboration than autonomous restriction.

---

## Evidence and auditability

FADS-GATE generates `918-IPCTX/1` evidence metadata and supports:

- SHA-256 content hashing,
- HMAC evidence signatures,
- append-only sequence numbers,
- previous-record hash linkage,
- chain hashes,
- replay-resistant ledger ingestion,
- Postgres-backed persistence,
- and whole-chain verification.

The evidence service exposes health data such as:

```json
{
  "status": "operational",
  "database_bound": true,
  "chain": {
    "valid": true,
    "checked": 0,
    "head": "GENESIS"
  }
}
```

A ledger outage does not block containment. It is reported separately as degraded evidence persistence.

---

## Defensive benchmark and release gates

FADS-GATE contains deterministic security regression scenarios covering clean baseline behavior, suspicious executable/install-hook behavior, credential access, published WaterPlum indicators, replay, policy tampering, capability stripping, and excluded-jurisdiction handling.

Run:

```bash
fads-benchmark
```

Release readiness is machine-enforced:

```bash
fads-release-gate --mode test
fads-release-gate --mode production
```

The repository distinguishes:

- **TEST_READY** — deterministic defensive regressions pass.
- **PRODUCTION_READY** — live infrastructure, coordinators, evidence storage, signing, keying, and version-consistency checks also pass.

This is deliberate: FADS should not claim a stronger deployment state than the evidence supports.

---

## Current release status

### v1.3

Current release:

```text
Release v1.3 attack-activated global defense
```

Verified repository gates include:

- normal CI,
- 918 WaterPlum Defense,
- World-Use Readiness.

The live architecture has been exercised as a globally distributed defensive test system.

### What this does **not** claim

FADS-GATE is **not yet independently certified as the strongest EDR/XDR platform in the world**.

That claim would require third-party adversarial evaluation against established enterprise systems.

The repository therefore describes itself as:

> **A real, deployed, experimental global defensive architecture with attack-activated containment and evidence-preserving capability control.**

---

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

Run the WaterPlum/FADS service:

```bash
fads-waterplum
```

Run the Universal Sensor:

```bash
fads-universal-sensor --token-file /path/to/fads.asset
```

Run the passive proximity client:

```bash
fads-proximity-jumper --help
```

Run the benchmark:

```bash
fads-benchmark
```

Run release readiness:

```bash
fads-release-gate --mode test
```

---

## Repository map

```text
src/fads_gate/
├── asset_auth.py
├── autonomous.py
├── beacon_sync.py
├── beacon_sync_auth.py
├── benchmark.py
├── continent_beacons.py
├── defense_posture.py
├── endpoint_sensor.py
├── evidence_ledger.py
├── evidence_signing.py
├── geo_attestation.py
├── proximity_coordinator.py
├── proximity_jumper.py
├── public_threat_arrays.py
├── release_gate.py
├── server.py
├── waterplum.py
└── watchdog.py
```

Documentation lives under [docs/](docs/).

---

## Security boundaries

FADS-GATE is built for defensive use.

It does not require attack-back operations, exploitation of third-party systems, credential theft, persistence on third-party devices, destructive actions, captive-portal bypass, covert authentication, or functional malware.

The intended boundary is:

```text
observe authorized telemetry
        ↓
evaluate
        ↓
reduce capability
        ↓
contain local asset
        ↓
preserve evidence
        ↓
raise global defensive posture
```

---

## 918 Technologies

FADS-GATE is a 918 Technologies defense-system project.

**Mission:** build defensive AI infrastructure that can observe, reason, reduce capability, contain compromised execution, preserve evidence, and improve its defensive posture without requiring attack-back behavior.

The project remains under active development.

---

## Responsible testing

Use FADS-GATE only on systems, accounts, networks, agents, and sensors you own or are authorized to defend.

The seven-continent mesh is a control-plane architecture. It does not grant authorization over third-party infrastructure.

---

**918 Technologies — FADS-GATE v1.3**

**Detect. Restrict. Contain. Preserve. Coordinate.**
