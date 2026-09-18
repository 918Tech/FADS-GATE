# FADS Guardian / Capability Gateway Architecture

## Security objective

FADS-GATE is a defensive mediation layer between an actor requesting tools and the tools themselves. Its first enforceable invariant is:

> No requested capability reaches an executor unless the gateway returns it in `granted`.

This implementation does not attempt to guess whether arbitrary human traffic is AI. `FADSGuardian` only recognizes explicit agent evidence at the trust boundary (declared kind/flag, tool manifest, and known agent protocol markers). That keeps detection deterministic and auditable.

## Data flow

```text
Incoming subject + manifest
          |
          v
+--------------------+
|   FADS Guardian    |  explicit agent evidence
+--------------------+
          |
          v
+--------------------+
| Capability Policy  |  hard deny -> ordered rules -> default
+--------------------+
          |
          v
+--------------------+
| Capability Gateway |  requested -> granted + stripped
+--------------------+
      |          |
      |          +----------------> hash-chained audit JSONL
      v
 downstream executor receives only `granted`
```

## Enforcement rules

1. **Default deny is the recommended mode.** Unknown capabilities receive elevated risk and are denied unless an explicit rule admits them.
2. **Hard denies are non-overridable by ordinary rules.** They are intended for capability classes such as secrets access or delegation.
3. **First matching rule wins.** Put narrow deny rules before broader allow rules.
4. **Capability reduction is explicit.** `strip_manifest()` returns a new manifest whose capability list contains only the allowed subset.
5. **Audit events are tamper-evident, not tamper-proof.** Each JSONL record includes the SHA-256 hash of the previous record.

## Trust boundaries

The gateway must execute outside the untrusted agent process. An agent-controlled process must not be able to replace the policy file, bypass the gateway, or call protected executors directly. Production deployments should isolate the gateway with OS/container permissions and route all privileged tool calls through it.

## Planned next interfaces

- Signed subject attestations and policy bundles.
- Executor adapters for shell, filesystem, GitHub, HTTP, and device RPC.
- Expiring capability leases with nonce/replay protection.
- 918-IPCTX evidence envelopes for audit/provenance events.
- Runtime metrics and policy decision telemetry.
