# 918 Global Defense Mesh

The 918 Global Defense Mesh extends FADS-GATE from a single regional evaluator into a federated defensive service for participating systems.

## Scope

The protection policy is `GLOBAL_EXCEPT_KP`.

- Participating systems outside North Korea may submit reduced security telemetry to the mesh.
- Assets explicitly declared with country code `KP` are returned as `OUT_OF_SCOPE` with route `NO_OPERATION`.
- Unknown country remains in scope so normal CI/CD and host telemetry can still be evaluated when geography is unavailable.
- The mesh is defensive only. It does not scan, probe, contact, attack, or redirect traffic toward suspected hostile infrastructure.

## Regional node contract

Every node exposes:

- `GET /healthz`
- `GET /v1/mesh`
- `POST /v1/evaluate`

Each response identifies:

- node id
- node region
- mesh scope
- WaterPlum profile
- 918-IPCTX evidence metadata

## Client failover

`fads-waterplum-scan` accepts repeated `--endpoint` values and attempts them in order.

Example:

```bash
fads-waterplum-scan \
  --root . \
  --endpoint https://node-us.example/v1/evaluate \
  --endpoint https://node-eu.example/v1/evaluate \
  --endpoint https://node-ap.example/v1/evaluate \
  --fail-on restricted
```

Only reduced telemetry is sent. Repository source text is not uploaded.
