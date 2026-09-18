# 918 Universal Sensor and Asset Enrollment

The Universal Sensor enrolls participating endpoints into the 918 Global Defense Mesh and submits reduced defensive telemetry to authenticated regional evaluators.

## Security model

- Mesh scope: `GLOBAL_EXCEPT_KP`.
- Enrollment rejects assets declared with country code `KP`.
- Enrollment requires the operator-held `FADS_ENROLLMENT_KEY`.
- Successful enrollment returns a signed short-lived asset token.
- `/v2/evaluate` requires a valid Bearer asset token.
- Country, region, platform, and asset identity are derived from the signed token, not trusted from request-body claims.
- The same `FADS_TOKEN_KEY` is installed on participating mesh nodes so tokens work across regional failover.
- Source code and arbitrary file contents are not transmitted. The endpoint sensor emits reduced indicators, WaterPlum-family process markers, matching remote IPs, and selected behavioral flags.
- The system performs no active scanning of third-party systems and no contact with suspected WaterPlum infrastructure.

## Server APIs

### Enroll

```text
POST /v1/enroll
X-918-Enrollment-Key: <operator secret>
```

Body:

```json
{
  "asset_id": "asset-123",
  "country": "US",
  "region": "us-central",
  "platform": "linux"
}
```

### Authenticated evaluation

```text
POST /v2/evaluate
Authorization: Bearer <asset token>
```

## Endpoint installation

```bash
python -m pip install "git+https://github.com/918Tech/FADS-GATE.git@<approved-commit>"
```

Enroll once:

```bash
export FADS_ENROLLMENT_KEY='<operator secret>'
fads-enroll-asset \
  --asset-id host-01 \
  --country US \
  --region us-central \
  --platform linux \
  --output ~/.config/918/fads.asset
```

Run a one-shot evaluation:

```bash
fads-universal-sensor \
  --token-file ~/.config/918/fads.asset \
  --scan-root ~/src
```

Continuous mode:

```bash
fads-universal-sensor \
  --token-file ~/.config/918/fads.asset \
  --scan-root ~/src \
  --interval 60
```

Regional failover is built into the client.
