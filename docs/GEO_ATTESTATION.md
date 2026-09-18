# Independent Geographic Attestation

FADS-GATE v0.6 removes operator-declared country as an authorization input.

## Enrollment

The server derives the source IP from the reverse-proxy forwarding chain, selects the rightmost globally routable address, and performs country lookup through at least two independent geolocation providers.

Default providers:

- ipwho.is
- ipapi.co

Enrollment succeeds only when both providers return the same two-letter country code.

The operator may optionally supply an expected country. It is used only as an assertion check. It cannot override the attested country.

## Token binding

The v2 asset token contains:

- asset id
- attested country
- declared operational region
- platform
- issue and expiration timestamps
- salted SHA-256 hash of the attested source IP
- attestation timestamp
- attestation-provider identities
- `GLOBAL_EXCEPT_KP` scope

The raw public IP is not embedded in the token.

## Evaluation

Every authenticated `POST /v2/evaluate` request is geographically re-attested.

Fail-closed outcomes:

- provider disagreement -> `503 geo_attestation_unavailable / NO_OPERATION`
- fewer than two successful providers -> `503 geo_attestation_unavailable / NO_OPERATION`
- token country differs from current attested country -> `403 geo_attestation_drift / NO_OPERATION`
- attested country is `KP` -> `451 geo_excluded / NO_OPERATION`
- invalid or expired token -> `401 asset_auth`

A changed public IP inside the same country is permitted. Country drift requires re-enrollment.

## Privacy

A deployment-specific `FADS_GEO_HASH_SALT` is required. FADS-GATE stores or returns only the salted hash of the source IP in the signed enrollment identity. Request logging remains disabled by the built-in HTTP handler.

## Configuration

Required server environment variables:

```text
FADS_TOKEN_KEY
FADS_ENROLLMENT_KEY
FADS_GEO_HASH_SALT
```

Optional:

```text
FADS_GEO_PROVIDERS=https://provider-a/{ip},https://provider-b/{ip}
FADS_TOKEN_TTL_SECONDS=2592000
```

The geo-provider list must contain at least two providers.
