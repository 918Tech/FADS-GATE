# 918 Public Threat Arrays

FADS-GATE v0.9 adds public Internet-observation and threat-intelligence arrays as a defensive enrichment layer for already-observed indicators.

## Purpose

The system tracks malicious devices and infrastructure in the network-security sense:

- malicious public IP infrastructure
- command-and-control endpoints
- malware distribution infrastructure
- botnet/scanner nodes
- IOC clusters and malware-family labels

It does not identify a private person from an IP address and does not perform physical-person tracking.

## Sources

### GreyNoise Community API

Used for public IP observations and classification:

- whether the IP has been observed scanning the Internet
- malicious/benign/unknown classification
- RIOT known-benign-service context
- organization/name context when available

The unauthenticated Community API is rate limited. `GREYNOISE_API_KEY` is optional and raises the available lookup allowance when an eligible key is configured.

### ThreatFox

Used for exact IOC lookups and threat-cluster context when `THREATFOX_AUTH_KEY` is configured:

- IOC type
- threat type
- malware family
- tags
- confidence
- first/last seen timestamps
- public reference

## Authenticated API

```text
POST /v2/threat-arrays/enrich
Authorization: Bearer <geo-attested 918 asset token>
```

Example body:

```json
{
  "observables": {
    "ips": ["198.51.100.1"],
    "domains": ["example.invalid"],
    "sha256": ["..."]
  }
}
```

Only indicators that an enrolled 918 system has already observed should be submitted.

## Output

```text
918-PUBLIC-THREAT-ARRAYS/1
sources_used
findings[]
malicious_infrastructure[]
threat_clusters[]
confidence
errors[]
personal_identity_inference=false
physical_person_tracking=false
```

An external feed label is evidence from that feed, not independent proof of a human operator's identity. BEACON must preserve the distinction between infrastructure attribution, operational-cluster attribution, aliases, and personal identity.
