# Arsenal Capability Registry

FADS-GATE v1.4 adds a metadata-only capability registry for external OSINT and
security catalogs such as rawfilejson/awesome-osint-arsenal.

The registry does not install, import, execute, clone, probe with, or contact
remote systems through any catalog tool. Catalog membership is not trust.

## Security model

Every imported entry is classified into a FADS/BEACON execution policy.

- DEFENSIVE_SENSOR_OR_THREAT_INTEL -> defensive sandbox candidate
- DFIR_OR_REVERSE_ENGINEERING -> enrolled-asset analysis only
- PUBLIC_IDENTITY_OSINT -> intelligence review only
- ACTIVE_RECON_OR_ENUMERATION -> explicit authorization only
- OFFENSIVE_OR_CREDENTIAL -> deny autonomous execution
- UNCLASSIFIED -> default deny

The registry enforces these invariants:

- default deny
- no autonomous remote contact
- no autonomous authority for offensive capabilities
- no execution material imported from the catalog
- FADS enforcement still requires local evidence
- BEACON may use catalog metadata for source/evidence correlation only

## Import

Fetch or vendor the third-party tools.json separately, then import only its metadata:

    fads-arsenal-registry import --input ./tools.json --output ./arsenal-registry.json --source-commit <pinned-upstream-commit>

Inspect one classified tool:

    fads-arsenal-registry inspect --registry ./arsenal-registry.json --tool-id zeek

The output records a SHA-256 hash of the source catalog and marks the source as
third-party. A registry hash is provenance/integrity metadata; it is not proof
that an upstream tool is safe.

## Integration boundary

    third-party tools.json
            |
            v
    Arsenal Capability Registry
            |
            +--> BEACON: catalog-reference / IOC-evidence correlation
            |
            +--> FADS: policy candidate only
                       |
                       v
                 local evidence
                       |
                       v
                 enforcement decision

No tool becomes executable merely because it exists in the registry.
