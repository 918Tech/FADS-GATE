# 918 Continent Beacon Mesh

The continent mesh gives the passive proximity jumper a named beacon for every continent.

## Beacon identities

| Logical continent | Beacon ID | Physical host region | Hosting continent | Relay hosted |
| --- | --- | --- | --- | --- |
| North America | 918-beacon-north-america | Ohio | North America | no |
| South America | 918-beacon-south-america | Virginia | North America | yes |
| Europe | 918-beacon-europe | Frankfurt | Europe | no |
| Africa | 918-beacon-africa | Frankfurt | Europe | yes |
| Asia | 918-beacon-asia | Singapore | Asia | no |
| Oceania | 918-beacon-oceania | Singapore | Asia | yes |
| Antarctica | 918-beacon-antarctica | Oregon | North America | yes |

A relay-hosted beacon is a logical continent routing and evidence node whose current cloud host is outside the logical continent. It must never be represented as a physical in-continent sensor.

## Passive-only role

Continent beacons receive only:

- enrolled asset identity
- pseudonymized captive-portal landmark IDs
- RSSI/channel/timestamp
- Echo proximity score
- 918-IPCTX evidence metadata

They do not:

- associate to Wi-Fi networks
- authenticate to captive portals
- send portal traffic
- probe third-party access points
- collect raw SSIDs/BSSIDs centrally

## Jump semantics

A jump means the location hypothesis advances from one enrolled 918 anchor to another when:

1. the anchors share passive portal landmarks,
2. the candidate observation is fresh,
3. the candidate has a higher Echo score,
4. the probabilistic world model ranks it highest among reachable enrolled anchors.

The jump is a control-plane routing decision only. No Wi-Fi connection is created.
