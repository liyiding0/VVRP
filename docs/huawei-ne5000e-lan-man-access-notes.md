# Huawei NE5000E LAN/MAN Access Notes

Source: `D:/ktb/NE5000E V800R025C10SPC500_1.pdf`

This file is a VVRP engineering reference note, not a copy of the manual. It summarizes command families, feature boundaries, and module mapping that are useful when implementing VVRP LAN/MAN access features.

## Document Map

- Pages: 363
- Version in PDF metadata: V800R025C10SPC500, document date 2026-03-30
- Main chapter: `1 LAN and MAN access`

Key page ranges:

- MAC: p19-p30
- Ethernet interfaces: p31-p59
- Eth-Trunk: p60-p121
- QinQ: p122-p135
- EVC / BD / VBDIF: p136-p160
- MAC-Flapping: p161-p167
- VXLAN: p168-p230

## VVRP Design Takeaways

- Keep host OS interface discovery/import separate from VVRP interfaces.
  - Host/debug: `show host interfaces`, `show dplane interfaces`
  - VVRP interface plane: `show interfaces`, `interface <name>`
- Ethernet and loopback are the current VVRP scope unless explicitly expanded.
- Interface commands should fit the existing VVRP configuration model:
  - configuration command modifies candidate state first when the feature requires `commit`
  - `commit` applies candidate to running state
  - `save` writes running state to `saved-configuration`
- Do not mix OS adapter configuration with VVRP data-plane configuration unless a command is explicitly a host/debug command.

## MAC Feature Family

Main concepts:

- Static MAC entries
- Static blackhole MAC entries
- Dynamic MAC aging
- MAC learning limit
- Sticky MAC
- Per-subinterface MAC address
- MAC hopping / flapping detection

Useful command shapes to mirror later:

- `mac-address static ...`
- `mac-address blackhole ...`
- `mac-address aging-time ...`
- `mac-address learning disable`
- `display mac-address ...`
- `display mac-address aging-time`
- `display mac-limit ...`
- `reset mac-address ...`

VVRP module mapping:

- Candidate future module: `VVRP.L2.MAC`
- Data structures:
  - global MAC table
  - per-BD MAC table
  - per-interface learning state
  - entry type: dynamic, static, blackhole, sticky

## Ethernet Interface Feature Family

Main concepts:

- Physical Ethernet interface state and protocol state
- MTU
- Speed and duplex
- Shutdown / undo shutdown
- Flow control
- Loopback detection
- Subinterface traffic statistics
- 802.1Q subinterface for VLAN interworking

Useful command shapes:

- `interface <ethernet-if>`
- `shutdown`
- `undo shutdown` in Huawei; VVRP currently uses `no shutdown`
- `mtu <value>`
- `ipv6 mtu <value>`
- `speed { 10 | 100 | 1000 | auto }`
- `duplex { full | half | auto }`
- `loopback-detect enable`
- `loopback-detect block <time>`
- `statistic enable`
- `subinterface traffic-statistics enable`
- `vlan-type dot1q <vlan-id>`
- `display interface [ <interface> ]`
- `display interface brief`

VVRP module mapping:

- Existing: `VVRP.IFNET.Ethernet`
- Future L2 subinterface support should probably live beside Ethernet, with shared IFNET model extensions:
  - parent interface
  - subinterface id
  - encapsulation type
  - VLAN tag handling
  - counters

Immediate relevance:

- Our `show interfaces` should keep using Huawei-like brief columns:
  - `Interface`
  - `PHY`
  - `Protocol`
  - `InUti`
  - `OutUti`
  - `inErrors`
  - `outErrors`
- Detailed output should grow toward Huawei `display interface` style as DPlane counters become available.

## Eth-Trunk Feature Family

Main concepts:

- Link aggregation for bandwidth and reliability
- Manual load-sharing mode
- Static LACP mode
- Member interface admission and selection
- Active link count / active bandwidth thresholds
- LACP system priority, port priority, timeout, preemption
- E-Trunk for dual-homing backup scenarios

Useful command shapes:

- `interface Eth-Trunk <id>`
- `mode lacp-static`
- `trunkport <interface-type> <interface-number>`
- `trunkport <interface-type> <interface-number> mode { active | passive }`
- `least active-linknumber <number>`
- `least active-bandwidth <bandwidth>`
- `max active-linknumber <number>`
- `lacp selected { priority | speed }`
- `lacp timeout ...`
- `lacp preempt ...`
- `display eth-trunk ...`
- `display interface Eth-Trunk ...`

VVRP module mapping:

- Candidate future module: `VVRP.IFNET.EthTrunk` or `VVRP.L2.EthTrunk`
- Eth-Trunk should be an IFNET interface type, not just an L2 feature.
- Member interfaces should remain normal IFNET interfaces but gain trunk membership state.

## QinQ Feature Family

Main concepts:

- Dot1q termination: one VLAN tag
- QinQ termination: two VLAN tags
- Explicit termination and range/fuzzy termination
- 802.1p mapping/trust for terminated QinQ traffic
- Statistics and maintenance commands

Useful command shapes:

- `encapsulation dot1q-termination [ rt-protocol ]`
- `dot1q termination vid <low> [ to <high> ]`
- `encapsulation qinq-termination [ rt-protocol ]`
- `qinq termination pe-vid <pe> [ to <pe-high> ] ce-vid <ce> [ to <ce-high> ]`
- `qinq 8021p-mode ...`
- `display dot1q information termination ...`
- `display qinq information termination ...`
- `display qinq statistics ...`
- `reset qinq statistics ...`

VVRP module mapping:

- Candidate future module: `VVRP.L2.QinQ`
- QinQ belongs to subinterface / service access logic, not the base physical Ethernet interface.
- Do not implement VPN-related variants unless explicitly requested.

## EVC / BD / VBDIF Feature Family

Main concepts:

- BD: bridge-domain, a Layer 2 broadcast domain
- EVC service instance: classifier and action on an interface/subinterface
- Encapsulation matching:
  - default
  - untag
  - dot1q
  - qinq
- Rewrite action:
  - push
  - pop single/double
  - map 1-to-1, 1-to-2, 2-to-1, 2-to-2
  - swap
- VBDIF: Layer 3 interface bound to a BD

Useful command shapes:

- `bridge-domain <bd-id>`
- `service-instance <id>`
- `encapsulation default`
- `encapsulation untag`
- `encapsulation dot1q vid ...`
- `encapsulation qinq vid ...`
- `rewrite push ...`
- `rewrite pop single`
- `rewrite pop double`
- `rewrite map ...`
- `rewrite swap`
- `bridge-domain <bd-id>` under service access view
- `interface vbdif <bd-id>`
- `ip address <ip-address> { <mask> | <mask-length> } [ sub ]`
- `display bridge-domain ...`
- `display ethernet uni information ...`

VVRP module mapping:

- Candidate future modules:
  - `VVRP.L2.BD`
  - `VVRP.L2.EVC`
  - `VVRP.IFNET.VBDIF`
- VBDIF should be modeled as an IFNET L3 logical interface.
- BD forwarding should consume MAC table services from the MAC module.

## MAC-Flapping Feature Family

Main concepts:

- Detect MAC movement between interfaces or inside a BD.
- Optionally block traffic or report alarms when loops are suspected.

Useful command shapes:

- `loop-detect eth-loop ...`
- `display loop-detect eth-loop ...`

VVRP module mapping:

- Candidate future module: `VVRP.L2.LoopDetect`
- Depends on MAC learning events and interface/BD membership.

## VXLAN Feature Family

Main concepts:

- NVE
- VTEP
- VNI
- BD-to-VNI mapping
- Head-end replication for static VXLAN
- BGP EVPN control-plane variants
- VBDIF as Layer 3 gateway

Useful command shapes:

- `active port-vxlan ...`
- `bridge-domain <bd-id>`
- `vxlan vni <vni-id>`
- `vxlan vni <vni-id> split-horizon-mode`
- `interface nve <nve-number>`
- `source <ip-address>`
- `vni <vni-id> head-end peer-list ...`
- `display vxlan vni ...`
- `display vxlan peer ...`
- `display interface nve ...`

VVRP module mapping:

- Candidate future modules:
  - `VVRP.Overlay.VXLAN`
  - `VVRP.Overlay.NVE`
  - `VVRP.L2.BD`
- VXLAN should not be started before the base L2 bridge-domain, MAC learning, and IFNET logical interface model are stable.
- EVPN and VPN-instance variants should stay out of scope unless explicitly requested.

## Near-Term VVRP Implementation Priority

Suggested order:

1. Finish `show interfaces` for VVRP imported Ethernet/Loopback interfaces.
2. Normalize VVRP interface configuration entry:
   - `interface <name>`
   - imported interface only
   - dynamic command validation
3. Add Ethernet interface attributes:
   - MTU in running/saved config
   - speed/duplex as VVRP data-plane settings, not host OS settings
   - counters placeholder wired to DPlane later
4. Add Ethernet subinterface model:
   - `<parent>.<sub-id>`
   - `vlan-type dot1q <vlan-id>`
   - per-subinterface IP address
5. Add L2 MAC table skeleton:
   - dynamic learning table
   - static/blackhole entries
   - show/reset commands
6. Add bridge-domain skeleton before QinQ/EVC/VXLAN.

