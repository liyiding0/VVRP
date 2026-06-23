# Huawei VRP Command Study Notes

These notes summarize VVRP engineering takeaways from the local Huawei NE5000E V800R025C10SPC500 configuration guide PDFs. They are not a copy of the manuals.

## Source Manuals

- `NE5000E V800R025C10SPC500 配置指南 接口与链路.pdf`
- `NE5000E V800R025C10SPC500 配置指南 IP业务.pdf`
- `NE5000E V800R025C10SPC500 配置指南 IP路由.pdf`
- `NE5000E V800R025C10SPC500 配置指南 局域网与城域网接入.pdf`
- `指导手册-eNSP Pro V100R001C00.pdf`
- `NE5000E V800R022C00SPC500 配置指南.pdf`

Extracted table-of-contents notes are under `context/replays/vrp_manual_notes/`.

The V800R022 `配置指南.pdf` is a large combined guide and should be treated as the broad command-family index. The V800R025 split PDFs are useful for focused implementation work.

## CLI Shape

VRP command design is strongly view-oriented:

- User view: operational inspection and simple tools.
- System view: global configuration.
- Interface view: per-interface configuration.
- Protocol views: routing protocol configuration such as OSPF, IS-IS, BGP, RIP.
- Feature views: L2/L3 feature-specific contexts.

VVRP should keep this structure:

- `show` can remain the current Cisco-like alias while `display` can be added later as a VRP-style alias.
- `config` currently maps to VRP `system-view`.
- `interface <name>` should be the normal VVRP interface view.
- Hidden host/debug commands should stay outside normal VRP-like user flow.

## IFNET Direction

The interface manual treats interfaces as managed system objects. That matches the VVRP design decision:

- IFNET should expose only VVRP-visible interfaces.
- Host import belongs below IFNET, like platform discovery or driver installation.
- RM must not depend on import provenance.
- Interface management events should report materialized interface facts to RM/IM.

Near-term VVRP interface commands should prioritize:

- `interface <name>`
- `shutdown`
- `no shutdown` for now, with possible future `undo shutdown` alias
- `mtu <value>`
- `mac-address <value>`
- `show/display interfaces`
- `show/display interfaces brief`

## IP Direction

IP service configuration is interface-centered for addresses and globally scoped for IP behavior.

Near-term VVRP IP commands should prioritize:

- `ip address <address> <mask-or-prefix>`
- `undo ip address` or `no ip address` compatibility path
- DHCP client enable/disable on Ethernet interfaces
- ICMP ping as an operational command
- ARP table display and aging behavior

IP owns address facts and should publish address events to RM/IM. IFNET should not include IP ownership logic beyond carrying current interface address snapshots for compatibility.

## RM And FIB Direction

The IP routing guide separates route sources and route usage:

- connected routes
- static routes
- dynamic protocol routes
- route policy and filtering
- routing table display

For VVRP, the immediate route-management path should be:

```text
IFNET facts + IP address facts
        -> EventBus
        -> RM.IM route-interface view
        -> RM connected/static route calculation
        -> FIB forwarding resolution
```

Command priorities:

- `show/display ip routing-table`
- `ip route-static <destination> <mask-or-prefix> <next-hop-or-interface>`
- connected route generation from RM.IM
- longest-prefix route lookup
- FIB resolution to data-plane interface/device

## LAN/MAN Direction

The LAN/MAN access guide is useful later for Ethernet and L2 features. Keep these out of the immediate routing core until IFNET, IP, RM, FIB, ARP, and ICMP are stable.

Likely future modules:

- `src.L2.MAC`
- `src.L2.BD`
- `src.L2.EVC`
- `src.IFNET.EthTrunk`
- `src.Overlay.VXLAN`

## eNSP Pro Direction

The eNSP Pro guide is useful for VVRP as an operator-experience reference rather than a protocol reference.

Near-term takeaways:

- Keep topology/lab workflows easy to replay.
- Prefer deterministic CLI examples that can be copied into saved configurations.
- Keep virtual device identity, interface naming, and host binding visible.
- Make future VVRP labs reproducible from context/session records.

## Naming Rule For New Code

New module-local functions and locals should use module prefixes:

- `RM_...`
- `RM_IM_...`
- `IFNET_...`
- `IP_...`
- `ARP_...`
- `ICMP_...`

New globals should use `g_...`, including module prefix:

- `g_RM_...`
- `g_RM_IM_...`
- `g_IP_...`

Existing names can remain until touched for functional reasons.
