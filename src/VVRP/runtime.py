from __future__ import annotations

from dataclasses import dataclass

from src.ARP import ArpTable
from src.ARP.commands import ARP_TABLE_STATE_KEY
from src.DPlane import DPlane_Backend, DPlane_create_backend
from src.DPlane.backend import DPlane_AdminProviderAdapter, DPlane_InterfaceProviderAdapter
from src.DPlane.input import DPlane_PacketInputService
from src.DPlane.ip_config import DPlane_DhcpClientProvider, DPlane_StaticIpv4Provider
from src.FIB import FIB_sync_active_routes
from src.FWD import FWD_default_forwarder
from src.IFNET.admin import InterfaceAdminProvider
from src.IFNET.discovery import InterfaceProvider
from src.IFNET.interfaces import IFNET_ethernet_interface_snapshots
from src.IFNET.inventory import get_ifnet_manager
from src.IP.dhcp import IP_DhcpClientProvider
from src.IP.input import IP_handle_local_ipv4_packet
from src.IP.static import IP_StaticIpv4Provider
from src.RM.commands import RM_refresh_connected_routes_from_interfaces
from .models import VVRP_RuntimeContext


g_VVRP_RUNTIME_STATE_KEY = "vvrp.runtime"


@dataclass
class VVRP_Runtime:
    VVRP_ifnet_provider: InterfaceProvider | None = None
    VVRP_ifnet_admin_provider: InterfaceAdminProvider | None = None
    VVRP_dhcp_provider: IP_DhcpClientProvider | None = None
    VVRP_static_ipv4_provider: IP_StaticIpv4Provider | None = None
    VVRP_arp_table: ArpTable | None = None
    VVRP_dplane_backend: DPlane_Backend | None = None

    def __post_init__(self) -> None:
        self.VVRP_dplane_backend = self.VVRP_dplane_backend or DPlane_create_backend(
            DPlane_ifnet_provider=self.VVRP_ifnet_provider,
            DPlane_admin_provider=self.VVRP_ifnet_admin_provider,
        )
        self.VVRP_ifnet_provider = self.VVRP_ifnet_provider or DPlane_InterfaceProviderAdapter(
            self.VVRP_dplane_backend
        )
        self.VVRP_ifnet_admin_provider = (
            self.VVRP_ifnet_admin_provider
            or DPlane_AdminProviderAdapter(self.VVRP_dplane_backend)
        )
        self.VVRP_dhcp_provider = self.VVRP_dhcp_provider or DPlane_DhcpClientProvider(
            self.VVRP_dplane_backend
        )
        self.VVRP_static_ipv4_provider = (
            self.VVRP_static_ipv4_provider
            or DPlane_StaticIpv4Provider(self.VVRP_dplane_backend)
        )
        self.VVRP_packet_input = DPlane_PacketInputService(
            DPlane_ifnet_provider=self.VVRP_ifnet_provider,
            DPlane_ifnet_admin_provider=self.VVRP_ifnet_admin_provider,
            DPlane_backend=self.VVRP_dplane_backend,
        )

    def VVRP_refresh_control_plane(self, VVRP_ctx):
        VVRP_runtime_ctx = self._VVRP_runtime_context(VVRP_ctx)
        self.VVRP_bind_state(VVRP_runtime_ctx.state)
        VVRP_interfaces = tuple(self.VVRP_list_ifnet_interfaces(VVRP_runtime_ctx))
        VVRP_rm_table = RM_refresh_connected_routes_from_interfaces(
            VVRP_runtime_ctx,
            lambda VVRP_current_ctx: VVRP_interfaces,
        )
        if not _VVRP_is_error_result(VVRP_rm_table):
            FIB_sync_active_routes(VVRP_runtime_ctx.state, VVRP_rm_table.RM_active_routes())
        VVRP_arp_table = VVRP_runtime_ctx.state.get(ARP_TABLE_STATE_KEY)
        if isinstance(VVRP_arp_table, ArpTable):
            VVRP_arp_table.sync_interface_entries(VVRP_interfaces)
        return self.VVRP_packet_input.DPlane_refresh(VVRP_runtime_ctx)

    def VVRP_bind_state(self, VVRP_state: dict) -> None:
        VVRP_state[g_VVRP_RUNTIME_STATE_KEY] = self
        if self.VVRP_arp_table is not None:
            VVRP_state[ARP_TABLE_STATE_KEY] = self.VVRP_arp_table

    def VVRP_list_ifnet_interfaces(self, VVRP_ctx):
        VVRP_runtime_ctx = self._VVRP_runtime_context(VVRP_ctx)
        VVRP_interfaces = get_ifnet_manager(
            VVRP_runtime_ctx.state,
            provider=self.VVRP_ifnet_provider,
            admin_provider=self.VVRP_ifnet_admin_provider,
        ).list_interfaces()
        return IFNET_ethernet_interface_snapshots(VVRP_runtime_ctx.state, VVRP_interfaces)

    def VVRP_socket_forwarder(self, VVRP_ctx):
        VVRP_runtime_ctx = self._VVRP_runtime_context(VVRP_ctx)
        return FWD_default_forwarder(
            VVRP_runtime_ctx.state,
            FWD_interfaces_provider=lambda: tuple(self.VVRP_list_ifnet_interfaces(VVRP_runtime_ctx)),
            FWD_ethernet_port_provider=lambda FWD_interface: self.VVRP_ethernet_port(
                FWD_interface
            ),
            FWD_arp_table=self.VVRP_arp_table,
            FWD_debug_ctx=VVRP_runtime_ctx,
            FWD_local_ipv4_input=lambda FWD_packet: IP_handle_local_ipv4_packet(
                VVRP_runtime_ctx.state,
                self.VVRP_list_ifnet_interfaces(VVRP_runtime_ctx),
                FWD_packet,
            ),
        )

    def VVRP_ethernet_port(self, VVRP_interface):
        VVRP_devices = self.VVRP_dplane_backend.DPlane_list_packet_devices()
        VVRP_device = self.VVRP_dplane_backend.DPlane_find_packet_device(
            VVRP_interface,
            VVRP_devices,
        )
        if VVRP_device is None:
            raise RuntimeError(f"FWD Ethernet device not found: {VVRP_interface.name}")
        VVRP_port = self.VVRP_dplane_backend.DPlane_open_packet_port(VVRP_device)
        VVRP_port.open()
        return VVRP_port

    def VVRP_shutdown(self) -> None:
        self.VVRP_packet_input.DPlane_stop()

    def _VVRP_runtime_context(self, VVRP_ctx) -> VVRP_RuntimeContext:
        if isinstance(VVRP_ctx, VVRP_RuntimeContext):
            return VVRP_ctx
        output = getattr(VVRP_ctx, "output", None)
        if output is None:
            return VVRP_RuntimeContext(state=getattr(VVRP_ctx, "state", VVRP_ctx))
        return VVRP_RuntimeContext(
            state=getattr(VVRP_ctx, "state", VVRP_ctx),
            output=output,
        )


def _VVRP_is_error_result(VVRP_value) -> bool:
    return hasattr(VVRP_value, "ok") and getattr(VVRP_value, "ok") is False


def VVRP_create_runtime(
    VVRP_ifnet_provider: InterfaceProvider | None = None,
    VVRP_ifnet_admin_provider: InterfaceAdminProvider | None = None,
    VVRP_dhcp_provider: IP_DhcpClientProvider | None = None,
    VVRP_static_ipv4_provider: IP_StaticIpv4Provider | None = None,
    VVRP_arp_table: ArpTable | None = None,
    VVRP_dplane_backend: DPlane_Backend | None = None,
) -> VVRP_Runtime:
    return VVRP_Runtime(
        VVRP_ifnet_provider=VVRP_ifnet_provider,
        VVRP_ifnet_admin_provider=VVRP_ifnet_admin_provider,
        VVRP_dhcp_provider=VVRP_dhcp_provider,
        VVRP_static_ipv4_provider=VVRP_static_ipv4_provider,
        VVRP_arp_table=VVRP_arp_table,
        VVRP_dplane_backend=VVRP_dplane_backend,
    )
