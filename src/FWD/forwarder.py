from __future__ import annotations

from collections.abc import Callable

from src.FIB import FIBEntry
from src.IFNET.models import NetworkInterface

from .ethernet import FWD_EthernetOutputHandler
from .models import FWD_OutputHandler, FWD_Result
from .null import FWD_NullOutputHandler


class FWD_Forwarder:
    def __init__(
        self,
        FWD_state: dict,
        *,
        FWD_interfaces_provider: Callable[[], tuple[NetworkInterface, ...]] | None = None,
        FWD_handlers: dict[str, FWD_OutputHandler] | None = None,
    ) -> None:
        self.FWD_state = FWD_state
        self.FWD_interfaces_provider = FWD_interfaces_provider or (lambda: ())
        self.FWD_handlers = dict(FWD_handlers or {})

    def FWD_register_handler(self, FWD_interface_kind: str, FWD_handler: FWD_OutputHandler) -> None:
        self.FWD_handlers[FWD_interface_kind] = FWD_handler

    def FWD_send_packet(self, FWD_packet: bytes, FWD_route: FIBEntry) -> FWD_Result:
        FWD_interface = self._FWD_interface_for_route(FWD_route)
        if FWD_interface is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=f"% FWD interface not found: {FWD_route.out_if_name}",
                FWD_route=FWD_route,
            )
        FWD_handler = self.FWD_handlers.get(FWD_interface.kind)
        if FWD_handler is None:
            return FWD_Result(
                FWD_ok=False,
                FWD_message=f"% FWD unsupported interface type: {FWD_interface.kind}",
                FWD_route=FWD_route,
            )
        return FWD_handler.FWD_send_packet(FWD_packet, FWD_route, FWD_interface)

    def _FWD_interface_for_route(self, FWD_route: FIBEntry) -> NetworkInterface | None:
        for FWD_interface in self.FWD_interfaces_provider():
            if FWD_route.out_if_index is not None and FWD_interface.ifnet_index == FWD_route.out_if_index:
                return FWD_interface
            if FWD_interface.name == FWD_route.out_if_name:
                return FWD_interface
        return None


def FWD_default_forwarder(
    FWD_state: dict,
    *,
    FWD_interfaces_provider: Callable[[], tuple[NetworkInterface, ...]] | None = None,
    FWD_ethernet_port_provider=None,
    FWD_arp_table=None,
    FWD_debug_ctx=None,
) -> FWD_Forwarder:
    FWD_forwarder = FWD_Forwarder(
        FWD_state,
        FWD_interfaces_provider=FWD_interfaces_provider,
    )
    FWD_forwarder.FWD_register_handler(
        "ethernet",
        FWD_EthernetOutputHandler(
            FWD_state,
            FWD_port_provider=FWD_ethernet_port_provider,
            FWD_arp_table=FWD_arp_table,
            FWD_debug_ctx=FWD_debug_ctx,
        ),
    )
    FWD_forwarder.FWD_register_handler("null", FWD_NullOutputHandler())
    return FWD_forwarder
