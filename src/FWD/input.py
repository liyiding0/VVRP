from __future__ import annotations

from src.CCmd.models import CliContext
from src.ETHERNET.input import ETHERNET_InputHandler
from src.IFNET.models import NetworkInterface

from .models import FWD_InputHandler


class FWD_InputDispatcher:
    def __init__(
        self,
        FWD_ctx: CliContext,
        *,
        FWD_handlers: dict[str, FWD_InputHandler] | None = None,
    ) -> None:
        self.FWD_ctx = FWD_ctx
        self.FWD_handlers = dict(FWD_handlers or {})

    def FWD_register_handler(self, FWD_interface_kind: str, FWD_handler: FWD_InputHandler) -> None:
        self.FWD_handlers[FWD_interface_kind] = FWD_handler

    def FWD_handle_frame(
        self,
        FWD_interface: NetworkInterface,
        FWD_frame: bytes,
    ) -> None:
        FWD_handler = self.FWD_handlers.get(FWD_interface.kind)
        if FWD_handler is None:
            return
        FWD_handler.FWD_handle_frame(FWD_interface, FWD_frame)


class FWD_EthernetInputHandler:
    def __init__(
        self,
        FWD_ctx: CliContext,
        FWD_send_frame,
    ) -> None:
        self.FWD_ethernet_input = ETHERNET_InputHandler(FWD_ctx, FWD_send_frame)

    def FWD_handle_frame(
        self,
        FWD_interface: NetworkInterface,
        FWD_frame: bytes,
    ) -> None:
        self.FWD_ethernet_input.ETHERNET_handle_frame(FWD_interface, FWD_frame)


def FWD_default_input_dispatcher(
    FWD_ctx: CliContext,
    *,
    FWD_ethernet_send_frame=None,
) -> FWD_InputDispatcher:
    FWD_dispatcher = FWD_InputDispatcher(FWD_ctx)
    if FWD_ethernet_send_frame is not None:
        FWD_dispatcher.FWD_register_handler(
            "ethernet",
            FWD_EthernetInputHandler(FWD_ctx, FWD_ethernet_send_frame),
        )
    return FWD_dispatcher
