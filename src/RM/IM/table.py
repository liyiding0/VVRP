from __future__ import annotations

from dataclasses import dataclass, replace

from src.events import VVRP_EventBus
from src.IFNET.models import InterfaceAddress, NetworkInterface

from .models import RM_IM_Interface


g_RM_IM_TABLE_STATE_KEY = "rm.im.interfaces"


@dataclass(frozen=True)
class RM_IM_InterfaceChanged:
    interface: NetworkInterface


@dataclass(frozen=True)
class RM_IM_InterfaceDeleted:
    name: str


@dataclass(frozen=True)
class RM_IM_InterfaceAddressAdded:
    name: str
    address: InterfaceAddress


class RM_IM_InterfaceTable:
    def __init__(self) -> None:
        self._RM_IM_interfaces: dict[str, RM_IM_Interface] = {}

    def RM_IM_upsert(self, RM_IM_interface: RM_IM_Interface) -> None:
        self._RM_IM_interfaces[RM_IM_interface.name] = RM_IM_interface

    def RM_IM_delete(self, RM_IM_name: str) -> None:
        self._RM_IM_interfaces.pop(RM_IM_name, None)

    def RM_IM_get(self, RM_IM_name: str) -> RM_IM_Interface | None:
        return self._RM_IM_interfaces.get(RM_IM_name)

    def RM_IM_list(self) -> tuple[RM_IM_Interface, ...]:
        return tuple(self._RM_IM_interfaces[RM_IM_name] for RM_IM_name in sorted(self._RM_IM_interfaces))


def RM_IM_interface_table_from_ifnet(RM_IM_interfaces: tuple[NetworkInterface, ...]) -> RM_IM_InterfaceTable:
    RM_IM_table = RM_IM_InterfaceTable()
    for RM_IM_interface in RM_IM_interfaces:
        RM_IM_table.RM_IM_upsert(
            RM_IM_from_ifnet_interface(RM_IM_interface, RM_IM_include_addresses=True)
        )
    return RM_IM_table


def RM_IM_from_ifnet_interface(
    RM_IM_interface: NetworkInterface,
    RM_IM_include_addresses: bool = False,
) -> RM_IM_Interface:
    return RM_IM_Interface(
        name=RM_IM_interface.name,
        ifnet_index=RM_IM_interface.ifnet_index,
        kind=RM_IM_interface.kind,
        is_up=RM_IM_interface.is_up,
        mac_address=RM_IM_interface.mac_address,
        mtu=RM_IM_interface.mtu,
        addresses=RM_IM_interface.addresses if RM_IM_include_addresses else (),
        os_id=RM_IM_interface.os_id,
        os_aliases=RM_IM_interface.os_aliases,
    )


def RM_IM_apply_interface_changed(
    RM_IM_table: RM_IM_InterfaceTable,
    RM_IM_event: RM_IM_InterfaceChanged,
) -> None:
    RM_IM_existing = RM_IM_table.RM_IM_get(RM_IM_event.interface.name)
    RM_IM_updated = RM_IM_from_ifnet_interface(RM_IM_event.interface)
    if RM_IM_existing is not None:
        RM_IM_updated = replace(RM_IM_updated, addresses=RM_IM_existing.addresses)
    RM_IM_table.RM_IM_upsert(RM_IM_updated)


def RM_IM_apply_interface_deleted(
    RM_IM_table: RM_IM_InterfaceTable,
    RM_IM_event: RM_IM_InterfaceDeleted,
) -> None:
    RM_IM_table.RM_IM_delete(RM_IM_event.name)


def RM_IM_apply_interface_address_added(
    RM_IM_table: RM_IM_InterfaceTable,
    RM_IM_event: RM_IM_InterfaceAddressAdded,
) -> None:
    RM_IM_interface = RM_IM_table.RM_IM_get(RM_IM_event.name)
    if RM_IM_interface is None:
        return
    RM_IM_addresses = tuple(
        RM_IM_address
        for RM_IM_address in RM_IM_interface.addresses
        if RM_IM_address != RM_IM_event.address
    )
    RM_IM_table.RM_IM_upsert(
        replace(RM_IM_interface, addresses=(*RM_IM_addresses, RM_IM_event.address))
    )


def RM_IM_register_event_handlers(
    RM_IM_bus: VVRP_EventBus,
    RM_IM_table: RM_IM_InterfaceTable,
) -> None:
    RM_IM_bus.VVRP_subscribe(
        RM_IM_InterfaceChanged,
        lambda RM_IM_event: RM_IM_apply_interface_changed(RM_IM_table, RM_IM_event),
    )
    RM_IM_bus.VVRP_subscribe(
        RM_IM_InterfaceDeleted,
        lambda RM_IM_event: RM_IM_apply_interface_deleted(RM_IM_table, RM_IM_event),
    )
    RM_IM_bus.VVRP_subscribe(
        RM_IM_InterfaceAddressAdded,
        lambda RM_IM_event: RM_IM_apply_interface_address_added(RM_IM_table, RM_IM_event),
    )
