"""IP services and command registrations for VVRP."""

from .input import IP_handle_local_ipv4_packet


def IP_register_commands(*args, **kwargs):
    from .commands import IP_register_commands as _IP_register_commands

    return _IP_register_commands(*args, **kwargs)


__all__ = ["IP_handle_local_ipv4_packet", "IP_register_commands"]
