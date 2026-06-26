"""IP services and command registrations for VVRP."""


def IP_register_commands(*args, **kwargs):
    from .commands import IP_register_commands as _IP_register_commands

    return _IP_register_commands(*args, **kwargs)


__all__ = ["IP_register_commands"]
