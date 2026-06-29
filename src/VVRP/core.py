from __future__ import annotations

from dataclasses import dataclass, field

from .models import VVRP_RuntimeContext
from .runtime import VVRP_Runtime, VVRP_create_runtime


@dataclass
class VVRP_Core:
    hostname: str = "Router"
    runtime: VVRP_Runtime = field(default_factory=VVRP_create_runtime)
    state: dict = field(default_factory=dict)
    started: bool = False

    def start(self) -> str:
        VVRP_status = self.runtime.VVRP_refresh_control_plane(
            VVRP_RuntimeContext(state=self.state)
        )
        self.started = True
        return VVRP_status

    def stop(self) -> None:
        self.runtime.VVRP_shutdown()
        self.started = False


def VVRP_create_core(
    *,
    hostname: str = "Router",
    runtime: VVRP_Runtime | None = None,
) -> VVRP_Core:
    return VVRP_Core(
        hostname=hostname,
        runtime=runtime or VVRP_create_runtime(),
    )
