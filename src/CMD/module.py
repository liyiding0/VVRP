from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path

from src.VVRP.core import VVRP_Core

from .examples import build_default_registry
from .interactive import run_interactive_cli


@dataclass
class CMD_Module:
    core: VVRP_Core
    history_file: str | Path | None = None
    saved_configuration_file: str | Path | None = None

    def __post_init__(self) -> None:
        self._exit_code = 0
        self._thread = threading.Thread(
            target=self._run,
            name="vvrp-cmd",
        )

    def start(self) -> None:
        self._thread.start()

    def join(self) -> int:
        self._thread.join()
        return self._exit_code

    def stop(self) -> None:
        self.core.stop()

    def _run(self) -> None:
        registry = build_default_registry(runtime=self.core.runtime)
        self._exit_code = run_interactive_cli(
            registry,
            hostname=self.core.hostname,
            history_file=self.history_file,
            saved_configuration_file=self.saved_configuration_file,
            state=self.core.state,
        )


def CMD_start_module(
    core: VVRP_Core,
    *,
    history_file: str | Path | None = None,
    saved_configuration_file: str | Path | None = None,
) -> int:
    module = CMD_Module(
        core,
        history_file=history_file,
        saved_configuration_file=saved_configuration_file,
    )
    module.start()
    try:
        return module.join()
    finally:
        module.stop()
