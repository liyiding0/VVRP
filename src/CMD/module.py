from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from src.VVRP.core import VVRP_Core
from src.VVRP.interrupt import VVRP_request_interrupt

from .banner import CMD_wait_for_login
from .examples import build_default_registry
from .interactive import run_interactive_cli


@dataclass
class CMD_Module:
    core: VVRP_Core
    history_file: str | Path | None = None
    saved_configuration_file: str | Path | None = None
    CMD_on_ready: Callable[[], None] | None = None

    def __post_init__(self) -> None:
        self._exit_code = 0
        self._completed = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="vvrp-cmd",
        )

    def start(self) -> None:
        self._thread.start()

    def join(self) -> int:
        while not self._completed.is_set():
            try:
                self._completed.wait(0.1)
            except KeyboardInterrupt:
                VVRP_request_interrupt(self.core.state)
        self._thread.join()
        return self._exit_code

    def stop(self) -> None:
        self.core.stop()

    def _run(self) -> None:
        try:
            registry = build_default_registry(runtime=self.core.runtime)
            if self.CMD_on_ready is not None:
                self.CMD_on_ready()
            CMD_wait_for_login()
            self._exit_code = run_interactive_cli(
                registry,
                hostname=self.core.hostname,
                history_file=self.history_file,
                saved_configuration_file=self.saved_configuration_file,
                state=self.core.state,
            )
        finally:
            self._completed.set()


def CMD_start_module(
    core: VVRP_Core,
    *,
    history_file: str | Path | None = None,
    saved_configuration_file: str | Path | None = None,
    CMD_on_ready: Callable[[], None] | None = None,
) -> int:
    module = CMD_Module(
        core,
        history_file=history_file,
        saved_configuration_file=saved_configuration_file,
        CMD_on_ready=CMD_on_ready,
    )
    module.start()
    try:
        return module.join()
    finally:
        module.stop()
