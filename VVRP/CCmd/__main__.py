from __future__ import annotations

import os
import sys

from .examples import build_default_registry
from .interactive import run_interactive_cli


def main() -> int:
    history_file = os.environ.get("VVRP_CCMD_HISTORY")
    running_config_file = os.environ.get("VVRP_RUNNING_CONFIG")
    hostname = os.environ.get("VVRP_CCMD_HOSTNAME", "Router")
    registry = build_default_registry()
    return run_interactive_cli(
        registry,
        hostname=hostname,
        history_file=history_file,
        running_config_file=running_config_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
