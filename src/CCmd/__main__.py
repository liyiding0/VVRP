from __future__ import annotations

import os
import sys
from pathlib import Path


if __package__ == "CCmd":
    project_root = Path(__file__).resolve().parents[2]
    project_root_text = str(project_root)
    if project_root_text not in sys.path:
        sys.path.insert(0, project_root_text)
    from src.CCmd.examples import build_default_registry
    from src.CCmd.interactive import run_interactive_cli
else:
    from .examples import build_default_registry
    from .interactive import run_interactive_cli


def main() -> int:
    history_file = os.environ.get("VVRP_CCMD_HISTORY")
    saved_configuration_file = os.environ.get("VVRP_SAVED_CONFIGURATION")
    hostname = os.environ.get("VVRP_CCMD_HOSTNAME", "Router")
    registry = build_default_registry()
    return run_interactive_cli(
        registry,
        hostname=hostname,
        history_file=history_file,
        saved_configuration_file=saved_configuration_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
