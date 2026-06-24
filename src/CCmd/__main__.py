from __future__ import annotations

import sys
from pathlib import Path


if __package__ == "CCmd":
    project_root = Path(__file__).resolve().parents[2]
    project_root_text = str(project_root)
    if project_root_text not in sys.path:
        sys.path.insert(0, project_root_text)
    from src.VVRP.__main__ import main as VVRP_main
else:
    from src.VVRP.__main__ import main as VVRP_main


def main() -> int:
    return VVRP_main()


if __name__ == "__main__":
    raise SystemExit(main())
