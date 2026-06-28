from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any, TextIO


@dataclass
class VVRP_RuntimeContext:
    state: dict[str, Any] = field(default_factory=dict)
    output: TextIO = field(default_factory=lambda: sys.stdout)

    def write(self, text: str = "") -> None:
        print(text, file=self.output)
