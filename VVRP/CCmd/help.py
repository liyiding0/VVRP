from __future__ import annotations

from .models import HelpCandidate


def format_help(candidates: tuple[HelpCandidate, ...]) -> str:
    if not candidates:
        return "% No help available"

    width = max(len(candidate.display) for candidate in candidates)
    return "\n".join(
        f"  {candidate.display:<{width}}  {candidate.help_text}".rstrip()
        for candidate in candidates
    )
