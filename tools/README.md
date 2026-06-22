# Codex Development Replay Tools

This is the v1.0 MVP for tracking Codex-assisted development.

## Record

```powershell
python tools\codex_logger.py "Refactor FIB routing table" --file src/FIB/table.py --decision "Keep route lookup in FIB"
```

Records are written to `context/sessions` and mirrored by commit SHA in `context/commits`.

## Replay

```powershell
python tools\replay.py
python tools\replay.py --verbose
```

## Timeline UI

```powershell
python tools\timeline.py
```

Open `context/replays/timeline.html` in a browser.
