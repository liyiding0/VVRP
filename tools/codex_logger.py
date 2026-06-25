import argparse
import json
import os
import subprocess
from datetime import datetime


BASE = os.path.dirname(os.path.dirname(__file__))
CTX = os.path.join(BASE, "context", "sessions")
COMMITS = os.path.join(BASE, "context", "commits")
MAX_DIFF_SUMMARY_LINES = 80
MAX_DIFF_SUMMARY_CHARS = 20000
MAX_CODEX_OUTPUT_CHARS = 20000


def _git(args):
    return subprocess.check_output(["git", *args], cwd=BASE, stderr=subprocess.DEVNULL).decode().strip()


def get_git_commit():
    try:
        return _git(["rev-parse", "HEAD"])
    except Exception:
        return None


def get_git_branch():
    try:
        return _git(["branch", "--show-current"])
    except Exception:
        return ""


def get_changed_files():
    try:
        output = _git(["status", "--short"])
    except Exception:
        return []

    files = []
    for line in output.splitlines():
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        if path:
            files.append(path)
    return files


def get_diff_stat():
    try:
        return _git(["diff", "--stat"])
    except Exception:
        return ""


def _truncate_text(value, max_chars):
    if len(value) <= max_chars:
        return value
    omitted = len(value) - max_chars
    return value[:max_chars] + f"\n... truncated {omitted} characters ..."


def get_diff_summary(max_lines=MAX_DIFF_SUMMARY_LINES, max_chars=MAX_DIFF_SUMMARY_CHARS):
    try:
        output = _git(["diff", "--", "."])
    except Exception:
        return ""

    lines = output.splitlines()
    if len(lines) > max_lines:
        output = "\n".join(lines[:max_lines] + [f"... truncated {len(lines) - max_lines} lines ..."])
    return _truncate_text(output, max_chars)


def infer_architecture(changed_files):
    modules = []
    for path in changed_files:
        parts = path.replace("\\", "/").split("/")
        if parts[0] == "src" and len(parts) > 1:
            modules.append(parts[1])
        elif parts[0] in {"tools", "context", "tests", "docs"}:
            modules.append(parts[0])
    return sorted(set(modules))


def log_codex_event(
    prompt,
    changed_files=None,
    note="",
    decisions=None,
    output="",
    include_diff=True,
):
    os.makedirs(CTX, exist_ok=True)
    os.makedirs(COMMITS, exist_ok=True)

    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    commit = get_git_commit()
    files = changed_files or get_changed_files()

    record = {
        "version": "1.0",
        "timestamp": ts,
        "prompt": prompt,
        "changed_files": files,
        "note": note,
        "decisions": decisions or [],
        "codex_output": _truncate_text(output, MAX_CODEX_OUTPUT_CHARS),
        "git_commit": commit,
        "git_branch": get_git_branch(),
        "git_dirty_files": get_changed_files(),
        "diff_stat": get_diff_stat() if include_diff else "",
        "diff_summary": get_diff_summary() if include_diff else "",
        "architecture": {
            "touched_modules": infer_architecture(files),
        },
    }

    file_path = os.path.join(CTX, f"{ts}.json")
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)

    if commit:
        commit_path = os.path.join(COMMITS, f"{commit[:12]}.json")
        with open(commit_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

    print(f"[CodexLogger] saved -> {file_path}")
    return file_path


def main():
    parser = argparse.ArgumentParser(description="Record a Codex development event.")
    parser.add_argument("prompt")
    parser.add_argument("--file", action="append", dest="files", default=[])
    parser.add_argument("--note", default="")
    parser.add_argument("--decision", action="append", dest="decisions", default=[])
    parser.add_argument("--output", default="")
    parser.add_argument("--no-diff", action="store_true")
    args = parser.parse_args()

    log_codex_event(
        prompt=args.prompt,
        changed_files=args.files or None,
        note=args.note,
        decisions=args.decisions,
        output=args.output,
        include_diff=not args.no_diff,
    )


if __name__ == "__main__":
    main()
