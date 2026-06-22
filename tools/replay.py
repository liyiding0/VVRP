import argparse
import json
import os


BASE = os.path.dirname(os.path.dirname(__file__))
CTX = os.path.join(BASE, "context", "sessions")


def load_records():
    if not os.path.isdir(CTX):
        return []

    records = []
    for name in sorted(f for f in os.listdir(CTX) if f.endswith(".json")):
        path = os.path.join(CTX, name)
        with open(path, "r", encoding="utf-8") as fp:
            record = json.load(fp)
        record["_path"] = path
        records.append(record)
    return records


def _short_commit(value):
    if not value:
        return None
    return value[:7]


def print_record(data, verbose=False):
    print(f"TIME: {data.get('timestamp')}")
    print(f"COMMIT: {_short_commit(data.get('git_commit'))}")
    print(f"BRANCH: {data.get('git_branch', '')}")
    print(f"PROMPT: {data.get('prompt')}")
    print(f"FILES: {data.get('changed_files', [])}")

    note = data.get("note")
    if note:
        print(f"NOTE: {note}")

    decisions = data.get("decisions") or []
    if decisions:
        print("DECISIONS:")
        for decision in decisions:
            print(f"  - {decision}")

    modules = (data.get("architecture") or {}).get("touched_modules") or []
    if modules:
        print(f"ARCH: {modules}")

    if verbose:
        diff_stat = data.get("diff_stat")
        if diff_stat:
            print("DIFF:")
            print(diff_stat)
        output = data.get("codex_output")
        if output:
            print("CODEX OUTPUT:")
            print(output)

    print("-" * 50)


def replay(verbose=False):
    print("\n=== AI DEVELOPMENT REPLAY ===\n")
    for record in load_records():
        print_record(record, verbose=verbose)


def main():
    parser = argparse.ArgumentParser(description="Replay Codex development events.")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    replay(verbose=args.verbose)


if __name__ == "__main__":
    main()
