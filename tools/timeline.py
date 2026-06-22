import html
import json
import os

from replay import load_records


BASE = os.path.dirname(os.path.dirname(__file__))
OUT = os.path.join(BASE, "context", "replays", "timeline.html")


def _esc(value):
    return html.escape("" if value is None else str(value))


def render_timeline(records):
    cards = []
    for record in records:
        commit = record.get("git_commit") or ""
        files = record.get("changed_files") or []
        decisions = record.get("decisions") or []
        modules = (record.get("architecture") or {}).get("touched_modules") or []
        diff_stat = record.get("diff_stat") or ""

        cards.append(
            f"""
            <article class="card">
              <div class="meta">
                <span>{_esc(record.get('timestamp'))}</span>
                <span>{_esc(record.get('git_branch', ''))}</span>
                <span>{_esc(commit[:7])}</span>
              </div>
              <h2>{_esc(record.get('prompt'))}</h2>
              <p>{_esc(record.get('note', ''))}</p>
              <h3>Files</h3>
              <ul>{''.join(f'<li>{_esc(path)}</li>' for path in files)}</ul>
              <h3>Decisions</h3>
              <ul>{''.join(f'<li>{_esc(item)}</li>' for item in decisions) or '<li>None recorded</li>'}</ul>
              <h3>Architecture</h3>
              <p>{_esc(', '.join(modules) if modules else 'No module tags')}</p>
              <details>
                <summary>Diff stat</summary>
                <pre>{_esc(diff_stat)}</pre>
              </details>
            </article>
            """
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Development Timeline</title>
  <style>
    body {{ margin: 0; font-family: Consolas, 'Segoe UI', monospace; background: #f6f7f9; color: #20242a; }}
    header {{ padding: 28px 36px; background: #111827; color: white; }}
    h1 {{ margin: 0; font-size: 28px; }}
    main {{ max-width: 980px; margin: 0 auto; padding: 28px; }}
    .card {{ background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 20px; margin-bottom: 18px; }}
    .meta {{ display: flex; gap: 10px; flex-wrap: wrap; color: #5c6675; font-size: 13px; }}
    h2 {{ margin: 10px 0 8px; font-size: 20px; }}
    h3 {{ margin: 16px 0 6px; font-size: 14px; color: #374151; }}
    ul {{ margin: 0; padding-left: 22px; }}
    pre {{ white-space: pre-wrap; background: #f3f4f6; padding: 12px; border-radius: 6px; overflow: auto; }}
    summary {{ cursor: pointer; color: #1f4f9a; }}
  </style>
</head>
<body>
  <header>
    <h1>Codex Development Timeline</h1>
    <p>AI behavior log, Git binding, replay, decisions, and architecture evolution.</p>
  </header>
  <main>
    {''.join(cards) or '<p>No events recorded.</p>'}
  </main>
  <script type="application/json" id="records">{_esc(json.dumps(records, ensure_ascii=False))}</script>
</body>
</html>
"""


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    records = load_records()
    with open(OUT, "w", encoding="utf-8") as fp:
        fp.write(render_timeline(records))
    print(f"[Timeline] saved -> {OUT}")


if __name__ == "__main__":
    main()
