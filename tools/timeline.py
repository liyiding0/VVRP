import html
import os
import shutil
import zipfile

from replay import load_records


BASE = os.path.dirname(os.path.dirname(__file__))
REPLAY_DIR = os.path.join(BASE, "context", "replays")
OUT = os.path.join(REPLAY_DIR, "timeline.html")
TIMELINE_DIR = os.path.join(REPLAY_DIR, "timeline")
TIMELINE_ZIP = os.path.join(REPLAY_DIR, "timeline.zip")
PAGE_SIZE = 10


def _clean_html(value):
    return "\n".join(line.rstrip() for line in value.splitlines()) + "\n"


def _esc(value):
    return html.escape("" if value is None else str(value))


def _page_name(index):
    return f"page-{index + 1:03d}.html"


def _render_nav(page_count, current_index=None):
    if page_count <= 1:
        return ""
    links = []
    for index in range(page_count):
        label = str(index + 1)
        href = _page_name(index)
        if current_index == index:
            links.append(f"<strong>{label}</strong>")
        else:
            links.append(f'<a href="{href}">{label}</a>')
    return f"<nav>{' '.join(links)}</nav>"


def render_timeline_page(records, *, page_count=1, current_index=0, record_offset=0):
    cards = []
    for index, record in enumerate(records, start=record_offset):
        commit = record.get("git_commit") or ""
        files = record.get("changed_files") or []
        decisions = record.get("decisions") or []
        modules = (record.get("architecture") or {}).get("touched_modules") or []
        diff_stat = record.get("diff_stat") or ""

        cards.append(
            f"""
            <article class="card" id="{index}">
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

    nav = _render_nav(page_count, current_index)
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
    nav {{ margin-bottom: 18px; display: flex; gap: 8px; flex-wrap: wrap; }}
    nav a, nav strong {{ padding: 4px 8px; border: 1px solid #cbd5e1; border-radius: 4px; background: white; }}
    nav a {{ color: #1f4f9a; text-decoration: none; }}
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
    {nav}
    {''.join(cards) or '<p>No events recorded.</p>'}
    {nav}
  </main>
</body>
</html>
"""


def render_index(records, page_count):
    rows = []
    for index, record in enumerate(records):
        page_index = index // PAGE_SIZE
        rows.append(
            f"""
            <tr>
              <td>{_esc(record.get('timestamp'))}</td>
              <td><a href="{_page_name(page_index)}#{index}">{_esc(record.get('prompt'))}</a></td>
              <td>{_esc((record.get('git_commit') or '')[:7])}</td>
              <td>{_esc(record.get('git_branch', ''))}</td>
            </tr>
            """
        )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Codex Development Timeline Index</title>
  <style>
    body {{ margin: 0; font-family: Consolas, 'Segoe UI', monospace; background: #f6f7f9; color: #20242a; }}
    header {{ padding: 28px 36px; background: #111827; color: white; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 28px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d8dee8; }}
    th, td {{ padding: 9px 10px; border-bottom: 1px solid #e5e7eb; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    a {{ color: #1f4f9a; text-decoration: none; }}
  </style>
</head>
<body>
  <header>
    <h1>Codex Development Timeline</h1>
    <p>{len(records)} events, split into {page_count} page(s).</p>
  </header>
  <main>
    <table>
      <thead>
        <tr><th>Time</th><th>Prompt</th><th>Commit</th><th>Branch</th></tr>
      </thead>
      <tbody>{''.join(rows) or '<tr><td colspan="4">No events recorded.</td></tr>'}</tbody>
    </table>
  </main>
</body>
</html>
"""


def _render_redirect():
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=timeline/index.html">
  <title>Codex Development Timeline</title>
</head>
<body>
  <p>Timeline has been split into pages. Open <a href="timeline/index.html">timeline/index.html</a>.</p>
</body>
</html>
"""


def _write_zip():
    if os.path.exists(TIMELINE_ZIP):
        os.remove(TIMELINE_ZIP)
    with zipfile.ZipFile(TIMELINE_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for root, _, files in os.walk(TIMELINE_DIR):
            for filename in files:
                path = os.path.join(root, filename)
                archive.write(path, os.path.relpath(path, REPLAY_DIR))


def main():
    os.makedirs(REPLAY_DIR, exist_ok=True)
    if os.path.isdir(TIMELINE_DIR):
        shutil.rmtree(TIMELINE_DIR)
    os.makedirs(TIMELINE_DIR, exist_ok=True)
    records = load_records()
    page_count = max(1, (len(records) + PAGE_SIZE - 1) // PAGE_SIZE)
    with open(os.path.join(TIMELINE_DIR, "index.html"), "w", encoding="utf-8") as fp:
        fp.write(_clean_html(render_index(records, page_count)))
    for page_index in range(page_count):
        start = page_index * PAGE_SIZE
        page_records = records[start : start + PAGE_SIZE]
        with open(os.path.join(TIMELINE_DIR, _page_name(page_index)), "w", encoding="utf-8") as fp:
            fp.write(
                _clean_html(
                render_timeline_page(
                    page_records,
                    page_count=page_count,
                    current_index=page_index,
                    record_offset=start,
                )
                )
            )
    with open(OUT, "w", encoding="utf-8") as fp:
        fp.write(_clean_html(_render_redirect()))
    _write_zip()
    print(f"[Timeline] saved -> {os.path.join(TIMELINE_DIR, 'index.html')}")
    print(f"[Timeline] archive -> {TIMELINE_ZIP}")


if __name__ == "__main__":
    main()
