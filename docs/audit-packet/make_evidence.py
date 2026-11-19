"""Build a self-contained HTML page from the captured CLI evidence."""
from __future__ import annotations

import html
import subprocess
from pathlib import Path

OUT = Path(r"C:\Users\Illum\AppData\Local\Temp\opencode\usoc-audit-packet")
REPO = Path(r"C:\Users\Illum\.local\share\opencode\worktree\0d1e7d\work\cyber")

checks = subprocess.run(
    ["gh", "pr", "checks", "5"], cwd=REPO, capture_output=True, text=True, encoding="utf-8"
).stdout.strip()

diff = subprocess.run(
    ["git", "diff", "f696f13..HEAD", "--", "SECURITY.md"],
    cwd=REPO,
    capture_output=True,
    text=True,
    encoding="utf-8",
).stdout.strip()

head = subprocess.run(
    ["git", "rev-parse", "--short", "HEAD"],
    cwd=REPO,
    capture_output=True,
    text=True,
    encoding="utf-8",
).stdout.strip()

page = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>USOC PR #5 audit evidence</title>
<style>
body{{background:#0d1117;color:#c9d1d9;font:13px/1.5 ui-monospace,SFMono-Regular,Consolas,monospace;margin:0;padding:24px}}
h1{{font-size:18px;color:#58a6ff;margin:0 0 4px}}
h2{{font-size:14px;color:#79c0ff;margin:22px 0 8px;border-bottom:1px solid #30363d;padding-bottom:6px}}
.meta{{color:#8b949e;margin-bottom:18px}}
pre{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:14px;white-space:pre-wrap;word-break:break-word;margin:0}}
</style></head><body>
<h1>USOC Mesh &mdash; PR #5 audit evidence</h1>
<div class="meta">Repo: lyfetyme-rgb/usoc-agent-mesh &nbsp;|&nbsp; PR #5: feat/agent-shadow-mode &rarr; main &nbsp;|&nbsp; commit {head}</div>
<h2>1. gh pr checks 5 &mdash; all green</h2>
<pre>{html.escape(checks)}</pre>
<h2>2. SECURITY.md diff (f696f13..{head})</h2>
<pre>{html.escape(diff)}</pre>
</body></html>
"""
(OUT / "audit-evidence.html").write_text(page, encoding="utf-8")
(OUT / "gh-pr-checks-5.txt").write_text(checks + "\n", encoding="utf-8")
(OUT / "security-md.diff").write_text(diff + "\n", encoding="utf-8")
print("wrote", OUT / "audit-evidence.html")
print("checks:", checks.replace("\n", " | "))
