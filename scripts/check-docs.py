"""Check local Markdown links in tracked and new repository documentation."""
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote

root = Path(__file__).resolve().parents[1]
paths = subprocess.check_output(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
).decode().split("\0")
errors = []
for name in sorted(set(paths)):
    if not name.endswith(".md"):
        continue
    source = root / name
    for link in re.findall(r"\[[^\]]*\]\(([^)]+)\)", source.read_text()):
        target = link.split("#", 1)[0]
        if not target or re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
            continue
        if not (source.parent / unquote(target)).exists():
            errors.append(f"{name}: broken local link {link}")
if errors:
    raise SystemExit("\n".join(errors))
print("Local Markdown file links passed.")
