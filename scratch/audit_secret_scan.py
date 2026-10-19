import re
import subprocess
from pathlib import Path

# Run git diff origin/part-1..HEAD
proc = subprocess.run(
    ["git", "diff", "origin/part-1..HEAD"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
)

diff_text = proc.stdout

PATTERNS = [
    ("Stripe live/test key", re.compile(r"sk_(live|test)_[0-9a-zA-Z]{20,}")),
    ("OpenRouter key", re.compile(r"sk-or-v1-[0-9a-fA-F]{30,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9a-zA-Z]{36,}")),
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+=]{40}['\"]")),
    ("Generic Bearer", re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{30,}")),
]

print("=== Scanning git diff origin/part-1..HEAD for secrets ===")
found_in_diff = 0
for line_idx, line in enumerate(diff_text.splitlines(), 1):
    if line.startswith("+") and not line.startswith("+++"):
        for name, pat in PATTERNS:
            m = pat.search(line)
            if m:
                found_in_diff += 1
                # Redact
                val = m.group(0)
                redacted = val[:4] + "..." + val[-4:]
                print(f"Match [{name}] at line in diff: {redacted}")

print(f"Total secret matches in commit diff: {found_in_diff}")

# Also scan working directory modified files
print("\n=== Scanning working directory modified/untracked files ===")
proc_status = subprocess.run(
    ["git", "status", "-s"],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
)

found_in_wt = 0
for line in proc_status.stdout.splitlines():
    status = line[:2]
    fname = line[3:].strip()
    fpath = Path(fname)
    if fpath.is_file() and not fname.startswith("scratch"):
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
            for line_no, content_line in enumerate(content.splitlines(), 1):
                for name, pat in PATTERNS:
                    m = pat.search(content_line)
                    if m:
                        found_in_wt += 1
                        val = m.group(0)
                        redacted = val[:4] + "..." + val[-4:]
                        print(f"File {fname}:{line_no} [{name}]: {redacted}")
        except Exception:
            pass

print(f"Total secret matches in working tree: {found_in_wt}")
