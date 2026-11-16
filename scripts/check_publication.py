"""Fail CI if private workspace artifacts or recognizable credentials enter Git.

This is an additional boundary check, not a comprehensive secret detector. It
reads only tracked/non-ignored candidate files, never ignored operational data.
"""
from pathlib import Path
import re
import subprocess
import sys


FORBIDDEN_ROOTS = {"keys", "logs", "private", ".claude", ".playwright-mcp"}
FORBIDDEN_SUFFIXES = {".exe", ".dll", ".pem", ".key", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}
PATTERNS = (
    re.compile(rb"(?:github_pat_[A-Za-z0-9_]{40,}|ghp_[A-Za-z0-9]{30,})"),
    re.compile(rb"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{40,}-----END"),
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                            cwd=root, capture_output=True, check=True)
    paths = sorted(set(result.stdout.decode("utf-8").split("\x00")) - {""})
    findings = []
    for name in paths:
        path = Path(name)
        parts = [part.lower() for part in path.parts]
        forbidden = (parts[0] in FORBIDDEN_ROOTS or parts[:2] == ["docs", "servers"]
                     or parts[:2] == ["tools", "xray-test"] or path.suffix.lower() in FORBIDDEN_SUFFIXES
                     or path.name.lower() == "servers.yaml"
                     or (path.name.lower().startswith(".env") and path.name.lower() != ".env.example"))
        if forbidden:
            findings.append((name, "private or binary artifact"))
            continue
        candidate = root / path
        if not candidate.is_file():
            continue
        if candidate.is_symlink():
            findings.append((name, "symbolic-link candidate"))
            continue
        if any(pattern.search(candidate.read_bytes()) for pattern in PATTERNS):
            findings.append((name, "credential pattern"))
    for name, reason in findings:
        print(f"Publication blocked: {name}: {reason}", file=sys.stderr)
    if findings:
        return 1
    print(f"Publication boundary: {len(paths)} candidate files checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
