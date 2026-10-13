# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
Dependency-free secret scanner for CI.

Catches the failure mode that actually happens: a real credential pasted into a config file, a
test, or a doc while debugging, then committed. It looks for credential *shapes* (provider
token prefixes, private key blocks, JWTs) and for high-entropy assignments to credential-looking
names, and it flags them regardless of file type.

Usage:
    python scripts/secret_scan.py [paths...]
    python scripts/secret_scan.py --staged      # only files staged in git

Exit codes: 0 clean, 1 findings.
"""

from __future__ import annotations

import argparse
import math
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Iterator
from pathlib import Path

#: Files that intentionally contain credential-shaped strings.
ALLOWED_PATHS = {
    ".env.example",
    "scripts/secret_scan.py",
    "tests/test_secret_scan.py",
    "docs/security.md",
    "README.md",
}

_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "htmlcov",
    "dist",
    "build",
    "var",
    "data",
    "backups",
}

_SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".ico",
    ".pdf",
    ".dump",
    ".enc",
    ".lock",
}

#: The scanner's own test fixtures must contain findings to be meaningful.
_TEST_FIXTURE_MARKER = "secret-scan:test-fixture"
_ALLOW_MARKER = "secret-scan:allow"

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Meta/WhatsApp token", re.compile(r"\bEAA[A-Za-z0-9]{40,}\b")),
    ("Vercel token", re.compile(r"\bvercel_[A-Za-z0-9]{20,}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("basic auth in URL", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]{6,}@")),
)

_ASSIGNMENT = re.compile(
    r"""(?ix)
    ^\s*[\w.\-]*
    (?:
        password|passwd|secret|token|credential
      | (?:api|ai|private|public|client|access|signing|encryption|refresh|master|session)?[_-]?key
      | secret[_-]?key | private[_-]?key | client[_-]?secret
    )
    [\w.\-]*\s*[:=]\s*
    (?P<quote>["']?)(?P<value>[^\s"'#;,]{12,})(?P=quote)
    """
)

#: Values that are obviously placeholders rather than credentials.
_PLACEHOLDER_HINTS = (
    # interpolation / runtime generation rather than a literal
    "${",
    "$(",
    "os.environ",
    "getenv",
    "settings.",
    "token_urlsafe",
    "generate_key",
    "secrets.",
    "stdin",
    "getpass",
    "input(",
    # obvious non-production values
    "example",
    "placeholder",
    "changeme",
    "change-me",
    "your-",
    "your_",
    "test",
    "dummy",
    "sample",
    "redacted",
    "ci-only",
    "ci_only",
    "fake",
    "local-only",
    "not-a-real",
    "none",
    "null",
    "true",
    "false",
    "xxx",
    "***",
    "todo",
    "redact",
)

#: Hosts that cannot be a production destination, so credentials in their URLs are placeholders.
_LOCAL_HOSTS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",  # noqa: S104 - a literal in a skip-list, not a bind address
    "::1",
    "postgres",
    "db",
    "host.docker.internal",
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(hint in lowered for hint in _PLACEHOLDER_HINTS)


#: Characters a literal credential is made of. Anything else (parentheses, brackets, spaces,
#: colons, quotes) means the right-hand side is an expression, a sentence, or a path - not a
#: secret typed into a file.
_LITERAL_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_\-.~]+$")

#: ``module.attribute`` references and constant names are code, not credentials.
_DOTTED_CHAIN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+")
_UPPER_CONSTANT = re.compile(r"[A-Z][A-Z0-9_]*")
_LOWER_TOKEN = re.compile(r"[a-z][a-z0-9_]*")


def _looks_like_secret(value: str) -> bool:
    """A high-entropy literal that could plausibly be a live credential."""
    if _is_placeholder(value) or value.startswith(("http://", "https://", "sqlite", "postgresql")):
        return False
    if not _LITERAL_ALPHABET.match(value):
        return False
    if _DOTTED_CHAIN.fullmatch(value):  # settings.google_oauth_client_secret
        return False
    if _UPPER_CONSTANT.fullmatch(value):  # CONSTANT_NAME
        return False
    if _LOWER_TOKEN.fullmatch(value) and not any(character.isdigit() for character in value):
        return False  # snake_case identifier
    if value.count(".") >= 3:  # a filename, module path or version string
        return False
    if len(value) < 20 or len(set(value)) < 8:
        return False
    if _entropy(value) < 3.3:
        return False
    # Character-class variety: a credential is not a dictionary word, a slug, or a repeated
    # pattern. Require at least two classes including an upper-case letter or a digit.
    classes = sum(
        bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    has_upper_or_digit = bool(re.search(r"[A-Z\d]", value))
    return classes >= 2 and has_upper_or_digit


def _iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if any(part in _SKIP_DIRS for part in candidate.parts):
                    continue
                if candidate.is_file() and candidate.suffix.lower() not in _SKIP_SUFFIXES:
                    yield candidate
        elif path.is_file():
            yield path


def _staged_files() -> list[Path]:
    git = shutil.which("git")
    if git is None:  # pragma: no cover - git is available in CI and on developer machines
        print("git not found; scanning the working tree instead", file=sys.stderr)
        return [Path(".")]
    output = subprocess.run(  # noqa: S603 - absolute interpreter path, fixed argv, no shell
        [git, "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [Path(line) for line in output.splitlines() if line.strip()]


def _is_local_or_placeholder_url(url: str) -> bool:
    """A ``scheme://user:password@host`` match that targets a local or placeholder host."""
    _, _, remainder = url.partition("://")
    credentials, _, host_part = remainder.rpartition("@")
    host = host_part.split("/")[0].split(":")[0].lower()
    if any(host == candidate or host.endswith(f".{candidate}") for candidate in _LOCAL_HOSTS):
        return True
    if "example" in host:  # documentation hosts (.example.com, example.org) are never real
        return True
    _user, _, password = credentials.partition(":")
    return _is_placeholder(password)


def scan_file(path: Path, *, root: Path) -> list[str]:
    relative = path.relative_to(root) if path.is_absolute() else path
    if str(relative) in ALLOWED_PATHS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[str] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _ALLOW_MARKER in line or _TEST_FIXTURE_MARKER in line:
            continue
        for label, pattern in _PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            if label == "basic auth in URL" and _is_local_or_placeholder_url(match.group(0)):
                continue
            findings.append(f"{relative}:{line_number}: {label}")
        assignment = _ASSIGNMENT.search(line)
        if assignment and _looks_like_secret(assignment.group("value")):
            findings.append(
                f"{relative}:{line_number}: high-entropy value assigned to a secret-like name"
            )
    return findings


def scan(paths: Iterable[Path], *, root: Path | None = None) -> list[str]:
    base = root or Path.cwd()
    findings: list[str] = []
    for path in _iter_files(paths):
        findings.extend(scan_file(path, root=base))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan the repository for committed secrets.")
    parser.add_argument("paths", nargs="*", default=None, help="files or directories to scan")
    parser.add_argument("--staged", action="store_true", help="scan only git-staged files")
    args = parser.parse_args(argv)

    root = Path.cwd()
    if args.staged:
        targets = _staged_files()
    else:
        targets = [Path(item) for item in args.paths] if args.paths else [Path(".")]

    findings = scan([target for target in targets if target.exists()], root=root)
    if findings:
        print("Potential secrets found:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(
            "\nRemove the value, rotate the credential, and load it from the environment. "
            f"If a line is intentionally credential-shaped, append '{_ALLOW_MARKER}'.",
            file=sys.stderr,
        )
        return 1
    print(f"secret scan clean ({len(list(_iter_files([t for t in targets if t.exists()])))} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
