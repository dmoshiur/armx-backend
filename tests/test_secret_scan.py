# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""The CI secret scanner must catch real credentials and ignore placeholders."""

from __future__ import annotations

from pathlib import Path

from scripts import secret_scan
from scripts.secret_scan import scan, scan_file

PLANTED = [
    "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789",
    "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    'token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"',  # noqa: E501 - a fixture JWT
    "postgres://armx:sup3rsecretpassword9x@db.internal.corp:5432/armx",
    "-----BEGIN RSA PRIVATE KEY-----",
    "ai_key = 'kQ3vT8mZ1pXr7LwB4nYc6Hj2Ds9Fg5Ab'",
]

PLACEHOLDERS = [
    "DATABASE_URL=${DATABASE_URL}",
    'JWT_SECRET_KEY=""',
    "SMTP_PASSWORD=<set-me-in-the-secrets-manager>",
    "GITHUB_TOKEN=your-github-token-here",
    'api_key = os.environ["OPENAI_API_KEY"]',
    "secret = settings.google_oauth_client_secret",
    "# rotate the signing key every SECRET_ROTATION_DUE_DAYS",
    "short = 'abc'",
]


def test_scanner_flags_each_planted_credential(tmp_path: Path) -> None:
    for index, line in enumerate(PLANTED):
        target = tmp_path / f"planted_{index}.py"
        target.write_text(f"{line}\n")
        findings = scan_file(target, root=tmp_path)
        assert findings, f"scanner missed: {line[:40]}"


def test_scanner_ignores_placeholders_and_interpolation(tmp_path: Path) -> None:
    target = tmp_path / "config.py"
    target.write_text("\n".join(PLACEHOLDERS) + "\n")
    assert scan_file(target, root=tmp_path) == []


def test_scanner_reports_file_and_line(tmp_path: Path) -> None:
    target = tmp_path / "leaky.py"
    target.write_text(
        "safe = 1\nANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789\n"
    )
    findings = scan_file(target, root=tmp_path)
    assert findings and ":2:" in findings[0]


def test_documented_placeholder_file_is_exempt() -> None:
    """``.env.example`` exists to list variable *names*; it is reviewed instead."""
    root = Path(__file__).resolve().parents[1]
    example = root / ".env.example"
    assert example.exists()
    assert scan_file(example, root=root) == []


def test_repository_is_clean() -> None:
    """The real repository must pass its own scanner."""
    root = Path(__file__).resolve().parents[1]
    findings = scan([root], root=root)
    assert findings == [], "committed secrets detected:\n" + "\n".join(findings)


class TestGeneratedFiles:
    """
    Build output is not source.

    ``pip install -e ".[dev]"`` (which every CI job runs) writes ``<package>.egg-info/`` into the
    working tree, and ``PKG-INFO`` embeds ``README.md`` - a file the scanner deliberately allows,
    reproduced at a path it does not. Scanning build output produced a CI failure about a file
    nobody wrote, so generated metadata is skipped by suffix.
    """

    def test_egg_info_is_skipped(self, tmp_path: Path) -> None:
        metadata = tmp_path / "armx_backend.egg-info"
        metadata.mkdir()
        (metadata / "PKG-INFO").write_text("Metadata-Version: 2.1\n")
        copied = metadata / "PKG-INFO"
        copied.write_text(copied.read_text())
        assert list(secret_scan._iter_files([tmp_path])) == []

    def test_a_generated_file_outside_metadata_is_still_scanned(self, tmp_path: Path) -> None:
        plain = tmp_path / "notes.txt"
        plain.write_text("nothing to see\n")
        assert [path.name for path in secret_scan._iter_files([tmp_path])] == ["notes.txt"]

    def test_a_path_outside_the_scan_root_is_reported_not_raised(self, tmp_path: Path) -> None:
        """Handed a path outside the working tree, the scanner reports it instead of crashing."""
        outside = tmp_path / "elsewhere.md"
        outside.write_text("password = 'A7bQ2xL9mZ4pR1sT6vW3'\n")
        findings = secret_scan.scan_file(outside, root=Path.cwd())
        assert findings, "a credential-shaped line must still be found"
        assert str(outside) in findings[0]
