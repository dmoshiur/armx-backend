# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Cloudinary / external-storage boundary tests.

Cloudinary is intentionally *not* integrated: the backend has no ordinary image-upload
feature, and biometric data (face images, face embeddings, voice samples) must never leave
the device (AGENTS.md rule 3). These tests keep that true structurally: no backend module may
import Cloudinary or any other external image/object-storage SDK, so a future
face-enrollment or intercom code path cannot even reach one by accident.

If Cloudinary is ever added for ordinary images (avatars, device photos), move the import
into a dedicated ``app/images`` module and update these tests with an explicit allow-list for
that module only — the biometric modules must stay unreachable from it.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = REPO_ROOT / "app"

# Top-level module names (or prefixes) that move caller data off-device.
FORBIDDEN_MODULE_PREFIXES = (
    "cloudinary",
    "boto3",
    "botocore",
    "google.cloud",
    "azure.storage",
    "minio",
    "dropbox",
)

# Modules that implement or gate biometric-adjacent flows. These must never gain an
# off-device storage dependency, directly or transitively.
BIOMETRIC_ADJACENT_MODULES = (
    "app/core/privacy.py",
    "app/core/verification.py",
    "app/unlock/routes.py",
    "app/intercom/routes.py",
    "app/devices/routes.py",
    "app/admin/routes.py",
)


def _iter_app_modules() -> list[Path]:
    return sorted(APP_ROOT.rglob("*.py"))


def _imported_module_names(source: str) -> set[str]:
    """Return every module name a source file imports (both import styles)."""

    names: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_backend_module_imports_an_external_image_or_object_storage_sdk() -> None:
    offenders: list[str] = []
    for path in _iter_app_modules():
        for module in _imported_module_names(path.read_text(encoding="utf-8")):
            if module.split(".")[0] in {p.split(".")[0] for p in FORBIDDEN_MODULE_PREFIXES}:
                offenders.append(f"{path.relative_to(REPO_ROOT)} imports {module}")
    assert offenders == [], (
        f"External image/object storage SDKs must not be importable: {offenders}"
    )


def test_cloudinary_is_not_a_declared_dependency() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declarations: list[str] = list(pyproject["project"].get("dependencies", []))
    for extra in pyproject["project"].get("optional-dependencies", {}).values():
        declarations.extend(extra)
    names = [
        declaration.split(">")[0].split("=")[0].split("[")[0].strip().lower()
        for declaration in declarations
    ]
    assert "cloudinary" not in names


def test_biometric_adjacent_modules_have_no_upload_or_storage_imports() -> None:
    for relative in BIOMETRIC_ADJACENT_MODULES:
        path = REPO_ROOT / relative
        assert path.is_file(), f"expected {relative} to exist"
        imported = _imported_module_names(path.read_text(encoding="utf-8"))
        for module in imported:
            assert module.split(".")[0] not in {"cloudinary", "boto3", "botocore", "minio"}, (
                f"{relative} must stay structurally unable to reach external storage "
                f"(found import {module})"
            )
        assert "app.images" not in imported, (
            f"{relative} must not depend on the (future, ordinary-images-only) app.images module"
        )


def test_intercom_audio_is_never_routed_to_external_storage() -> None:
    """The only media-upload endpoint stores audio in the database, not off-device."""

    source = (REPO_ROOT / "app/intercom/routes.py").read_text(encoding="utf-8")
    assert "audio_bytes=audio_data" in source
    for marker in FORBIDDEN_MODULE_PREFIXES:
        assert marker not in source.lower()
