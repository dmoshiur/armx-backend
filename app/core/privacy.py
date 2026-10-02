# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import re
from typing import Any

_FORBIDDEN_KEY_COMPONENTS = {
    "audio",
    "audios",
    "base64",
    "biometric",
    "biometrics",
    "embedding",
    "embeddings",
    "face",
    "faces",
    "frame",
    "frames",
    "image",
    "images",
    "palm",
    "palms",
    "pcm",
    "photo",
    "photos",
    "recording",
    "recordings",
    "raw",
    "template",
    "templates",
    "video",
    "videos",
    "voice",
    "voices",
}
_FORBIDDEN_VALUE = re.compile(
    r"data:(?:image|audio)/|(?:face|voice|palm)[_-]?(?:template|embedding|geometry|"
    r"raw[_-]?data|image|recording|print)|biometric[_-]?(?:template|embedding)",
    re.IGNORECASE,
)
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{256,}={0,2}(?![A-Za-z0-9+/_=-])")


def _key_has_prohibited_component(value: str) -> bool:
    snake_case = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value).lower()
    components = set(re.split(r"[^a-z0-9]+", snake_case))
    return bool(components.intersection(_FORBIDDEN_KEY_COMPONENTS))


def contains_raw_biometric_data(value: Any) -> bool:
    """Detect common raw biometric media markers in structured untrusted input."""

    if isinstance(value, dict):
        return any(
            _key_has_prohibited_component(str(key)) or contains_raw_biometric_data(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(contains_raw_biometric_data(child) for child in value)
    if isinstance(value, str):
        return bool(_FORBIDDEN_VALUE.search(value) or _BASE64_BLOB.search(value))
    return False
