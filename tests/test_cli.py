# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
The first-admin CLI.

`scripts/create_admin.py` (and `python -m app.cli.create_admin`) is the only way an account is
created without going through signup, which means its validation is part of the security surface:
an address the API would reject is an account nobody can ever sign into.
"""

from __future__ import annotations

import argparse

import pytest

from app.cli.create_admin import _normalise_email, _parse_args


def test_the_address_is_normalised() -> None:
    assert _normalise_email("  Owner@Example.COM ") == "owner@example.com"


@pytest.mark.parametrize(
    "address",
    [
        "someone@armx.local",  # special-use domain: the API's EmailStr rejects it
        "not-an-address",
        "missing@domain",
        "@example.com",
    ],
)
def test_an_address_the_api_would_reject_is_refused_here(address: str) -> None:
    with pytest.raises(SystemExit) as caught:
        _normalise_email(address)
    message = str(caught.value)
    assert "Email rejected" in message
    assert "real domain" in message, "the operator needs to know why and what to do"


def test_the_parser_requires_an_email_and_allows_a_role() -> None:
    with pytest.raises(SystemExit):
        _parse_args([])
    parsed = _parse_args(["--email", "owner@example.com", "--role", "vip"])
    assert isinstance(parsed, argparse.Namespace)
    assert parsed.role == "vip"
    assert parsed.password_stdin is False
