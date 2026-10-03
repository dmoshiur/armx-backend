# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Pytest bootstrap: keep ``app.main`` importable without a Groq API key.

The default LLM provider is Groq and ``Settings`` fails fast when ``LLM_PROVIDER=groq``
but ``GROQ_API_KEY`` is unset. ``app/main.py`` builds a module-level ``app = create_app()``
at import time, so the test environment pins the offline local provider for that unused
module-level instance. Tests that exercise the LLM construct their own ``Settings`` (see
``tests/helpers.py`` and the provider-specific test modules) and are unaffected by this default.
"""

import os

os.environ.setdefault("LLM_PROVIDER", "ollama")
