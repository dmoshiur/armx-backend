# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""
HTTP middleware.

Order matters, and it is deliberate:

1. **Body-size guard** runs first so an oversized payload is rejected before anything reads
   it.
2. **Request context** assigns the request/correlation ids used by every log line, audit row
   and metric for the rest of the request.
3. **TLS enforcement** refuses plaintext outside an explicit local/demo profile.
4. **Security headers** are attached to every response, including error responses, because a
   handler that raises must not skip them.

Metrics use the first path segment as their route label: cardinality stays bounded and a
user id in a path can never end up as a metric label.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Final
from uuid import uuid4

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint

from app.config import Settings
from app.core.errors import ErrorCode
from app.core.logging import bind_trace_context, clear_trace_context, get_logger
from app.core.metrics import inc, observe

__all__ = ["client_ip", "register_middleware"]

logger = get_logger("api")

#: Paths that skip the TLS check: the platform liveness probe on the private network.
_PLAINTEXT_EXEMPT_PREFIXES: Final = ("/health",)

#: Sensible upper bound for a JSON API body. The image editor takes uploads through its own
#: endpoint, which enforces IMAGE_MAX_BYTES precisely.
_MAX_BODY_BYTES: Final = 16 * 1024 * 1024


def _coarse_route(path: str) -> str:
    segment = next((part for part in path.split("/") if part), "root")
    if segment.startswith(("v1", "v2")):
        parts = [part for part in path.split("/") if part]
        segment = parts[1] if len(parts) > 1 else segment
    # Only an allowlisted shape is used as a label; anything else collapses to "other".
    if segment.replace("-", "").replace("_", "").isalpha():
        return f"/{segment}"
    return "/other"


def client_ip(request: Request) -> str | None:
    """
    Caller IP, honouring ``X-Forwarded-For`` only from a configured trusted proxy.

    Trusting the header unconditionally would let any client forge its own source address
    and sidestep the per-IP login limits.
    """
    direct = request.client.host if request.client else None
    trusted = getattr(request.app.state, "trusted_proxies", ())
    if trusted and direct:
        try:
            direct_ip = ipaddress.ip_address(direct)
            is_trusted = any(direct_ip in net for net in trusted)
        except ValueError:
            is_trusted = False
        if is_trusted:
            forwarded = request.headers.get("x-forwarded-for", "")
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return direct


def _trusted_networks(
    settings: Settings,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for entry in settings.trusted_proxy_list:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logger.warning("ignoring invalid TRUSTED_PROXY_IPS entry: %s", entry)
    return tuple(networks)


def register_middleware(application: FastAPI, settings: Settings) -> None:
    """Attach the CORS, request-context, TLS and size-guard middleware."""
    application.state.trusted_proxies = _trusted_networks(settings)

    if settings.cors_origin_list:
        from fastapi.middleware.cors import CORSMiddleware

        application.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origin_list),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Request-Id",
                "X-Device-Key",
                "X-Idempotency-Key",
                "X-Signature",
            ],
            expose_headers=["X-Request-Id", "Retry-After"],
        )

    @application.middleware("http")
    async def request_context(request: Request, call_next: RequestResponseEndpoint) -> Response:
        started = time.perf_counter()
        request_id = request.headers.get("x-request-id") or uuid4().hex[:16]
        request.state.request_id = request_id
        trace_id = request.headers.get("x-trace-id") or request_id
        request.state.trace_id = trace_id
        bind_trace_context(request_id=request_id, trace_id=trace_id)

        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > _MAX_BODY_BYTES:
            response: Response = JSONResponse(
                status_code=413,
                content={
                    "code": ErrorCode.PAYLOAD_TOO_LARGE,
                    "message": "Request body is too large",
                    "retryable": False,
                    "request_id": request_id,
                },
            )
        else:
            scheme = request.url.scheme.lower()
            exempt = (
                settings.allow_plain_http_health_probe
                and request.method == "GET"
                and request.url.path.startswith(_PLAINTEXT_EXEMPT_PREFIXES)
            )
            if not settings.demo_insecure and scheme != "https" and not exempt:
                # The TLS connection is terminated by nginx or the platform edge; reaching
                # this branch means the client really did speak plaintext.
                response = JSONResponse(
                    status_code=400,
                    content={
                        "code": ErrorCode.TLS_REQUIRED,
                        "message": "HTTPS is required",
                        "retryable": False,
                        "request_id": request_id,
                    },
                )
            else:
                try:
                    response = await call_next(request)
                finally:
                    clear_trace_context()

        route_label = _coarse_route(request.url.path)
        inc(
            "http_requests",
            {"method": request.method, "route": route_label, "status": str(response.status_code)},
        )
        observe("http_request_duration", time.perf_counter() - started, {"route": route_label})
        response.headers["X-Request-Id"] = request_id
        for header, value in (getattr(request.state, "rate_limit_headers", None) or {}).items():
            response.headers.setdefault(header, value)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
        return response
