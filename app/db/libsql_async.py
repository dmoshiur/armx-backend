# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

"""Asyncio SQLAlchemy dialect for libSQL / Turso.

Why this module exists
----------------------
The official libSQL Python clients (``libsql`` and the legacy ``libsql-experimental``) are
*synchronous* DB-API drivers, and ``sqlalchemy-libsql`` only ships a synchronous dialect (its
``sqlite+aiolibsql`` entry point reuses a synchronous DB-API and a synchronous pool class, so
``create_async_engine`` rejects it).  Dropping a synchronous driver into an asyncio
application would block the event loop for the duration of every statement - unacceptable for
the WebSocket chat/tool flows, especially against a remote Turso database where each
statement is a network round trip.

This module provides the missing asyncio adapter: a small DB-API shim whose blocking calls
run on one dedicated worker thread per connection (the same architecture as the ``aiosqlite``
dialect), plugged into SQLAlchemy's generic asyncio adapters.  Result metadata
(``description``/``rowcount``/``lastrowid``) is captured on the worker thread, so the event
loop never touches the native driver.

Measured driver caveat (libsql 0.1.11 / libsql-experimental 0.0.55)
------------------------------------------------------------------
The native driver holds the CPython GIL for the whole duration of a call, including network
writes and reads, and it exposes no connect timeout.  Consequences, verified by measurement:

* Every statement is serialized with the event loop; a slow Turso round trip stalls other
  coroutines (WebSocket streaming included) for its duration.  The worker thread still buys
  correctness (DB-API thread affinity) and the async API shape SQLAlchemy requires, and it
  will buy real concurrency as soon as the upstream driver releases the GIL around I/O.
* An endpoint that accepts TCP but never answers hangs the call indefinitely.  Keep the
  Turso database in the same region as the service and let the platform's health checks
  recycle an instance that gets stuck.

These limits, and the options around them, are documented in ``docs/deploy-render.md``.

URL forms supported (``DATABASE_URL``)
--------------------------------------
``sqlite+libsql://<db>.<org>.turso.io?secure=true``  remote Turso/libSQL over TLS
``sqlite+libsql://127.0.0.1:8080?secure=false``      local ``turso dev`` server (demo only)
``sqlite+libsql:////absolute/path/to/armx.db``       local libSQL file (development)

Authentication tokens are passed as ``connect_args={"auth_token": ...}`` from settings and
are never embedded in the URL, logged, or stored in the database.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from types import ModuleType
from typing import Any, cast
from urllib.parse import urlunsplit

from sqlalchemy import pool
from sqlalchemy.connectors.asyncio import (
    AsyncAdapt_dbapi_connection,
    AsyncAdapt_dbapi_cursor,
    AsyncAdapt_dbapi_module,
)
from sqlalchemy.dialects.sqlite.pysqlite import SQLiteDialect_pysqlite
from sqlalchemy.engine.url import URL
from sqlalchemy.util.concurrency import await_

# Message fragments (lower-cased) used to translate the driver's plain ``ValueError``
# failures into the DB-API exception hierarchy SQLAlchemy expects.  libSQL reports SQLite
# errors as text without exposing result codes, so matching on text is the only signal
# available.  Unmatched errors become ``sqlite3.DatabaseError``.
_INTEGRITY_FRAGMENTS = (
    "unique constraint failed",
    "not null constraint failed",
    "check constraint failed",
    "foreign key constraint failed",
    "constraint failed",
)
_OPERATIONAL_FRAGMENTS = (
    "no such table",
    "no such column",
    "no such function",
    "no such index",
    "syntax error",
    "unable to open database",
    "database is locked",
    "database or disk is full",
    "disk i/o error",
    "read-only",
    "hrana",
    "http error",
    "dns error",
    "error trying to connect",
    "connection",
    "websocket",
    "timed out",
    "timeout",
    "unauthorized",
    "forbidden",
    "invalid token",
    "auth token",
    "unauthorized",
)
_DISCONNECT_FRAGMENTS = (
    "hrana",
    "http error",
    "dns error",
    "error trying to connect",
    "connection reset",
    "connection closed",
    "connection refused",
    "broken pipe",
    "timed out",
    "timeout",
    "websocket",
)


def _last_value(value: Any) -> Any:
    """Return the final value when a URL query parameter is repeated."""

    if isinstance(value, (list, tuple)):
        return value[-1] if value else None
    return value


def _normalize_parameter(value: Any) -> Any:
    """Convert values the driver cannot bind (only ``bytes`` is accepted for BLOBs)."""

    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    return value


def _normalize_parameters(parameters: Any) -> Any:
    """Normalize a DB-API parameter set for the libSQL driver."""

    if isinstance(parameters, dict):
        return {key: _normalize_parameter(value) for key, value in parameters.items()}
    if isinstance(parameters, (list, tuple)):
        return tuple(_normalize_parameter(value) for value in parameters)
    return _normalize_parameter(parameters)


def translate_driver_error(error: BaseException) -> BaseException:
    """Map a low-level libSQL failure onto the DB-API exception hierarchy."""

    if isinstance(error, sqlite3.Error):
        return error
    message = str(error).strip() or error.__class__.__name__
    lowered = message.lower()
    if any(fragment in lowered for fragment in _INTEGRITY_FRAGMENTS):
        return sqlite3.IntegrityError(message)
    if any(fragment in lowered for fragment in _OPERATIONAL_FRAGMENTS):
        return sqlite3.OperationalError(message)
    return sqlite3.DatabaseError(message)


def is_disconnect_error(error: BaseException) -> bool:
    """Return whether a translated DB-API error means the remote connection is gone."""

    if not isinstance(error, sqlite3.OperationalError):
        return False
    lowered = str(error).lower()
    return any(fragment in lowered for fragment in _DISCONNECT_FRAGMENTS)


class _ConnectionWorker:
    """Runs every blocking libSQL call on one dedicated thread per connection.

    A single thread per connection preserves libSQL's thread-affinity requirement and
    serializes statements on that connection, matching the DB-API contract.
    """

    __slots__ = ("_executor", "_factory", "_native")

    def __init__(self, factory: Callable[[], Any]) -> None:
        self._factory = factory
        self._native: Any | None = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="armx-libsql")

    async def run(self, operation: Callable[[Any], Any]) -> Any:
        """Execute ``operation(native_connection)`` on the connection's worker thread."""

        loop = asyncio.get_running_loop()

        def call() -> Any:
            try:
                if self._native is None:
                    self._native = self._factory()
                return operation(self._native)
            except Exception as error:  # noqa: BLE001 - translated to DB-API errors here.
                raise translate_driver_error(error) from error

        return await loop.run_in_executor(self._executor, call)

    async def open(self) -> None:
        """Establish the native connection eagerly so failures surface at connect time."""

        await self.run(lambda connection: None)

    async def close(self) -> None:
        try:
            await self.run(lambda connection: connection.close())
        finally:
            self._native = None
            self._executor.shutdown(wait=False, cancel_futures=True)


class LibSQLAsyncCursor:
    """Async DB-API cursor over one blocking libSQL cursor."""

    __slots__ = ("_arraysize", "_description", "_lastrowid", "_native", "_rowcount", "_worker")

    def __init__(self, worker: _ConnectionWorker) -> None:
        self._worker = worker
        self._native: Any | None = None
        self._description: Any | None = None
        self._rowcount = -1
        self._lastrowid = 0
        self._arraysize = 1

    def _cursor(self, connection: Any) -> Any:
        if self._native is None:
            self._native = connection.cursor()
            self._native.arraysize = self._arraysize
        return self._native

    def _capture(self, cursor: Any) -> None:
        # Copied on the worker thread so the event loop never reads driver objects.
        self._description = cursor.description
        self._rowcount = cursor.rowcount
        self._lastrowid = cursor.lastrowid

    async def execute(
        self, operation: str, parameters: Sequence[Any] | dict[str, Any] | None = None
    ) -> LibSQLAsyncCursor:
        def call(connection: Any) -> None:
            cursor = self._cursor(connection)
            if parameters is None:
                cursor.execute(operation)
            else:
                cursor.execute(operation, _normalize_parameters(parameters))
            self._capture(cursor)

        await self._worker.run(call)
        return self

    async def executemany(self, operation: str, seq_of_parameters: Any) -> LibSQLAsyncCursor:
        def call(connection: Any) -> None:
            cursor = self._cursor(connection)
            for parameters in seq_of_parameters:
                cursor.execute(operation, _normalize_parameters(parameters))
            self._capture(cursor)

        await self._worker.run(call)
        return self

    async def executescript(self, script: str) -> LibSQLAsyncCursor:
        def call(connection: Any) -> None:
            cursor = self._cursor(connection)
            cursor.executescript(script)
            self._capture(cursor)

        await self._worker.run(call)
        return self

    async def fetchone(self) -> Any | None:
        return await self._worker.run(lambda connection: self._cursor(connection).fetchone())

    async def fetchmany(self, size: int | None = None) -> list[Any]:
        rows = await self._worker.run(
            lambda connection: self._cursor(connection).fetchmany(size or self._arraysize)
        )
        return list(rows)

    async def fetchall(self) -> list[Any]:
        rows = await self._worker.run(lambda connection: self._cursor(connection).fetchall())
        return list(rows)

    async def close(self) -> None:
        native = self._native
        self._native = None
        if native is not None:
            await self._worker.run(lambda connection: native.close())

    async def setinputsizes(self, sizes: Sequence[Any]) -> None:
        del sizes

    async def setoutputsize(self, size: Any, column: Any = None) -> None:
        del size, column

    async def nextset(self) -> None:
        return None

    async def __aenter__(self) -> LibSQLAsyncCursor:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.close()

    @property
    def description(self) -> Any | None:
        return self._description

    @property
    def rowcount(self) -> int:
        return self._rowcount

    @property
    def lastrowid(self) -> int:
        return self._lastrowid

    @property
    def arraysize(self) -> int:
        return self._arraysize

    @arraysize.setter
    def arraysize(self, value: int) -> None:
        self._arraysize = value
        if self._native is not None:
            self._native.arraysize = value


class LibSQLAsyncConnection:
    """Async DB-API connection over one blocking libSQL connection."""

    __slots__ = ("_isolation_level", "_worker")

    def __init__(self, worker: _ConnectionWorker) -> None:
        self._worker = worker
        self._isolation_level: str | None = None

    def cursor(self, *args: Any, **kwargs: Any) -> LibSQLAsyncCursor:
        del args, kwargs
        return LibSQLAsyncCursor(self._worker)

    async def commit(self) -> None:
        await self._worker.run(lambda connection: connection.commit())

    async def rollback(self) -> None:
        await self._worker.run(lambda connection: connection.rollback())

    async def close(self) -> None:
        await self._worker.close()

    async def open(self) -> None:
        await self._worker.open()

    @property
    def isolation_level(self) -> str | None:
        return self._isolation_level

    @isolation_level.setter
    def isolation_level(self, value: str | None) -> None:
        # libSQL's native ``isolation_level`` is read-only; the driver default ("DEFERRED")
        # is left untouched, which matches the implicit-transaction behaviour SQLAlchemy's
        # SQLite dialect expects from pysqlite.
        if value not in (None, "", "DEFERRED"):
            raise sqlite3.OperationalError(
                "libSQL only supports the driver's DEFERRED isolation level"
            )
        self._isolation_level = value


class AsyncAdapt_libsql_cursor(AsyncAdapt_dbapi_cursor):
    __slots__ = ()


class AsyncAdapt_libsql_connection(AsyncAdapt_dbapi_connection):
    __slots__ = ("_tracked_isolation_level",)

    _cursor_cls = AsyncAdapt_libsql_cursor

    def __init__(self, dbapi: Any, connection: LibSQLAsyncConnection) -> None:
        # The generic adapter type-hints the DB-API protocol, which the shim satisfies
        # structurally at runtime; ``Any`` keeps mypy strict mode satisfied here.
        super().__init__(dbapi, cast("Any", connection))
        self._tracked_isolation_level: str | None = None

    @property
    def isolation_level(self) -> str | None:
        return self._tracked_isolation_level

    @isolation_level.setter
    def isolation_level(self, value: str | None) -> None:
        self._tracked_isolation_level = value

    def create_function(self, *args: Any, **kw: Any) -> None:
        """libSQL has no UDF support; SQLAlchemy's regexp/floor helpers are skipped."""

        del args, kw


class AsyncAdapt_libsql_dbapi(AsyncAdapt_dbapi_module):
    """DB-API module facade handed to SQLAlchemy for the ``sqlite+libsql`` dialect."""

    def __init__(self, libsql_module: ModuleType) -> None:
        # sqlite3 supplies the exception hierarchy and type constructors; the driver reports
        # plain ``ValueError`` failures which ``translate_driver_error`` maps over.
        super().__init__(libsql_module, dbapi_module=sqlite3)
        self.paramstyle = "qmark"
        self.sqlite_version_info = libsql_module.sqlite_version_info
        self.sqlite_version = getattr(libsql_module, "sqlite_version", "libSQL")
        for name in (
            "Binary",
            "DataError",
            "DatabaseError",
            "Error",
            "IntegrityError",
            "InterfaceError",
            "InternalError",
            "NotSupportedError",
            "OperationalError",
            "ProgrammingError",
            "Warning",
        ):
            setattr(self, name, getattr(sqlite3, name))
        self.PARSE_COLNAMES = 0
        self.PARSE_DECLTYPES = 0

    def connect(self, *args: Any, **kwargs: Any) -> AsyncAdapt_libsql_connection:
        driver = self.driver

        def factory() -> Any:
            return driver.connect(*args, **kwargs)

        connection = LibSQLAsyncConnection(_ConnectionWorker(factory))
        # ``connect()`` runs inside a SQLAlchemy greenlet, so the eager native connect can be
        # awaited without blocking the event loop.
        await_(connection.open())
        return AsyncAdapt_libsql_connection(self, connection)


class SQLiteDialect_libsql(SQLiteDialect_pysqlite):
    """Asyncio dialect for libSQL/Turso (``sqlite+libsql://``)."""

    driver = "libsql"
    supports_statement_cache = True
    is_async = True

    @classmethod
    def import_dbapi(cls) -> AsyncAdapt_libsql_dbapi:
        return AsyncAdapt_libsql_dbapi(__import__("libsql"))

    @classmethod
    def get_pool_class(cls, url: URL) -> type[pool.Pool]:
        if cls._is_url_file_db(url):
            return pool.AsyncAdaptedQueuePool
        return pool.StaticPool

    def create_connect_args(self, url: URL) -> tuple[list[Any], dict[str, Any]]:
        opts = {key: _last_value(value) for key, value in url.query.items()}
        secure = str(opts.pop("secure", "true")).strip().lower() not in {"false", "0", "no"}
        connect_args: dict[str, Any] = {}
        if (timeout := opts.pop("timeout", None)) is not None:
            connect_args["timeout"] = float(timeout)
        if auth_token := opts.pop("auth_token", None):
            connect_args["auth_token"] = str(auth_token)

        if url.host:
            scheme = "https" if secure else "http"
            netloc = f"{url.host}:{url.port}" if url.port else url.host
            path = (url.database or "").lstrip("/")
            return ([urlunsplit((scheme, netloc, path, "", ""))], connect_args)

        return ([url.database or ":memory:"], connect_args)

    def get_driver_connection(self, connection: Any) -> Any:
        return connection._connection

    def is_disconnect(self, e: Exception, connection: Any, cursor: Any) -> bool:
        del connection, cursor
        return is_disconnect_error(e)


dialect = SQLiteDialect_libsql

# Make ``sqlite+libsql://`` resolvable by SQLAlchemy (and therefore by Alembic) as soon as
# this module is imported.
from sqlalchemy.dialects import registry as _registry  # noqa: E402

_registry.register("sqlite.libsql", __name__, "SQLiteDialect_libsql")
