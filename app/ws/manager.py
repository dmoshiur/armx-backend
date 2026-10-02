# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger("armx.ws")


@dataclass(frozen=True, slots=True)
class SocketIdentity:
    user_id: uuid.UUID
    device_id: uuid.UUID


class ConnectionManager:
    """Tracks authenticated sockets for targeted events and immediate revocation."""

    def __init__(self) -> None:
        self._sockets: dict[WebSocket, SocketIdentity] = {}
        self._send_locks: dict[WebSocket, asyncio.Lock] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, identity: SocketIdentity) -> None:
        await websocket.accept()
        async with self._lock:
            self._sockets[websocket] = identity
            self._send_locks[websocket] = asyncio.Lock()

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._sockets.pop(websocket, None)
            self._send_locks.pop(websocket, None)

    async def send(self, websocket: WebSocket, event: dict[str, Any]) -> None:
        async with self._lock:
            send_lock = self._send_locks.get(websocket)
            connected = websocket in self._sockets
        if not connected or send_lock is None:
            return
        async with send_lock:
            await websocket.send_json(event)

    async def send_to_user(self, user_id: uuid.UUID, event: dict[str, Any]) -> int:
        return await self._send_matching(lambda identity: identity.user_id == user_id, event)

    async def send_to_device(self, device_id: uuid.UUID, event: dict[str, Any]) -> int:
        return await self._send_matching(lambda identity: identity.device_id == device_id, event)

    async def broadcast(self, event: dict[str, Any]) -> int:
        return await self._send_matching(lambda _: True, event)

    async def _send_matching(self, predicate: Any, event: dict[str, Any]) -> int:
        async with self._lock:
            recipients = [
                (ws, self._send_locks[ws])
                for ws, identity in self._sockets.items()
                if predicate(identity) and ws in self._send_locks
            ]
        delivered = 0
        failed: list[WebSocket] = []
        for websocket, send_lock in recipients:
            try:
                async with send_lock:
                    await websocket.send_json(event)
                delivered += 1
            except Exception:
                failed.append(websocket)
        if failed:
            async with self._lock:
                for websocket in failed:
                    self._sockets.pop(websocket, None)
                    self._send_locks.pop(websocket, None)
        return delivered

    async def close_device(self, device_id: uuid.UUID, code: int = 4403) -> int:
        return await self._close_matching(lambda identity: identity.device_id == device_id, code)

    async def close_user(self, user_id: uuid.UUID, code: int = 4403) -> int:
        return await self._close_matching(lambda identity: identity.user_id == user_id, code)

    async def kill_all(self, *, reason: str, actor: str) -> int:
        event = {
            "type": "system.killed",
            "engaged": True,
            "reason": reason,
            "actor": actor,
        }
        await self.broadcast(event)
        return await self._close_matching(lambda _: True, 1001)

    async def _close_matching(self, predicate: Any, code: int) -> int:
        async with self._lock:
            recipients = [
                (websocket, identity)
                for websocket, identity in self._sockets.items()
                if predicate(identity)
            ]
            for websocket, _ in recipients:
                self._sockets.pop(websocket, None)
                self._send_locks.pop(websocket, None)
        for websocket, _ in recipients:
            try:
                await websocket.close(code=code)
            except Exception:
                logger.debug("WebSocket was already closed")
        return len(recipients)

    async def count(self) -> int:
        async with self._lock:
            return len(self._sockets)


connection_manager = ConnectionManager()
