# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.

import asyncio


class ExecutionRegistry:
    """Tracks confirmed side effects so the kill-switch can cancel in-flight work."""

    def __init__(self) -> None:
        self._tasks: set[asyncio.Task[object]] = set()
        self._lock = asyncio.Lock()

    async def register(self, task: asyncio.Task[object]) -> None:
        async with self._lock:
            self._tasks.add(task)

    async def unregister(self, task: asyncio.Task[object]) -> None:
        async with self._lock:
            self._tasks.discard(task)

    async def cancel_all(self) -> int:
        current = asyncio.current_task()
        async with self._lock:
            tasks = [task for task in self._tasks if task is not current and not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return len(tasks)


execution_registry = ExecutionRegistry()
