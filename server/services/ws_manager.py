"""
WebSocket broadcast manager — pushes real-time events to all connected operator UIs.
"""
import json
import logging
from typing import List

from fastapi import WebSocket

logger = logging.getLogger("ws_manager")


class WSManager:
    def __init__(self):
        self._conns: List[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._conns.append(ws)
        logger.debug("WS connected — %d total", len(self._conns))

    def disconnect(self, ws: WebSocket) -> None:
        try:
            self._conns.remove(ws)
        except ValueError:
            pass
        logger.debug("WS disconnected — %d total", len(self._conns))

    async def broadcast(self, event: dict) -> None:
        if not self._conns:
            return
        payload = json.dumps(event)
        dead = []
        for ws in list(self._conns):
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = WSManager()
