"""Milli Kiber-DNT — WebSocket Connection Manager

Manages real-time WebSocket connections to frontend clients.
Broadcasts scan results, log entries, and BAS verification data
as they happen (server-sent events over WebSocket).
"""

import json
import asyncio
from typing import Set, Dict, Any
from datetime import datetime


class ConnectionManager:
    """Manages WebSocket connections and broadcasts to all clients."""

    def __init__(self):
        self._connections: Set[Any] = set()
        self._connection_count = 0

    async def connect(self, websocket) -> str:
        await websocket.accept()
        self._connections.add(websocket)
        self._connection_count += 1
        client_id = f"client-{self._connection_count}"
        await self.broadcast({
            "type": "system",
            "event": "CLIENT_CONNECTED",
            "message": f"New client connected ({len(self._connections)} total)",
            "timestamp": datetime.utcnow().isoformat()
        })
        return client_id

    async def disconnect(self, websocket):
        self._connections.discard(websocket)
        await self.broadcast({
            "type": "system",
            "event": "CLIENT_DISCONNECTED",
            "message": f"Client disconnected ({len(self._connections)} remaining)",
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast(self, message: Dict):
        """Send a message to all connected WebSocket clients."""
        if not self._connections:
            return
        dead = set()
        payload = json.dumps(message, default=str)
        for ws in self._connections:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        self._connections -= dead

    async def send_to(self, websocket, message: Dict):
        """Send a message to a specific client."""
        try:
            await websocket.send_text(json.dumps(message, default=str))
        except Exception:
            await self.disconnect(websocket)

    async def broadcast_scan_result(self, assets: list, incident_id: str = None):
        """Broadcast real-time scan results as they are discovered."""
        for asset in assets:
            await self.broadcast({
                "type": "scan",
                "event": "ASSET_DISCOVERED",
                "data": asset,
                "incident_id": incident_id,
                "timestamp": datetime.utcnow().isoformat()
            })

    async def broadcast_log(self, incident_id: str, phase: str,
                             event_type: str, message: str,
                             severity: str = "info", data: Dict = None):
        """Broadcast a real-time log entry."""
        await self.broadcast({
            "type": "log",
            "event": event_type,
            "phase": phase,
            "message": message,
            "severity": severity,
            "data": data or {},
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_epss(self, epss_data: Dict):
        """Broadcast EPSS score update."""
        await self.broadcast({
            "type": "epss",
            "event": "EPSS_SCORE",
            "data": epss_data,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_rule(self, rule_data: Dict):
        """Broadcast generated WAF/IPS rule."""
        await self.broadcast({
            "type": "rule",
            "event": "RULE_GENERATED",
            "data": rule_data,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_bas(self, bas_data: Dict):
        """Broadcast BAS verification result."""
        await self.broadcast({
            "type": "bas",
            "event": "BAS_RESULT",
            "data": bas_data,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_report(self, report_data: Dict):
        """Broadcast generated report chunk."""
        await self.broadcast({
            "type": "report",
            "event": "REPORT_CHUNK",
            "data": report_data,
            "timestamp": datetime.utcnow().isoformat()
        })

    async def broadcast_phase_update(self, phase: int, status: str,
                                      incident_id: str = None):
        """Broadcast core loop phase status update."""
        phase_names = {
            1: "Kəşfiyyat & Kəşf",
            2: "AI Qərar Verici",
            3: "SOAR & Remediasiya",
            4: "BAS Doğrulama",
            5: "İnsident Öyrənmə"
        }
        await self.broadcast({
            "type": "phase",
            "event": "PHASE_UPDATE",
            "phase": phase,
            "phase_name": phase_names.get(phase, f"Mərhələ {phase}"),
            "status": status,
            "incident_id": incident_id,
            "timestamp": datetime.utcnow().isoformat()
        })

    @property
    def active_connections(self) -> int:
        return len(self._connections)
