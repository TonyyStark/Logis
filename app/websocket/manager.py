"""
WebSocket connection manager for real-time communication.
"""
import asyncio
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manage WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.connection_info: Dict[WebSocket, Dict[str, Any]] = {}
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.connection_info[websocket] = {
            "connected_at": datetime.utcnow(),
            "client_ip": websocket.client.host if websocket.client else "unknown",
        }
        logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
        
        # Send welcome message
        await self.send_personal_message({
            "type": "connected",
            "data": {
                "message": "Connected to CyberAI SOC Platform",
                "timestamp": datetime.utcnow().isoformat(),
            }
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        if websocket in self.connection_info:
            del self.connection_info[websocket]
        logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """Send a message to a specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message: {e}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast a message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def send_alert(self, alert: Dict[str, Any]):
        """Send a real-time alert to all connected clients."""
        await self.broadcast({
            "type": "alert",
            "data": alert,
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    async def send_log(self, log: Dict[str, Any]):
        """Send a real-time log entry to all connected clients."""
        await self.broadcast({
            "type": "log",
            "data": log,
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    async def send_stats(self, stats: Dict[str, Any]):
        """Send dashboard stats update."""
        await self.broadcast({
            "type": "stats",
            "data": stats,
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    async def send_anomaly(self, anomaly: Dict[str, Any]):
        """Send anomaly detection result."""
        await self.broadcast({
            "type": "anomaly",
            "data": anomaly,
            "timestamp": datetime.utcnow().isoformat(),
        })
    
    async def send_heartbeat(self):
        """Send periodic heartbeat to keep connections alive."""
        await self.broadcast({
            "type": "heartbeat",
            "data": {"timestamp": datetime.utcnow().isoformat()},
        })
    
    def get_connection_count(self) -> int:
        """Get the number of active connections."""
        return len(self.active_connections)
    
    async def handle_client_message(self, websocket: WebSocket, message: Dict[str, Any]):
        """Handle incoming message from client."""
        msg_type = message.get("type", "")
        
        if msg_type == "ping":
            await self.send_personal_message({
                "type": "pong",
                "data": {"timestamp": datetime.utcnow().isoformat()}
            }, websocket)
        elif msg_type == "subscribe":
            channel = message.get("channel", "")
            self.connection_info[websocket]["subscription"] = channel
            await self.send_personal_message({
                "type": "subscribed",
                "data": {"channel": channel}
            }, websocket)
        elif msg_type == "request_stats":
            # Client requesting immediate stats
            pass  # Will be handled by the endpoint


# Global WebSocket manager instance
ws_manager = WebSocketManager()
