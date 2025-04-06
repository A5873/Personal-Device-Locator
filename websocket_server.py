import asyncio
import websockets
import json
import logging
import ssl
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('LocationServer')

class LocationUpdateServer:
    def __init__(self, host="localhost", port=8765):
        self.host = host
        self.port = port
        self.clients = set()
        self.device_subscriptions = {}  # Map device_ids to set of clients
        
    async def register(self, websocket):
        """Register a new client connection"""
        self.clients.add(websocket)
        logger.info(f"New client connected. Total clients: {len(self.clients)}")
        
    async def unregister(self, websocket):
        """Unregister a client connection"""
        self.clients.remove(websocket)
        # Remove from device subscriptions
        for device_subs in self.device_subscriptions.values():
            device_subs.discard(websocket)
        logger.info(f"Client disconnected. Remaining clients: {len(self.clients)}")
        
    async def subscribe_to_device(self, websocket, device_id):
        """Subscribe a client to updates for a specific device"""
        if device_id not in self.device_subscriptions:
            self.device_subscriptions[device_id] = set()
        self.device_subscriptions[device_id].add(websocket)
        logger.info(f"Client subscribed to device {device_id}")
        
    async def unsubscribe_from_device(self, websocket, device_id):
        """Unsubscribe a client from updates for a specific device"""
        if device_id in self.device_subscriptions:
            self.device_subscriptions[device_id].discard(websocket)
            if not self.device_subscriptions[device_id]:
                del self.device_subscriptions[device_id]
        logger.info(f"Client unsubscribed from device {device_id}")
        
    async def broadcast_location_update(self, device_id, location_data):
        """Broadcast location update to subscribed clients"""
        if device_id in self.device_subscriptions:
            message = json.dumps({
                "type": "location_update",
                "device_id": device_id,
                "data": location_data,
                "timestamp": datetime.now().isoformat()
            })
            
            disconnected = set()
            for client in self.device_subscriptions[device_id]:
                try:
                    await client.send(message)
                except websockets.exceptions.ConnectionClosed:
                    disconnected.add(client)
                    
            # Clean up disconnected clients
            for client in disconnected:
                await self.unregister(client)
                
    async def handle_client(self, websocket, path):
        """Handle client connection and messages"""
        await self.register(websocket)
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    if data["action"] == "subscribe":
                        await self.subscribe_to_device(websocket, data["device_id"])
                    elif data["action"] == "unsubscribe":
                        await self.unsubscribe_from_device(websocket, data["device_id"])
                    elif data["action"] == "update":
                        await self.broadcast_location_update(data["device_id"], data["location"])
                except json.JSONDecodeError:
                    logger.error("Invalid JSON message received")
                except KeyError as e:
                    logger.error(f"Missing required field in message: {e}")
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            await self.unregister(websocket)
            
    async def start_server(self):
        """Start the WebSocket server"""
        server = await websockets.serve(
            self.handle_client,
            self.host,
            self.port
        )
        logger.info(f"Location update server started on ws://{self.host}:{self.port}")
        return server

def main():
    """Main entry point for the server"""
    server = LocationUpdateServer()
    
    # Start the server
    loop = asyncio.get_event_loop()
    loop.run_until_complete(server.start_server())
    
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    finally:
        loop.close()

if __name__ == "__main__":
    main()

