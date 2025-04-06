import pytest
import os
import sys
import asyncio
import websockets
import json
from datetime import datetime

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

@pytest.fixture
def test_db():
    """Fixture for test database"""
    db_path = "test_device_locator.db"
    yield db_path
    if os.path.exists(db_path):
        os.remove(db_path)

@pytest.fixture
def test_encryption_key():
    """Fixture for test encryption key"""
    key_file = "test_encryption_key.key"
    yield key_file
    if os.path.exists(key_file):
        os.remove(key_file)

@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test case"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def websocket_server():
    """Fixture for websocket server"""
    from websocket_server import LocationUpdateServer
    server = LocationUpdateServer(host="localhost", port=8765)
    server_task = asyncio.create_task(server.start_server())
    await asyncio.sleep(0.1)  # Give the server time to start
    yield server
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass
