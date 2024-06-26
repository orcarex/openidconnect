import asyncio
import websockets
import time
import tracemalloc
from memory_profiler import profile

@profile
async def hello(uri):
    async with websockets.connect(uri) as websocket:

        await websocket.send("Jimmy")
        print(f"(client) send to server: Jimmy")
        name = await websocket.recv()
        print(f"(client) recv from server {name}")
        print(time.time())



asyncio.get_event_loop().run_until_complete(
    hello('ws://localhost:8765'))

