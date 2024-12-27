from fastapi import WebSocket, WebSocketDisconnect
import asyncio


connected_clients = []


async def handle_websocket(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        while True:
            
            await asyncio.sleep(1)  
    except WebSocketDisconnect:
       
        connected_clients.remove(websocket)


async def notify_clients(data):
    for client in connected_clients:
        try:
            await client.send_json(data)  
        except Exception:
            connected_clients.remove(client)
