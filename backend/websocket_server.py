import asyncio
import websockets
import json
from get_devices import scan_network, scan_network_quick, get_local_ip_range
import psutil
import time

connected_clients = set()
last_full_scan = 0
FULL_SCAN_INTERVAL = 60  # Do full scan every 60 seconds

async def send_device_update(websocket, device, scan_type="quick"):
    """Send a single device update to the websocket."""
    try:
        update = {
            "type": "device_update",
            "scan_type": scan_type,
            "device": device
        }
        print(f"Sending device update: {device['ip_address']}")
        await websocket.send(json.dumps(update))
    except Exception as e:
        print(f"Error sending device update: {e}")

async def send_network_stats(websocket):
    """Send current network statistics."""
    try:
        stats = {
            "type": "network_stats",
            "stats": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
                "packets_sent": psutil.net_io_counters().packets_sent,
                "packets_recv": psutil.net_io_counters().packets_recv,
            }
        }
        await websocket.send(json.dumps(stats))
    except Exception as e:
        print(f"Error sending network stats: {e}")

async def device_callback(websocket, device, scan_type):
    """Wrapper for device update callback to handle async properly."""
    await send_device_update(websocket, device, scan_type)

async def register(websocket):
    print("New client connected")
    connected_clients.add(websocket)
    try:
        # Start with network stats
        await send_network_stats(websocket)
        
        # Start a quick scan and send updates in real-time
        print("Starting initial device scan...")
        await scan_network_quick(
            get_local_ip_range(),
            callback=lambda dev: device_callback(websocket, dev, "quick")
        )
        print("Initial scan complete")
        
        # Keep connection alive
        await websocket.wait_closed()
    except Exception as e:
        print(f"Error in register: {e}")
    finally:
        print("Client disconnected")
        connected_clients.remove(websocket)

async def broadcast_network_data():
    global last_full_scan
    while True:
        try:
            if connected_clients:
                current_time = time.time()
                
                # Send network stats to all clients
                for websocket in connected_clients:
                    await send_network_stats(websocket)
                
                # Determine if we need a full scan
                if current_time - last_full_scan >= FULL_SCAN_INTERVAL:
                    print("Starting full network scan...")
                    scan_type = "full"
                    last_full_scan = current_time
                    for websocket in connected_clients:
                        await scan_network_quick(
                            get_local_ip_range(),
                            callback=lambda dev: device_callback(websocket, dev, scan_type)
                        )
                    print("Full scan complete")
                else:
                    print("Starting quick network scan...")
                    scan_type = "quick"
                    for websocket in connected_clients:
                        await scan_network_quick(
                            get_local_ip_range(),
                            callback=lambda dev: device_callback(websocket, dev, scan_type)
                        )
                    print("Quick scan complete")
            
            await asyncio.sleep(2)  # Update every 2 seconds
        except Exception as e:
            print(f"Error in broadcast: {e}")
            await asyncio.sleep(2)

async def main():
    print("Starting websocket server...")
    async with websockets.serve(register, "localhost", 8765):
        print("Websocket server is running on ws://localhost:8765")
        await broadcast_network_data()

if __name__ == "__main__":
    asyncio.run(main())
