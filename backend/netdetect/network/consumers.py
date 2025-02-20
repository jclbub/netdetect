import json
import scapy.all as scapy
import socket
import time
import threading
import asyncio
from collections import defaultdict
from channels.generic.websocket import AsyncWebsocketConsumer
import requests
import nmap
import logging
import platform
import sys
import os
import aiohttp

# Add the parent directory to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from get_devices import get_all_device_info, get_local_ip_range

# Configure logging
logging.basicConfig(level=logging.INFO)

class NetworkMonitorConsumer(AsyncWebsocketConsumer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.device_traffic = {}
        self.device_last_seen = {}

    async def connect(self):
        await self.accept()
        print("Network Monitor WebSocket connected")
        asyncio.create_task(self.monitor_network())

    async def disconnect(self, close_code):
        print("Network Monitor WebSocket disconnected")

    async def monitor_network(self):
        """Monitor the network and send data to WebSocket clients."""
        try:
            while True:
                # Get current network devices
                devices = await asyncio.to_thread(get_all_device_info)
                
                for device in devices:
                    device_type = await self.get_device_type(device)
                    os_name = await self.get_os_name(device)
                    await self.send_device_info(device, device_type, os_name)
                
                await asyncio.sleep(30)  # Update every 30 seconds
                
        except Exception as e:
            print(f"Error in monitor_network: {e}")

    async def packet_handler(self, packet):
        """Handle captured packets and update traffic data."""
        try:
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Update traffic counters
                self.device_traffic.setdefault(src_ip, 0)
                self.device_traffic.setdefault(dst_ip, 0)
                self.device_traffic[src_ip] += len(packet)
                self.device_traffic[dst_ip] += len(packet)
                
                # Update last seen time
                current_time = time.time()
                self.device_last_seen[src_ip] = current_time
                self.device_last_seen[dst_ip] = current_time
                
                # Send updated stats
                await self.send_device_stats({
                    'traffic': self.device_traffic,
                    'last_seen': self.device_last_seen
                })
                
        except Exception as e:
            print(f"Error handling packet: {e}")

    async def get_device_type(self, device):
        """Infer the device type based on hostname and MAC address."""
        try:
            ip, mac, hostname = device["ip"], device["mac"], device["hostname"]
            
            # Check hostname first
            if hostname:
                hostname_lower = hostname.lower()
                if any(phone in hostname_lower for phone in ["iphone", "android", "phone"]):
                    return "Mobile Phone"
                elif any(laptop in hostname_lower for laptop in ["laptop", "macbook", "notebook"]):
                    return "Laptop"
                elif any(desktop in hostname_lower for desktop in ["desktop", "pc", "computer"]):
                    return "Desktop"
                elif "printer" in hostname_lower:
                    return "Printer"
                elif any(router in hostname_lower for router in ["router", "gateway", "ap"]):
                    return "Router"
            
            # Check vendor
            vendor = await self.get_mac_vendor(mac)
            vendor_lower = vendor.lower()
            
            if any(apple in vendor_lower for apple in ["apple", "macintosh"]):
                return "Apple Device"
            elif any(mobile in vendor_lower for mobile in ["samsung", "xiaomi", "huawei", "oppo", "vivo"]):
                return "Mobile Device"
            elif any(pc in vendor_lower for pc in ["dell", "hp", "lenovo", "asus", "acer"]):
                return "Computer"
            elif any(network in vendor_lower for network in ["cisco", "tp-link", "netgear", "d-link", "ubiquiti"]):
                return "Network Device"
            
            return "Unknown Device"
            
        except Exception as e:
            print(f"Error determining device type: {e}")
            return "Unknown Device"

    async def get_os_name(self, device):
        """Retrieve OS name for a device."""
        try:
            mac = device["mac"]
            vendor = await self.get_mac_vendor(mac)
            
            if "Apple" in vendor:
                return "macOS/iOS"
            elif "Microsoft" in vendor:
                return "Windows"
            elif any(android in vendor.lower() for android in ["samsung", "xiaomi", "huawei", "oppo", "vivo"]):
                return "Android"
            elif any(linux in vendor.lower() for linux in ["raspberry", "ubuntu", "linux"]):
                return "Linux"
            
            return "Unknown OS"
            
        except Exception as e:
            print(f"Error determining OS: {e}")
            return "Unknown OS"

    async def get_mac_vendor(self, mac):
        """Get vendor information for a MAC address."""
        try:
            # Use aiohttp for async HTTP requests
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.macvendors.com/{mac}", timeout=2) as response:
                    if response.status == 200:
                        return await response.text()
            return "Unknown Vendor"
        except Exception as e:
            print(f"Error getting vendor: {e}")
            return "Unknown Vendor"

    async def send_device_info(self, device, device_type, os_name):
        """Send device information to the WebSocket client."""
        try:
            device_info = {
                "ip": device["ip"],
                "mac": device["mac"],
                "hostname": device["hostname"],
                "deviceType": device_type,
                "osName": os_name,
                "lastSeen": self.device_last_seen.get(device["ip"], time.time()),
                "traffic": self.device_traffic.get(device["ip"], 0)
            }
            await self.send(text_data=json.dumps(device_info))
        except Exception as e:
            print(f"Error sending device info: {e}")

    async def send_device_stats(self, stats):
        """Send device statistics to the WebSocket client."""
        try:
            await self.send(text_data=json.dumps({
                "type": "stats",
                "data": stats
            }))
        except Exception as e:
            print(f"Error sending stats: {e}")

class NetworkScannerConsumer(AsyncWebsocketConsumer):
    scanning = False
    scan_task = None
    loop = None  # Store the event loop

    async def connect(self):
        await self.accept()
        self.loop = asyncio.get_event_loop()  # Store the event loop when connecting
        print("WebSocket connected")

    async def disconnect(self, close_code):
        self.stop_scanning()
        print("WebSocket disconnected")

    def stop_scanning(self):
        if self.scan_task:
            self.scan_task.cancel()
            self.scanning = False
            self.scan_task = None

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            command = data.get('command')

            if command == 'start_scan':
                if not self.scanning:
                    self.scanning = True
                    # Send initial scanning status
                    await self.send(json.dumps({
                        'type': 'status',
                        'status': 'scanning'
                    }))
                    # Start scanning in background
                    self.scan_task = asyncio.create_task(self.real_time_scan())
            elif command == 'stop_scan':
                self.stop_scanning()
                await self.send(json.dumps({
                    'type': 'status',
                    'status': 'stopped'
                }))

        except Exception as e:
            print(f"Error processing message: {e}")
            await self.send(json.dumps({
                'type': 'error',
                'error': str(e)
            }))

    async def real_time_scan(self):
        """Perform real-time scanning of the network."""
        try:
            while self.scanning:
                # Get the local IP range
                ip_range = get_local_ip_range()
                
                # Create a callback that uses the stored event loop
                def device_callback(data):
                    if self.loop and not self.loop.is_closed():
                        asyncio.run_coroutine_threadsafe(
                            self.send(json.dumps(data)),
                            self.loop
                        )
                
                # Run the device scan in a thread pool to avoid blocking
                devices = await asyncio.to_thread(
                    get_all_device_info,
                    ip_range,
                    device_callback  # Pass the callback for real-time updates
                )
                
                # Send final update with all devices
                if self.scanning:  # Check if we're still supposed to be scanning
                    await self.send(json.dumps({
                        'type': 'devices',
                        'devices': devices
                    }))
                    
                    # Wait before next scan
                    await asyncio.sleep(30)  # Scan every 30 seconds
                
        except asyncio.CancelledError:
            print("Scan task cancelled")
        except Exception as e:
            print(f"Error during real-time scan: {e}")
            if self.scanning:
                await self.send(json.dumps({
                    'type': 'error',
                    'error': str(e)
                }))

async def scan_network(ip_range):
    """Scan the network and return a list of devices with details."""
    try:
        print(f"Starting network scan on range: {ip_range}")
        
        # Use ARP scanning which is faster and more reliable for local network
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        # Send ARP request and get responses
        print("Sending ARP requests...")
        answered_list = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: scapy.srp(arp_request_broadcast, timeout=3, verbose=True)[0]
        )
        
        devices = []
        print(f"Got {len(answered_list)} responses")
        
        for sent, received in answered_list:
            try:
                ip_address = received.psrc
                mac_address = received.hwsrc
                
                print(f"Processing device: IP={ip_address}, MAC={mac_address}")
                
                # Try to get hostname (with timeout)
                hostname = "Unknown"
                try:
                    hostname = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: socket.gethostbyaddr(ip_address)[0]
                    )
                except:
                    pass
                
                device = {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "hostname": hostname,
                    "vendor": await get_mac_vendor(mac_address),
                    "device_type": "Unknown",
                    "os": "Unknown"
                }
                
                print(f"Found device: {device}")
                devices.append(device)
                
            except Exception as e:
                print(f"Error processing device response: {e}")
                continue
        
        return devices
        
    except Exception as e:
        print(f"Error in network scan: {e}")
        return []

def get_hostname(ip):
    """Retrieve hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

async def get_mac_vendor(mac):
    """Fetch vendor information for a MAC address using macvendors.com API."""
    try:
        # Use aiohttp for async HTTP requests
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.macvendors.com/{mac}", timeout=2) as response:
                if response.status == 200:
                    return await response.text()
        return "Unknown Vendor"
    except Exception as e:
        print(f"Error getting vendor: {e}")
        return "Unknown Vendor"

def get_local_ip_range():
    # Get the local IP range dynamically
    local_ip = socket.gethostbyname(socket.gethostname())
    ip_parts = local_ip.split(".")[:3]
    ip_range = f"{'.'.join(ip_parts)}.0/24"
    return ip_range
