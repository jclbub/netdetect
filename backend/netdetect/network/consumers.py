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

device_traffic = defaultdict(int)  # Store traffic per IP
device_last_seen = defaultdict(float)  # Store last update time per IP
lock = threading.Lock()

class NetworkMonitorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection
        await self.accept()
        # Start monitoring in a separate thread
        self.monitoring_thread = threading.Thread(target=self.monitor_network)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()

    async def disconnect(self, close_code):
        # Handle WebSocket disconnection
        print("WebSocket disconnected:", close_code)

    async def send_device_stats(self, stats):
        # Send device stats to the WebSocket client
        await self.send(text_data=json.dumps(stats))

    def monitor_network(self):
        """Monitor the network and send data to WebSocket clients."""
        ip_range = "192.168.3.0/24"
        interval = 5
        sniff_thread = threading.Thread(target=lambda: scapy.sniff(prn=self.packet_handler, store=False, promisc=True))
        sniff_thread.daemon = True
        sniff_thread.start()

        while True:
            time.sleep(interval)
            devices = scan_network(ip_range)
            now = time.time()
            stats = []

            with lock:
                for device in devices:
                    ip, mac, hostname = device["ip"], device["mac"], device["hostname"]
                    device_type = infer_device_type(hostname, mac)
                    total_bytes = device_traffic.get(ip, 0)
                    mbps = (total_bytes * 8) / (1024 * 1024 * interval)
                    stats.append({
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "deviceType": device_type,
                        "totalBytes": total_bytes,
                        "mbps": round(mbps, 2)
                    })
                # Clean up old entries
                stale_ips = [ip for ip, last_seen in device_last_seen.items() if now - last_seen > interval * 2]
                for ip in stale_ips:
                    del device_traffic[ip]
                    del device_last_seen[ip]

            # Send stats to WebSocket clients
            asyncio.run(self.send_device_stats(stats))

    def packet_handler(self, packet):
        """Handle captured packets and update traffic data."""
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst
            packet_size = len(packet)
            with lock:
                device_traffic[src_ip] += packet_size
                device_traffic[dst_ip] += packet_size
                device_last_seen[src_ip] = time.time()
                device_last_seen[dst_ip] = time.time()


def scan_network(ip_range):
    """Scan the network and return a list of devices with details."""
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    devices = []
    for element in answered_list:
        devices.append({
            "ip": element[1].psrc,
            "mac": element[1].hwsrc,
            "hostname": get_hostname(element[1].psrc)
        })
    return devices


def get_hostname(ip):
    """Retrieve hostname for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"


def get_mac_vendor(mac):
    """Fetch vendor information for a MAC address using macvendors.com API."""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if response.status_code == 200:
            return response.text
        elif response.status_code == 429:
            return "Rate Limited"
        else:
            return "Unregistered MAC"
    except requests.exceptions.RequestException:
        return "Unregistered MAC"


def infer_device_type(hostname, mac):
    """Infer the device type based on hostname and MAC address."""
    if hostname:
        hostname_lower = hostname.lower()
        if "desktop" in hostname_lower:
            return "Desktop"
        elif "laptop" in hostname_lower:
            return "Laptop"
        elif "android" in hostname_lower or "oppo" in hostname_lower or "realme" in hostname_lower:
            return "Phone"
        elif "iphone" in hostname_lower or "ipad" in hostname_lower:
            return "Phone"
        elif "zte" in hostname_lower:
            return "Router or IoT Device"

    vendor = get_mac_vendor(mac)
    if "Apple" in vendor:
        return "Phone or Laptop (Apple)"
    elif "Samsung" in vendor:
        return "Phone or Tablet (Samsung)"
    elif "OPPO" in vendor or "Realme" in vendor:
        return "Phone"
    elif "Dell" in vendor or "HP" in vendor or "Lenovo" in vendor:
        return "Laptop or Desktop"
    elif "ZTE" in vendor:
        return "Router or IoT Device"
    elif "GUANGDONG" in vendor:
        return "Phone"
    elif "Xiaomi" in vendor or "Redmi" in vendor:
        return "Phone or Tablet (Xiaomi)"
    elif "ASUS" in vendor:
        return "Laptop or Desktop (ASUS)"
    elif "Microsoft" in vendor:
        return "Laptop or Desktop (Microsoft)"
    elif "Toshiba" in vendor:
        return "Laptop or Desktop (Toshiba)"
    elif "Acer" in vendor:
        return "Laptop or Desktop (Acer)"
    elif "Huawei" in vendor:
        return "Phone or Tablet (Huawei)"
    elif "Sony" in vendor:
        return "Laptop or Tablet (Sony)"
    elif "LG" in vendor:
        return "Phone or Tablet (LG)"
    elif "Lenovo" in vendor:
        return "Laptop or Desktop (Lenovo)"
    elif "Unregistered MAC" in vendor:
        return "Unregistered Device"  # If MAC address is unregistered
    # Default to unknown
    return "Unregistered MAC"


class NetworkScannerConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection
        await self.accept()
        self.scanning = True  # Flag to control the scanning loop
        self.scan_task = None  # Initialize the scan task variable

        # Start the real-time scan in the background
        self.scan_task = asyncio.create_task(self.real_time_scan("192.168.1.0/24"))

    async def disconnect(self, close_code):
        # Stop the real-time scan when the WebSocket disconnects
        self.scanning = False
        if self.scan_task:
            # Cancel the task and wait for it to finish
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass

    async def receive(self, text_data):
        # Optionally handle messages from the client
        data = json.loads(text_data)
        ip_range = data.get("ip_range", "192.168.3.0/24")

        # Update the scan task with a new IP range
        self.scanning = False  # Stop the current scan
        if self.scan_task:
            self.scan_task.cancel()
            try:
                await self.scan_task
            except asyncio.CancelledError:
                pass
        self.scanning = True  # Restart with the new IP range
        self.scan_task = asyncio.create_task(self.real_time_scan(ip_range))

    async def real_time_scan(self, ip_range):
        """Perform real-time scanning and send updates to the WebSocket."""
        nm = nmap.PortScanner()
        try:
            while self.scanning:
                nm.scan(hosts=ip_range, ports="1-1000", arguments="-sS")
                results = []

                for host in nm.all_hosts():
                    host_info = {
                        "host": host,
                        "hostname": nm[host].hostname(),
                        "state": nm[host].state(),
                        "ports": [],
                        "danger_level": self.evaluate_danger_level(nm, host),
                    }

                    if "tcp" in nm[host]:
                        for port, port_info in nm[host]["tcp"].items():
                            host_info["ports"].append({
                                "port": port,
                                "state": port_info["state"],
                                "service": port_info.get("name", "unknown"),
                            })

                    results.append(host_info)

                # Send scan results to the WebSocket client
                await self.send(text_data=json.dumps({"scan_results": results}))

                # Wait for a while before the next scan
                await asyncio.sleep(10)  # Adjust the interval as needed
        except asyncio.CancelledError:
            # Handle the task cancellation gracefully
            pass

    def evaluate_danger_level(self, nm, host):
        open_ports = nm[host]['tcp'] if 'tcp' in nm[host] else {}
        default_ports = [23, 21, 445]  # Commonly attacked ports
        risky_ports = [port for port in open_ports if port in default_ports]

        if risky_ports:
            return "High"
        elif len(open_ports) > 5:
            return "Medium"
        else:
            return "Low"
