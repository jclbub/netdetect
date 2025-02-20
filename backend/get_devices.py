import nmap
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
import uuid
import re
import netifaces
import asyncio
import time
import psutil
import struct


def get_local_ip_range():
    """Get the local IP range for scanning."""
    try:
        # Get network interfaces
        addrs = psutil.net_if_addrs()
        for interface, addresses in addrs.items():
            for addr in addresses:
                # Skip non-IPv4 addresses
                if addr.family != socket.AF_INET:
                    continue
                # Skip loopback and inactive interfaces
                if addr.address.startswith('127.') or addr.address == '0.0.0.0':
                    continue
                # Found a valid IPv4 address
                ip = addr.address
                netmask = addr.netmask
                if ip and netmask:
                    # Convert IP and netmask to network address
                    ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
                    mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
                    network = ip_int & mask_int
                    network_addr = socket.inet_ntoa(struct.pack('!I', network))
                    return [f"{network_addr}/24"]
        
        # Fallback to default range if no interface found
        return ["192.168.1.0/24"]
    except Exception as e:
        print(f"Error getting IP range: {e}")
        return ["192.168.1.0/24"]


def populate_arp(ip_range):
    """Ping devices in the IP range to populate the ARP table."""
    print("Populating ARP cache...")
    try:
        if platform.system() == "Windows":
            for i in range(1, 255):
                subprocess.run(
                    f"ping -n 1 {ip_range.split('/')[0]}{i}",
                    shell=True,
                    stdout=subprocess.PIPE,
                )
        else:
            subprocess.run(f"nmap -sn {ip_range}", shell=True, stdout=subprocess.PIPE)
    except Exception as e:
        print(f"Error populating ARP cache: {e}")


def get_mac_from_arp(ip_address):
    """Retrieve the MAC address for an IP address from the ARP table."""
    try:
        command = "arp -a" if platform.system() == "Windows" else f"arp -n {ip_address}"
        output = subprocess.check_output(command, shell=True, universal_newlines=True)
        for line in output.splitlines():
            if ip_address in line:
                mac = re.findall(r"(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})", line)
                return mac[0][0] if mac else "N/A"
    except subprocess.CalledProcessError:
        return "N/A"
    return "N/A"


def retry_arp_for_missing_mac(ip_address):
    """Retry ARP request for a specific IP to fetch its MAC address."""
    print(f"Retrying ARP for IP: {ip_address}")
    try:
        ping_command = (
            f"ping -n 1 {ip_address}"
            if platform.system() == "Windows"
            else f"ping -c 1 {ip_address}"
        )
        subprocess.run(ping_command, shell=True, stdout=subprocess.PIPE)
        return get_mac_from_arp(ip_address)
    except Exception as e:
        print(f"Retry ARP failed for {ip_address}: {e}")
        return "N/A"


def get_hostname(ip_address):
    """Get hostname for an IP address using multiple methods."""
    try:
        # For common router IPs, return a default name if lookup fails
        common_router_ips = {
            '192.168.0.1': 'Router',
            '192.168.1.1': 'Router',
            '192.168.2.1': 'Router',
            '192.168.3.1': 'Router',
            '10.0.0.1': 'Router',
            '10.1.1.1': 'Router'
        }
        
        # Check if it's a common router IP first
        if ip_address in common_router_ips:
            return common_router_ips[ip_address]
            
        # Try DNS lookup first
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            if hostname and hostname != ip_address:
                return hostname
        except (socket.herror, socket.gaierror):
            pass
            
        # Try NetBIOS lookup
        try:
            output = subprocess.check_output(f"nbtstat -A {ip_address}", shell=True, stderr=subprocess.PIPE, timeout=2).decode()
            for line in output.split('\n'):
                if '<00>' in line and 'UNIQUE' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        return parts[0].strip()
        except:
            pass
            
        return "Unknown"
        
    except Exception as e:
        print(f"Error in hostname lookup for {ip_address}: {e}")
        # Return Router for common router IPs even if lookup fails
        if ip_address in common_router_ips:
            return common_router_ips[ip_address]
        return "Unknown"


def get_host_mac():
    """Retrieve the MAC address of the host device."""
    try:
        mac = uuid.getnode()
        return ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except Exception as e:
        print(f"Failed to retrieve host MAC: {e}")
        return "N/A"


def parse_device_type(nm, ip_address):
    """Improved device type parsing based on Nmap scan results."""
    device_type = "Unknown Device"

    if ip_address not in nm.all_hosts():
        return device_type

    # Look at OS match results
    os_matches = nm[ip_address].get("osmatch", [])
    os_classes = nm[ip_address].get("osclass", [])

    for match in os_matches:
        os_name = match.get("name", "").lower()
        if "android" in os_name:
            return "Mobile Device"
        if "ios" in os_name or "iphone" in os_name:
            return "Mobile Device"
        if "windows" in os_name:
            return "Windows Laptop/Desktop"
        if "linux" in os_name:
            return "Linux Laptop/Desktop"
        if "mac" in os_name:
            return "MacOS Laptop/Desktop"

    for os_class in os_classes:
        if os_class.get("type") in ["phone", "tablet"]:
            return "Mobile Device"
        if os_class.get("type") == "computer":
            return "Laptop/Desktop"

    # Further check the MAC address vendor for some devices like printers, routers, etc.
    mac_address = nm[ip_address].get("addresses", {}).get("mac", "")
    if mac_address:
        vendor = get_vendor_from_mac(mac_address)
        if vendor:
            if "apple" in vendor.lower():
                return "MacOS Laptop/Desktop"
            if "samsung" in vendor.lower() or "xiaomi" in vendor.lower():
                return "Mobile Device"
            if "dell" in vendor.lower() or "hp" in vendor.lower():
                return "Windows Laptop/Desktop"
            if "lenovo" in vendor.lower():
                return "Windows Laptop/Desktop"

    return device_type


def get_vendor_from_mac(mac_address):
    """Return the vendor name based on the MAC address (using a simple prefix lookup)."""
    try:
        if not mac_address or len(mac_address) < 8:
            return "Unknown"
            
        # Normalize MAC address format (remove any separators and convert to uppercase)
        mac_clean = mac_address.replace(':', '').replace('-', '').replace('.', '').upper()
        
        # Get first 6 characters (OUI - Organizationally Unique Identifier)
        oui = mac_clean[:6]
        
        # Convert to standard format (XX:XX:XX)
        mac_prefix = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
        
        # Try exact match first
        vendor = mac_vendor_prefixes.get(mac_prefix)
        if vendor:
            return vendor
            
        # Try partial matches
        for prefix, name in mac_vendor_prefixes.items():
            prefix_clean = prefix.replace(':', '')
            if oui.startswith(prefix_clean[:4]):  # Match first 4 characters
                return name
                
        # Additional common vendors not in our database
        common_prefixes = {
            'C8': 'Cisco/Meraki',
            'B4': 'Samsung',
            'B8': 'Dell',
            'DC': 'Dell',
            '44': 'Xiaomi',
            '48': 'Dell',
            '4C': 'Dell',
            '50': 'Apple',
            '54': 'Samsung',
            '58': 'Xiaomi',
            '5C': 'Samsung',
            '60': 'Apple',
            '64': 'Samsung',
            '68': 'Apple',
            '6C': 'Samsung',
            '70': 'Apple',
            '74': 'Apple',
            '78': 'Apple',
            '7C': 'Apple',
            '80': 'Apple',
            '84': 'Apple',
            '88': 'Apple',
            '8C': 'Apple',
            '90': 'Apple',
            '94': 'Apple',
            '98': 'Apple',
            '9C': 'Apple',
            'A0': 'Apple',
            'A4': 'Apple',
            'A8': 'Apple',
            'AC': 'Apple',
            'B0': 'Apple',
            'B4': 'Apple',
            'B8': 'Apple',
            'BC': 'Apple',
            'C0': 'Apple',
            'C4': 'Apple',
            'C8': 'Apple',
            'CC': 'Apple',
            'D0': 'Apple',
            'D4': 'Apple',
            'D8': 'Apple',
            'DC': 'Apple',
            'E0': 'Apple',
            'E4': 'Apple',
            'E8': 'Apple',
            'EC': 'Apple',
            'F0': 'Apple',
            'F4': 'Apple',
            'F8': 'Apple',
            'FC': 'Apple'
        }
        
        # Try matching with common prefixes
        if len(mac_clean) >= 2:
            vendor = common_prefixes.get(mac_clean[:2])
            if vendor:
                return vendor
                
        return "Unknown"
        
    except Exception as e:
        print(f"Error in vendor lookup: {e}")
        return "Unknown"


def scan_mac_addresses():
    """Scan and return all MAC addresses found in the network."""
    try:
        ip_range = get_local_ip_range()
        populate_arp(ip_range)
        
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')
        
        mac_addresses = {}
        for host in nm.all_hosts():
            mac = get_mac_from_arp(host)
            if mac != "N/A":
                mac_addresses[host] = mac
        
        return mac_addresses
    except Exception as e:
        print(f"Error scanning MAC addresses: {e}")
        return {}


def scan_ip_addresses():
    """Scan and return all active IP addresses in the network."""
    try:
        ip_range = get_local_ip_range()
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_range, arguments='-sn')
        
        return {
            ip: {
                'status': 'active',
                'hostname': get_hostname(ip)
            }
            for ip in nm.all_hosts()
        }
    except Exception as e:
        print(f"Error scanning IP addresses: {e}")
        return {}


def scan_device_names():
    """Scan and return device names for all active hosts."""
    try:
        ip_addresses = scan_ip_addresses()
        device_names = {}
        
        for ip in ip_addresses:
            try:
                name = socket.gethostbyaddr(ip)[0]
                device_names[ip] = name
            except socket.herror:
                device_names[ip] = "Unknown"
                
        return device_names
    except Exception as e:
        print(f"Error scanning device names: {e}")
        return {}


def scan_hostnames():
    """Scan and return hostnames for all active hosts."""
    try:
        nm = nmap.PortScanner()
        ip_range = get_local_ip_range()
        nm.scan(hosts=ip_range, arguments='-sn')
        
        hostnames = {}
        for host in nm.all_hosts():
            try:
                if 'hostnames' in nm[host] and nm[host]['hostnames']:
                    hostnames[host] = nm[host]['hostnames'][0]['name']
                else:
                    hostnames[host] = socket.gethostbyaddr(host)[0]
            except:
                hostnames[host] = "Unknown"
                
        return hostnames
    except Exception as e:
        print(f"Error scanning hostnames: {e}")
        return {}


def scan_device_types():
    """Scan and return device types for all active hosts."""
    try:
        nm = nmap.PortScanner()
        ip_range = get_local_ip_range()
        nm.scan(hosts=ip_range, arguments='-sn -O')
        
        device_types = {}
        for host in nm.all_hosts():
            device_type = parse_device_type(nm, host)
            if not device_type:
                mac = get_mac_from_arp(host)
                if mac != "N/A":
                    vendor = get_vendor_from_mac(mac)
                    device_type = f"{vendor} device" if vendor else "Unknown device"
            device_types[host] = device_type
            
        return device_types
    except Exception as e:
        print(f"Error scanning device types: {e}")
        return {}


def get_all_device_info(ip_ranges=None, callback=None):
    """Get comprehensive information about all devices."""
    if not ip_ranges:
        ip_ranges = get_local_ip_range()
    
    print("Starting device scan...")
    devices = []
    
    try:
        # First try ARP scan which is faster
        print("Performing ARP scan...")
        arp_output = subprocess.check_output("arp -a", shell=True).decode()
        
        # Parse ARP output
        for line in arp_output.split('\n'):
            if 'dynamic' in line.lower():  # Only get dynamic (active) entries
                # Split by whitespace and filter out empty strings
                parts = [p for p in line.split() if p.strip()]
                if len(parts) >= 3:  # We need at least IP, MAC, and type
                    ip = parts[0]
                    mac = parts[1].upper()  # Keep the hyphens for now
                    
                    # Skip invalid or broadcast MACs
                    if mac.upper() in ["FF-FF-FF-FF-FF-FF", "00-00-00-00-00-00"]:
                        continue
                        
                    # Convert MAC format for vendor lookup (from AA-BB-CC-DD-EE-FF to AA:BB:CC:DD:EE:FF)
                    mac_for_vendor = mac.replace('-', ':')
                    vendor = get_vendor_from_mac(mac_for_vendor)
                    
                    # Get hostname
                    hostname = get_hostname(ip)
                    if hostname == "Unknown":
                        # Try to get NetBIOS name
                        try:
                            output = subprocess.check_output(f"nbtstat -A {ip}", shell=True, stderr=subprocess.PIPE).decode()
                            for nbt_line in output.split('\n'):
                                if '<00>' in nbt_line and 'UNIQUE' in nbt_line:
                                    nbt_parts = nbt_line.split()
                                    if len(nbt_parts) >= 1:
                                        hostname = nbt_parts[0].strip()
                                        break
                        except:
                            pass
                    
                    device = {
                        'ip_address': ip,
                        'mac_address': mac_for_vendor,  # Store in standard format with colons
                        'hostname': hostname,
                        'status': 'up',
                        'last_seen': time.time(),
                        'vendor': vendor
                    }
                    devices.append(device)
                    print(f"Added device: IP={ip}, MAC={mac_for_vendor}, Hostname={hostname}, Vendor={vendor}")
                    
                    # Send immediate update through callback
                    if callback:
                        callback({
                            'type': 'device_found',
                            'device': device,
                            'devices': devices  # Send full list for immediate update
                        })
        
        # If ARP scan found nothing or we want to be thorough, try nmap
        print("Running nmap scan for additional devices...")
        nm = nmap.PortScanner()
        nm.scan(hosts=",".join(ip_ranges), arguments="-sn -T4")
        
        for host in nm.all_hosts():
            try:
                if nm[host].state() != "up":
                    continue
                
                mac_address = get_mac_from_arp(host)
                if mac_address == "N/A":
                    continue
                
                # Convert MAC format
                mac_address = mac_address.upper().replace('-', ':')
                vendor = get_vendor_from_mac(mac_address)
                hostname = get_hostname(host)
                
                # Check if device already found via ARP
                if not any(d['mac_address'] == mac_address for d in devices):
                    device = {
                        'ip_address': host,
                        'mac_address': mac_address,
                        'hostname': hostname,
                        'status': 'up',
                        'last_seen': time.time(),
                        'vendor': vendor
                    }
                    devices.append(device)
                    print(f"Added device via nmap: IP={host}, MAC={mac_address}, Hostname={hostname}, Vendor={vendor}")
                    
                    # Send immediate update through callback
                    if callback:
                        callback({
                            'type': 'device_found',
                            'device': device,
                            'devices': devices  # Send full list for immediate update
                        })
            except Exception as e:
                print(f"Error scanning host {host}: {e}")
                continue
        
        print(f"Scan complete. Found {len(devices)} devices")
        return devices
        
    except Exception as e:
        print(f"Error during device scan: {e}")
        return devices  # Return any devices found before the error


def scan_host(ip_address):
    """Scan a single host and retrieve information, including device type."""
    nm = nmap.PortScanner()

    if ip_address == socket.gethostbyname(socket.gethostname()):
        return {
            "hostname": socket.gethostname(),
            "ip_address": ip_address,
            "mac_address": get_host_mac(),
            "device_type": "Host Device",
            "os": platform.system(),
        }

    try:
        print(f"Scanning host: {ip_address}")
        nm.scan(ip_address, arguments="-A -T4 -O --osscan-guess --osscan-limit")
    except Exception as e:
        print(f"Scan failed for {ip_address}: {e}")
        return {
            "hostname": "N/A",
            "ip_address": ip_address,
            "mac_address": "N/A",
            "device_type": "N/A",
            "os": "N/A",
        }

    hostname = get_hostname(ip_address)
    mac_address = nm[ip_address]["addresses"].get("mac", "")
    if mac_address == "N/A":
        mac_address = retry_arp_for_missing_mac(ip_address)

    # Use the improved device type parsing function
    device_type = parse_device_type(nm, ip_address)

    # Retrieve the device's operating system
    device_os = get_device_os(nm, ip_address)

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "device_type": device_type,
        "os": device_os,
    }


async def scan_network_quick(ip_ranges, callback=None):
    """Quick network scan for periodic updates with real-time device discovery."""
    if isinstance(ip_ranges, str):
        ip_ranges = [ip_ranges]
    
    print(f"Scanning IP ranges: {ip_ranges}")
    nm = nmap.PortScanner()
    
    try:
        # Fast scan without OS detection
        nm.scan(hosts=",".join(ip_ranges), arguments="-sn -T4")
        print(f"Found {len(nm.all_hosts())} hosts")
    except Exception as e:
        print(f"Network scan failed: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        try:
            # Basic host info
            host_info = nm[host]
            status = "up" if host_info.state() == "up" else "down"
            
            # Get MAC address
            mac_address = get_mac_from_arp(host)
            if mac_address == "N/A":
                # Try to ping the host to update ARP cache
                subprocess.run(
                    f"ping -n 1 {host}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                mac_address = get_mac_from_arp(host)
            
            device = {
                "ip_address": host,
                "mac_address": mac_address,
                "hostname": get_hostname(host),
                "status": status,
                "last_seen": time.time()
            }
            
            if device["mac_address"] != "N/A":
                print(f"Found device: {device['ip_address']} ({device['hostname']})")
                devices.append(device)
                if callback:
                    await callback(device)
            else:
                print(f"Skipping device with no MAC: {host}")
                
        except Exception as e:
            print(f"Error scanning {host}: {e}")

    print(f"Scan complete. Found {len(devices)} devices with MAC addresses")
    return devices


def scan_network(ip_ranges, callback=None):
    """Full network scan with detailed device information and real-time updates."""
    if isinstance(ip_ranges, str):
        ip_ranges = [ip_ranges]
    
    for ip_range in ip_ranges:
        populate_arp(ip_range)
    print(f"Scanning network: {ip_ranges}")

    nm = nmap.PortScanner()
    try:
        # Full scan with OS detection
        nm.scan(hosts=",".join(ip_ranges), arguments="-T4 -O --osscan-guess")
    except Exception as e:
        print(f"Network scan failed: {e}")
        return []

    devices = []
    for host in nm.all_hosts():
        try:
            device = scan_host(host)
            devices.append(device)
            if callback and asyncio.iscoroutinefunction(callback):
                asyncio.create_task(callback(device))
            elif callback:
                callback(device)
        except Exception as e:
            print(f"Error scanning {host}: {e}")

    return devices


def get_device_os(nm, ip_address):
    """Enhanced OS detection with more fallbacks."""
    try:
        if ip_address not in nm.all_hosts():
            return "Unknown OS"

        os_matches = nm[ip_address].get("osmatch", [])
        if os_matches:
            return os_matches[0].get("name", "Unknown OS")

        # Additional fallback: check open ports to deduce the OS (more complex)
        open_ports = nm[ip_address].get("tcp", {}).keys()
        if 22 in open_ports:
            return "Linux/Unix (SSH)"
        if 3389 in open_ports:
            return "Windows (RDP)"
        if 80 in open_ports:
            return "HTTP (Web Server)"

        return "Unknown OS"
    except Exception as e:
        print(f"Error detecting OS for {ip_address}: {e}")
        return "Unknown OS"


mac_vendor_prefixes = {
    # Apple devices
    "00:21:5D": "Apple Inc.",
    "00:1C:B3": "Apple Inc.",
    "00:1E:52": "Apple Inc.",
    "00:1F:5B": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "04:0C:CE": "Apple Inc.",
    "04:15:52": "Apple Inc.",
    "04:26:65": "Apple Inc.",
    "04:DB:56": "Apple Inc.",
    "04:F7:E4": "Apple Inc.",
    "0C:74:C2": "Apple Inc.",
    
    # Samsung devices
    "00:19:66": "Samsung Electronics",
    "00:23:39": "Samsung Electronics",
    "00:24:54": "Samsung Electronics",
    "00:26:37": "Samsung Electronics",
    "08:08:C2": "Samsung Electronics",
    "08:37:3D": "Samsung Electronics",
    "0C:14:20": "Samsung Electronics",
    
    # Intel devices
    "00:02:B3": "Intel Corporation",
    "00:03:47": "Intel Corporation",
    "00:04:23": "Intel Corporation",
    "00:0C:F1": "Intel Corporation",
    "00:0E:0C": "Intel Corporation",
    "00:0E:35": "Intel Corporation",
    
    # Dell devices
    "00:1A:2B": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "00:24:E8": "Dell Inc.",
    "00:26:B9": "Dell Inc.",
    "14:FE:B5": "Dell Inc.",
    "18:A9:9B": "Dell Inc.",
    "18:DB:F2": "Dell Inc.",
    
    # HP devices
    "00:14:22": "HP Inc.",
    "00:17:A4": "HP Inc.",
    "00:18:71": "HP Inc.",
    "00:1B:78": "HP Inc.",
    "00:1C:C4": "HP Inc.",
    "00:1E:0B": "HP Inc.",
    
    # Lenovo devices
    "B4:E6:2D": "Lenovo",
    "00:23:AE": "Lenovo",
    "60:D9:C7": "Lenovo",
    "88:70:8C": "Lenovo",
    "C8:DD:C9": "Lenovo",
    
    # Xiaomi devices
    "00:1A:11": "Xiaomi Communications",
    "00:9E:C8": "Xiaomi Communications",
    "0C:1D:AF": "Xiaomi Communications",
    "14:F6:5A": "Xiaomi Communications",
    "18:59:36": "Xiaomi Communications",
    
    # ASUS devices
    "00:1F:C6": "ASUSTek Computer Inc.",
    "00:23:54": "ASUSTek Computer Inc.",
    "00:24:8C": "ASUSTek Computer Inc.",
    "04:92:26": "ASUSTek Computer Inc.",
    "08:60:6E": "ASUSTek Computer Inc.",
    
    # Network equipment vendors
    "00:18:F3": "TP-Link Technologies",
    "00:40:96": "Cisco Systems",
    "00:1B:67": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:23:EB": "Cisco Systems",
    "00:25:9C": "Cisco Systems",
    "00:0B:86": "Aruba Networks",
    "00:1A:1E": "Aruba Networks",
    "04:BD:88": "Aruba Networks",
    "24:DE:C6": "Aruba Networks",
    "94:B4:0F": "Aruba Networks",
    
    # IoT and smart home devices
    "18:B4:30": "Nest Labs Inc.",
    "64:16:66": "Nest Labs Inc.",
    "00:24:E4": "Withings",
    "00:02:D1": "Vivotek Inc.",
    "00:12:2A": "VTech Telecommunications Ltd.",
    "00:1D:C9": "GainSpan Corp.",
}
