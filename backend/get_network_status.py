import speedtest
import psutil
import socket
import requests
import os
import platform
import nmap
import netifaces
from scapy.all import ARP, Ether, srp

def _run_speedtest():
    """Run a speed test to measure download/upload speeds and ping."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()

        # Set User-Agent header
        st._http.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'

        download_speed = st.download() / 1_000_000
        upload_speed = st.upload() / 1_000_000
        ping = st.results.ping

        return {
            "Download Speed (Mbps)": round(download_speed, 2),
            "Upload Speed (Mbps)": round(upload_speed, 2),
            "Ping (ms)": ping,
        }
    except speedtest.SpeedtestException as e:
        print(f"Speedtest error: {e}")
        return {
            "Download Speed (Mbps)": "N/A",
            "Upload Speed (Mbps)": "N/A",
            "Ping (ms)": "N/A",
        }


def _get_network_info():
    """Retrieve network info, including local IP, external IP, router, and DNS servers."""
    network_info = {}

    # Get device and OS information
    try:
        network_info["Device Name"] = platform.node()
        network_info["Operating System"] = f"{platform.system()} {platform.release()}"
        network_info["OS Version"] = platform.version()
    except Exception as e:
        print(f"Error fetching device/OS info: {e}")
        network_info["Device Name"] = "N/A"
        network_info["Operating System"] = "N/A"
        network_info["OS Version"] = "N/A"

    # Find active network interface and its IP
    try:
        active_ip = None
        active_mac = None
        
        # Create a test socket to determine the default route
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't actually connect or send any packets
            s.connect(('8.8.8.8', 1))
            active_ip = s.getsockname()[0]
        except Exception:
            print("Error getting active interface")
        finally:
            s.close()
            
        # Get MAC address for the active interface
        if active_ip:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == active_ip:
                        # Found the active interface, now get its MAC
                        for addr in addrs:
                            if addr.family == psutil.AF_LINK:
                                active_mac = addr.address
                                break
                        break
                if active_mac:
                    break
        
        network_info["Local IP"] = active_ip if active_ip else "N/A"
        network_info["MAC Address"] = active_mac if active_mac else "N/A"
        
    except Exception as e:
        print(f"Error fetching network interface info: {e}")
        network_info["Local IP"] = "N/A"
        network_info["MAC Address"] = "N/A"

    # Fetching external IP
    try:
        external_ip = requests.get("https://api.ipify.org", timeout=5).text
        network_info["External IP"] = external_ip
    except requests.RequestException as e:
        print(f"Error fetching external IP: {e}")
        network_info["External IP"] = "Unable to fetch"

    return network_info


def scan_mac_addresses():
    """Scan for MAC addresses of devices in the local network."""
    try:
        # Get the default gateway
        gws = netifaces.gateways()
        default_gateway = gws['default'][netifaces.AF_INET][0]
        
        # Create ARP request packet
        arp = ARP(pdst=f"{default_gateway}/24")
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        result = srp(packet, timeout=3, verbose=0)[0]
        devices = []
        
        for sent, received in result:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc
            })
            
        return devices
    except Exception as e:
        print(f"Error scanning MAC addresses: {e}")
        return []


def scan_ip_addresses():
    """Scan for IP addresses in the local network."""
    try:
        nm = nmap.PortScanner()
        # Get default gateway
        gws = netifaces.gateways()
        default_gateway = gws['default'][netifaces.AF_INET][0]
        
        # Scan the network
        nm.scan(hosts=f"{default_gateway}/24", arguments='-sn')
        
        ip_addresses = []
        for host in nm.all_hosts():
            ip_addresses.append({
                'ip': host,
                'status': nm[host].state()
            })
        return ip_addresses
    except Exception as e:
        print(f"Error scanning IP addresses: {e}")
        return []


def get_device_names():
    """Get device names from the local network."""
    try:
        devices = []
        for ip in scan_ip_addresses():
            try:
                hostname = socket.gethostbyaddr(ip['ip'])[0]
                devices.append({
                    'ip': ip['ip'],
                    'hostname': hostname
                })
            except:
                continue
        return devices
    except Exception as e:
        print(f"Error getting device names: {e}")
        return []


def get_device_type(mac_address):
    """Determine device type based on MAC address OUI."""
    try:
        # You might want to use a MAC address OUI database here
        # For now, returning a simplified version
        return "Unknown"
    except Exception as e:
        print(f"Error determining device type: {e}")
        return "Unknown"


def get_network_devices():
    """Get comprehensive information about all network devices."""
    devices = []
    
    # Get MAC and IP addresses
    mac_addresses = scan_mac_addresses()
    device_names = get_device_names()
    
    # Combine information
    for mac_info in mac_addresses:
        device = {
            'mac_address': mac_info['mac'],
            'ip_address': mac_info['ip'],
            'device_name': 'Unknown',
            'hostname': 'Unknown',
            'device_type': get_device_type(mac_info['mac'])
        }
        
        # Try to find matching hostname
        for name_info in device_names:
            if name_info['ip'] == mac_info['ip']:
                device['hostname'] = name_info['hostname']
                break
                
        devices.append(device)
    
    return devices


if __name__ == "__main__":
    # Run and display speed test results
    speedtest_results = _run_speedtest()
    print("\n=== Speed Test Results ===")
    for key, value in speedtest_results.items():
        print(f"{key}: {value}")

    # Fetch and display network info
    network_info = _get_network_info()
    print("\n=== Network Information ===")
    for key, value in network_info.items():
        print(f"{key}: {value}")

    # Fetch and display network devices
    network_devices = get_network_devices()
    print("\n=== Network Devices ===")
    for device in network_devices:
        print(f"MAC Address: {device['mac_address']}")
        print(f"IP Address: {device['ip_address']}")
        print(f"Device Name: {device['device_name']}")
        print(f"Hostname: {device['hostname']}")
        print(f"Device Type: {device['device_type']}")
        print("-" * 50)
