import netifaces
import scapy.all as scapy
import socket
import asyncio
import sys

def get_local_ip_range():
    """Retrieve all local network IP ranges."""
    try:
        ip_ranges = []
        interfaces = netifaces.interfaces()
        print(f"\nFound network interfaces: {interfaces}")
        
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            print(f"\nChecking interface {interface}...")
            
            # Get IPv4 addresses
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    if 'addr' in addr and 'netmask' in addr:
                        ip = addr['addr']
                        netmask = addr['netmask']
                        print(f"Found IP address {ip} with netmask {netmask}")
                        
                        # Skip loopback and virtual addresses
                        if ip.startswith('127.') or ip.startswith('169.254'):
                            print(f"Skipping {ip} (loopback/virtual)")
                            continue
                            
                        # Calculate network address
                        ip_parts = [int(x) for x in ip.split('.')]
                        mask_parts = [int(x) for x in netmask.split('.')]
                        network = '.'.join(str(ip_parts[i] & mask_parts[i]) for i in range(4))
                        
                        # Calculate CIDR notation
                        cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
                        ip_range = f"{network}/{cidr}"
                        
                        print(f"Adding network range: {ip_range}")
                        ip_ranges.append(ip_range)
        
        if not ip_ranges:
            print("\nNo valid network interfaces found, using default range")
            return ["192.168.1.0/24"]
            
        print(f"\nFinal network ranges to scan: {ip_ranges}")
        return ip_ranges
        
    except Exception as e:
        print(f"\nError retrieving network ranges: {e}")
        return ["192.168.1.0/24"]

async def scan_network(ip_range):
    """Scan the network and return a list of devices with details."""
    try:
        print(f"\nStarting network scan on range: {ip_range}")
        
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
        print(f"\nGot {len(answered_list)} responses")
        
        for sent, received in answered_list:
            try:
                ip_address = received.psrc
                mac_address = received.hwsrc
                
                print(f"\nFound device: IP={ip_address}, MAC={mac_address}")
                
                # Try to get hostname (with timeout)
                hostname = "Unknown"
                try:
                    hostname = await asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: socket.gethostbyaddr(ip_address)[0]
                    )
                    print(f"Hostname: {hostname}")
                except:
                    print("Could not resolve hostname")
                
                device = {
                    "ip_address": ip_address,
                    "mac_address": mac_address,
                    "hostname": hostname
                }
                
                devices.append(device)
                
            except Exception as e:
                print(f"Error processing device response: {e}")
                continue
        
        return devices
        
    except Exception as e:
        print(f"Error in network scan: {e}")
        return []

async def main():
    # Get network ranges
    ip_ranges = get_local_ip_range()
    
    # Scan each range
    for ip_range in ip_ranges:
        print(f"\nScanning range: {ip_range}")
        devices = await scan_network(ip_range)
        print(f"\nDevices found in {ip_range}:")
        for device in devices:
            print(f"  {device}")

if __name__ == "__main__":
    # Check if running with admin privileges
    try:
        is_admin = False
        if sys.platform.startswith('win'):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            
        print(f"Running with admin privileges: {is_admin}")
        if not is_admin:
            print("Warning: Network scanning may require admin privileges")
            print("Try running this script as administrator")
    except:
        print("Could not determine admin status")
    
    # Run the test
    asyncio.run(main())
