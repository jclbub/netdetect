import socket
import psutil
import requests
import platform

def test_network_info():
    """Test network information retrieval."""
    print("\n=== Network Information Test ===")
    
    # Test active interface detection
    print("\n1. Testing Active Interface Detection:")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 1))
            active_ip = s.getsockname()[0]
            print(f"[OK] Active IP detected: {active_ip}")
        except Exception as e:
            print(f"[ERROR] Error getting active interface: {e}")
        finally:
            s.close()
    except Exception as e:
        print(f"[ERROR] Socket creation error: {e}")

    # Test interface enumeration
    print("\n2. Network Interfaces:")
    try:
        for interface, addrs in psutil.net_if_addrs().items():
            print(f"\nInterface: {interface}")
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    print(f"  IPv4: {addr.address}")
                elif addr.family == psutil.AF_LINK:
                    print(f"  MAC:  {addr.address}")
    except Exception as e:
        print(f"[ERROR] Error listing interfaces: {e}")

    # Test external IP detection
    print("\n3. Testing External IP Detection:")
    try:
        external_ip = requests.get("https://api.ipify.org", timeout=5).text
        print(f"[OK] External IP detected: {external_ip}")
    except Exception as e:
        print(f"[ERROR] Error getting external IP: {e}")

    # Test system information
    print("\n4. System Information:")
    try:
        print(f"Device Name: {platform.node()}")
        print(f"OS: {platform.system()} {platform.release()}")
    except Exception as e:
        print(f"[ERROR] Error getting system info: {e}")

if __name__ == "__main__":
    test_network_info()
