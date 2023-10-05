import socket
from scapy.all import ARP, Ether, srp

def scan_ip():
    target_ip = "192.168.1.110/24"  # Replace with your network's subnet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    # Print the list of active IP addresses
    print("Scanned IPs on the network:")
    for sent, received in result:
        print(received.psrc)

def scan_port(target_host, target_port):
    try:
        # Create a socket object
        socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout in seconds (adjust as needed)
        socket_obj.settimeout(1)
        
        # Attempt to connect to the target host and port
        socket_obj.connect((target_host, target_port))
        
        # If the connection succeeds, the port is open
        print(f"Port {target_port} is open")
        
        # Close the socket
        socket_obj.close()
        
    except (socket.timeout, ConnectionRefusedError):
        # If the connection times out or is refused, the port is closed
        print(f"Port {target_port} is closed")

def main():
    scan_ip()
    target_host = input("Enter the target host: ")
    target_ports = input("Enter the target ports (comma-separated): ").split(",")
    for port in target_ports:
        scan_port(target_host, int(port))

if __name__ == "__main__":
    main()