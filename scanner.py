import scapy.all as scapy
import nmap
def discover_devices(network):
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device_info = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        devices.append(device_info)
    
    return devices



def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, '1-1024')  # Scan ports 1 to 1024
    open_ports = []
    for proto in nm[ip].all_protocols():
        lport = nm[ip][proto].keys()
        for port in lport:
            if nm[ip][proto][port]['state'] == 'open':
                open_ports.append(port)
    return open_ports

def main():
    network = input("Enter the network to scan (e.g., 192.168.1.0/24): ")
    devices = discover_devices(network)
    if devices:
        print("Discovered devices:")
        for device in devices:
            print(f"IP: {device['ip']}, MAC: {device['mac']}")
            open_ports = scan_ports(device['ip'])
            if open_ports:
                print(f"Open ports on {device['ip']}: {open_ports}")
            else:
                print(f"No open ports found on {device['ip']}")
    else:
        print("No devices were discovered on the network.")

if __name__ == "__main__":
    main()
