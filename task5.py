from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = None
        payload = None

        # Determine protocol
        if TCP in packet:
            protocol = "TCP"
            payload = bytes(packet[TCP].payload).decode(errors="ignore")
        elif UDP in packet:
            protocol = "UDP"
            payload = bytes(packet[UDP].payload).decode(errors="ignore")
        elif ICMP in packet:
            protocol = "ICMP"
            payload = bytes(packet[ICMP].payload).decode(errors="ignore")
        else:
            protocol = "Other"

        # Display packet information
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}\n")

def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Replace 'your_interface' with your network interface name, e.g., 'eth0', 'wlan0', etc.
start_sniffing(interface="Wi-Fi")
