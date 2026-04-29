from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    print("\n=== New Packet Captured ===")

    # Check IP Layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP        : {ip_layer.src}")
        print(f"Destination IP   : {ip_layer.dst}")

        # Convert protocol number to readable form
        protocol = ip_layer.proto
        if protocol == 6:
            proto_name = "TCP"
        elif protocol == 17:
            proto_name = "UDP"
        elif protocol == 1:
            proto_name = "ICMP"
        else:
            proto_name = str(protocol)

        print(f"Protocol         : {proto_name}")

        # TCP Layer
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Type             : TCP")
            print(f"Source Port      : {tcp.sport}")
            print(f"Destination Port : {tcp.dport}")

        # UDP Layer
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Type             : UDP")
            print(f"Source Port      : {udp.sport}")
            print(f"Destination Port : {udp.dport}")

        # ICMP Layer
        elif packet.haslayer(ICMP):
            print("Type             : ICMP")

        # Packet Size
        print(f"Packet Size      : {len(packet)} bytes")

def main():
    print("Starting Network Sniffer...")
    print("Press CTRL+C to stop.\n")

    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nSniffer stopped.")

if __name__ == "__main__":
    main()
    