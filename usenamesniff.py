import pyshark
import re

# Regular expressions to find potential usernames and passwords
user_pattern = re.compile(r'\buser(?:name)?=([^&\s]+)', re.IGNORECASE)
password_pattern = re.compile(r'\bpass(?:word)?=([^&\s]+)', re.IGNORECASE)

def process_packet(packet):
    if 'IP' in packet:
        protocol = packet.transport_layer   # TCP or UDP
        src_addr = packet.ip.src            # Source IP address
        dst_addr = packet.ip.dst            # Destination IP address
        src_port = packet[packet.transport_layer].srcport   # Source port
        dst_port = packet[packet.transport_layer].dstport   # Destination port
        
        # Explain what these terms mean
        print(f"\nCaptured {protocol} packet from {src_addr}:{src_port} to {dst_addr}:{dst_port}")
        print("Explanation: This shows the protocol used (TCP/UDP) and the IP addresses and ports involved in the communication.")
        
        encrypted = "No"
        if 'TLS' in packet or 'SSL' in packet:
            encrypted = "Yes (SSL/TLS)"
            print("This packet is encrypted using SSL/TLS, a cryptographic protocol designed to provide secure communication over a computer network.")

        print(f"Encrypted: {encrypted}")

        try:
            if 'HTTP' in packet and 'HTTPS' not in packet:
                search_for_credentials(str(packet.http))
            elif 'FTP' in packet and not encrypted:
                search_for_credentials(str(packet.ftp))
            elif 'TELNET' in packet and not encrypted:
                search_for_credentials(str(packet.telnet))
        except AttributeError:
            pass
    else:
        print("This packet does not contain an IP layer, which means it might be non-IP traffic such as ARP.")

def search_for_credentials(packet_data):
    usernames = user_pattern.findall(packet_data)
    passwords = password_pattern.findall(packet_data)
    if usernames or passwords:
        print(">>> Credentials Detected! <<<")
        print(f"Usernames: {usernames}, Passwords: {passwords}")
        print("Warning: Credentials should not be sent over unencrypted connections.")
    else:
        print("No credentials found in this packet. This might be normal, especially if the packet is encrypted or doesn't carry login information.")

def capture_packets(interface):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        process_packet(packet)

if __name__ == "__main__":
    interface = 'eth0'  # Specify your network interface here
    print("Starting packet capture system...\n")
    capture_packets(interface)
