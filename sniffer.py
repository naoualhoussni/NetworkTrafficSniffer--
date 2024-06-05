import logging
from scapy.all import sniff, IP, TCP, UDP, wrpcap, conf

# Ensure Npcap is being used
if not conf.L3socket:
    raise RuntimeError("Npcap not installed or not configured correctly")

# Setup logging
logging.basicConfig(filename='packet_details.log', level=logging.INFO, format='%(asctime)s - %(message)s')

captured_packets = []

def packet_callback(packet):
    try:
        captured_packets.append(packet)
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto

            protocol_name = {6: "TCP", 17: "UDP"}.get(protocol, "Other")

            packet_info = f"\nIP Packet: {ip_src} -> {ip_dst} | Protocol: {protocol_name}"

            if TCP in packet:
                tcp_src_port = packet[TCP].sport
                tcp_dst_port = packet[TCP].dport
                payload = bytes(packet[TCP].payload)
                packet_info += f"\nTCP Segment: {tcp_src_port} -> {tcp_dst_port}\nTCP Payload: {payload if payload else 'No Payload'}"

            elif UDP in packet:
                udp_src_port = packet[UDP].sport
                udp_dst_port = packet[UDP].dport
                payload = bytes(packet[UDP].payload)
                packet_info += f"\nUDP Segment: {udp_src_port} -> {udp_dst_port}\nUDP Payload: {payload if payload else 'No Payload'}"

            print(packet_info)
            logging.info(packet_info)
        else:
            print("\nNon-IP Packet")
            logging.info("Non-IP Packet")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")

try:
    # Start sniffing with a filter to capture only HTTP and HTTPS traffic
    print("Starting packet capture for HTTP and HTTPS traffic...")
    sniff(prn=packet_callback, count=10, filter="tcp port 80 or tcp port 443")
    
    # Save captured packets to a file
    output_file = "captured_packets.pcap"
    wrpcap(output_file, captured_packets)
    print(f"\nCaptured packets saved to {output_file}")
    logging.info(f"Captured packets saved to {output_file}")
except Exception as e:
    logging.error(f"Error during packet capture: {e}")
    print(f"Error: {e}")
