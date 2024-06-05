
# NetworkTrafficSniffer

A Python-based packet sniffer for capturing, logging, and saving HTTP and HTTPS network traffic using Scapy.

## Description

This project uses Scapy to capture network packets, specifically HTTP and HTTPS traffic. It logs detailed information about the packets and saves the captured data to a PCAP file. Additionally, it now includes a log file (`packet_details.log`) to store detailed information about the captured packets.

## Requirements

- Python 3.x
- Scapy
- Npcap (for Windows)

## Installation

1. Install Scapy:

```bash
pip install scapy
Install Npcap (for Windows):

Download and install from the Npcap website.

2.Usage
Run the script to start capturing HTTP and HTTPS traffic:

```bash
Copier le code
python sniffer.py
The captured network traffic will be logged in the packet_details.log file.

Log File (packet_details.log)
The packet_details.log file contains detailed information about the captured packets, including timestamps, source and destination IP addresses, protocol, and payload details. This file can be used for further analysis of the captured network traffic.

License
This project is licensed under the MIT License. See the LICENSE file for details.

bash
Copier le code








