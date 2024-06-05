# NetworkTrafficSniffer

A Python-based packet sniffer for capturing, logging, and saving HTTP and HTTPS network traffic using Scapy.

## Description

This project uses Scapy to capture network packets, specifically HTTP and HTTPS traffic. It logs detailed information about the packets and saves the captured data to a PCAP file.

## Requirements

- Python 3.x
- Scapy
- Npcap (for Windows)

## Installation

1. Install Scapy:
    ```sh
    pip install scapy
    ```

2. Install Npcap:
    - Download and install from [Npcap website](https://nmap.org/npcap/)

## Usage

Run the script to start capturing HTTP and HTTPS traffic:
```sh
python sniffer.py
