# Python Port Scanner

A TCP port scanner built from scratch using Python's socket 
library — no Nmap or external scanning tools used.

## Features
- TCP connect scanning using raw sockets
- Multi-threaded — scans 100 ports simultaneously
- Banner grabbing to identify service versions
- Security observations for risky open ports
- Saves results to timestamped report files
- Supports single ports, ranges, lists, or all 65535 ports
- Validated against Nmap on scanme.nmap.org

## Usage
python scanner.py

## How It Works
Creates a TCP socket for each port and calls connect_ex().
A return value of 0 means the port accepted the connection
(open). Uses ThreadPoolExecutor for concurrent scanning.

## Tools & Concepts
Python · Sockets · TCP/IP · Threading · 
Banner Grabbing · Network Reconnaissance