# 4SCAN

### Lightweight TCP Port Scanner

A simple Python-based TCP port scanner built for **network security learning, authorized testing, and homelab use**.

## ⚡ Features

- 🔍 TCP port scanning
- ⚡ Multithreaded scanning
- 🎯 IP address & hostname support
- 🔢 Custom ports and port ranges
- 📡 Common service detection
- ⏱️ Port response-time measurement
- 📊 Scan progress & statistics
- 🚀 Scan speed calculation
- 🔓 Open-port filtering
- 🎨 Colored terminal interface
- 💾 JSON & CSV export
- 🛑 Graceful `Ctrl+C` handling
- 🆘 Built-in CLI help

## 🛠️ Usage

Scan a port range:

```bash
python3 4scan.py -t 192.168.1.1 -p 1-1000

Scan specific ports:

python3 4scan.py -t 192.168.1.1 -p 22,80,443,3306

Scan common ports:

python3 4scan.py -t 192.168.1.1 --top-ports 100

Show only open ports:

python3 4scan.py -t 192.168.1.1 -p 1-1000 --open-only

Export results:

python3 4scan.py -t 192.168.1.1 -p 1-1000 --json results.json
python3 4scan.py -t 192.168.1.1 -p 1-1000 --csv results.csv

View available options:

python3 4scan.py --help
📋 Example
╭──────────────────────────────────────────────╮
│                  4SCAN                       │
│          Lightweight TCP Scanner             │
╰──────────────────────────────────────────────╯


Target  : 192.168.1.1
Ports   : 1-1000
Mode    : TCP Connect


[OPEN]  22    SSH
[OPEN]  80    HTTP
[OPEN]  443   HTTPS


╭────────────── Scan Summary ──────────────╮
│ Open ports : 3                           │
│ Duration   : 2.41s                       │
│ Speed      : 414 ports/sec               │
╰──────────────────────────────────────────╯
💻 Requirements
Python 3
Standard Python libraries only
No additional dependencies
🎯 Purpose

4SCAN is primarily a learning and authorized security-testing tool for practicing:

Networking
TCP/IP
Python socket programming
Port enumeration
Service identification
Security reconnaissance
⚠️ Disclaimer

Only scan systems and networks that you own or have explicit permission to test.

Unauthorized port scanning may violate organizational policies, terms of service, or applicable laws.

⚡ 4SCAN

Learn • Scan • Analyze • Improve

