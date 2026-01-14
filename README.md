# 🔥 PyAirgeddon

<div align="center">

![Version](https://img.shields.io/badge/version-1.1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)
![License](https://img.shields.io/badge/license-MIT-purple.svg)

**Python Wireless Security Auditing Tool**

_A comprehensive GUI application inspired by Airgeddon for wireless network security assessment_

```
 ██████╗ ██╗   ██╗ █████╗ ██╗██████╗  ██████╗ ███████╗██████╗ ██████╗  ██████╗ ███╗   ██╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
 ██████╔╝ ╚████╔╝ ███████║██║██████╔╝██║  ███╗█████╗  ██║  ██║██║  ██║██║   ██║██╔██╗ ██║
 ██╔═══╝   ╚██╔╝  ██╔══██║██║██╔══██╗██║   ██║██╔══╝  ██║  ██║██║  ██║██║   ██║██║╚██╗██║
 ██║        ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗██████╔╝██████╔╝╚██████╔╝██║ ╚████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
```

</div>

---

## 📋 Overview

**PyAirgeddon** is a powerful, Python-based wireless security auditing toolkit with an intuitive GUI. It combines multiple attack vectors and cracking methods into a single, cohesive application designed for security professionals and penetration testers.

### ✨ Key Features

| Feature                         | Description                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 📡 **Network Scanning**         | Discover wireless networks with real-time signal strength, encryption detection, and client enumeration |
| ⚡ **Deauthentication Attacks** | Disconnect clients from target networks for handshake capture                                           |
| 🎯 **DoS Attacks**              | Beacon flood, authentication flood, and Michael shutdown exploits                                       |
| 🔐 **WPS Attacks**              | Pixie Dust and PIN brute force using Reaver/Bully                                                       |
| 📦 **Handshake Capture**        | WPA/WPA2 4-way handshake and PMKID capture                                                              |
| 🔓 **Password Cracking**        | Dictionary attacks, brute force, and Hashcat GPU integration                                            |
| 👿 **Evil Twin AP**             | Rogue access point with captive portal credential harvesting                                            |
| 🛠️ **Auto-Installation**        | Automatic Python dependency management with progress tracking                                           |

---

## 🚀 Quick Start

### Prerequisites

- **Operating System**: Linux (Kali, Ubuntu, Debian, Arch, Fedora)
- **Python**: 3.8 or higher
- **Hardware**: Wireless adapter supporting monitor mode and packet injection

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/pyairgeddon.git
cd pyairgeddon

# Install Python dependencies
pip install -r requirements.txt

# Install external tools (Debian/Ubuntu)
sudo apt install aircrack-ng hostapd dnsmasq hcxdumptool hcxtools hashcat reaver bully mdk4

# Run PyAirgeddon
sudo python pyairgeddon.py
```

### One-Line Install (Debian/Ubuntu)

```bash
sudo apt install aircrack-ng hostapd dnsmasq hcxdumptool hcxtools hashcat reaver bully mdk4 && pip install -r requirements.txt
```

---

## 📁 Project Structure

```
pyairgeddon/
├── pyairgeddon.py           # Main GUI application with dependency manager
├── pyairgeddon_core.py      # Wireless interface management & network scanning
├── pyairgeddon_attacks.py   # Deauth, DoS, and WPS attack modules
├── pyairgeddon_cracker.py   # Dictionary, brute force, and Hashcat integration
├── pyairgeddon_eviltwin.py  # Evil Twin AP with captive portal templates
├── install_tools.py         # External tools installer utility
├── setup.py                 # Python package setup script
├── requirements.txt         # Python dependencies
└── README.md                # This documentation
```

---

## 🛠️ Modules

### 🖥️ Main GUI (`pyairgeddon.py`)

- Dark-themed interface with matrix splash screen animation
- Tabbed interface: Scan, Attacks, Cracker, Evil Twin, Logs
- Real-time status updates and progress tracking
- Interface selector with monitor mode toggle
- Automatic Python dependency installation

### 📡 Core Module (`pyairgeddon_core.py`)

- `WirelessInterface`: Interface detection, mode switching, MAC spoofing
- `NetworkScanner`: Continuous scanning with CSV parsing from airodump-ng
- `HandshakeCapture`: WPA/WPA2 handshake and PMKID capture
- Cross-platform dependency checking

### ⚡ Attacks Module (`pyairgeddon_attacks.py`)

- `DeauthAttack`: Continuous deauthentication with packet counting
- `DoSAttack`: Beacon flood, auth flood, Michael shutdown (mdk3/mdk4)
- `WPSAttack`: Pixie Dust, brute force PIN, custom PIN testing

### 🔓 Cracker Module (`pyairgeddon_cracker.py`)

- `DictionaryAttack`: Wordlist-based cracking with aircrack-ng
- `BruteForceAttack`: Custom charset generator (digits, alpha, alphanum, etc.)
- `HashcatCracker`: GPU-accelerated cracking with hash conversion

### 👿 Evil Twin Module (`pyairgeddon_eviltwin.py`)

- `EvilTwinAP`: Rogue AP with hostapd/dnsmasq integration
- Built-in captive portal templates (generic, router update, Google sign-in)
- `CredentialHandler`: HTTP server for credential harvesting
- `EvilTwinDeauth`: Companion deauth to force reconnection

---

## 🔧 External Tools Required

| Tool          | Purpose                     | Install (Debian)          |
| ------------- | --------------------------- | ------------------------- |
| `aircrack-ng` | Suite for wireless auditing | `apt install aircrack-ng` |
| `hostapd`     | Access point daemon         | `apt install hostapd`     |
| `dnsmasq`     | DHCP/DNS server             | `apt install dnsmasq`     |
| `hcxdumptool` | PMKID capture               | `apt install hcxdumptool` |
| `hcxtools`    | Hash conversion             | `apt install hcxtools`    |
| `hashcat`     | GPU password cracker        | `apt install hashcat`     |
| `reaver`      | WPS attacks                 | `apt install reaver`      |
| `bully`       | Alternative WPS tool        | `apt install bully`       |
| `mdk4`        | DoS attacks                 | `apt install mdk4`        |

### Check Tool Status

```bash
python install_tools.py --check
```

### Install All Missing Tools

```bash
sudo python install_tools.py --all
```

---

## 📖 Usage Examples

### Network Scanning

```python
from pyairgeddon_core import WirelessInterface, NetworkScanner

# Get interfaces
iface_mgr = WirelessInterface()
interfaces = iface_mgr.refresh_interfaces()

# Enable monitor mode
iface_mgr.set_monitor_mode('wlan0')

# Start scanning
scanner = NetworkScanner('wlan0mon')
scanner.start_scan(channel=0, callback=lambda nets, clients: print(nets))
```

### Capture Handshake

```python
from pyairgeddon_core import HandshakeCapture

capture = HandshakeCapture('wlan0mon')
result = capture.capture_handshake(
    target_bssid='AA:BB:CC:DD:EE:FF',
    channel=6,
    timeout=120,
    deauth=True
)
if result.success:
    print(f"Handshake saved: {result.file_path}")
```

### Dictionary Attack

```python
from pyairgeddon_cracker import DictionaryAttack

attack = DictionaryAttack()
result = attack.crack(
    capture_file='handshake.cap',
    wordlist='/usr/share/wordlists/rockyou.txt'
)
if result.success:
    print(f"Password: {result.password}")
```

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**

- Only use on networks you own or have explicit permission to test
- Unauthorized access to computer networks is illegal
- The developers assume no liability for misuse of this software
- Always follow local laws and regulations regarding wireless security testing

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes
- New features
- Documentation improvements
- Template designs

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Inspired by [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon)
- Built with the [aircrack-ng](https://www.aircrack-ng.org/) suite
- Uses [Scapy](https://scapy.net/) for packet manipulation
- GUI powered by Python Tkinter

---

<div align="center">

**Made with ❤️ by the PyAirgeddon Team**

⭐ Star this repo if you find it useful!

</div>
