<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-red.svg?style=for-the-badge" alt="Version"/>
  <img src="https://img.shields.io/badge/python-3.8+-green.svg?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/platform-Linux-orange.svg?style=for-the-badge&logo=linux&logoColor=white" alt="Platform"/>
  <img src="https://img.shields.io/badge/license-MIT-purple.svg?style=for-the-badge" alt="License"/>
</p>

<h1 align="center">🔥 PyAirgeddon - Red Team Edition</h1>

<p align="center">
  <b>Python Wireless Security Auditing Tool for Professional Red Team Operations</b>
</p>

<p align="center">
  <i>A comprehensive toolkit for WiFi reconnaissance, rogue AP attacks, and stealth operations</i>
</p>

```
 ██████╗ ██╗   ██╗ █████╗ ██╗██████╗  ██████╗ ███████╗██████╗ ██████╗  ██████╗ ███╗   ██╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
 ██████╔╝ ╚████╔╝ ███████║██║██████╔╝██║  ███╗█████╗  ██║  ██║██║  ██║██║   ██║██╔██╗ ██║
 ██╔═══╝   ╚██╔╝  ██╔══██║██║██╔══██╗██║   ██║██╔══╝  ██║  ██║██║  ██║██║   ██║██║╚██╗██║
 ██║        ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗██████╔╝██████╔╝╚██████╔╝██║ ╚████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                              RED TEAM EDITION v2.0
```

---

## ⚠️ Disclaimer

> **This tool is for AUTHORIZED SECURITY TESTING and EDUCATIONAL purposes ONLY.**
>
> - ✅ Only use on networks you own or have explicit written permission to test
> - ✅ Follow responsible disclosure practices
> - ❌ Unauthorized access to computer networks is **ILLEGAL**
> - ❌ The developers assume **NO LIABILITY** for misuse

---

## ✨ Features

<table>
<tr><td>

### 🔍 Reconnaissance

- Beacon frame analysis
- WPA3/PMF detection
- Hidden SSID revelation
- Client fingerprinting
- Probe request tracking
- Vendor identification

</td><td>

### ⚡ Attacks

- Karma (respond to probes)
- MANA (full rogue AP)
- Loud-MANA (beacon flood)
- Deauthentication
- WPS Pixie Dust
- Evil Twin + Captive Portal

</td><td>

### 🛡️ Evasion

- Vendor-aware MAC spoofing
- TX power control
- Timing jitter
- WIDS detection
- Stealth scanning
- Low-profile operations

</td></tr>
</table>

---

## 🚀 Quick Start

### Prerequisites

- **OS**: Linux (Kali recommended)
- **Python**: 3.8+
- **Hardware**: Wireless adapter with monitor mode + packet injection

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/pyairgeddon.git
cd pyairgeddon

# Install Python dependencies
pip install -r requirements.txt

# Install system tools (Kali/Debian/Ubuntu)
sudo apt install aircrack-ng hostapd dnsmasq hcxtools hashcat reaver bully mdk4 macchanger

# Run
sudo python pyairgeddon.py
```

### One-Liner (Kali)

```bash
sudo apt install aircrack-ng hostapd dnsmasq hcxtools hashcat mdk4 macchanger && pip install -r requirements.txt && sudo python pyairgeddon.py
```

---

## 📁 Project Structure

```
pyairgeddon/
├── pyairgeddon.py           # Main GUI application
├── pyairgeddon_core.py      # Interface management & scanning
├── pyairgeddon_attacks.py   # Deauth, DoS, WPS attacks
├── pyairgeddon_cracker.py   # Password cracking
├── pyairgeddon_eviltwin.py  # Rogue AP & captive portal
├── pyairgeddon_recon.py     # 🆕 Reconnaissance module
├── pyairgeddon_karma.py     # 🆕 Karma/MANA attacks
├── pyairgeddon_evasion.py   # 🆕 Stealth & evasion
├── install_tools.py         # Tool installer
├── requirements.txt         # Python dependencies
└── README.md
```

---

## 🛠️ Modules

### 🔍 Reconnaissance (`pyairgeddon_recon.py`)

```python
from pyairgeddon_recon import ReconCoordinator

recon = ReconCoordinator('wlan0mon')
recon.start_full_recon()

# Get results
networks = recon.beacon_analyzer.get_beacons()
security_issues = recon.beacon_analyzer.get_security_issues()
clients = recon.probe_tracker.get_clients()
```

**Classes**: `BeaconAnalyzer`, `ProbeTracker`, `HiddenNetworkDetector`, `ClientFingerprinter`, `VendorLookup`

### ⚡ Karma/MANA (`pyairgeddon_karma.py`)

```python
from pyairgeddon_karma import KarmaAttack, MANAAttack

# Basic Karma
karma = KarmaAttack('wlan0mon')
karma.start(channel=6)

# Full MANA with rogue AP
mana = MANAAttack('wlan0')
mana.start(ssid="FreeWifi", loud_mode=True)
```

**Classes**: `KarmaAttack`, `MANAAttack`, `LoudMANA`, `PNLCollector`

### 🛡️ Evasion (`pyairgeddon_evasion.py`)

```python
from pyairgeddon_evasion import EvasionCoordinator, StealthScanner

# Setup stealth mode
evasion = EvasionCoordinator('wlan0')
evasion.setup_stealth_mode(level=2)  # MAC + Low power

# Stealth scan
scanner = StealthScanner('wlan0mon')
result = scanner.start_passive_scan(duration=60, stealth_level=3)
```

**Classes**: `MACRandomizer`, `PowerController`, `TimingController`, `WIDSDetector`, `StealthScanner`

---

## 🔧 Required Tools

| Tool        | Purpose        | Install                   |
| ----------- | -------------- | ------------------------- |
| aircrack-ng | Wireless suite | `apt install aircrack-ng` |
| hostapd     | Access point   | `apt install hostapd`     |
| dnsmasq     | DHCP/DNS       | `apt install dnsmasq`     |
| hashcat     | GPU cracking   | `apt install hashcat`     |
| mdk4        | DoS attacks    | `apt install mdk4`        |
| macchanger  | MAC spoofing   | `apt install macchanger`  |

```bash
# Check tool status
python install_tools.py --check

# Install missing
sudo python install_tools.py --all
```

---

## 📖 Usage Examples

### Stealth Network Scan

```python
from pyairgeddon_evasion import StealthScanner

scanner = StealthScanner('wlan0mon')
result = scanner.start_passive_scan(duration=60, stealth_level=3)

for net in result.networks:
    print(f"{net['ssid']} - {net['encryption']} - {net['signal']}dBm")
```

### Collect Client PNLs

```python
from pyairgeddon_karma import PNLCollector

collector = PNLCollector('wlan0mon')
collector.start_collection()
# Wait...
collector.stop_collection()
collector.export_data('pnl_data.json')
```

### Evil Twin Attack

```python
from pyairgeddon_eviltwin import EvilTwinAP

ap = EvilTwinAP('wlan0')
ap.start(ssid="TargetNetwork", channel=6, template='generic')
# Victims connect, credentials captured
creds = ap.get_credentials()
ap.stop()
```

---

## 🤝 Contributing

Contributions welcome! Please submit PRs for:

- Bug fixes
- New attack modules
- Captive portal templates
- Documentation

---

## 📄 License

MIT License - See [LICENSE](LICENSE)

---

## 🙏 Acknowledgments

- [Airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) - Inspiration
- [hostapd-mana](https://github.com/sensepost/hostapd-mana) - MANA concepts
- [aircrack-ng](https://www.aircrack-ng.org/) - Wireless suite
- [Scapy](https://scapy.net/) - Packet manipulation

---

<p align="center">
  <b>Made with ❤️ for the Security Community</b><br>
  ⭐ Star this repo if you find it useful!
</p>
