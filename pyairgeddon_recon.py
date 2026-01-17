#!/usr/bin/env python3
"""
PyAirgeddon Reconnaissance Module
Advanced WiFi reconnaissance tools for red team operations

Features:
- WiFi Beacon Analyzer: Parse beacon frames for security misconfigurations
- Probe Request Tracker: Track client probe requests for PNL gathering
- Hidden Network Detector: Detect hidden SSIDs from probe responses
- Client Fingerprinting: OS/Device fingerprinting from WiFi behavior
- Vendor Lookup: MAC address to vendor resolution
"""

import subprocess
import threading
import time
import os
import re
import json
import struct
from typing import Callable, Optional, List, Dict, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

# Try to import optional dependencies
try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Elt, RadioTap, sendp, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# OUI (Vendor) Database - Common vendors
# ============================================================================

OUI_DATABASE = {
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:03:6B": "Cisco",
    "00:0A:41": "Cisco",
    "00:0B:BE": "Cisco",
    "00:0D:BD": "Cisco",
    "00:0E:83": "Cisco",
    "00:0F:23": "Cisco",
    "00:11:21": "Cisco",
    "00:13:7F": "Cisco",
    "00:00:5E": "IANA",
    "00:1A:2B": "Ayecom",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "00:1C:42": "Parallels",
    "08:00:27": "VirtualBox",
    "00:03:FF": "Microsoft",
    "00:50:F2": "Microsoft",
    "00:17:FA": "Microsoft",
    "00:0D:3A": "Microsoft Azure",
    "00:1B:21": "Intel",
    "00:13:02": "Intel",
    "00:15:00": "Intel",
    "00:21:5C": "Intel",
    "3C:A9:F4": "Intel",
    "5C:51:4F": "Intel",
    "00:1E:65": "Intel",
    "DC:A6:32": "Raspberry Pi",
    "B8:27:EB": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:23:76": "HTC",
    "38:E7:D8": "HTC",
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "00:17:F2": "Apple",
    "00:1B:63": "Apple",
    "00:1E:52": "Apple",
    "00:1F:5B": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:C6:10": "Apple",
    "14:10:9F": "Apple",
    "28:0B:5C": "Apple",
    "30:10:E4": "Apple",
    "40:30:04": "Apple",
    "54:AE:27": "Apple",
    "6C:40:08": "Apple",
    "00:1E:E2": "Samsung",
    "00:21:4C": "Samsung",
    "00:23:99": "Samsung",
    "00:24:54": "Samsung",
    "00:25:66": "Samsung",
    "00:26:37": "Samsung",
    "5C:0A:5B": "Samsung",
    "84:25:DB": "Samsung",
    "8C:77:12": "Samsung",
    "AC:5F:3E": "Samsung",
    "D0:DF:C7": "Samsung",
    "EC:1F:72": "Samsung",
    "F8:04:2E": "Samsung",
    "00:19:47": "Huawei",
    "00:1E:10": "Huawei",
    "00:25:68": "Huawei",
    "00:46:4B": "Huawei",
    "00:9A:CD": "Huawei",
    "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei",
    "04:BD:70": "Huawei",
    "20:F3:A3": "Huawei",
    "24:09:95": "Huawei",
    "00:24:01": "Dell",
    "00:1E:4F": "Dell",
    "00:22:19": "Dell",
    "00:26:B9": "Dell",
    "14:FE:B5": "Dell",
    "18:A9:9B": "Dell",
    "24:B6:FD": "Dell",
    "34:17:EB": "Dell",
    "44:A8:42": "Dell",
    "5C:26:0A": "Dell",
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class BeaconInfo:
    """Information parsed from a beacon frame"""
    bssid: str
    ssid: str
    channel: int
    signal: int
    encryption: str
    cipher: str
    auth: str
    wps: bool
    wps_locked: bool = False
    hidden: bool = False
    vendor: str = ""
    capabilities: List[str] = field(default_factory=list)
    rates: List[float] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    beacon_interval: int = 100
    country: str = ""
    ht_capable: bool = False
    vht_capable: bool = False
    pmf_required: bool = False  # Protected Management Frames (WPA3)
    sae_supported: bool = False  # WPA3 SAE


@dataclass
class ProbeRequest:
    """Client probe request information"""
    client_mac: str
    ssid: str
    signal: int
    vendor: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class ClientInfo:
    """Aggregated client information"""
    mac: str
    vendor: str
    probed_ssids: Set[str] = field(default_factory=set)
    connected_to: str = ""
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    signal_history: List[int] = field(default_factory=list)
    packet_count: int = 0
    os_fingerprint: str = ""


@dataclass
class HiddenNetwork:
    """Hidden network detected from probe responses"""
    bssid: str
    ssid: str
    channel: int
    encryption: str
    discovered_from: str  # Client MAC that revealed it
    timestamp: datetime = field(default_factory=datetime.now)


# ============================================================================
# VENDOR LOOKUP
# ============================================================================

class VendorLookup:
    """MAC address to vendor resolution"""
    
    def __init__(self):
        self.oui_db = OUI_DATABASE.copy()
        self.cache: Dict[str, str] = {}
    
    def lookup(self, mac: str) -> str:
        """
        Look up vendor from MAC address
        Returns vendor name or 'Unknown'
        """
        if not mac:
            return "Unknown"
        
        # Normalize MAC format
        mac = mac.upper().replace("-", ":").replace(".", ":")
        
        # Check cache
        if mac in self.cache:
            return self.cache[mac]
        
        # Get OUI (first 3 octets)
        parts = mac.split(":")
        if len(parts) >= 3:
            oui = ":".join(parts[:3])
            vendor = self.oui_db.get(oui, "Unknown")
            self.cache[mac] = vendor
            return vendor
        
        return "Unknown"
    
    def is_randomized(self, mac: str) -> bool:
        """
        Check if MAC appears to be randomized (locally administered)
        The second least significant bit of the first octet is set to 1
        """
        mac = mac.upper().replace("-", ":").replace(".", ":")
        parts = mac.split(":")
        if parts:
            try:
                first_byte = int(parts[0], 16)
                return bool(first_byte & 0x02)  # Locally administered bit
            except ValueError:
                pass
        return False


# ============================================================================
# BEACON ANALYZER
# ============================================================================

class BeaconAnalyzer:
    """
    Analyze WiFi beacon frames for security information
    Detects:
    - Encryption type (WEP, WPA, WPA2, WPA3)
    - WPS status and vulnerabilities
    - Hidden networks
    - Security misconfigurations
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.beacons: Dict[str, BeaconInfo] = {}
        self.vendor_lookup = VendorLookup()
        self._sniffer_thread = None
        self._callback = None
        self._log_callback = None
    
    def _parse_beacon(self, packet) -> Optional[BeaconInfo]:
        """Parse a beacon frame into BeaconInfo"""
        if not packet.haslayer(Dot11Beacon):
            return None
        
        try:
            # Get BSSID
            bssid = packet[Dot11].addr2
            if not bssid:
                return None
            
            # Get signal strength
            signal = -100
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except:
                    pass
            
            # Parse information elements
            ssid = ""
            channel = 0
            encryption = "OPEN"
            cipher = ""
            auth = ""
            wps = False
            wps_locked = False
            hidden = False
            rates = []
            ht_capable = False
            vht_capable = False
            pmf_required = False
            sae_supported = False
            capabilities = []
            beacon_interval = 100
            country = ""
            
            # Get capability info
            cap = packet[Dot11Beacon].cap
            if cap.privacy:
                encryption = "WEP"  # Will be overwritten if WPA/WPA2
            
            beacon_interval = packet[Dot11Beacon].beacon_interval
            
            # Parse tagged parameters
            elt = packet[Dot11Elt]
            while elt:
                eid = elt.ID
                info = elt.info
                
                # SSID
                if eid == 0:
                    try:
                        ssid = info.decode('utf-8', errors='ignore')
                        if not ssid or ssid == '\x00' * len(info):
                            hidden = True
                            ssid = "<Hidden>"
                    except:
                        hidden = True
                        ssid = "<Hidden>"
                
                # Supported rates
                elif eid == 1 or eid == 50:
                    for rate in info:
                        rates.append((rate & 0x7F) * 0.5)
                
                # Channel
                elif eid == 3:
                    if len(info) >= 1:
                        channel = info[0]
                
                # Country
                elif eid == 7:
                    try:
                        country = info[:2].decode('utf-8', errors='ignore')
                    except:
                        pass
                
                # RSN (WPA2/WPA3)
                elif eid == 48:
                    encryption, cipher, auth, pmf_required, sae_supported = \
                        self._parse_rsn(info)
                    if sae_supported:
                        capabilities.append("WPA3-SAE")
                    if pmf_required:
                        capabilities.append("PMF-Required")
                
                # Vendor specific (WPA1, WPS)
                elif eid == 221:
                    if len(info) >= 4:
                        oui = info[:3]
                        vendor_type = info[3]
                        
                        # Microsoft WPA
                        if oui == b'\x00\x50\xf2' and vendor_type == 1:
                            if encryption == "OPEN" or encryption == "WEP":
                                encryption = "WPA"
                            enc, c, a, _, _ = self._parse_wpa(info[4:])
                            if not cipher:
                                cipher = c
                            if not auth:
                                auth = a
                        
                        # WPS
                        elif oui == b'\x00\x50\xf2' and vendor_type == 4:
                            wps = True
                            # Check WPS state
                            if len(info) > 10:
                                wps_locked = self._check_wps_locked(info)
                
                # HT Capabilities (802.11n)
                elif eid == 45:
                    ht_capable = True
                    capabilities.append("802.11n")
                
                # VHT Capabilities (802.11ac)
                elif eid == 191:
                    vht_capable = True
                    capabilities.append("802.11ac")
                
                # Move to next element
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break
            
            # Create BeaconInfo
            return BeaconInfo(
                bssid=bssid.upper(),
                ssid=ssid,
                channel=channel,
                signal=signal,
                encryption=encryption,
                cipher=cipher,
                auth=auth,
                wps=wps,
                wps_locked=wps_locked,
                hidden=hidden,
                vendor=self.vendor_lookup.lookup(bssid),
                capabilities=capabilities,
                rates=rates,
                beacon_interval=beacon_interval,
                country=country,
                ht_capable=ht_capable,
                vht_capable=vht_capable,
                pmf_required=pmf_required,
                sae_supported=sae_supported
            )
            
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"Error parsing beacon: {e}")
            return None
    
    def _parse_rsn(self, data: bytes) -> Tuple[str, str, str, bool, bool]:
        """Parse RSN (Robust Security Network) information element"""
        encryption = "WPA2"
        cipher = ""
        auth = ""
        pmf_required = False
        sae_supported = False
        
        try:
            if len(data) < 8:
                return encryption, cipher, auth, pmf_required, sae_supported
            
            # Version
            version = struct.unpack('<H', data[0:2])[0]
            
            # Group cipher suite
            group_cipher = data[2:6]
            cipher = self._cipher_suite_to_str(group_cipher)
            
            # Pairwise cipher count and suites
            if len(data) >= 8:
                pairwise_count = struct.unpack('<H', data[6:8])[0]
                offset = 8
                
                for i in range(pairwise_count):
                    if offset + 4 <= len(data):
                        pairwise = data[offset:offset+4]
                        # Already have cipher, skip
                        offset += 4
                
                # AKM count and suites
                if offset + 2 <= len(data):
                    akm_count = struct.unpack('<H', data[offset:offset+2])[0]
                    offset += 2
                    
                    for i in range(akm_count):
                        if offset + 4 <= len(data):
                            akm = data[offset:offset+4]
                            akm_type = akm[3] if len(akm) >= 4 else 0
                            
                            # SAE (WPA3)
                            if akm_type == 8:
                                sae_supported = True
                                auth = "SAE"
                                encryption = "WPA3"
                            # PSK
                            elif akm_type == 2:
                                if not auth:
                                    auth = "PSK"
                            # 802.1X
                            elif akm_type == 1:
                                auth = "802.1X"
                            
                            offset += 4
                    
                    # RSN capabilities
                    if offset + 2 <= len(data):
                        rsn_cap = struct.unpack('<H', data[offset:offset+2])[0]
                        # MFP required (bit 6)
                        pmf_required = bool(rsn_cap & 0x40)
                        # MFP capable (bit 7)
                        if rsn_cap & 0x80:
                            pass  # PMF capable but not required
            
        except Exception:
            pass
        
        return encryption, cipher, auth, pmf_required, sae_supported
    
    def _parse_wpa(self, data: bytes) -> Tuple[str, str, str, bool, bool]:
        """Parse WPA1 information"""
        return self._parse_rsn(data)
    
    def _cipher_suite_to_str(self, suite: bytes) -> str:
        """Convert cipher suite OUI to string"""
        if len(suite) < 4:
            return "Unknown"
        
        cipher_type = suite[3]
        ciphers = {
            1: "WEP-40",
            2: "TKIP",
            3: "WRAP",
            4: "CCMP",
            5: "WEP-104",
            8: "GCMP",
            9: "GCMP-256",
        }
        return ciphers.get(cipher_type, f"Unknown({cipher_type})")
    
    def _check_wps_locked(self, data: bytes) -> bool:
        """Check if WPS is locked from WPS IE"""
        try:
            # Look for WPS State attribute (0x1044)
            i = 4
            while i + 4 < len(data):
                attr_type = (data[i] << 8) | data[i+1]
                attr_len = (data[i+2] << 8) | data[i+3]
                
                # AP Setup Locked (0x1057)
                if attr_type == 0x1057 and attr_len == 1:
                    return data[i+4] == 1
                
                i += 4 + attr_len
        except:
            pass
        return False
    
    def _packet_handler(self, packet):
        """Handle captured packets"""
        if packet.haslayer(Dot11Beacon):
            beacon = self._parse_beacon(packet)
            if beacon:
                self.beacons[beacon.bssid] = beacon
                if self._callback:
                    self._callback(beacon)
    
    def start_analysis(self, callback: Callable = None, 
                      log_callback: Callable = None,
                      channel: int = 0) -> bool:
        """
        Start beacon analysis
        channel: 0 for channel hopping, specific channel otherwise
        """
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        self._callback = callback
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting beacon analysis on {self.interface}")
        
        def sniffer():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                log(f"[!] Sniffer error: {e}")
        
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        
        return True
    
    def stop_analysis(self, log_callback: Callable = None):
        """Stop beacon analysis"""
        self.running = False
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping beacon analysis...")
        
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
    
    def get_beacons(self) -> List[BeaconInfo]:
        """Get all captured beacons"""
        return list(self.beacons.values())
    
    def get_security_issues(self) -> List[Dict]:
        """Analyze beacons for security issues"""
        issues = []
        
        for bssid, beacon in self.beacons.items():
            network_issues = []
            
            # WEP is insecure
            if beacon.encryption == "WEP":
                network_issues.append({
                    "severity": "CRITICAL",
                    "issue": "WEP Encryption",
                    "description": "WEP is cryptographically broken and can be cracked in minutes"
                })
            
            # WPA1 with TKIP
            if beacon.encryption == "WPA" and beacon.cipher == "TKIP":
                network_issues.append({
                    "severity": "HIGH",
                    "issue": "WPA with TKIP",
                    "description": "TKIP has known vulnerabilities, upgrade to WPA2-CCMP"
                })
            
            # Open network
            if beacon.encryption == "OPEN":
                network_issues.append({
                    "severity": "HIGH" if not beacon.hidden else "MEDIUM",
                    "issue": "Open Network",
                    "description": "No encryption - all traffic is visible"
                })
            
            # WPS enabled (not locked)
            if beacon.wps and not beacon.wps_locked:
                network_issues.append({
                    "severity": "MEDIUM",
                    "issue": "WPS Enabled",
                    "description": "WPS PIN can be brute-forced (Reaver/Bully attack)"
                })
            
            # No PMF on WPA2
            if beacon.encryption == "WPA2" and not beacon.pmf_required:
                network_issues.append({
                    "severity": "LOW",
                    "issue": "PMF Not Required",
                    "description": "Vulnerable to deauthentication attacks"
                })
            
            if network_issues:
                issues.append({
                    "bssid": bssid,
                    "ssid": beacon.ssid,
                    "issues": network_issues
                })
        
        return issues


# ============================================================================
# PROBE REQUEST TRACKER
# ============================================================================

class ProbeTracker:
    """
    Track client probe requests to gather:
    - Preferred Network Lists (PNL)
    - Client fingerprinting information
    - Movement patterns
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.clients: Dict[str, ClientInfo] = {}
        self.probes: List[ProbeRequest] = []
        self.ssid_clients: Dict[str, Set[str]] = defaultdict(set)  # SSID -> client MACs
        self.vendor_lookup = VendorLookup()
        self._sniffer_thread = None
        self._callback = None
        self._log_callback = None
    
    def _packet_handler(self, packet):
        """Handle captured probe requests"""
        if not packet.haslayer(Dot11ProbeReq):
            return
        
        try:
            # Get client MAC
            client_mac = packet[Dot11].addr2
            if not client_mac:
                return
            
            client_mac = client_mac.upper()
            
            # Get signal strength
            signal = -100
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except:
                    pass
            
            # Get SSID
            ssid = ""
            elt = packet[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    except:
                        pass
                    break
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break
            
            # Get vendor
            vendor = self.vendor_lookup.lookup(client_mac)
            is_random = self.vendor_lookup.is_randomized(client_mac)
            
            # Create probe request
            probe = ProbeRequest(
                client_mac=client_mac,
                ssid=ssid,
                signal=signal,
                vendor=vendor if not is_random else "Randomized"
            )
            self.probes.append(probe)
            
            # Update client info
            if client_mac not in self.clients:
                self.clients[client_mac] = ClientInfo(
                    mac=client_mac,
                    vendor=vendor if not is_random else "Randomized"
                )
            
            client = self.clients[client_mac]
            client.last_seen = datetime.now()
            client.packet_count += 1
            client.signal_history.append(signal)
            
            # Keep only last 100 signal readings
            if len(client.signal_history) > 100:
                client.signal_history = client.signal_history[-100:]
            
            # Add SSID to probed list
            if ssid:
                client.probed_ssids.add(ssid)
                self.ssid_clients[ssid].add(client_mac)
            
            # Callback
            if self._callback:
                self._callback(probe, client)
                
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"Error handling probe: {e}")
    
    def start_tracking(self, callback: Callable = None,
                       log_callback: Callable = None) -> bool:
        """Start tracking probe requests"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        self._callback = callback
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting probe tracking on {self.interface}")
        
        def sniffer():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    filter="type mgt subtype probe-req",
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                log(f"[!] Sniffer error: {e}")
        
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        
        return True
    
    def stop_tracking(self, log_callback: Callable = None):
        """Stop tracking"""
        self.running = False
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping probe tracking...")
        
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
    
    def get_clients(self) -> List[ClientInfo]:
        """Get all tracked clients"""
        return list(self.clients.values())
    
    def get_pnl(self, client_mac: str) -> Set[str]:
        """Get Preferred Network List for a client"""
        client_mac = client_mac.upper()
        if client_mac in self.clients:
            return self.clients[client_mac].probed_ssids
        return set()
    
    def get_clients_for_ssid(self, ssid: str) -> Set[str]:
        """Get clients that have probed for a specific SSID"""
        return self.ssid_clients.get(ssid, set())
    
    def get_common_ssids(self, min_count: int = 2) -> List[Tuple[str, int]]:
        """Get SSIDs probed by multiple clients"""
        common = []
        for ssid, clients in self.ssid_clients.items():
            if len(clients) >= min_count:
                common.append((ssid, len(clients)))
        return sorted(common, key=lambda x: x[1], reverse=True)
    
    def export_pnl_report(self, filepath: str, 
                          log_callback: Callable = None) -> bool:
        """Export PNL data to JSON file"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            report = {
                "timestamp": datetime.now().isoformat(),
                "interface": self.interface,
                "total_clients": len(self.clients),
                "total_probes": len(self.probes),
                "clients": []
            }
            
            for mac, client in self.clients.items():
                report["clients"].append({
                    "mac": mac,
                    "vendor": client.vendor,
                    "probed_ssids": list(client.probed_ssids),
                    "first_seen": client.first_seen.isoformat(),
                    "last_seen": client.last_seen.isoformat(),
                    "packet_count": client.packet_count,
                    "avg_signal": sum(client.signal_history) / len(client.signal_history) 
                                  if client.signal_history else -100
                })
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            log(f"[+] Exported PNL report to {filepath}")
            return True
            
        except Exception as e:
            log(f"[!] Export error: {e}")
            return False


# ============================================================================
# HIDDEN NETWORK DETECTOR
# ============================================================================

class HiddenNetworkDetector:
    """
    Detect hidden networks by capturing probe responses
    When a client probes for a hidden network by name,
    the AP responds revealing the SSID
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.hidden_networks: Dict[str, HiddenNetwork] = {}
        self.known_bssids: Set[str] = set()  # BSSIDs seen as hidden in beacons
        self._sniffer_thread = None
        self._callback = None
        self._log_callback = None
    
    def add_hidden_bssid(self, bssid: str):
        """Add a BSSID known to be hidden from beacon analysis"""
        self.known_bssids.add(bssid.upper())
    
    def _packet_handler(self, packet):
        """Handle probe responses to reveal hidden SSIDs"""
        try:
            # Check for probe response
            if packet.haslayer(Dot11ProbeResp):
                bssid = packet[Dot11].addr2
                if not bssid:
                    return
                
                bssid = bssid.upper()
                client_mac = packet[Dot11].addr1
                
                # Only interested if we know this was hidden
                # or we can detect it's a response to our probe
                
                # Get SSID from probe response
                ssid = ""
                channel = 0
                encryption = "OPEN"
                
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 0:  # SSID
                        try:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                        except:
                            pass
                    elif elt.ID == 3:  # Channel
                        if len(elt.info) >= 1:
                            channel = elt.info[0]
                    elif elt.ID == 48:  # RSN
                        encryption = "WPA2"
                    elif elt.ID == 221:  # Vendor (WPA)
                        if len(elt.info) >= 4:
                            if elt.info[:4] == b'\x00\x50\xf2\x01':
                                if encryption == "OPEN":
                                    encryption = "WPA"
                    
                    try:
                        elt = elt.payload.getlayer(Dot11Elt)
                    except:
                        break
                
                # If this is a known hidden network or new network with SSID
                if bssid in self.known_bssids and ssid:
                    if bssid not in self.hidden_networks:
                        hidden = HiddenNetwork(
                            bssid=bssid,
                            ssid=ssid,
                            channel=channel,
                            encryption=encryption,
                            discovered_from=client_mac.upper() if client_mac else "Unknown"
                        )
                        self.hidden_networks[bssid] = hidden
                        
                        if self._log_callback:
                            self._log_callback(
                                f"[+] Hidden SSID revealed: {ssid} ({bssid}) "
                                f"from client {client_mac}"
                            )
                        
                        if self._callback:
                            self._callback(hidden)
                            
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"Error: {e}")
    
    def start_detection(self, callback: Callable = None,
                        log_callback: Callable = None) -> bool:
        """Start hidden network detection"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        self._callback = callback
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting hidden network detection on {self.interface}")
        log(f"[*] Monitoring {len(self.known_bssids)} hidden BSSIDs")
        
        def sniffer():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    filter="type mgt subtype probe-resp",
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                log(f"[!] Sniffer error: {e}")
        
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        
        return True
    
    def stop_detection(self, log_callback: Callable = None):
        """Stop detection"""
        self.running = False
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping hidden network detection...")
        
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
    
    def get_revealed_networks(self) -> List[HiddenNetwork]:
        """Get all revealed hidden networks"""
        return list(self.hidden_networks.values())


# ============================================================================
# CLIENT FINGERPRINTING
# ============================================================================

class ClientFingerprinter:
    """
    Fingerprint WiFi clients based on:
    - Probe request patterns
    - Timing characteristics
    - Supported rates
    - HT/VHT capabilities
    """
    
    # Known device fingerprints based on behavior
    FINGERPRINTS = {
        "apple": {
            "probe_burst": True,
            "randomized_mac": True,
            "probe_interval": (1, 5),
            "ht_capable": True
        },
        "android": {
            "probe_burst": True,
            "randomized_mac": True,  # Android 10+
            "probe_interval": (2, 10),
            "ht_capable": True
        },
        "windows": {
            "probe_burst": False,
            "randomized_mac": False,  # Limited support
            "probe_interval": (5, 30),
            "ht_capable": True
        },
        "linux": {
            "probe_burst": False,
            "randomized_mac": False,  # Requires NetworkManager config
            "probe_interval": (10, 60),
            "ht_capable": True
        },
        "iot": {
            "probe_burst": False,
            "randomized_mac": False,
            "probe_interval": (30, 300),
            "ht_capable": False
        }
    }
    
    def __init__(self):
        self.vendor_lookup = VendorLookup()
        self.client_data: Dict[str, Dict] = {}
    
    def analyze(self, client: ClientInfo) -> str:
        """
        Analyze client behavior and return OS fingerprint
        """
        vendor = client.vendor.lower()
        
        # Easy vendor-based detection
        if "apple" in vendor:
            return "iOS/macOS"
        if "samsung" in vendor or "huawei" in vendor or "xiaomi" in vendor:
            return "Android"
        if "microsoft" in vendor:
            return "Windows"
        if "intel" in vendor:
            return "Windows/Linux"
        if "raspberry" in vendor:
            return "Linux (Raspberry Pi)"
        
        # Check for randomized MAC
        if self.vendor_lookup.is_randomized(client.mac):
            # Most devices with randomized MACs are mobile
            if len(client.probed_ssids) > 10:
                return "Mobile (iOS/Android)"
            return "Mobile Device"
        
        # Analyze probe behavior
        if client.packet_count > 0:
            # High probe rate suggests active scanning
            time_span = (client.last_seen - client.first_seen).total_seconds()
            if time_span > 0:
                probe_rate = client.packet_count / time_span
                if probe_rate > 1:
                    return "Active Scanner"
                elif probe_rate < 0.1:
                    return "IoT/Embedded"
        
        return "Unknown"
    
    def get_device_info(self, mac: str) -> Dict:
        """Get device information for a MAC address"""
        mac = mac.upper()
        vendor = self.vendor_lookup.lookup(mac)
        is_random = self.vendor_lookup.is_randomized(mac)
        
        return {
            "mac": mac,
            "vendor": vendor,
            "randomized": is_random,
            "type": "Mobile" if is_random else "Unknown"
        }


# ============================================================================
# MAIN RECON COORDINATOR
# ============================================================================

class ReconCoordinator:
    """
    Coordinates all reconnaissance activities
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.beacon_analyzer = BeaconAnalyzer(interface)
        self.probe_tracker = ProbeTracker(interface)
        self.hidden_detector = HiddenNetworkDetector(interface)
        self.fingerprinter = ClientFingerprinter()
        self.running = False
    
    def start_full_recon(self, log_callback: Callable = None):
        """Start all reconnaissance components"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Starting full reconnaissance suite")
        log(f"[*] Interface: {self.interface}")
        
        # Start beacon analysis
        def on_beacon(beacon):
            if beacon.hidden:
                self.hidden_detector.add_hidden_bssid(beacon.bssid)
        
        self.beacon_analyzer.start_analysis(
            callback=on_beacon,
            log_callback=log_callback
        )
        
        # Start probe tracking
        self.probe_tracker.start_tracking(log_callback=log_callback)
        
        # Start hidden network detection
        self.hidden_detector.start_detection(log_callback=log_callback)
        
        self.running = True
        log("[+] All recon components started")
    
    def stop_recon(self, log_callback: Callable = None):
        """Stop all reconnaissance"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping reconnaissance...")
        
        self.beacon_analyzer.stop_analysis(log_callback)
        self.probe_tracker.stop_tracking(log_callback)
        self.hidden_detector.stop_detection(log_callback)
        
        self.running = False
        log("[+] All recon components stopped")
    
    def generate_report(self, output_dir: str = ".", 
                        log_callback: Callable = None) -> Dict:
        """Generate comprehensive reconnaissance report"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "interface": self.interface,
            "networks": [],
            "clients": [],
            "hidden_revealed": [],
            "security_issues": []
        }
        
        # Networks
        for beacon in self.beacon_analyzer.get_beacons():
            report["networks"].append({
                "bssid": beacon.bssid,
                "ssid": beacon.ssid,
                "channel": beacon.channel,
                "encryption": beacon.encryption,
                "cipher": beacon.cipher,
                "wps": beacon.wps,
                "hidden": beacon.hidden,
                "vendor": beacon.vendor,
                "wpa3": beacon.sae_supported,
                "pmf": beacon.pmf_required
            })
        
        # Clients with fingerprints
        for client in self.probe_tracker.get_clients():
            os_fp = self.fingerprinter.analyze(client)
            report["clients"].append({
                "mac": client.mac,
                "vendor": client.vendor,
                "probed_ssids": list(client.probed_ssids),
                "os_fingerprint": os_fp,
                "first_seen": client.first_seen.isoformat(),
                "last_seen": client.last_seen.isoformat()
            })
        
        # Hidden networks revealed
        for hidden in self.hidden_detector.get_revealed_networks():
            report["hidden_revealed"].append({
                "bssid": hidden.bssid,
                "ssid": hidden.ssid,
                "discovered_from": hidden.discovered_from
            })
        
        # Security issues
        report["security_issues"] = self.beacon_analyzer.get_security_issues()
        
        # Save report
        report_path = os.path.join(output_dir, f"recon_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2)
            log(f"[+] Report saved to {report_path}")
        except Exception as e:
            log(f"[!] Could not save report: {e}")
        
        return report


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode():
    """Interactive reconnaissance mode"""
    print("\n" + "=" * 60)
    print("  PyAirgeddon Reconnaissance Module")
    print("  WiFi Intelligence Gathering for Red Team Operations")
    print("=" * 60 + "\n")
    
    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy is not installed")
        print("[*] Install with: pip install scapy")
        return
    
    print("[*] Available functions:")
    print("  1. Beacon Analysis - Analyze all visible networks")
    print("  2. Probe Tracking  - Track client probe requests")
    print("  3. Hidden Detector - Reveal hidden SSIDs")
    print("  4. Full Recon      - Run all modules")
    print("  5. Client Lookup   - Look up MAC vendor")
    print("  0. Exit")
    
    interface = input("\n[?] Enter monitor mode interface: ").strip()
    if not interface:
        interface = "wlan0mon"
    
    choice = input("[?] Select option (1-5): ").strip()
    
    def log(msg):
        print(msg)
    
    if choice == "1":
        analyzer = BeaconAnalyzer(interface)
        print("\n[*] Starting beacon analysis (Ctrl+C to stop)...")
        analyzer.start_analysis(log_callback=log)
        try:
            while True:
                time.sleep(5)
                beacons = analyzer.get_beacons()
                print(f"\n[*] Found {len(beacons)} networks:")
                for b in beacons[:10]:
                    print(f"  {b.ssid:32} {b.bssid} Ch{b.channel:2} "
                          f"{b.encryption:6} {b.signal}dBm")
        except KeyboardInterrupt:
            analyzer.stop_analysis(log)
            
    elif choice == "2":
        tracker = ProbeTracker(interface)
        print("\n[*] Starting probe tracking (Ctrl+C to stop)...")
        tracker.start_tracking(log_callback=log)
        try:
            while True:
                time.sleep(5)
                clients = tracker.get_clients()
                print(f"\n[*] Tracking {len(clients)} clients:")
                for c in list(clients)[:10]:
                    ssids = ", ".join(list(c.probed_ssids)[:3])
                    print(f"  {c.mac} ({c.vendor}) -> {ssids}")
        except KeyboardInterrupt:
            tracker.stop_tracking(log)
            
    elif choice == "3":
        detector = HiddenNetworkDetector(interface)
        bssid = input("[?] Enter hidden network BSSID (or leave empty): ").strip()
        if bssid:
            detector.add_hidden_bssid(bssid)
        print("\n[*] Monitoring for hidden SSIDs (Ctrl+C to stop)...")
        detector.start_detection(log_callback=log)
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            detector.stop_detection(log)
            
    elif choice == "4":
        coordinator = ReconCoordinator(interface)
        print("\n[*] Starting full recon (Ctrl+C to stop)...")
        coordinator.start_full_recon(log_callback=log)
        try:
            while True:
                time.sleep(10)
                networks = len(coordinator.beacon_analyzer.get_beacons())
                clients = len(coordinator.probe_tracker.get_clients())
                hidden = len(coordinator.hidden_detector.get_revealed_networks())
                print(f"[*] Networks: {networks} | Clients: {clients} | Hidden revealed: {hidden}")
        except KeyboardInterrupt:
            coordinator.stop_recon(log)
            coordinator.generate_report(log_callback=log)
            
    elif choice == "5":
        lookup = VendorLookup()
        while True:
            mac = input("\n[?] Enter MAC address (or 'quit'): ").strip()
            if mac.lower() == 'quit':
                break
            vendor = lookup.lookup(mac)
            random = lookup.is_randomized(mac)
            print(f"[*] Vendor: {vendor}")
            print(f"[*] Randomized: {'Yes' if random else 'No'}")


if __name__ == "__main__":
    interactive_mode()
