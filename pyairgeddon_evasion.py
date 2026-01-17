#!/usr/bin/env python3
"""
PyAirgeddon Evasion Module
Stealth and evasion capabilities for red team wireless operations

Features:
- MAC Randomization: Per-probe MAC randomization with vendor spoofing
- Power Control: Adjust TX power for stealth scanning
- Timing Jitter: Randomize packet timing to evade detection
- WIDS Profile Detection: Detect common WIDS signatures
- Stealth Scanner: Low-profile network scanning
"""

import subprocess
import threading
import time
import os
import re
import random
import hashlib
from typing import Callable, Optional, List, Dict, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

# Try to import optional dependencies
try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Elt, RadioTap, sendp, conf, RandMAC, Dot11Deauth,
        get_if_hwaddr
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# VENDOR OUI DATABASE FOR SPOOFING
# ============================================================================

VENDOR_OUIS = {
    "apple": [
        "00:17:F2", "00:1B:63", "00:1E:52", "00:1F:5B", "00:21:E9",
        "00:22:41", "00:23:12", "00:23:32", "00:23:6C", "00:24:36",
        "00:25:00", "00:25:BC", "00:26:08", "00:26:4A", "00:26:B0",
        "14:10:9F", "28:0B:5C", "30:10:E4", "40:30:04", "54:AE:27",
        "6C:40:08", "70:DE:E2", "78:CA:39", "84:FC:FE", "88:C6:63",
    ],
    "samsung": [
        "00:1E:E2", "00:21:4C", "00:23:99", "00:24:54", "00:25:66",
        "00:26:37", "5C:0A:5B", "84:25:DB", "8C:77:12", "AC:5F:3E",
        "D0:DF:C7", "EC:1F:72", "F8:04:2E", "FC:F1:36", "00:21:19",
    ],
    "google": [
        "00:1A:11", "3C:5A:B4", "54:60:09", "F4:F5:D8", "94:EB:2C",
        "F8:8F:CA", "A4:77:33", "20:DF:B9", "E8:B2:AC",
    ],
    "intel": [
        "00:1B:21", "00:13:02", "00:15:00", "00:21:5C", "3C:A9:F4",
        "5C:51:4F", "00:1E:65", "00:1F:3B", "00:20:A6", "00:22:FA",
    ],
    "huawei": [
        "00:19:47", "00:1E:10", "00:25:68", "00:46:4B", "00:9A:CD",
        "00:E0:FC", "04:02:1F", "04:BD:70", "20:F3:A3", "24:09:95",
    ],
    "random": [
        "02:00:00", "06:00:00", "0A:00:00", "0E:00:00",  # Locally administered
    ],
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class WIDSAlert:
    """WIDS/IDS detection alert"""
    timestamp: datetime
    alert_type: str
    description: str
    source: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class StealthScanResult:
    """Result of stealth scan"""
    networks: List[Dict]
    duration: float
    packets_sent: int
    detected: bool
    detection_events: List[str]


# ============================================================================
# MAC RANDOMIZATION
# ============================================================================

class MACRandomizer:
    """
    Advanced MAC address randomization with vendor spoofing
    
    Features:
    - Generate realistic vendor-specific MACs
    - Track used MACs to avoid duplicates
    - Support for both locally administered and vendor MACs
    """
    
    def __init__(self, prefer_vendor: str = None):
        """
        Initialize randomizer
        
        Args:
            prefer_vendor: Preferred vendor (apple, samsung, google, intel, huawei, random)
        """
        self.prefer_vendor = prefer_vendor
        self.used_macs: Set[str] = set()
        self.original_mac: Dict[str, str] = {}  # interface -> original MAC
    
    def generate_random_mac(self, vendor: str = None) -> str:
        """
        Generate a random MAC address
        
        Args:
            vendor: Specific vendor or None for random selection
        """
        if vendor is None:
            vendor = self.prefer_vendor or random.choice(list(VENDOR_OUIS.keys()))
        
        ouis = VENDOR_OUIS.get(vendor, VENDOR_OUIS["random"])
        oui = random.choice(ouis)
        
        # Generate random suffix
        suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
        mac = f"{oui}:{suffix}"
        
        # Ensure uniqueness
        while mac in self.used_macs:
            suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
            mac = f"{oui}:{suffix}"
        
        self.used_macs.add(mac)
        return mac
    
    def generate_locally_administered(self) -> str:
        """
        Generate a locally administered MAC address
        The second bit of the first octet is set to 1
        """
        # Start with locally administered prefix
        first_byte = random.randint(0, 255) | 0x02  # Set LA bit
        first_byte &= 0xFE  # Clear multicast bit
        
        mac = f"{first_byte:02X}"
        mac += ":" + ":".join([f"{random.randint(0, 255):02X}" for _ in range(5)])
        
        self.used_macs.add(mac)
        return mac
    
    def get_current_mac(self, interface: str) -> str:
        """Get current MAC address of interface"""
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', interface],
                capture_output=True, text=True
            )
            match = re.search(r'link/ether ([0-9a-fA-F:]{17})', result.stdout)
            if match:
                return match.group(1).upper()
        except:
            pass
        return ""
    
    def save_original_mac(self, interface: str):
        """Save the original MAC for later restoration"""
        if interface not in self.original_mac:
            self.original_mac[interface] = self.get_current_mac(interface)
    
    def set_mac(self, interface: str, mac: str, 
                log_callback: Callable = None) -> bool:
        """
        Set MAC address on interface
        
        Note: Requires root privileges and interface must be down
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            # Save original
            self.save_original_mac(interface)
            
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', interface, 'down'],
                          capture_output=True, check=True)
            
            # Change MAC
            subprocess.run(['ip', 'link', 'set', interface, 'address', mac],
                          capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['ip', 'link', 'set', interface, 'up'],
                          capture_output=True, check=True)
            
            log(f"[+] MAC changed to {mac}")
            return True
            
        except subprocess.CalledProcessError as e:
            log(f"[!] Failed to change MAC: {e}")
            return False
        except Exception as e:
            log(f"[!] Error: {e}")
            return False
    
    def restore_mac(self, interface: str, log_callback: Callable = None) -> bool:
        """Restore original MAC address"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if interface not in self.original_mac:
            log("[!] No original MAC saved")
            return False
        
        return self.set_mac(interface, self.original_mac[interface], log_callback)
    
    def randomize_interface(self, interface: str, vendor: str = None,
                            log_callback: Callable = None) -> str:
        """Randomize interface MAC and return new MAC"""
        new_mac = self.generate_random_mac(vendor)
        if self.set_mac(interface, new_mac, log_callback):
            return new_mac
        return ""


# ============================================================================
# POWER CONTROL
# ============================================================================

class PowerController:
    """
    Control wireless transmission power for stealth operations
    
    Lower TX power = shorter range but harder to detect
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.original_power: Optional[int] = None
    
    def get_current_power(self) -> int:
        """Get current TX power in dBm"""
        try:
            result = subprocess.run(
                ['iwconfig', self.interface],
                capture_output=True, text=True
            )
            # Look for "Tx-Power=XX dBm"
            match = re.search(r'Tx-Power[=:](\d+)\s*dBm', result.stdout)
            if match:
                return int(match.group(1))
        except:
            pass
        return 20  # Default assumption
    
    def save_original_power(self):
        """Save original power level"""
        if self.original_power is None:
            self.original_power = self.get_current_power()
    
    def set_power(self, power_dbm: int, 
                  log_callback: Callable = None) -> bool:
        """
        Set TX power level
        
        Args:
            power_dbm: Power in dBm (typically 1-30, depends on driver/region)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.save_original_power()
        
        try:
            # Try iwconfig first
            result = subprocess.run(
                ['iwconfig', self.interface, 'txpower', f'{power_dbm}dBm'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                log(f"[+] TX power set to {power_dbm} dBm")
                return True
            
            # Try iw
            result = subprocess.run(
                ['iw', 'dev', self.interface, 'set', 'txpower', 'fixed', 
                 str(power_dbm * 100)],  # iw uses mBm
                capture_output=True, text=True
            )
            if result.returncode == 0:
                log(f"[+] TX power set to {power_dbm} dBm")
                return True
            
            log(f"[!] Failed to set TX power")
            return False
            
        except Exception as e:
            log(f"[!] Error: {e}")
            return False
    
    def set_stealth_power(self, log_callback: Callable = None) -> bool:
        """Set minimum power for stealth operation"""
        return self.set_power(1, log_callback)  # 1 dBm = ~1.26 mW
    
    def set_low_power(self, log_callback: Callable = None) -> bool:
        """Set low power (5 dBm = ~3 mW)"""
        return self.set_power(5, log_callback)
    
    def set_medium_power(self, log_callback: Callable = None) -> bool:
        """Set medium power (10 dBm = ~10 mW)"""
        return self.set_power(10, log_callback)
    
    def restore_power(self, log_callback: Callable = None) -> bool:
        """Restore original power level"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if self.original_power is None:
            log("[!] No original power saved")
            return False
        
        return self.set_power(self.original_power, log_callback)


# ============================================================================
# TIMING JITTER
# ============================================================================

class TimingController:
    """
    Randomize packet timing to evade WIDS detection
    
    WIDS often detect attacks based on regular timing patterns:
    - Constant probe intervals
    - Predictable deauth timing
    - Uniform beacon intervals
    """
    
    def __init__(self, base_interval: float = 0.1):
        """
        Initialize timing controller
        
        Args:
            base_interval: Base interval in seconds
        """
        self.base_interval = base_interval
        self.jitter_min = 0.5  # 50% of base
        self.jitter_max = 2.0  # 200% of base
        self.burst_mode = False
        self.burst_count = 5
        self.burst_interval = 0.01
    
    def get_jittered_interval(self) -> float:
        """Get a randomized interval"""
        jitter = random.uniform(self.jitter_min, self.jitter_max)
        return self.base_interval * jitter
    
    def get_exponential_backoff(self, attempt: int, max_interval: float = 10.0) -> float:
        """Get exponentially increasing interval with jitter"""
        base = min(self.base_interval * (2 ** attempt), max_interval)
        return base * random.uniform(0.8, 1.2)
    
    def get_burst_timing(self) -> List[float]:
        """
        Get timing for burst transmission
        Fast burst followed by longer pause
        """
        timings = []
        
        # Burst phase
        for _ in range(self.burst_count):
            timings.append(self.burst_interval * random.uniform(0.5, 1.5))
        
        # Pause phase
        timings.append(self.base_interval * random.uniform(3.0, 5.0))
        
        return timings
    
    def random_sleep(self):
        """Sleep for a random jittered interval"""
        time.sleep(self.get_jittered_interval())
    
    def human_like_timing(self) -> float:
        """
        Generate human-like timing patterns
        Occasional longer pauses, random clusters
        """
        # Most intervals are short
        if random.random() < 0.8:
            return self.base_interval * random.uniform(0.5, 1.5)
        
        # Occasional long pause (thinking/distraction)
        if random.random() < 0.5:
            return self.base_interval * random.uniform(5.0, 15.0)
        
        # Occasional very short (quick actions)
        return self.base_interval * random.uniform(0.1, 0.3)


# ============================================================================
# WIDS DETECTION AND EVASION
# ============================================================================

class WIDSDetector:
    """
    Detect and evade Wireless Intrusion Detection Systems
    
    Common WIDS signatures:
    - High probe rate from single MAC
    - Deauth floods
    - Beacon anomalies
    - Association floods
    - Fake AP indicators
    """
    
    # Known WIDS vendors/patterns
    WIDS_SIGNATURES = {
        "kismet": {
            "probes_per_minute": 30,
            "deauth_threshold": 10,
            "description": "Kismet wireless monitor"
        },
        "airmagnet": {
            "probes_per_minute": 20,
            "deauth_threshold": 5,
            "description": "AirMagnet enterprise WIDS"
        },
        "aruba": {
            "probes_per_minute": 25,
            "deauth_threshold": 8,
            "description": "Aruba Wireless IDS"
        },
        "cisco": {
            "probes_per_minute": 20,
            "deauth_threshold": 10,
            "description": "Cisco adaptive wIPS"
        }
    }
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.alerts: List[WIDSAlert] = []
        self.detected_patterns: Dict[str, int] = defaultdict(int)
        self._sniffer_thread = None
        self._log_callback = None
        
        # Detection thresholds
        self.probe_window = 60  # seconds
        self.probe_threshold = 30
        self.deauth_threshold = 5
        
        # Tracking
        self.probe_times: List[datetime] = []
        self.deauth_times: List[datetime] = []
    
    def _detect_wids_ap(self, packet) -> Optional[str]:
        """Check if beacon appears to be from WIDS sensor"""
        if not packet.haslayer(Dot11Beacon):
            return None
        
        try:
            # Get SSID and vendor
            ssid = ""
            elt = packet[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    ssid = elt.info.decode('utf-8', errors='ignore').lower()
                    break
                elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
            
            # Check for WIDS-related SSIDs
            wids_keywords = ['honeypot', 'rogue', 'wids', 'ids', 'sensor', 'monitor']
            for keyword in wids_keywords:
                if keyword in ssid:
                    return f"Possible WIDS sensor: SSID contains '{keyword}'"
            
            # Check for hidden networks with monitoring indicators
            bssid = packet[Dot11].addr2
            if bssid:
                # Some vendors use specific OUI ranges for sensors
                oui = bssid[:8].upper()
                sensor_ouis = ["00:0B:85", "00:24:6C"]  # Example sensor OUIs
                if oui in sensor_ouis:
                    return f"Possible WIDS sensor: Known sensor OUI {oui}"
                    
        except:
            pass
        
        return None
    
    def _check_rate_detection(self) -> Optional[str]:
        """Check if our probe rate might trigger detection"""
        now = datetime.now()
        cutoff = now.timestamp() - self.probe_window
        
        # Clean old entries
        self.probe_times = [t for t in self.probe_times if t.timestamp() > cutoff]
        
        if len(self.probe_times) > self.probe_threshold:
            return f"High probe rate: {len(self.probe_times)} in {self.probe_window}s"
        
        return None
    
    def _packet_handler(self, packet):
        """Monitor for WIDS indicators"""
        try:
            # Check for WIDS sensor beacons
            wids_check = self._detect_wids_ap(packet)
            if wids_check:
                self._add_alert("WIDS_SENSOR", wids_check, "HIGH")
            
            # Track our probe timing
            if packet.haslayer(Dot11ProbeReq):
                self.probe_times.append(datetime.now())
                
                # Check if we might be detected
                rate_check = self._check_rate_detection()
                if rate_check:
                    self._add_alert("RATE_DETECTION", rate_check, "MEDIUM")
            
            # Track deauth (might be countermeasures)
            if packet.haslayer(Dot11Deauth):
                self.deauth_times.append(datetime.now())
                
                # Multiple deauths might be WIDS response
                cutoff = datetime.now().timestamp() - 10
                recent_deauths = [t for t in self.deauth_times if t.timestamp() > cutoff]
                if len(recent_deauths) > self.deauth_threshold:
                    self._add_alert(
                        "COUNTERMEASURE",
                        f"Possible WIDS countermeasure: {len(recent_deauths)} deauths in 10s",
                        "CRITICAL"
                    )
                    
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"[!] Detection error: {e}")
    
    def _add_alert(self, alert_type: str, description: str, severity: str):
        """Add a WIDS detection alert"""
        alert = WIDSAlert(
            timestamp=datetime.now(),
            alert_type=alert_type,
            description=description,
            source=self.interface,
            severity=severity
        )
        self.alerts.append(alert)
        self.detected_patterns[alert_type] += 1
        
        if self._log_callback:
            self._log_callback(f"[ALERT] [{severity}] {description}")
    
    def start_monitoring(self, log_callback: Callable = None) -> bool:
        """Start WIDS detection monitoring"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Starting WIDS detection monitoring")
        
        def sniffer():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                log(f"[!] Monitor error: {e}")
        
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        
        log("[+] Monitoring started")
        return True
    
    def stop_monitoring(self, log_callback: Callable = None):
        """Stop monitoring"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
        
        log(f"[*] Stopped. Detected {len(self.alerts)} potential issues")
    
    def get_alerts(self) -> List[WIDSAlert]:
        """Get all alerts"""
        return self.alerts
    
    def get_evasion_recommendations(self) -> List[str]:
        """Get recommendations based on detected patterns"""
        recommendations = []
        
        if self.detected_patterns.get("RATE_DETECTION", 0) > 0:
            recommendations.append("Reduce probe rate - use longer intervals")
            recommendations.append("Enable MAC randomization between probes")
        
        if self.detected_patterns.get("WIDS_SENSOR", 0) > 0:
            recommendations.append("WIDS sensor detected - increase stealth")
            recommendations.append("Reduce TX power")
            recommendations.append("Use timing jitter")
        
        if self.detected_patterns.get("COUNTERMEASURE", 0) > 0:
            recommendations.append("Active countermeasures detected!")
            recommendations.append("Consider aborting or changing location")
            recommendations.append("Change MAC and wait before resuming")
        
        return recommendations


# ============================================================================
# STEALTH SCANNER
# ============================================================================

class StealthScanner:
    """
    Low-profile network scanner with evasion capabilities
    
    Combines:
    - MAC randomization
    - Power control
    - Timing jitter
    - WIDS monitoring
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.networks: Dict[str, Dict] = {}
        
        # Evasion components
        self.mac_randomizer = MACRandomizer(prefer_vendor="apple")
        self.power_controller = PowerController(interface)
        self.timing_controller = TimingController(base_interval=2.0)
        self.wids_detector = WIDSDetector(interface)
        
        self._sniffer_thread = None
        self._log_callback = None
        self._packets_sent = 0
        self._start_time = None
    
    def _passive_scan_handler(self, packet):
        """Handle captured beacons (passive only)"""
        if not packet.haslayer(Dot11Beacon):
            return
        
        try:
            bssid = packet[Dot11].addr2
            if not bssid:
                return
            
            bssid = bssid.upper()
            
            # Get basic info
            ssid = ""
            channel = 0
            encryption = "OPEN"
            signal = -100
            
            if packet.haslayer(RadioTap):
                try:
                    signal = packet[RadioTap].dBm_AntSignal
                except:
                    pass
            
            elt = packet[Dot11Elt]
            while elt:
                if elt.ID == 0:
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                    except:
                        ssid = "<Hidden>"
                elif elt.ID == 3:
                    if len(elt.info) >= 1:
                        channel = elt.info[0]
                elif elt.ID == 48:  # RSN
                    encryption = "WPA2"
                elif elt.ID == 221:
                    if len(elt.info) >= 4:
                        if elt.info[:4] == b'\x00\x50\xf2\x01':
                            if encryption == "OPEN":
                                encryption = "WPA"
                
                try:
                    elt = elt.payload.getlayer(Dot11Elt)
                except:
                    break
            
            self.networks[bssid] = {
                "ssid": ssid,
                "bssid": bssid,
                "channel": channel,
                "encryption": encryption,
                "signal": signal,
                "last_seen": datetime.now().isoformat()
            }
            
        except:
            pass
    
    def _send_probe(self, ssid: str = "") -> bool:
        """Send a single probe request with evasion"""
        if not SCAPY_AVAILABLE:
            return False
        
        try:
            # Generate random source MAC
            src_mac = self.mac_randomizer.generate_locally_administered()
            
            # Build probe request
            dot11 = Dot11(
                type=0, subtype=4,  # Probe request
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=src_mac,  # Our random MAC
                addr3="ff:ff:ff:ff:ff:ff"
            )
            
            probe = Dot11ProbeReq()
            ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode() if ssid else b'')
            rates_elt = Dot11Elt(ID='Rates', info=b'\x02\x04\x0b\x16')
            
            packet = RadioTap() / dot11 / probe / ssid_elt / rates_elt
            
            sendp(packet, iface=self.interface, verbose=False)
            self._packets_sent += 1
            
            return True
            
        except:
            return False
    
    def start_passive_scan(self, duration: int = 60,
                           channel_hop: bool = True,
                           stealth_level: int = 2,
                           log_callback: Callable = None) -> StealthScanResult:
        """
        Start passive (listening only) stealth scan
        
        Args:
            duration: Scan duration in seconds
            channel_hop: Whether to hop channels
            stealth_level: 1=low, 2=medium, 3=high (affects power/timing)
        """
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return StealthScanResult([], 0, 0, False, [])
        
        self._log_callback = log_callback
        self._start_time = datetime.now()
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Preparing stealth scan...")
        
        # Apply stealth settings based on level
        if stealth_level >= 2:
            # Randomize MAC
            new_mac = self.mac_randomizer.randomize_interface(
                self.interface, "apple", log_callback
            )
            if new_mac:
                log(f"[+] MAC randomized: {new_mac}")
        
        if stealth_level >= 3:
            # Low power
            self.power_controller.set_low_power(log_callback)
        
        # Start WIDS monitoring
        self.wids_detector.start_monitoring(log_callback)
        
        self.running = True
        detected = False
        detection_events = []
        
        log(f"[*] Starting passive scan (stealth level {stealth_level})")
        
        # Channel hopping setup
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
        current_channel_idx = 0
        last_hop = time.time()
        hop_interval = 0.5 if stealth_level < 3 else 1.0
        
        # Start passive sniffer
        def sniffer():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._passive_scan_handler,
                    store=False,
                    timeout=duration,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                log(f"[!] Sniffer error: {e}")
        
        self._sniffer_thread = threading.Thread(target=sniffer, daemon=True)
        self._sniffer_thread.start()
        
        # Main loop with channel hopping
        start = time.time()
        while self.running and (time.time() - start) < duration:
            # Channel hop
            if channel_hop and (time.time() - last_hop) >= hop_interval:
                channel = channels[current_channel_idx % len(channels)]
                try:
                    subprocess.run(
                        ['iwconfig', self.interface, 'channel', str(channel)],
                        capture_output=True
                    )
                except:
                    pass
                current_channel_idx += 1
                last_hop = time.time()
            
            # Check for WIDS detection
            alerts = self.wids_detector.get_alerts()
            if alerts:
                for alert in alerts[len(detection_events):]:
                    detection_events.append(alert.description)
                    if alert.severity in ["HIGH", "CRITICAL"]:
                        detected = True
            
            # Apply jitter to loop timing
            time.sleep(self.timing_controller.get_jittered_interval())
        
        self.running = False
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
        
        # Stop monitoring
        self.wids_detector.stop_monitoring(log_callback)
        
        # Cleanup
        if stealth_level >= 2:
            self.mac_randomizer.restore_mac(self.interface, log_callback)
        if stealth_level >= 3:
            self.power_controller.restore_power(log_callback)
        
        elapsed = (datetime.now() - self._start_time).total_seconds()
        
        result = StealthScanResult(
            networks=list(self.networks.values()),
            duration=elapsed,
            packets_sent=self._packets_sent,
            detected=detected,
            detection_events=detection_events
        )
        
        log(f"[+] Scan complete: {len(result.networks)} networks found")
        if detected:
            log(f"[!] Possible detection: {len(detection_events)} events")
        
        return result
    
    def start_active_scan(self, duration: int = 30,
                          target_ssids: List[str] = None,
                          stealth_level: int = 2,
                          log_callback: Callable = None) -> StealthScanResult:
        """
        Active scan with probe requests (higher risk of detection)
        
        Args:
            duration: Scan duration
            target_ssids: Specific SSIDs to probe (None for broadcast)
            stealth_level: 1-3 (higher = stealthier but slower)
        """
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return StealthScanResult([], 0, 0, False, [])
        
        self._log_callback = log_callback
        self._start_time = datetime.now()
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Preparing active stealth scan...")
        
        # Apply stealth
        if stealth_level >= 1:
            self.mac_randomizer.randomize_interface(self.interface, log_callback=log_callback)
        if stealth_level >= 2:
            self.power_controller.set_low_power(log_callback)
        if stealth_level >= 3:
            self.timing_controller.base_interval = 5.0  # Slow down significantly
        
        # Start monitoring
        self.wids_detector.start_monitoring(log_callback)
        
        self.running = True
        detected = False
        detection_events = []
        
        # Start passive capture in background
        def sniffer():
            sniff(
                iface=self.interface,
                prn=self._passive_scan_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        
        threading.Thread(target=sniffer, daemon=True).start()
        
        log("[*] Starting active scan...")
        
        start = time.time()
        ssids_to_probe = target_ssids if target_ssids else [""]  # Empty = broadcast
        
        while self.running and (time.time() - start) < duration:
            for ssid in ssids_to_probe:
                if not self.running:
                    break
                
                # Randomize MAC for each probe if high stealth
                if stealth_level >= 3:
                    self.mac_randomizer.randomize_interface(
                        self.interface, log_callback=log_callback
                    )
                
                # Send probe
                self._send_probe(ssid)
                
                # Check for detection
                alerts = self.wids_detector.get_alerts()
                for alert in alerts[len(detection_events):]:
                    detection_events.append(alert.description)
                    if alert.severity in ["HIGH", "CRITICAL"]:
                        detected = True
                        log(f"[!] Detection risk: {alert.description}")
                
                # Jittered delay
                time.sleep(self.timing_controller.human_like_timing())
        
        self.running = False
        self.wids_detector.stop_monitoring(log_callback)
        
        # Cleanup
        self.mac_randomizer.restore_mac(self.interface, log_callback)
        self.power_controller.restore_power(log_callback)
        
        elapsed = (datetime.now() - self._start_time).total_seconds()
        
        result = StealthScanResult(
            networks=list(self.networks.values()),
            duration=elapsed,
            packets_sent=self._packets_sent,
            detected=detected,
            detection_events=detection_events
        )
        
        log(f"[+] Scan complete: {len(result.networks)} networks")
        return result


# ============================================================================
# EVASION COORDINATOR
# ============================================================================

class EvasionCoordinator:
    """
    Coordinates all evasion capabilities for red team operations
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.mac_randomizer = MACRandomizer()
        self.power_controller = PowerController(interface)
        self.timing_controller = TimingController()
        self.wids_detector = WIDSDetector(interface)
        self.stealth_scanner = StealthScanner(interface)
    
    def setup_stealth_mode(self, level: int = 2,
                           log_callback: Callable = None) -> bool:
        """
        Setup interface for stealth operations
        
        Level 1: MAC randomization
        Level 2: + Low power
        Level 3: + Aggressive timing jitter
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Setting up stealth mode (level {level})")
        success = True
        
        if level >= 1:
            mac = self.mac_randomizer.randomize_interface(
                self.interface, log_callback=log_callback
            )
            if not mac:
                log("[!] MAC randomization failed")
                success = False
        
        if level >= 2:
            if not self.power_controller.set_low_power(log_callback):
                log("[!] Power control failed")
                success = False
        
        if level >= 3:
            self.timing_controller.base_interval = 5.0
            self.timing_controller.jitter_min = 0.3
            self.timing_controller.jitter_max = 3.0
            log("[+] Aggressive timing enabled")
        
        return success
    
    def cleanup_stealth_mode(self, log_callback: Callable = None):
        """Restore original settings"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Restoring original settings...")
        self.mac_randomizer.restore_mac(self.interface, log_callback)
        self.power_controller.restore_power(log_callback)
        self.timing_controller.base_interval = 0.1
        log("[+] Settings restored")
    
    def get_status(self) -> Dict:
        """Get current evasion status"""
        return {
            "interface": self.interface,
            "current_mac": self.mac_randomizer.get_current_mac(self.interface),
            "original_mac": self.mac_randomizer.original_mac.get(self.interface, "Unknown"),
            "current_power": self.power_controller.get_current_power(),
            "original_power": self.power_controller.original_power,
            "base_timing": self.timing_controller.base_interval,
            "wids_alerts": len(self.wids_detector.alerts)
        }


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode():
    """Interactive evasion mode"""
    print("\n" + "=" * 60)
    print("  PyAirgeddon Evasion Module")
    print("  Stealth Operations for Red Team")
    print("=" * 60 + "\n")
    
    if not SCAPY_AVAILABLE:
        print("[!] Warning: Scapy not installed (limited functionality)")
        print("[*] Install with: pip install scapy")
    
    print("[*] Available tools:")
    print("  1. MAC Randomizer    - Spoof MAC address")
    print("  2. Power Control     - Adjust TX power")
    print("  3. Stealth Scanner   - Low-profile network scan")
    print("  4. WIDS Monitor      - Detect intrusion systems")
    print("  5. Full Stealth Mode - Setup all evasion")
    print("  0. Exit")
    
    interface = input("\n[?] Enter wireless interface: ").strip()
    if not interface:
        interface = "wlan0"
    
    choice = input("[?] Select option (1-5): ").strip()
    
    def log(msg):
        print(msg)
    
    if choice == "1":
        randomizer = MACRandomizer()
        print(f"\n[*] Current MAC: {randomizer.get_current_mac(interface)}")
        
        vendor = input("[?] Vendor (apple/samsung/google/intel/random): ").strip()
        vendor = vendor if vendor in VENDOR_OUIS else "random"
        
        new_mac = randomizer.generate_random_mac(vendor)
        print(f"[*] Generated MAC: {new_mac}")
        
        confirm = input("[?] Apply this MAC? (y/N): ").strip().lower()
        if confirm == 'y':
            if randomizer.set_mac(interface, new_mac, log):
                print(f"[+] MAC changed successfully")
                
                restore = input("[?] Restore original? (y/N): ").strip().lower()
                if restore == 'y':
                    randomizer.restore_mac(interface, log)
                    
    elif choice == "2":
        controller = PowerController(interface)
        print(f"\n[*] Current TX power: {controller.get_current_power()} dBm")
        
        print("[*] Options: 1=Stealth(1dBm), 2=Low(5dBm), 3=Medium(10dBm), 4=Custom")
        level = input("[?] Select power level: ").strip()
        
        if level == "1":
            controller.set_stealth_power(log)
        elif level == "2":
            controller.set_low_power(log)
        elif level == "3":
            controller.set_medium_power(log)
        elif level == "4":
            custom = input("[?] Enter power in dBm (1-30): ").strip()
            try:
                controller.set_power(int(custom), log)
            except ValueError:
                print("[!] Invalid power value")
                
    elif choice == "3":
        scanner = StealthScanner(interface)
        
        duration = input("[?] Scan duration in seconds (default 30): ").strip()
        duration = int(duration) if duration else 30
        
        level = input("[?] Stealth level 1-3 (default 2): ").strip()
        level = int(level) if level else 2
        
        scan_type = input("[?] Scan type (P)assive or (A)ctive? (default P): ").strip().lower()
        
        print("\n[*] Starting scan...")
        
        if scan_type == 'a':
            result = scanner.start_active_scan(duration, stealth_level=level, log_callback=log)
        else:
            result = scanner.start_passive_scan(duration, stealth_level=level, log_callback=log)
        
        print(f"\n[+] Results:")
        print(f"    Networks found: {len(result.networks)}")
        print(f"    Packets sent: {result.packets_sent}")
        print(f"    Duration: {result.duration:.1f}s")
        print(f"    Detection events: {len(result.detection_events)}")
        
        if result.networks:
            print("\n[*] Networks:")
            for net in sorted(result.networks, key=lambda x: x.get('signal', -100), reverse=True)[:10]:
                print(f"    {net['ssid']:32} {net['bssid']} Ch{net.get('channel', 0):2} "
                      f"{net['encryption']:6} {net.get('signal', -100)}dBm")
                      
    elif choice == "4":
        detector = WIDSDetector(interface)
        
        print("\n[*] Starting WIDS detection monitor (Ctrl+C to stop)...")
        detector.start_monitoring(log)
        
        try:
            while True:
                time.sleep(5)
                alerts = detector.get_alerts()
                if alerts:
                    print(f"\n[!] {len(alerts)} alerts detected")
        except KeyboardInterrupt:
            detector.stop_monitoring(log)
            
            recs = detector.get_evasion_recommendations()
            if recs:
                print("\n[*] Recommendations:")
                for rec in recs:
                    print(f"    - {rec}")
                    
    elif choice == "5":
        coordinator = EvasionCoordinator(interface)
        
        level = input("[?] Stealth level 1-3: ").strip()
        level = int(level) if level else 2
        
        coordinator.setup_stealth_mode(level, log)
        
        status = coordinator.get_status()
        print(f"\n[*] Status:")
        print(f"    Current MAC: {status['current_mac']}")
        print(f"    Original MAC: {status['original_mac']}")
        print(f"    TX Power: {status['current_power']} dBm")
        
        input("\n[*] Press Enter to restore settings...")
        coordinator.cleanup_stealth_mode(log)


if __name__ == "__main__":
    interactive_mode()
