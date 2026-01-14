<<<<<<< HEAD
#!/usr/bin/env python3
"""
PyAirgeddon Password Cracker Module
Dictionary attacks, brute force, and external tool integration
"""

import subprocess
import threading
import time
import os
import re
import itertools
import string
from typing import Callable, Optional, List, Generator
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor


@dataclass
class CrackResult:
    """Result of password cracking attempt"""
    success: bool
    password: str = ""
    method: str = ""
    attempts: int = 0
    time_elapsed: float = 0
    message: str = ""


# ============================================================================
# DICTIONARY ATTACK
# ============================================================================

class DictionaryAttack:
    """
    Dictionary-based password cracking using aircrack-ng
    """
    
    def __init__(self):
        self.running = False
        self.process = None
        self.attempts = 0
        self.current_password = ""
        
    def crack(self, capture_file: str, wordlist: str,
              bssid: str = None, essid: str = None,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Crack WPA/WPA2 handshake using dictionary
        capture_file: .cap file with captured handshake
        wordlist: Path to wordlist file
        bssid: Optional BSSID to target
        essid: Optional ESSID to target
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(capture_file):
            return CrackResult(success=False, message=f"Capture file not found: {capture_file}")
        
        if not os.path.exists(wordlist):
            return CrackResult(success=False, message=f"Wordlist not found: {wordlist}")
        
        # Count wordlist size
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                total_words = sum(1 for _ in f)
            log(f"[*] Wordlist contains {total_words} passwords")
        except:
            total_words = 0
        
        log(f"[*] Starting dictionary attack...")
        log(f"[*] Capture: {capture_file}")
        log(f"[*] Wordlist: {wordlist}")
        
        start_time = time.time()
        self.running = True
        self.attempts = 0
        
        cmd = ['aircrack-ng', '-w', wordlist, capture_file]
        
        if bssid:
            cmd.extend(['-b', bssid])
        if essid:
            cmd.extend(['-e', essid])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            password = ""
            
            for line in self.process.stdout:
                if not self.running:
                    break
                
                # Parse progress
                if 'keys tested' in line.lower():
                    try:
                        match = re.search(r'(\d+)\s*keys', line)
                        if match:
                            self.attempts = int(match.group(1))
                            if total_words > 0 and progress_callback:
                                progress = (self.attempts / total_words) * 100
                                progress_callback(progress, self.attempts, total_words)
                    except:
                        pass
                
                # Check for current password being tested
                if 'Current passphrase:' in line:
                    self.current_password = line.split(':')[-1].strip()
                
                # Check for success
                if 'KEY FOUND!' in line or 'Key Found' in line:
                    match = re.search(r'\[\s*(.+?)\s*\]', line)
                    if match:
                        password = match.group(1)
                        log(f"[+] PASSWORD FOUND: {password}")
                        break
            
            self.process.wait()
            elapsed = time.time() - start_time
            
            if password:
                return CrackResult(
                    success=True,
                    password=password,
                    method="dictionary",
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message=f"Password found in {elapsed:.1f}s after {self.attempts} attempts"
                )
            else:
                log("[-] Password not found in wordlist")
                return CrackResult(
                    success=False,
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message="Password not found"
                )
                
        except FileNotFoundError:
            log("[-] aircrack-ng not found")
            return CrackResult(success=False, message="aircrack-ng not installed")
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def stop(self, log_callback: Callable = None):
        """Stop dictionary attack"""
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
        log("[+] Dictionary attack stopped")


# ============================================================================
# BRUTE FORCE ATTACK
# ============================================================================

class BruteForceAttack:
    """
    Brute force password cracking with custom charset
    """
    
    CHARSETS = {
        'digits': string.digits,
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'alpha': string.ascii_letters,
        'alphanum': string.ascii_letters + string.digits,
        'all': string.ascii_letters + string.digits + string.punctuation,
        'hex': '0123456789abcdef',
        'phone': string.digits  # Phone numbers
    }
    
    def __init__(self):
        self.running = False
        self.process = None
        self.attempts = 0
        
    def generate_passwords(self, charset: str, min_len: int, max_len: int,
                           prefix: str = "", suffix: str = "") -> Generator[str, None, None]:
        """Generate passwords using specified charset and length range"""
        chars = self.CHARSETS.get(charset, charset)
        
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(chars, repeat=length):
                yield prefix + ''.join(combo) + suffix
    
    def crack(self, capture_file: str, charset: str = 'digits',
              min_len: int = 8, max_len: int = 8,
              prefix: str = "", suffix: str = "",
              bssid: str = None,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Brute force attack using aircrack-ng with generated passwords
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(capture_file):
            return CrackResult(success=False, message=f"Capture file not found: {capture_file}")
        
        # Calculate total combinations
        chars = self.CHARSETS.get(charset, charset)
        total = sum(len(chars) ** l for l in range(min_len, max_len + 1))
        log(f"[*] Total combinations to try: {total:,}")
        
        if total > 1000000000:
            log("[!] WARNING: This will take an extremely long time!")
        
        log(f"[*] Starting brute force attack...")
        log(f"[*] Charset: {charset} ({len(chars)} chars)")
        log(f"[*] Length range: {min_len}-{max_len}")
        
        start_time = time.time()
        self.running = True
        self.attempts = 0
        
        cmd = ['aircrack-ng', '-w', '-', capture_file]
        if bssid:
            cmd.extend(['-b', bssid])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            result_password = ""
            
            # Feed passwords to aircrack-ng
            def feed_passwords():
                for password in self.generate_passwords(charset, min_len, max_len, prefix, suffix):
                    if not self.running:
                        break
                    try:
                        self.process.stdin.write(password + '\n')
                        self.process.stdin.flush()
                        self.attempts += 1
                        
                        if self.attempts % 1000 == 0:
                            if progress_callback:
                                progress = (self.attempts / total) * 100 if total > 0 else 0
                                progress_callback(progress, self.attempts, total)
                    except:
                        break
                
                try:
                    self.process.stdin.close()
                except:
                    pass
            
            feed_thread = threading.Thread(target=feed_passwords, daemon=True)
            feed_thread.start()
            
            # Monitor output
            for line in self.process.stdout:
                if 'KEY FOUND!' in line or 'Key Found' in line:
                    match = re.search(r'\[\s*(.+?)\s*\]', line)
                    if match:
                        result_password = match.group(1)
                        log(f"[+] PASSWORD FOUND: {result_password}")
                        self.running = False
                        break
            
            feed_thread.join(timeout=1)
            elapsed = time.time() - start_time
            
            if result_password:
                return CrackResult(
                    success=True,
                    password=result_password,
                    method="bruteforce",
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message=f"Cracked in {elapsed:.1f}s"
                )
            else:
                log("[-] Brute force exhausted without success")
                return CrackResult(
                    success=False,
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message="Password not found"
                )
                
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def stop(self, log_callback: Callable = None):
        """Stop brute force attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
        log("[+] Brute force attack stopped")


# ============================================================================
# HASHCAT INTEGRATION
# ============================================================================

class HashcatCracker:
    """
    Integration with Hashcat for GPU-accelerated cracking
    """
    
    # Hashcat modes
    MODES = {
        'wpa': 22000,       # WPA-PBKDF2-PMKID+EAPOL (hashcat mode)
        'wpa_pmkid': 22000, # Same
        'wpa_old': 2500,    # Legacy WPA/WPA2
    }
    
    def __init__(self):
        self.running = False
        self.process = None
        self.hashcat_path = self._find_hashcat()
        
    def _find_hashcat(self) -> str:
        """Find hashcat executable"""
        try:
            result = subprocess.run(['which', 'hashcat'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Common paths
        for path in ['/usr/bin/hashcat', '/usr/local/bin/hashcat', 
                     '/opt/hashcat/hashcat', 'hashcat.bin']:
            if os.path.exists(path):
                return path
        
        return 'hashcat'
    
    def convert_to_hashcat(self, capture_file: str, output_file: str = None,
                           log_callback: Callable = None) -> Optional[str]:
        """
        Convert .cap file to hashcat format using hcxpcapngtool
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not output_file:
            output_file = capture_file.rsplit('.', 1)[0] + '.22000'
        
        log(f"[*] Converting {capture_file} to hashcat format...")
        
        try:
            # Try hcxpcapngtool (newer)
            result = subprocess.run([
                'hcxpcapngtool',
                '-o', output_file,
                capture_file
            ], capture_output=True, text=True)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                log(f"[+] Converted to {output_file}")
                return output_file
            
            # Fallback to cap2hccapx
            hccapx_file = capture_file.rsplit('.', 1)[0] + '.hccapx'
            result = subprocess.run([
                'cap2hccapx', capture_file, hccapx_file
            ], capture_output=True, text=True)
            
            if os.path.exists(hccapx_file):
                log(f"[+] Converted to {hccapx_file}")
                return hccapx_file
            
            log("[-] Conversion failed")
            return None
            
        except FileNotFoundError:
            log("[-] hcxpcapngtool not found")
            return None
    
    def crack(self, hash_file: str, wordlist: str = None,
              attack_mode: int = 0, rules: str = None,
              mask: str = None, increment: bool = False,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Crack hash using hashcat
        attack_mode: 0=Dictionary, 3=Brute-force, 6=Hybrid
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(hash_file):
            return CrackResult(success=False, message=f"Hash file not found: {hash_file}")
        
        # Determine hash mode
        hash_mode = 22000 if hash_file.endswith('.22000') else 2500
        
        log(f"[*] Starting Hashcat attack (mode {hash_mode})...")
        
        cmd = [
            self.hashcat_path,
            '-m', str(hash_mode),
            '-a', str(attack_mode),
            '--status',
            '--status-timer', '5',
            '-o', hash_file + '.cracked',
            hash_file
        ]
        
        if attack_mode == 0:  # Dictionary
            if not wordlist or not os.path.exists(wordlist):
                return CrackResult(success=False, message="Wordlist required for dictionary attack")
            cmd.append(wordlist)
            if rules:
                cmd.extend(['-r', rules])
        
        elif attack_mode == 3:  # Brute-force
            if mask:
                cmd.append(mask)
                if increment:
                    cmd.append('--increment')
        
        start_time = time.time()
        self.running = True
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            for line in self.process.stdout:
                if not self.running:
                    break
                
                # Parse progress
                if 'Progress' in line:
                    try:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match and progress_callback:
                            progress_callback(float(match.group(1)))
                    except:
                        pass
                
                # Log important lines
                if any(x in line for x in ['Recovered', 'Status', 'Speed', 'Cracked']):
                    log(f"    {line.strip()}")
            
            self.process.wait()
            elapsed = time.time() - start_time
            
            # Check for cracked password
            cracked_file = hash_file + '.cracked'
            if os.path.exists(cracked_file):
                with open(cracked_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        password = content.split(':')[-1]
                        log(f"[+] PASSWORD FOUND: {password}")
                        return CrackResult(
                            success=True,
                            password=password,
                            method="hashcat",
                            time_elapsed=elapsed,
                            message="Cracked by Hashcat"
                        )
            
            log("[-] Hashcat did not find password")
            return CrackResult(success=False, time_elapsed=elapsed, message="Password not found")
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def benchmark(self, log_callback: Callable = None) -> dict:
        """Run hashcat benchmark"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Running Hashcat benchmark for WPA...")
        
        try:
            result = subprocess.run([
                self.hashcat_path, '-b', '-m', '22000'
            ], capture_output=True, text=True, timeout=60)
            
            speed = ""
            for line in result.stdout.split('\n'):
                if 'Speed' in line:
                    speed = line.strip()
                    log(f"    {speed}")
            
            return {'success': True, 'speed': speed}
            
        except Exception as e:
            log(f"[-] Benchmark failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop(self, log_callback: Callable = None):
        """Stop hashcat"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
        log("[+] Hashcat stopped")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("[*] PyAirgeddon Cracker Module")
    print("-" * 40)
    
    # Test brute force generator
    bf = BruteForceAttack()
    print("[*] Available charsets:")
    for name, chars in bf.CHARSETS.items():
        print(f"    - {name}: {len(chars)} characters")
    
    # Test hashcat detection
    hc = HashcatCracker()
    print(f"\n[*] Hashcat path: {hc.hashcat_path}")
=======
#!/usr/bin/env python3
"""
PyAirgeddon Password Cracker Module
Dictionary attacks, brute force, and external tool integration
"""

import subprocess
import threading
import time
import os
import re
import itertools
import string
from typing import Callable, Optional, List, Generator
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor


@dataclass
class CrackResult:
    """Result of password cracking attempt"""
    success: bool
    password: str = ""
    method: str = ""
    attempts: int = 0
    time_elapsed: float = 0
    message: str = ""


# ============================================================================
# DICTIONARY ATTACK
# ============================================================================

class DictionaryAttack:
    """
    Dictionary-based password cracking using aircrack-ng
    """
    
    def __init__(self):
        self.running = False
        self.process = None
        self.attempts = 0
        self.current_password = ""
        
    def crack(self, capture_file: str, wordlist: str,
              bssid: str = None, essid: str = None,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Crack WPA/WPA2 handshake using dictionary
        capture_file: .cap file with captured handshake
        wordlist: Path to wordlist file
        bssid: Optional BSSID to target
        essid: Optional ESSID to target
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(capture_file):
            return CrackResult(success=False, message=f"Capture file not found: {capture_file}")
        
        if not os.path.exists(wordlist):
            return CrackResult(success=False, message=f"Wordlist not found: {wordlist}")
        
        # Count wordlist size
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                total_words = sum(1 for _ in f)
            log(f"[*] Wordlist contains {total_words} passwords")
        except:
            total_words = 0
        
        log(f"[*] Starting dictionary attack...")
        log(f"[*] Capture: {capture_file}")
        log(f"[*] Wordlist: {wordlist}")
        
        start_time = time.time()
        self.running = True
        self.attempts = 0
        
        cmd = ['aircrack-ng', '-w', wordlist, capture_file]
        
        if bssid:
            cmd.extend(['-b', bssid])
        if essid:
            cmd.extend(['-e', essid])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            password = ""
            
            for line in self.process.stdout:
                if not self.running:
                    break
                
                # Parse progress
                if 'keys tested' in line.lower():
                    try:
                        match = re.search(r'(\d+)\s*keys', line)
                        if match:
                            self.attempts = int(match.group(1))
                            if total_words > 0 and progress_callback:
                                progress = (self.attempts / total_words) * 100
                                progress_callback(progress, self.attempts, total_words)
                    except:
                        pass
                
                # Check for current password being tested
                if 'Current passphrase:' in line:
                    self.current_password = line.split(':')[-1].strip()
                
                # Check for success
                if 'KEY FOUND!' in line or 'Key Found' in line:
                    match = re.search(r'\[\s*(.+?)\s*\]', line)
                    if match:
                        password = match.group(1)
                        log(f"[+] PASSWORD FOUND: {password}")
                        break
            
            self.process.wait()
            elapsed = time.time() - start_time
            
            if password:
                return CrackResult(
                    success=True,
                    password=password,
                    method="dictionary",
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message=f"Password found in {elapsed:.1f}s after {self.attempts} attempts"
                )
            else:
                log("[-] Password not found in wordlist")
                return CrackResult(
                    success=False,
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message="Password not found"
                )
                
        except FileNotFoundError:
            log("[-] aircrack-ng not found")
            return CrackResult(success=False, message="aircrack-ng not installed")
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def stop(self, log_callback: Callable = None):
        """Stop dictionary attack"""
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
        log("[+] Dictionary attack stopped")


# ============================================================================
# BRUTE FORCE ATTACK
# ============================================================================

class BruteForceAttack:
    """
    Brute force password cracking with custom charset
    """
    
    CHARSETS = {
        'digits': string.digits,
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'alpha': string.ascii_letters,
        'alphanum': string.ascii_letters + string.digits,
        'all': string.ascii_letters + string.digits + string.punctuation,
        'hex': '0123456789abcdef',
        'phone': string.digits  # Phone numbers
    }
    
    def __init__(self):
        self.running = False
        self.process = None
        self.attempts = 0
        
    def generate_passwords(self, charset: str, min_len: int, max_len: int,
                           prefix: str = "", suffix: str = "") -> Generator[str, None, None]:
        """Generate passwords using specified charset and length range"""
        chars = self.CHARSETS.get(charset, charset)
        
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(chars, repeat=length):
                yield prefix + ''.join(combo) + suffix
    
    def crack(self, capture_file: str, charset: str = 'digits',
              min_len: int = 8, max_len: int = 8,
              prefix: str = "", suffix: str = "",
              bssid: str = None,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Brute force attack using aircrack-ng with generated passwords
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(capture_file):
            return CrackResult(success=False, message=f"Capture file not found: {capture_file}")
        
        # Calculate total combinations
        chars = self.CHARSETS.get(charset, charset)
        total = sum(len(chars) ** l for l in range(min_len, max_len + 1))
        log(f"[*] Total combinations to try: {total:,}")
        
        if total > 1000000000:
            log("[!] WARNING: This will take an extremely long time!")
        
        log(f"[*] Starting brute force attack...")
        log(f"[*] Charset: {charset} ({len(chars)} chars)")
        log(f"[*] Length range: {min_len}-{max_len}")
        
        start_time = time.time()
        self.running = True
        self.attempts = 0
        
        cmd = ['aircrack-ng', '-w', '-', capture_file]
        if bssid:
            cmd.extend(['-b', bssid])
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            result_password = ""
            
            # Feed passwords to aircrack-ng
            def feed_passwords():
                for password in self.generate_passwords(charset, min_len, max_len, prefix, suffix):
                    if not self.running:
                        break
                    try:
                        self.process.stdin.write(password + '\n')
                        self.process.stdin.flush()
                        self.attempts += 1
                        
                        if self.attempts % 1000 == 0:
                            if progress_callback:
                                progress = (self.attempts / total) * 100 if total > 0 else 0
                                progress_callback(progress, self.attempts, total)
                    except:
                        break
                
                try:
                    self.process.stdin.close()
                except:
                    pass
            
            feed_thread = threading.Thread(target=feed_passwords, daemon=True)
            feed_thread.start()
            
            # Monitor output
            for line in self.process.stdout:
                if 'KEY FOUND!' in line or 'Key Found' in line:
                    match = re.search(r'\[\s*(.+?)\s*\]', line)
                    if match:
                        result_password = match.group(1)
                        log(f"[+] PASSWORD FOUND: {result_password}")
                        self.running = False
                        break
            
            feed_thread.join(timeout=1)
            elapsed = time.time() - start_time
            
            if result_password:
                return CrackResult(
                    success=True,
                    password=result_password,
                    method="bruteforce",
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message=f"Cracked in {elapsed:.1f}s"
                )
            else:
                log("[-] Brute force exhausted without success")
                return CrackResult(
                    success=False,
                    attempts=self.attempts,
                    time_elapsed=elapsed,
                    message="Password not found"
                )
                
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def stop(self, log_callback: Callable = None):
        """Stop brute force attack"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
        log("[+] Brute force attack stopped")


# ============================================================================
# HASHCAT INTEGRATION
# ============================================================================

class HashcatCracker:
    """
    Integration with Hashcat for GPU-accelerated cracking
    """
    
    # Hashcat modes
    MODES = {
        'wpa': 22000,       # WPA-PBKDF2-PMKID+EAPOL (hashcat mode)
        'wpa_pmkid': 22000, # Same
        'wpa_old': 2500,    # Legacy WPA/WPA2
    }
    
    def __init__(self):
        self.running = False
        self.process = None
        self.hashcat_path = self._find_hashcat()
        
    def _find_hashcat(self) -> str:
        """Find hashcat executable"""
        try:
            result = subprocess.run(['which', 'hashcat'], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        # Common paths
        for path in ['/usr/bin/hashcat', '/usr/local/bin/hashcat', 
                     '/opt/hashcat/hashcat', 'hashcat.bin']:
            if os.path.exists(path):
                return path
        
        return 'hashcat'
    
    def convert_to_hashcat(self, capture_file: str, output_file: str = None,
                           log_callback: Callable = None) -> Optional[str]:
        """
        Convert .cap file to hashcat format using hcxpcapngtool
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not output_file:
            output_file = capture_file.rsplit('.', 1)[0] + '.22000'
        
        log(f"[*] Converting {capture_file} to hashcat format...")
        
        try:
            # Try hcxpcapngtool (newer)
            result = subprocess.run([
                'hcxpcapngtool',
                '-o', output_file,
                capture_file
            ], capture_output=True, text=True)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                log(f"[+] Converted to {output_file}")
                return output_file
            
            # Fallback to cap2hccapx
            hccapx_file = capture_file.rsplit('.', 1)[0] + '.hccapx'
            result = subprocess.run([
                'cap2hccapx', capture_file, hccapx_file
            ], capture_output=True, text=True)
            
            if os.path.exists(hccapx_file):
                log(f"[+] Converted to {hccapx_file}")
                return hccapx_file
            
            log("[-] Conversion failed")
            return None
            
        except FileNotFoundError:
            log("[-] hcxpcapngtool not found")
            return None
    
    def crack(self, hash_file: str, wordlist: str = None,
              attack_mode: int = 0, rules: str = None,
              mask: str = None, increment: bool = False,
              log_callback: Callable = None,
              progress_callback: Callable = None) -> CrackResult:
        """
        Crack hash using hashcat
        attack_mode: 0=Dictionary, 3=Brute-force, 6=Hybrid
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        if not os.path.exists(hash_file):
            return CrackResult(success=False, message=f"Hash file not found: {hash_file}")
        
        # Determine hash mode
        hash_mode = 22000 if hash_file.endswith('.22000') else 2500
        
        log(f"[*] Starting Hashcat attack (mode {hash_mode})...")
        
        cmd = [
            self.hashcat_path,
            '-m', str(hash_mode),
            '-a', str(attack_mode),
            '--status',
            '--status-timer', '5',
            '-o', hash_file + '.cracked',
            hash_file
        ]
        
        if attack_mode == 0:  # Dictionary
            if not wordlist or not os.path.exists(wordlist):
                return CrackResult(success=False, message="Wordlist required for dictionary attack")
            cmd.append(wordlist)
            if rules:
                cmd.extend(['-r', rules])
        
        elif attack_mode == 3:  # Brute-force
            if mask:
                cmd.append(mask)
                if increment:
                    cmd.append('--increment')
        
        start_time = time.time()
        self.running = True
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            for line in self.process.stdout:
                if not self.running:
                    break
                
                # Parse progress
                if 'Progress' in line:
                    try:
                        match = re.search(r'(\d+\.?\d*)%', line)
                        if match and progress_callback:
                            progress_callback(float(match.group(1)))
                    except:
                        pass
                
                # Log important lines
                if any(x in line for x in ['Recovered', 'Status', 'Speed', 'Cracked']):
                    log(f"    {line.strip()}")
            
            self.process.wait()
            elapsed = time.time() - start_time
            
            # Check for cracked password
            cracked_file = hash_file + '.cracked'
            if os.path.exists(cracked_file):
                with open(cracked_file, 'r') as f:
                    content = f.read().strip()
                    if content:
                        password = content.split(':')[-1]
                        log(f"[+] PASSWORD FOUND: {password}")
                        return CrackResult(
                            success=True,
                            password=password,
                            method="hashcat",
                            time_elapsed=elapsed,
                            message="Cracked by Hashcat"
                        )
            
            log("[-] Hashcat did not find password")
            return CrackResult(success=False, time_elapsed=elapsed, message="Password not found")
            
        except Exception as e:
            log(f"[-] Error: {e}")
            return CrackResult(success=False, message=str(e))
        finally:
            self.running = False
    
    def benchmark(self, log_callback: Callable = None) -> dict:
        """Run hashcat benchmark"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Running Hashcat benchmark for WPA...")
        
        try:
            result = subprocess.run([
                self.hashcat_path, '-b', '-m', '22000'
            ], capture_output=True, text=True, timeout=60)
            
            speed = ""
            for line in result.stdout.split('\n'):
                if 'Speed' in line:
                    speed = line.strip()
                    log(f"    {speed}")
            
            return {'success': True, 'speed': speed}
            
        except Exception as e:
            log(f"[-] Benchmark failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def stop(self, log_callback: Callable = None):
        """Stop hashcat"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        if self.process:
            self.process.terminate()
        log("[+] Hashcat stopped")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("[*] PyAirgeddon Cracker Module")
    print("-" * 40)
    
    # Test brute force generator
    bf = BruteForceAttack()
    print("[*] Available charsets:")
    for name, chars in bf.CHARSETS.items():
        print(f"    - {name}: {len(chars)} characters")
    
    # Test hashcat detection
    hc = HashcatCracker()
    print(f"\n[*] Hashcat path: {hc.hashcat_path}")
>>>>>>> 7a1df55f49f3097f4e39d6a09d98fe1482ca394e
