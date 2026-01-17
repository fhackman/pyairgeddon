#!/usr/bin/env python3
"""
PyAirgeddon - Python Wireless Security Auditing Tool
A comprehensive GUI application inspired by Airgeddon
Requires: Linux with aircrack-ng suite, hostapd, dnsmasq

Version: 1.1.0
Author: PyAirgeddon Team
"""

import subprocess
import sys
import os
import shutil
import time
from typing import Dict, List, Tuple, Optional, Callable

# ============================================================================
# DEPENDENCY MANAGER - Professional Auto-Installation System
# ============================================================================

class DependencyManager:
    """
    Professional dependency management system with:
    - Automatic package detection and installation
    - Progress tracking with visual feedback
    - Cross-platform support (Windows/Linux)
    - Retry logic for failed installations
    - Colored terminal output
    """
    
    # Python package dependencies
    REQUIRED_MODULES: Dict[str, str] = {
        'scapy': 'scapy>=2.5.0',           # Packet manipulation
    }
    
    OPTIONAL_MODULES: Dict[str, str] = {
        'netifaces': 'netifaces>=0.11.0',  # Network interface info
    }
    
    # ANSI color codes
    class Color:
        RESET = '\033[0m'
        BOLD = '\033[1m'
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        
        @classmethod
        def supports_color(cls) -> bool:
            """Check if terminal supports color output"""
            if os.name == 'nt':
                # Windows: check for ANSICON or Windows Terminal
                return bool(os.environ.get('ANSICON') or 
                           os.environ.get('WT_SESSION') or
                           os.environ.get('TERM'))
            return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    
    def __init__(self):
        self.is_windows = os.name == 'nt'
        self.installed_count = 0
        self.failed_count = 0
        self.use_colors = self.Color.supports_color()
        
        # Enable ANSI colors on Windows 10+
        if self.is_windows:
            self._enable_windows_ansi()
    
    def _enable_windows_ansi(self) -> None:
        """Enable ANSI escape sequences on Windows"""
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except:
            pass
    
    def _print(self, message: str, color: str = '', bold: bool = False) -> None:
        """Print with optional color"""
        if self.use_colors and color:
            prefix = self.Color.BOLD if bold else ''
            print(f"{prefix}{color}{message}{self.Color.RESET}")
        else:
            print(message)
    
    def _print_header(self) -> None:
        """Print styled header"""
        platform_name = "Windows" if self.is_windows else "Linux"
        
        self._print("\n" + "═" * 60, self.Color.CYAN)
        self._print("  🔧 PyAirgeddon - Dependency Manager", self.Color.CYAN, bold=True)
        self._print("═" * 60, self.Color.CYAN)
        self._print(f"  Platform: {platform_name} | Python: {sys.version.split()[0]}", self.Color.BLUE)
        self._print("─" * 60, self.Color.CYAN)
        print()
    
    def _print_progress(self, current: int, total: int, message: str = '') -> None:
        """Print progress bar"""
        bar_length = 30
        progress = current / total if total > 0 else 0
        filled = int(bar_length * progress)
        bar = "█" * filled + "░" * (bar_length - filled)
        
        status = f"  [{bar}] {current}/{total}"
        if message:
            status += f" - {message}"
        
        # Use carriage return to overwrite line
        print(f"\r{status}", end='', flush=True)
    
    def check_module(self, module_name: str) -> Tuple[bool, str]:
        """
        Check if a module is installed
        Returns: (is_installed, version_or_error)
        """
        try:
            mod = __import__(module_name)
            version = getattr(mod, '__version__', 'unknown')
            return True, version
        except ImportError as e:
            return False, str(e)
    
    def install_module(self, module_name: str, pip_name: str, 
                       retries: int = 2) -> bool:
        """
        Install a module using pip with retry logic
        """
        for attempt in range(retries + 1):
            try:
                # Upgrade pip first if this is a retry
                if attempt > 0:
                    subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'],
                        capture_output=True, timeout=60
                    )
                
                # Install the package
                result = subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', pip_name, 
                     '--quiet', '--disable-pip-version-check'],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    return True
                    
            except subprocess.TimeoutExpired:
                self._print(f"    ⏱ Timeout on attempt {attempt + 1}", self.Color.YELLOW)
            except Exception as e:
                if attempt == retries:
                    self._print(f"    ✗ Error: {e}", self.Color.RED)
        
        return False
    
    def check_and_install(self, progress_callback: Optional[Callable] = None) -> bool:
        """
        Check and install all required dependencies
        Returns: True if all required modules are available
        """
        self._print_header()
        
        all_modules = list(self.REQUIRED_MODULES.items()) + list(self.OPTIONAL_MODULES.items())
        total = len(all_modules)
        
        missing_required: List[Tuple[str, str]] = []
        missing_optional: List[Tuple[str, str]] = []
        
        # Phase 1: Check all modules
        self._print("  📋 Checking Python packages...", self.Color.YELLOW)
        print()
        
        for idx, (module, pip_name) in enumerate(all_modules):
            is_required = module in self.REQUIRED_MODULES
            installed, version = self.check_module(module)
            
            if installed:
                icon = "✓"
                color = self.Color.GREEN
                status = f"v{version}"
            else:
                if is_required:
                    icon = "✗"
                    color = self.Color.RED
                    status = "MISSING (required)"
                    missing_required.append((module, pip_name))
                else:
                    icon = "○"
                    color = self.Color.YELLOW
                    status = "not installed (optional)"
                    missing_optional.append((module, pip_name))
            
            self._print(f"  [{icon}] {module:20} {status}", color)
        
        print()
        
        # Phase 2: Install missing required modules
        if missing_required:
            self._print(f"  ⚡ Installing {len(missing_required)} required package(s)...", 
                       self.Color.YELLOW, bold=True)
            print()
            
            for idx, (module, pip_name) in enumerate(missing_required):
                self._print(f"  [{idx+1}/{len(missing_required)}] Installing {pip_name}...", 
                           self.Color.BLUE)
                
                if self.install_module(module, pip_name):
                    self._print(f"      ✓ {module} installed successfully!", self.Color.GREEN)
                    self.installed_count += 1
                else:
                    self._print(f"      ✗ Failed to install {module}", self.Color.RED)
                    self.failed_count += 1
            
            print()
        
        # Phase 3: Try to install optional modules
        if missing_optional:
            self._print(f"  📦 Attempting to install optional packages...", self.Color.BLUE)
            
            for module, pip_name in missing_optional:
                if self.install_module(module, pip_name, retries=1):
                    self._print(f"      ✓ {module} installed", self.Color.GREEN)
                    self.installed_count += 1
                else:
                    self._print(f"      ○ {module} skipped (optional)", self.Color.YELLOW)
            
            print()
        
        # Summary
        self._print("─" * 60, self.Color.CYAN)
        
        if self.failed_count == 0:
            self._print("  ✓ All required dependencies satisfied!", self.Color.GREEN, bold=True)
        else:
            self._print(f"  ⚠ {self.failed_count} package(s) failed to install", 
                       self.Color.RED, bold=True)
        
        if self.installed_count > 0:
            self._print(f"  📦 Installed {self.installed_count} new package(s)", self.Color.BLUE)
        
        # Platform-specific notes
        print()
        if self.is_windows:
            self._print("  ℹ Note: Running on Windows - some features may be limited", 
                       self.Color.YELLOW)
            self._print("  ℹ For full functionality, use WSL or Linux", self.Color.YELLOW)
        else:
            self._print("  ℹ External tools: sudo apt install aircrack-ng hostapd dnsmasq", 
                       self.Color.BLUE)
        
        self._print("═" * 60, self.Color.CYAN)
        print()
        
        return self.failed_count == 0


def check_and_install_modules():
    """Legacy function for backward compatibility"""
    manager = DependencyManager()
    return manager.check_and_install()


# Run dependency check before other imports
check_and_install_modules()

# Standard library imports
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import random
from datetime import datetime
from typing import Optional, Callable

# Import PyAirgeddon modules
try:
    from pyairgeddon_core import (
        WirelessInterface, NetworkScanner, HandshakeCapture,
        WirelessNetwork, check_root, check_dependencies, get_timestamp
    )
    from pyairgeddon_attacks import DeauthAttack, DoSAttack, WPSAttack
    from pyairgeddon_cracker import DictionaryAttack, BruteForceAttack, HashcatCracker
    from pyairgeddon_eviltwin import EvilTwinAP, CAPTIVE_PORTAL_TEMPLATES
except ImportError as e:
    print(f"[!] Error importing modules: {e}")
    print("[!] Make sure all pyairgeddon_*.py files are in the same directory")
    sys.exit(1)


# ============================================================================
# THEME AND CONSTANTS
# ============================================================================

COLORS = {
    'bg_dark': '#050508',
    'bg_panel': '#0d0d14',
    'bg_input': '#14141f',
    'bg_hover': '#1a1a28',
    'accent': '#00ff88',
    'accent2': '#00d4ff',
    'accent3': '#ff00ff',
    'warning': '#ff4757',
    'text': '#e8e8e8',
    'text_dim': '#555566',
    'success': '#00ff88',
    'error': '#ff4444',
    'border': '#1f1f2e',
    'glow': '#00ff88'
}

ASCII_BANNER = r'''
 ██████╗ ██╗   ██╗ █████╗ ██╗██████╗  ██████╗ ███████╗██████╗ ██████╗  ██████╗ ███╗   ██╗
 ██╔══██╗╚██╗ ██╔╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
 ██████╔╝ ╚████╔╝ ███████║██║██████╔╝██║  ███╗█████╗  ██║  ██║██║  ██║██║   ██║██╔██╗ ██║
 ██╔═══╝   ╚██╔╝  ██╔══██║██║██╔══██╗██║   ██║██╔══╝  ██║  ██║██║  ██║██║   ██║██║╚██╗██║
 ██║        ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗██████╔╝██████╔╝╚██████╔╝██║ ╚████║
 ╚═╝        ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                    ╔═══════════════════════════════════════════╗
                    ║   🔥 WIRELESS SECURITY AUDITING TOOL 🔥   ║
                    ╚═══════════════════════════════════════════╝
'''

MATRIX_CHARS = "アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン0123456789"


# ============================================================================
# SPLASH SCREEN WITH MATRIX EFFECT
# ============================================================================

class SplashScreen:
    """Animated splash screen with matrix rain effect"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.overrideredirect(True)
        self.root.configure(bg=COLORS['bg_dark'])
        
        # Center on screen
        width, height = 700, 450
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Matrix canvas
        self.canvas = tk.Canvas(self.root, bg=COLORS['bg_dark'], 
                                highlightthickness=0, width=width, height=height)
        self.canvas.pack(fill='both', expand=True)
        
        # Matrix rain columns
        self.columns = []
        for i in range(0, width, 15):
            self.columns.append({
                'x': i,
                'y': random.randint(-200, 0),
                'speed': random.randint(5, 15),
                'chars': [random.choice(MATRIX_CHARS) for _ in range(20)]
            })
        
        # Banner
        self.canvas.create_text(width//2, height//2 - 50, text=ASCII_BANNER,
                               font=('Consolas', 6), fill=COLORS['accent'], anchor='center')
        
        # Loading text
        self.loading_text = self.canvas.create_text(width//2, height - 60,
            text="Initializing...", font=('Consolas', 11), fill=COLORS['text'])
        
        # Progress bar background
        self.canvas.create_rectangle(100, height-30, width-100, height-20,
                                     fill=COLORS['bg_input'], outline=COLORS['border'])
        
        # Progress bar
        self.progress_bar = self.canvas.create_rectangle(100, height-30, 100, height-20,
                                    fill=COLORS['accent'], outline='')
        
        self.progress = 0
        self.running = True
        
    def update_matrix(self):
        """Update matrix rain animation"""
        if not self.running:
            return
            
        # Clear only matrix chars (not banner)
        self.canvas.delete('matrix')
        
        for col in self.columns:
            col['y'] += col['speed']
            if col['y'] > 450:
                col['y'] = random.randint(-100, 0)
                col['chars'] = [random.choice(MATRIX_CHARS) for _ in range(20)]
            
            for i, char in enumerate(col['chars'][:10]):
                y = col['y'] + i * 15
                if 0 <= y <= 450:
                    alpha = max(0, 255 - i * 25)
                    color = f'#{alpha:02x}ff{alpha:02x}'
                    self.canvas.create_text(col['x'], y, text=char,
                        font=('Consolas', 10), fill=color, tags='matrix')
        
        self.root.after(50, self.update_matrix)
        
    def update_progress(self, value: int, message: str = ""):
        """Update progress bar and message"""
        self.progress = value
        width = 700
        bar_width = (width - 200) * (value / 100)
        self.canvas.coords(self.progress_bar, 100, 420, 100 + bar_width, 430)
        
        if message:
            self.canvas.itemconfig(self.loading_text, text=message)
        
        self.root.update()
        
    def close(self):
        """Close splash screen"""
        self.running = False
        self.root.destroy()
        
    def run(self, callback):
        """Run splash screen with initialization callback"""
        self.update_matrix()
        self.root.after(100, lambda: callback(self))
        self.root.mainloop()




class PyAirgeddonGUI:
    """Main PyAirgeddon GUI Application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("PyAirgeddon - Wireless Security Auditing Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg=COLORS['bg_dark'])
        self.root.minsize(1000, 700)
        
        # State
        self.interface_mgr = WirelessInterface()
        self.scanner: Optional[NetworkScanner] = None
        self.current_interface = None
        self.selected_network: Optional[WirelessNetwork] = None
        self.networks = []
        
        # Attack instances
        self.deauth_attack: Optional[DeauthAttack] = None
        self.dos_attack: Optional[DoSAttack] = None
        self.wps_attack: Optional[WPSAttack] = None
        self.dict_attack: Optional[DictionaryAttack] = None
        self.evil_twin: Optional[EvilTwinAP] = None
        
        self.setup_styles()
        self.setup_ui()
        self.check_environment()
        
    def setup_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Notebook tabs
        style.configure('TNotebook', background=COLORS['bg_dark'], borderwidth=0)
        style.configure('TNotebook.Tab', 
            background=COLORS['bg_panel'],
            foreground=COLORS['text'],
            padding=[15, 8],
            font=('Consolas', 10, 'bold')
        )
        style.map('TNotebook.Tab',
            background=[('selected', COLORS['bg_input'])],
            foreground=[('selected', COLORS['accent'])]
        )
        
        # Treeview
        style.configure('Treeview',
            background=COLORS['bg_input'],
            foreground=COLORS['text'],
            fieldbackground=COLORS['bg_input'],
            font=('Consolas', 9),
            rowheight=25
        )
        style.configure('Treeview.Heading',
            background=COLORS['bg_panel'],
            foreground=COLORS['accent'],
            font=('Consolas', 9, 'bold')
        )
        
        # Combobox
        style.configure('TCombobox',
            fieldbackground=COLORS['bg_input'],
            background=COLORS['bg_panel'],
            foreground=COLORS['text']
        )
        
        # Progressbar
        style.configure('green.Horizontal.TProgressbar',
            troughcolor=COLORS['bg_input'],
            background=COLORS['accent']
        )
        
    def setup_ui(self):
        """Build the main UI"""
        # Header
        header = tk.Frame(self.root, bg=COLORS['bg_dark'])
        header.pack(fill='x', padx=10, pady=5)
        
        # Banner
        banner_lbl = tk.Label(header, text=ASCII_BANNER, 
            font=('Consolas', 6), fg=COLORS['accent'], bg=COLORS['bg_dark'],
            justify='left')
        banner_lbl.pack(anchor='w')
        
        # Version info
        info_frame = tk.Frame(header, bg=COLORS['bg_dark'])
        info_frame.pack(fill='x')
        tk.Label(info_frame, text="v1.0 | Python Wireless Security Auditing Tool",
            font=('Consolas', 9), fg=COLORS['text_dim'], bg=COLORS['bg_dark']).pack(side='left')
        
        # Interface selector
        iface_frame = tk.Frame(info_frame, bg=COLORS['bg_dark'])
        iface_frame.pack(side='right')
        
        tk.Label(iface_frame, text="Interface:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_dark']).pack(side='left', padx=5)
        
        self.iface_combo = ttk.Combobox(iface_frame, width=15, state='readonly')
        self.iface_combo.pack(side='left', padx=5)
        self.iface_combo.bind('<<ComboboxSelected>>', self.on_interface_select)
        
        self.mode_btn = tk.Button(iface_frame, text="Enable Monitor", 
            font=('Consolas', 9), bg=COLORS['bg_panel'], fg=COLORS['accent'],
            activebackground=COLORS['accent'], activeforeground=COLORS['bg_dark'],
            command=self.toggle_monitor_mode, relief='flat', padx=10)
        self.mode_btn.pack(side='left', padx=5)
        
        self.refresh_btn = tk.Button(iface_frame, text="↻", 
            font=('Consolas', 12), bg=COLORS['bg_panel'], fg=COLORS['accent'],
            command=self.refresh_interfaces, relief='flat', width=3)
        self.refresh_btn.pack(side='left', padx=2)
        
        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_scan_tab()
        self.create_attack_tab()
        self.create_cracker_tab()
        self.create_eviltwin_tab()
        self.create_log_tab()
        
        # Status bar
        status_frame = tk.Frame(self.root, bg=COLORS['bg_panel'], height=40)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)  # Keep fixed height
        
        # Status text on left
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(status_frame, textvariable=self.status_var,
            font=('Consolas', 9), fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left', padx=10, pady=8)
        
        # Progress section on right
        progress_frame = tk.Frame(status_frame, bg=COLORS['bg_panel'])
        progress_frame.pack(side='right', padx=10, pady=5)
        
        # Activity label (shows ▶ when active)
        self.activity_var = tk.StringVar(value="")
        self.activity_label = tk.Label(progress_frame, textvariable=self.activity_var,
            font=('Consolas', 10, 'bold'), fg=COLORS['accent'], bg=COLORS['bg_panel'])
        self.activity_label.pack(side='left', padx=5)
        
        # Progress bar - larger and more visible
        self.progress = ttk.Progressbar(progress_frame, mode='determinate',
            style='green.Horizontal.TProgressbar', length=300)
        self.progress.pack(side='left', padx=5)
        
        # Percentage label
        self.progress_pct = tk.StringVar(value="0%")
        tk.Label(progress_frame, textvariable=self.progress_pct,
            font=('Consolas', 9), fg=COLORS['text'], bg=COLORS['bg_panel'], width=5).pack(side='left')
        
    def create_scan_tab(self):
        """Create network scanning tab"""
        tab = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(tab, text=" 📡 Scan ")
        
        # Controls
        ctrl_frame = tk.Frame(tab, bg=COLORS['bg_panel'])
        ctrl_frame.pack(fill='x', padx=5, pady=5)
        
        self.scan_btn = tk.Button(ctrl_frame, text="▶ Start Scan",
            font=('Consolas', 10, 'bold'), bg=COLORS['accent'], fg=COLORS['bg_dark'],
            command=self.start_scan, relief='flat', padx=20, pady=5)
        self.scan_btn.pack(side='left', padx=5, pady=5)
        
        self.stop_scan_btn = tk.Button(ctrl_frame, text="■ Stop",
            font=('Consolas', 10), bg=COLORS['warning'], fg='white',
            command=self.stop_scan, relief='flat', padx=15, pady=5, state='disabled')
        self.stop_scan_btn.pack(side='left', padx=5, pady=5)
        
        # Channel selector
        tk.Label(ctrl_frame, text="Channel:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left', padx=(20,5))
        self.channel_var = tk.StringVar(value="All")
        channel_combo = ttk.Combobox(ctrl_frame, textvariable=self.channel_var,
            values=['All'] + [str(i) for i in range(1, 15)] + ['36','40','44','48'],
            width=8, state='readonly')
        channel_combo.pack(side='left', padx=5)
        
        # Network list
        list_frame = tk.Frame(tab, bg=COLORS['bg_dark'])
        list_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        columns = ('ssid', 'bssid', 'channel', 'signal', 'encryption', 'clients')
        self.network_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        self.network_tree.heading('ssid', text='SSID')
        self.network_tree.heading('bssid', text='BSSID')
        self.network_tree.heading('channel', text='CH')
        self.network_tree.heading('signal', text='PWR')
        self.network_tree.heading('encryption', text='ENC')
        self.network_tree.heading('clients', text='Clients')
        
        self.network_tree.column('ssid', width=200)
        self.network_tree.column('bssid', width=150)
        self.network_tree.column('channel', width=50)
        self.network_tree.column('signal', width=60)
        self.network_tree.column('encryption', width=100)
        self.network_tree.column('clients', width=60)
        
        scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=self.network_tree.yview)
        self.network_tree.configure(yscrollcommand=scrollbar.set)
        
        self.network_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        self.network_tree.bind('<<TreeviewSelect>>', self.on_network_select)
        
    def create_attack_tab(self):
        """Create attacks tab"""
        tab = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(tab, text=" ⚡ Attacks ")
        
        # Target info
        target_frame = tk.LabelFrame(tab, text=" Target ", bg=COLORS['bg_panel'],
            fg=COLORS['accent'], font=('Consolas', 10, 'bold'))
        target_frame.pack(fill='x', padx=10, pady=10)
        
        self.target_info = tk.Label(target_frame, text="No target selected. Select a network from Scan tab.",
            font=('Consolas', 10), fg=COLORS['text_dim'], bg=COLORS['bg_panel'])
        self.target_info.pack(padx=10, pady=10)
        
        # Attack buttons frame
        attacks_frame = tk.Frame(tab, bg=COLORS['bg_dark'])
        attacks_frame.pack(fill='both', expand=True, padx=10)
        
        # Deauth Attack
        deauth_frame = tk.LabelFrame(attacks_frame, text=" Deauthentication Attack ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        deauth_frame.pack(fill='x', pady=5)
        
        deauth_inner = tk.Frame(deauth_frame, bg=COLORS['bg_panel'])
        deauth_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Label(deauth_inner, text="Target Client:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left')
        self.deauth_client = tk.Entry(deauth_inner, width=20, bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'])
        self.deauth_client.pack(side='left', padx=5)
        self.deauth_client.insert(0, "FF:FF:FF:FF:FF:FF")
        
        self.deauth_btn = tk.Button(deauth_inner, text="▶ Start Deauth",
            font=('Consolas', 10), bg=COLORS['warning'], fg='white',
            command=self.toggle_deauth, relief='flat', padx=15)
        self.deauth_btn.pack(side='right', padx=5)
        
        # DoS Attack
        dos_frame = tk.LabelFrame(attacks_frame, text=" DoS Attacks ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        dos_frame.pack(fill='x', pady=5)
        
        dos_inner = tk.Frame(dos_frame, bg=COLORS['bg_panel'])
        dos_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Button(dos_inner, text="Beacon Flood", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.beacon_flood,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        tk.Button(dos_inner, text="Auth Flood", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.auth_flood,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        self.dos_stop_btn = tk.Button(dos_inner, text="■ Stop DoS",
            font=('Consolas', 9), bg=COLORS['warning'], fg='white',
            command=self.stop_dos, relief='flat', padx=10, state='disabled')
        self.dos_stop_btn.pack(side='right', padx=5)
        
        # WPS Attack
        wps_frame = tk.LabelFrame(attacks_frame, text=" WPS Attacks ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        wps_frame.pack(fill='x', pady=5)
        
        wps_inner = tk.Frame(wps_frame, bg=COLORS['bg_panel'])
        wps_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Button(wps_inner, text="Pixie Dust", font=('Consolas', 9),
            bg=COLORS['accent2'], fg=COLORS['bg_dark'], command=self.pixie_dust,
            relief='flat', padx=15).pack(side='left', padx=5)
        
        tk.Button(wps_inner, text="PIN Brute Force", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.wps_bruteforce,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        tk.Label(wps_inner, text="Custom PIN:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left', padx=(20,5))
        self.custom_pin = tk.Entry(wps_inner, width=10, bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'])
        self.custom_pin.pack(side='left', padx=5)
        
        tk.Button(wps_inner, text="Try PIN", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.try_custom_pin,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        # Handshake Capture
        hs_frame = tk.LabelFrame(attacks_frame, text=" Handshake Capture ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        hs_frame.pack(fill='x', pady=5)
        
        hs_inner = tk.Frame(hs_frame, bg=COLORS['bg_panel'])
        hs_inner.pack(fill='x', padx=10, pady=10)
        
        self.capture_btn = tk.Button(hs_inner, text="▶ Capture Handshake",
            font=('Consolas', 10), bg=COLORS['accent'], fg=COLORS['bg_dark'],
            command=self.capture_handshake, relief='flat', padx=15)
        self.capture_btn.pack(side='left', padx=5)
        
        tk.Button(hs_inner, text="Capture PMKID", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.capture_pmkid,
            relief='flat', padx=10).pack(side='left', padx=5)
        
    def create_cracker_tab(self):
        """Create password cracker tab"""
        tab = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(tab, text=" 🔓 Cracker ")
        
        # Capture file selection
        file_frame = tk.LabelFrame(tab, text=" Capture File ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        file_frame.pack(fill='x', padx=10, pady=10)
        
        file_inner = tk.Frame(file_frame, bg=COLORS['bg_panel'])
        file_inner.pack(fill='x', padx=10, pady=10)
        
        self.capture_file_entry = tk.Entry(file_inner, width=60, bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'])
        self.capture_file_entry.pack(side='left', padx=5)
        
        tk.Button(file_inner, text="Browse", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.browse_capture,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        # Dictionary Attack
        dict_frame = tk.LabelFrame(tab, text=" Dictionary Attack ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        dict_frame.pack(fill='x', padx=10, pady=5)
        
        dict_inner = tk.Frame(dict_frame, bg=COLORS['bg_panel'])
        dict_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Label(dict_inner, text="Wordlist:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left')
        
        self.wordlist_entry = tk.Entry(dict_inner, width=40, bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'])
        self.wordlist_entry.pack(side='left', padx=5)
        self.wordlist_entry.insert(0, "/usr/share/wordlists/rockyou.txt")
        
        tk.Button(dict_inner, text="Browse", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.browse_wordlist,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        self.dict_btn = tk.Button(dict_inner, text="▶ Start Dictionary Attack",
            font=('Consolas', 10), bg=COLORS['accent'], fg=COLORS['bg_dark'],
            command=self.start_dict_attack, relief='flat', padx=15)
        self.dict_btn.pack(side='right', padx=5)
        
        # Brute Force
        bf_frame = tk.LabelFrame(tab, text=" Brute Force ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        bf_frame.pack(fill='x', padx=10, pady=5)
        
        bf_inner = tk.Frame(bf_frame, bg=COLORS['bg_panel'])
        bf_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Label(bf_inner, text="Charset:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left')
        
        self.charset_combo = ttk.Combobox(bf_inner, width=12, state='readonly',
            values=['digits', 'lowercase', 'uppercase', 'alpha', 'alphanum', 'all'])
        self.charset_combo.pack(side='left', padx=5)
        self.charset_combo.set('digits')
        
        tk.Label(bf_inner, text="Length:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left', padx=(10,5))
        
        self.min_len = tk.Spinbox(bf_inner, from_=1, to=20, width=3, bg=COLORS['bg_input'],
            fg=COLORS['text'])
        self.min_len.pack(side='left')
        self.min_len.delete(0, 'end')
        self.min_len.insert(0, '8')
        
        tk.Label(bf_inner, text="-", bg=COLORS['bg_panel'], fg=COLORS['text']).pack(side='left')
        
        self.max_len = tk.Spinbox(bf_inner, from_=1, to=20, width=3, bg=COLORS['bg_input'],
            fg=COLORS['text'])
        self.max_len.pack(side='left')
        self.max_len.delete(0, 'end')
        self.max_len.insert(0, '8')
        
        tk.Button(bf_inner, text="▶ Start Brute Force", font=('Consolas', 10),
            bg=COLORS['warning'], fg='white', command=self.start_bruteforce,
            relief='flat', padx=15).pack(side='right', padx=5)
        
        # Hashcat
        hc_frame = tk.LabelFrame(tab, text=" Hashcat (GPU) ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        hc_frame.pack(fill='x', padx=10, pady=5)
        
        hc_inner = tk.Frame(hc_frame, bg=COLORS['bg_panel'])
        hc_inner.pack(fill='x', padx=10, pady=10)
        
        tk.Button(hc_inner, text="Convert to Hashcat", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.convert_hashcat,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        tk.Button(hc_inner, text="▶ Run Hashcat", font=('Consolas', 10),
            bg=COLORS['accent2'], fg=COLORS['bg_dark'], command=self.run_hashcat,
            relief='flat', padx=15).pack(side='left', padx=5)
        
        tk.Button(hc_inner, text="Benchmark", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.hashcat_benchmark,
            relief='flat', padx=10).pack(side='left', padx=5)
        
        # Cracking status
        status_frame = tk.Frame(tab, bg=COLORS['bg_dark'])
        status_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.crack_status = tk.Label(status_frame, text="",
            font=('Consolas', 12, 'bold'), fg=COLORS['accent'], bg=COLORS['bg_dark'])
        self.crack_status.pack(pady=20)
        
    def create_eviltwin_tab(self):
        """Create Evil Twin tab"""
        tab = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(tab, text=" 👻 Evil Twin ")
        
        # Configuration
        config_frame = tk.LabelFrame(tab, text=" Evil Twin Configuration ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        config_frame.pack(fill='x', padx=10, pady=10)
        
        # SSID
        row1 = tk.Frame(config_frame, bg=COLORS['bg_panel'])
        row1.pack(fill='x', padx=10, pady=5)
        
        tk.Label(row1, text="Target SSID:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel'], width=15, anchor='e').pack(side='left')
        self.et_ssid = tk.Entry(row1, width=30, bg=COLORS['bg_input'],
            fg=COLORS['text'], insertbackground=COLORS['text'])
        self.et_ssid.pack(side='left', padx=10)
        
        tk.Button(row1, text="← From Scan", font=('Consolas', 8),
            bg=COLORS['bg_input'], fg=COLORS['text_dim'], command=self.copy_ssid_from_scan,
            relief='flat').pack(side='left')
        
        # Channel
        row2 = tk.Frame(config_frame, bg=COLORS['bg_panel'])
        row2.pack(fill='x', padx=10, pady=5)
        
        tk.Label(row2, text="Channel:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel'], width=15, anchor='e').pack(side='left')
        self.et_channel = tk.Spinbox(row2, from_=1, to=14, width=5, bg=COLORS['bg_input'],
            fg=COLORS['text'])
        self.et_channel.pack(side='left', padx=10)
        
        # Template
        tk.Label(row2, text="Portal Template:", font=('Consolas', 9),
            fg=COLORS['text'], bg=COLORS['bg_panel']).pack(side='left', padx=(30,5))
        self.et_template = ttk.Combobox(row2, width=15, state='readonly',
            values=list(CAPTIVE_PORTAL_TEMPLATES.keys())[:-1])  # Exclude 'success'
        self.et_template.pack(side='left', padx=5)
        self.et_template.set('generic')
        
        # Controls
        ctrl_frame = tk.Frame(config_frame, bg=COLORS['bg_panel'])
        ctrl_frame.pack(fill='x', padx=10, pady=15)
        
        self.et_start_btn = tk.Button(ctrl_frame, text="▶ Start Evil Twin",
            font=('Consolas', 11, 'bold'), bg=COLORS['warning'], fg='white',
            command=self.start_evil_twin, relief='flat', padx=20, pady=8)
        self.et_start_btn.pack(side='left', padx=10)
        
        self.et_stop_btn = tk.Button(ctrl_frame, text="■ Stop",
            font=('Consolas', 11), bg=COLORS['bg_input'], fg=COLORS['text'],
            command=self.stop_evil_twin, relief='flat', padx=20, pady=8, state='disabled')
        self.et_stop_btn.pack(side='left', padx=5)
        
        self.et_deauth_var = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl_frame, text="Companion Deauth", variable=self.et_deauth_var,
            font=('Consolas', 9), fg=COLORS['text'], bg=COLORS['bg_panel'],
            selectcolor=COLORS['bg_input'], activebackground=COLORS['bg_panel']).pack(side='left', padx=20)
        
        # Captured Credentials
        creds_frame = tk.LabelFrame(tab, text=" Captured Credentials ",
            bg=COLORS['bg_panel'], fg=COLORS['accent'], font=('Consolas', 10))
        creds_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        columns = ('time', 'ip', 'password', 'extra')
        self.creds_tree = ttk.Treeview(creds_frame, columns=columns, show='headings', height=8)
        
        self.creds_tree.heading('time', text='Time')
        self.creds_tree.heading('ip', text='Client IP')
        self.creds_tree.heading('password', text='Password')
        self.creds_tree.heading('extra', text='Extra Data')
        
        self.creds_tree.column('time', width=120)
        self.creds_tree.column('ip', width=120)
        self.creds_tree.column('password', width=200)
        self.creds_tree.column('extra', width=200)
        
        self.creds_tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Export button
        tk.Button(creds_frame, text="💾 Export Credentials", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.export_credentials,
            relief='flat', padx=10).pack(pady=5)
        
    def create_log_tab(self):
        """Create logs tab"""
        tab = tk.Frame(self.notebook, bg=COLORS['bg_dark'])
        self.notebook.add(tab, text=" 📋 Logs ")
        
        # Log controls
        ctrl_frame = tk.Frame(tab, bg=COLORS['bg_panel'])
        ctrl_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Button(ctrl_frame, text="Clear", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.clear_logs,
            relief='flat', padx=10).pack(side='left', padx=5, pady=5)
        
        tk.Button(ctrl_frame, text="Save Logs", font=('Consolas', 9),
            bg=COLORS['bg_input'], fg=COLORS['text'], command=self.save_logs,
            relief='flat', padx=10).pack(side='left', padx=5, pady=5)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(tab, 
            font=('Consolas', 9), bg=COLORS['bg_input'], fg=COLORS['text'],
            insertbackground=COLORS['text'], wrap='word')
        self.log_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Configure tags
        self.log_text.tag_configure('info', foreground=COLORS['text'])
        self.log_text.tag_configure('success', foreground=COLORS['success'])
        self.log_text.tag_configure('error', foreground=COLORS['error'])
        self.log_text.tag_configure('warning', foreground=COLORS['warning'])
        self.log_text.tag_configure('accent', foreground=COLORS['accent'])
        
    # ========================================================================
    # UTILITY METHODS
    # ========================================================================
    
    def log(self, message: str, tag: str = 'info'):
        """Add message to log"""
        timestamp = get_timestamp()
        self.log_text.insert('end', f"[{timestamp}] {message}\n", tag)
        self.log_text.see('end')
        
    def update_status(self, message: str):
        """Update status bar"""
        self.status_var.set(message)
    
    def show_activity(self, message: str = "Processing..."):
        """Show activity indicator"""
        self.activity_var.set("▶")
        self.status_var.set(message)
        self.progress.configure(value=0)
        self.progress_pct.set("0%")
        self.root.update_idletasks()
    
    def hide_activity(self, message: str = "Ready"):
        """Hide activity indicator"""
        self.activity_var.set("")
        self.status_var.set(message)
        self.progress.configure(value=0)
        self.progress_pct.set("")
        self.root.update_idletasks()
    
    def update_progress(self, value: float, message: str = None):
        """Update progress bar with percentage"""
        value = min(100, max(0, value))  # Clamp to 0-100
        self.progress.configure(value=value)
        self.progress_pct.set(f"{int(value)}%")
        if message:
            self.status_var.set(message)
        self.root.update_idletasks()
        
    def check_environment(self):
        """Check root and dependencies"""
        self.log("=" * 60, 'accent')
        self.log("PyAirgeddon - Wireless Security Auditing Tool", 'accent')
        self.log("=" * 60, 'accent')
        
        # Check root
        if not os.name == 'nt' and not check_root():
            self.log("[!] WARNING: Not running as root. Many features will fail.", 'warning')
        else:
            self.log("[+] Running with root privileges", 'success')
        
        # Check dependencies
        deps = check_dependencies()
        self.log("\n[*] Dependency Check:", 'info')
        for tool, available in deps.items():
            status = "✓" if available else "✗"
            tag = 'success' if available else 'error'
            self.log(f"    {status} {tool}", tag)
        
        # Refresh interfaces
        self.refresh_interfaces()
        
    def refresh_interfaces(self):
        """Refresh wireless interfaces list"""
        interfaces = self.interface_mgr.refresh_interfaces()
        self.iface_combo['values'] = interfaces
        
        if interfaces:
            self.iface_combo.current(0)
            self.on_interface_select(None)
            self.log(f"\n[*] Found {len(interfaces)} wireless interface(s)", 'info')
        else:
            self.log("\n[!] No wireless interfaces found", 'error')
            
    def on_interface_select(self, event):
        """Handle interface selection"""
        iface = self.iface_combo.get()
        if iface:
            self.current_interface = iface
            info = self.interface_mgr.interfaces.get(iface, {})
            mode = info.get('mode', 'unknown')
            
            if mode == 'monitor':
                self.mode_btn.configure(text="Disable Monitor", bg=COLORS['success'])
            else:
                self.mode_btn.configure(text="Enable Monitor", bg=COLORS['bg_panel'])
                
            self.log(f"[*] Selected interface: {iface} ({mode} mode)", 'info')
            
    def toggle_monitor_mode(self):
        """Toggle monitor mode on current interface"""
        if not self.current_interface:
            return
            
        info = self.interface_mgr.interfaces.get(self.current_interface, {})
        
        if info.get('mode') == 'monitor':
            threading.Thread(target=self._disable_monitor, daemon=True).start()
        else:
            threading.Thread(target=self._enable_monitor, daemon=True).start()
            
    def _enable_monitor(self):
        """Enable monitor mode (threaded)"""
        success, result = self.interface_mgr.set_monitor_mode(
            self.current_interface, log_callback=self.log)
        if success:
            self.current_interface = result
            self.root.after(0, self.refresh_interfaces)
            
    def _disable_monitor(self):
        """Disable monitor mode (threaded)"""
        success, result = self.interface_mgr.set_managed_mode(
            self.current_interface, log_callback=self.log)
        if success:
            self.root.after(0, self.refresh_interfaces)
            
    def on_network_select(self, event):
        """Handle network selection from tree"""
        selection = self.network_tree.selection()
        if selection:
            item = self.network_tree.item(selection[0])
            values = item['values']
            
            # Find the network object
            for net in self.networks:
                if net.bssid == values[1]:
                    self.selected_network = net
                    self.target_info.configure(
                        text=f"SSID: {net.ssid or '<Hidden>'}  |  BSSID: {net.bssid}  |  "
                             f"CH: {net.channel}  |  ENC: {net.encryption}",
                        fg=COLORS['accent']
                    )
                    self.et_ssid.delete(0, 'end')
                    self.et_ssid.insert(0, net.ssid)
                    self.et_channel.delete(0, 'end')
                    self.et_channel.insert(0, str(net.channel))
                    break
                    
    # ========================================================================
    # SCAN METHODS
    # ========================================================================
    
    def start_scan(self):
        """Start network scanning"""
        if not self.current_interface:
            messagebox.showwarning("Warning", "Please select an interface first")
            return
            
        channel = self.channel_var.get()
        ch = 0 if channel == 'All' else int(channel)
        
        self.scanner = NetworkScanner(self.current_interface)
        self.scanner.start_scan(
            channel=ch,
            callback=self.update_network_list,
            log_callback=self.log
        )
        
        self.scan_btn.configure(state='disabled')
        self.stop_scan_btn.configure(state='normal')
        self.show_activity("Scanning networks...")
        
    def stop_scan(self):
        """Stop network scanning"""
        if self.scanner:
            self.scanner.stop_scan(log_callback=self.log)
            
        self.scan_btn.configure(state='normal')
        self.stop_scan_btn.configure(state='disabled')
        self.hide_activity("Scan stopped")
        
    def update_network_list(self, networks, clients):
        """Update network tree with scan results"""
        self.networks = networks
        
        def update():
            # Clear tree
            for item in self.network_tree.get_children():
                self.network_tree.delete(item)
            
            # Add networks
            for net in networks:
                self.network_tree.insert('', 'end', values=(
                    net.ssid or '<Hidden>',
                    net.bssid,
                    net.channel,
                    net.signal,
                    net.encryption,
                    len(net.clients)
                ))
            
            self.update_status(f"Found {len(networks)} networks, {len(clients)} clients")
        
        self.root.after(0, update)
        
    # ========================================================================
    # ATTACK METHODS
    # ========================================================================
    
    def toggle_deauth(self):
        """Toggle deauth attack"""
        if self.deauth_attack and self.deauth_attack.running:
            self.deauth_attack.stop(log_callback=self.log)
            self.deauth_attack = None
            self.deauth_btn.configure(text="▶ Start Deauth", bg=COLORS['warning'])
            self.hide_activity("Deauth stopped")
        else:
            if not self.selected_network:
                messagebox.showwarning("Warning", "Select a target network first")
                return
                
            self.deauth_attack = DeauthAttack(self.current_interface)
            client = self.deauth_client.get() or None
            if client == "FF:FF:FF:FF:FF:FF":
                client = None
                
            self.deauth_attack.start(
                self.selected_network.bssid,
                client_mac=client,
                log_callback=self.log
            )
            self.deauth_btn.configure(text="■ Stop Deauth", bg=COLORS['success'])
            self.show_activity("Deauth attack running...")
            
    def beacon_flood(self):
        """Start beacon flood attack"""
        self.dos_attack = DoSAttack(self.current_interface)
        self.dos_attack.beacon_flood(log_callback=self.log)
        self.dos_stop_btn.configure(state='normal')
        self.show_activity("Beacon flood running...")
        
    def auth_flood(self):
        """Start auth flood attack"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        self.dos_attack = DoSAttack(self.current_interface)
        self.dos_attack.auth_flood(self.selected_network.bssid, log_callback=self.log)
        self.dos_stop_btn.configure(state='normal')
        self.show_activity("Auth flood running...")
        
    def stop_dos(self):
        """Stop DoS attack"""
        if self.dos_attack:
            self.dos_attack.stop(log_callback=self.log)
            self.dos_attack = None
        self.dos_stop_btn.configure(state='disabled')
        self.hide_activity("DoS stopped")
        
    def pixie_dust(self):
        """Run Pixie Dust attack"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        def run():
            self.wps_attack = WPSAttack(self.current_interface)
            result = self.wps_attack.pixie_dust(
                self.selected_network.bssid,
                self.selected_network.channel,
                log_callback=self.log
            )
            if result.success:
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"PIN: {result.pin}\nPSK: {result.psk}"))
                    
        threading.Thread(target=run, daemon=True).start()
        
    def wps_bruteforce(self):
        """Run WPS brute force"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        def run():
            self.wps_attack = WPSAttack(self.current_interface)
            result = self.wps_attack.brute_force_pin(
                self.selected_network.bssid,
                self.selected_network.channel,
                log_callback=self.log,
                progress_callback=lambda p: self.root.after(0, 
                    lambda: self.progress.configure(value=p))
            )
            
        threading.Thread(target=run, daemon=True).start()
        
    def try_custom_pin(self):
        """Try custom WPS PIN"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        pin = self.custom_pin.get()
        if not pin or len(pin) != 8:
            messagebox.showwarning("Warning", "PIN must be 8 digits")
            return
            
        def run():
            self.wps_attack = WPSAttack(self.current_interface)
            result = self.wps_attack.custom_pin(
                self.selected_network.bssid,
                self.selected_network.channel,
                pin,
                log_callback=self.log
            )
            if result.success:
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"PSK: {result.psk}"))
                    
        threading.Thread(target=run, daemon=True).start()
        
    def capture_handshake(self):
        """Capture WPA handshake"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        def run():
            from pyairgeddon_core import HandshakeCapture
            capture = HandshakeCapture(self.current_interface)
            result = capture.capture_handshake(
                self.selected_network.bssid,
                self.selected_network.channel,
                log_callback=self.log,
                progress_callback=lambda e, t: self.root.after(0,
                    lambda: self.progress.configure(value=(e/t)*100))
            )
            if result.success:
                self.capture_file_entry.delete(0, 'end')
                self.capture_file_entry.insert(0, result.file_path)
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"Handshake saved to:\n{result.file_path}"))
                    
        threading.Thread(target=run, daemon=True).start()
        
    def capture_pmkid(self):
        """Capture PMKID"""
        if not self.selected_network:
            messagebox.showwarning("Warning", "Select a target network first")
            return
            
        def run():
            from pyairgeddon_core import HandshakeCapture
            capture = HandshakeCapture(self.current_interface)
            result = capture.capture_pmkid(
                self.selected_network.bssid,
                self.selected_network.channel,
                log_callback=self.log
            )
            if result.success:
                self.capture_file_entry.delete(0, 'end')
                self.capture_file_entry.insert(0, result.file_path)
                    
        threading.Thread(target=run, daemon=True).start()
        
    # ========================================================================
    # CRACKER METHODS
    # ========================================================================
    
    def browse_capture(self):
        """Browse for capture file"""
        path = filedialog.askopenfilename(
            filetypes=[("Capture files", "*.cap *.pcap *.22000 *.hccapx"), ("All", "*.*")]
        )
        if path:
            self.capture_file_entry.delete(0, 'end')
            self.capture_file_entry.insert(0, path)
            
    def browse_wordlist(self):
        """Browse for wordlist"""
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All", "*.*")]
        )
        if path:
            self.wordlist_entry.delete(0, 'end')
            self.wordlist_entry.insert(0, path)
            
    def start_dict_attack(self):
        """Start dictionary attack"""
        capture = self.capture_file_entry.get()
        wordlist = self.wordlist_entry.get()
        
        if not capture or not os.path.exists(capture):
            messagebox.showwarning("Warning", "Select a valid capture file")
            return
        if not wordlist or not os.path.exists(wordlist):
            messagebox.showwarning("Warning", "Select a valid wordlist")
            return
            
        def run():
            self.dict_attack = DictionaryAttack()
            result = self.dict_attack.crack(
                capture, wordlist,
                log_callback=self.log,
                progress_callback=lambda p, a, t: self.root.after(0, lambda: (
                    self.progress.configure(value=p),
                    self.crack_status.configure(text=f"Tried: {a:,} / {t:,}")
                ))
            )
            if result.success:
                self.root.after(0, lambda: (
                    self.crack_status.configure(text=f"PASSWORD: {result.password}",
                        fg=COLORS['success']),
                    messagebox.showinfo("Success", f"Password: {result.password}")
                ))
                
        self.dict_btn.configure(state='disabled')
        threading.Thread(target=run, daemon=True).start()
        
    def start_bruteforce(self):
        """Start brute force attack"""
        capture = self.capture_file_entry.get()
        if not capture or not os.path.exists(capture):
            messagebox.showwarning("Warning", "Select a valid capture file")
            return
            
        charset = self.charset_combo.get()
        min_l = int(self.min_len.get())
        max_l = int(self.max_len.get())
        
        def run():
            bf = BruteForceAttack()
            result = bf.crack(
                capture, charset=charset,
                min_len=min_l, max_len=max_l,
                log_callback=self.log,
                progress_callback=lambda p, a, t: self.root.after(0, lambda: (
                    self.progress.configure(value=p),
                    self.crack_status.configure(text=f"Tried: {a:,}")
                ))
            )
            if result.success:
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"Password: {result.password}"))
                    
        threading.Thread(target=run, daemon=True).start()
        
    def convert_hashcat(self):
        """Convert capture to hashcat format"""
        capture = self.capture_file_entry.get()
        if not capture:
            messagebox.showwarning("Warning", "Select a capture file first")
            return
            
        def run():
            hc = HashcatCracker()
            result = hc.convert_to_hashcat(capture, log_callback=self.log)
            if result:
                self.root.after(0, lambda: (
                    self.capture_file_entry.delete(0, 'end'),
                    self.capture_file_entry.insert(0, result)
                ))
                
        threading.Thread(target=run, daemon=True).start()
        
    def run_hashcat(self):
        """Run Hashcat attack"""
        capture = self.capture_file_entry.get()
        wordlist = self.wordlist_entry.get()
        
        if not capture:
            messagebox.showwarning("Warning", "Select a capture/hash file")
            return
            
        def run():
            hc = HashcatCracker()
            result = hc.crack(
                capture, wordlist,
                log_callback=self.log,
                progress_callback=lambda p: self.root.after(0,
                    lambda: self.progress.configure(value=p))
            )
            if result.success:
                self.root.after(0, lambda: messagebox.showinfo("Success",
                    f"Password: {result.password}"))
                    
        threading.Thread(target=run, daemon=True).start()
        
    def hashcat_benchmark(self):
        """Run Hashcat benchmark"""
        def run():
            hc = HashcatCracker()
            hc.benchmark(log_callback=self.log)
            
        threading.Thread(target=run, daemon=True).start()
        
    # ========================================================================
    # EVIL TWIN METHODS
    # ========================================================================
    
    def copy_ssid_from_scan(self):
        """Copy SSID from selected network"""
        if self.selected_network:
            self.et_ssid.delete(0, 'end')
            self.et_ssid.insert(0, self.selected_network.ssid)
            self.et_channel.delete(0, 'end')
            self.et_channel.insert(0, str(self.selected_network.channel))
            
    def start_evil_twin(self):
        """Start Evil Twin attack"""
        ssid = self.et_ssid.get()
        if not ssid:
            messagebox.showwarning("Warning", "Enter target SSID")
            return
            
        channel = int(self.et_channel.get())
        template = self.et_template.get()
        
        def run():
            self.evil_twin = EvilTwinAP(self.current_interface)
            success = self.evil_twin.start(
                ssid, channel, template,
                log_callback=self.log
            )
            if success:
                self.root.after(0, lambda: (
                    self.et_start_btn.configure(state='disabled'),
                    self.et_stop_btn.configure(state='normal')
                ))
                
                # Start credential polling
                def poll_creds():
                    while self.evil_twin and self.evil_twin.running:
                        creds = self.evil_twin.get_credentials()
                        self.root.after(0, lambda c=creds: self.update_creds_tree(c))
                        threading.Event().wait(2)
                        
                threading.Thread(target=poll_creds, daemon=True).start()
                
        threading.Thread(target=run, daemon=True).start()
        
    def stop_evil_twin(self):
        """Stop Evil Twin"""
        if self.evil_twin:
            self.evil_twin.stop(log_callback=self.log)
            self.evil_twin = None
            
        self.et_start_btn.configure(state='normal')
        self.et_stop_btn.configure(state='disabled')
        
    def update_creds_tree(self, creds):
        """Update credentials tree"""
        # Clear
        for item in self.creds_tree.get_children():
            self.creds_tree.delete(item)
            
        # Add credentials
        for cred in creds:
            extra = ", ".join(f"{k}={v}" for k, v in cred.extra_fields.items())
            self.creds_tree.insert('', 'end', values=(
                cred.timestamp, cred.client_ip, cred.password, extra
            ))
            
    def export_credentials(self):
        """Export captured credentials"""
        if not self.evil_twin:
            messagebox.showwarning("Warning", "No Evil Twin session active")
            return
            
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        if path:
            self.evil_twin.save_credentials(path, log_callback=self.log)
            
    # ========================================================================
    # LOG METHODS
    # ========================================================================
    
    def clear_logs(self):
        """Clear log text"""
        self.log_text.delete('1.0', 'end')
        
    def save_logs(self):
        """Save logs to file"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")]
        )
        if path:
            with open(path, 'w') as f:
                f.write(self.log_text.get('1.0', 'end'))
            self.log(f"[+] Logs saved to {path}", 'success')


# ============================================================================
# MAIN
# ============================================================================

def main():
    """Main entry point with splash screen"""
    import time
    
    def initialize(splash):
        """Initialize application with splash screen progress"""
        try:
            splash.update_progress(10, "Checking root privileges...")
            time.sleep(0.3)
            
            splash.update_progress(25, "Checking dependencies...")
            deps = check_dependencies()
            time.sleep(0.3)
            
            splash.update_progress(50, "Detecting wireless interfaces...")
            time.sleep(0.3)
            
            splash.update_progress(75, "Loading attack modules...")
            time.sleep(0.3)
            
            splash.update_progress(90, "Initializing GUI...")
            time.sleep(0.2)
            
            splash.update_progress(100, "Ready!")
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[!] Initialization error: {e}")
        finally:
            splash.close()
        
        # Launch main GUI
        root = tk.Tk()
        try:
            root.iconbitmap('pyairgeddon.ico')
        except:
            pass
        
        app = PyAirgeddonGUI(root)
        root.mainloop()
    
    # Show splash screen
    print("\n[*] Starting PyAirgeddon...")
    splash = SplashScreen()
    splash.run(initialize)


if __name__ == "__main__":
    main()

