#!/usr/bin/env python3
"""
PyAirgeddon External Tools Installer
Automatically installs required system tools for wireless security auditing

Usage:
    python install_tools.py           # Interactive installation
    python install_tools.py --check   # Check tool availability only
    python install_tools.py --all     # Install all tools (requires sudo)
"""

import subprocess
import sys
import os
import shutil
import platform
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from enum import Enum


# ============================================================================
# CONSTANTS AND CONFIGURATION
# ============================================================================

class Color:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    
    @staticmethod
    def supports_color() -> bool:
        """Check if terminal supports color"""
        if os.name == 'nt':
            return os.environ.get('TERM') or 'ANSICON' in os.environ
        return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


class PackageManager(Enum):
    """Supported package managers"""
    APT = 'apt'           # Debian/Ubuntu
    DNF = 'dnf'           # Fedora/RHEL 8+
    YUM = 'yum'           # CentOS/RHEL 7
    PACMAN = 'pacman'     # Arch Linux
    BREW = 'brew'         # macOS
    UNKNOWN = 'unknown'


@dataclass
class ToolInfo:
    """Information about an external tool"""
    name: str
    description: str
    check_cmd: str                      # Command to check if installed
    packages: Dict[str, str]            # Package manager -> package name
    optional: bool = False              # If False, tool is required
    windows_note: str = ""              # Note for Windows users


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

REQUIRED_TOOLS: List[ToolInfo] = [
    ToolInfo(
        name='airmon-ng',
        description='Wireless interface monitor mode control',
        check_cmd='airmon-ng --help',
        packages={
            'apt': 'aircrack-ng',
            'dnf': 'aircrack-ng',
            'yum': 'aircrack-ng',
            'pacman': 'aircrack-ng',
            'brew': 'aircrack-ng'
        },
        windows_note='Part of aircrack-ng suite. Windows: Use WSL or Kali Linux VM.'
    ),
    ToolInfo(
        name='airodump-ng',
        description='Wireless network scanner and packet capture',
        check_cmd='airodump-ng --help',
        packages={
            'apt': 'aircrack-ng',
            'dnf': 'aircrack-ng',
            'yum': 'aircrack-ng',
            'pacman': 'aircrack-ng',
            'brew': 'aircrack-ng'
        }
    ),
    ToolInfo(
        name='aireplay-ng',
        description='Packet injection and deauthentication attacks',
        check_cmd='aireplay-ng --help',
        packages={
            'apt': 'aircrack-ng',
            'dnf': 'aircrack-ng',
            'yum': 'aircrack-ng',
            'pacman': 'aircrack-ng',
            'brew': 'aircrack-ng'
        }
    ),
    ToolInfo(
        name='aircrack-ng',
        description='WEP/WPA-PSK password cracker',
        check_cmd='aircrack-ng --help',
        packages={
            'apt': 'aircrack-ng',
            'dnf': 'aircrack-ng',
            'yum': 'aircrack-ng',
            'pacman': 'aircrack-ng',
            'brew': 'aircrack-ng'
        },
        windows_note='Available for Windows. Download from: https://www.aircrack-ng.org/'
    ),
    ToolInfo(
        name='iw',
        description='Wireless configuration tool',
        check_cmd='iw --version',
        packages={
            'apt': 'iw',
            'dnf': 'iw',
            'yum': 'iw',
            'pacman': 'iw',
            'brew': ''  # Not available on macOS
        },
        windows_note='Linux-only tool. Not required on Windows.'
    ),
]

OPTIONAL_TOOLS: List[ToolInfo] = [
    ToolInfo(
        name='hostapd',
        description='Access point daemon for Evil Twin attacks',
        check_cmd='hostapd -v',
        packages={
            'apt': 'hostapd',
            'dnf': 'hostapd',
            'yum': 'hostapd',
            'pacman': 'hostapd',
            'brew': ''
        },
        optional=True,
        windows_note='Linux-only. Required for Evil Twin functionality.'
    ),
    ToolInfo(
        name='dnsmasq',
        description='DHCP/DNS server for Evil Twin attacks',
        check_cmd='dnsmasq --version',
        packages={
            'apt': 'dnsmasq',
            'dnf': 'dnsmasq',
            'yum': 'dnsmasq',
            'pacman': 'dnsmasq',
            'brew': 'dnsmasq'
        },
        optional=True
    ),
    ToolInfo(
        name='hcxdumptool',
        description='PMKID capture tool',
        check_cmd='hcxdumptool --version',
        packages={
            'apt': 'hcxdumptool',
            'dnf': 'hcxdumptool',
            'yum': '',
            'pacman': 'hcxtools',
            'brew': ''
        },
        optional=True,
        windows_note='Linux-only. For PMKID attacks.'
    ),
    ToolInfo(
        name='hcxpcapngtool',
        description='PCAP to hashcat format converter',
        check_cmd='hcxpcapngtool --version',
        packages={
            'apt': 'hcxtools',
            'dnf': 'hcxtools',
            'yum': '',
            'pacman': 'hcxtools',
            'brew': ''
        },
        optional=True
    ),
    ToolInfo(
        name='hashcat',
        description='GPU-accelerated password cracker',
        check_cmd='hashcat --version',
        packages={
            'apt': 'hashcat',
            'dnf': 'hashcat',
            'yum': 'hashcat',
            'pacman': 'hashcat',
            'brew': 'hashcat'
        },
        optional=True,
        windows_note='Available for Windows. Download from: https://hashcat.net/hashcat/'
    ),
    ToolInfo(
        name='reaver',
        description='WPS brute force attack tool',
        check_cmd='reaver --help',
        packages={
            'apt': 'reaver',
            'dnf': 'reaver',
            'yum': '',
            'pacman': 'reaver',
            'brew': ''
        },
        optional=True
    ),
    ToolInfo(
        name='bully',
        description='Alternative WPS attack tool',
        check_cmd='bully --help',
        packages={
            'apt': 'bully',
            'dnf': '',
            'yum': '',
            'pacman': 'bully',
            'brew': ''
        },
        optional=True
    ),
    ToolInfo(
        name='mdk4',
        description='Wireless attack tool for DoS attacks',
        check_cmd='mdk4 --help',
        packages={
            'apt': 'mdk4',
            'dnf': '',
            'yum': '',
            'pacman': 'mdk4',
            'brew': ''
        },
        optional=True
    ),
    ToolInfo(
        name='hostapd-mana',
        description='Modified hostapd for MANA/Karma attacks',
        check_cmd='hostapd-mana -v',
        packages={
            'apt': 'hostapd-mana',
            'dnf': '',
            'yum': '',
            'pacman': '',
            'brew': ''
        },
        optional=True,
        windows_note='Linux-only. Build from: https://github.com/sensepost/hostapd-mana'
    ),
    ToolInfo(
        name='macchanger',
        description='MAC address spoofing utility',
        check_cmd='macchanger --version',
        packages={
            'apt': 'macchanger',
            'dnf': 'macchanger',
            'yum': '',
            'pacman': 'macchanger',
            'brew': ''
        },
        optional=True
    ),
    ToolInfo(
        name='kismet',
        description='Wireless network detector and WIDS',
        check_cmd='kismet --version',
        packages={
            'apt': 'kismet',
            'dnf': 'kismet',
            'yum': '',
            'pacman': 'kismet',
            'brew': 'kismet'
        },
        optional=True
    ),
    ToolInfo(
        name='wifite',
        description='Automated wireless attack script',
        check_cmd='wifite --help',
        packages={
            'apt': 'wifite',
            'dnf': '',
            'yum': '',
            'pacman': 'wifite',
            'brew': ''
        },
        optional=True
    ),
]




# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_colored(text: str, color: str = '', bold: bool = False) -> None:
    """Print colored text if supported"""
    if Color.supports_color():
        prefix = Color.BOLD if bold else ''
        print(f"{prefix}{color}{text}{Color.RESET}")
    else:
        print(text)


def print_header(text: str) -> None:
    """Print section header"""
    print()
    print_colored("=" * 60, Color.CYAN)
    print_colored(f"  {text}", Color.CYAN, bold=True)
    print_colored("=" * 60, Color.CYAN)
    print()


def print_status(name: str, status: bool, message: str = '') -> None:
    """Print tool status"""
    icon = "✓" if status else "✗"
    color = Color.GREEN if status else Color.RED
    status_text = f"  [{icon}] {name:20}"
    if message:
        status_text += f" - {message}"
    print_colored(status_text, color)


def detect_package_manager() -> PackageManager:
    """Detect the system's package manager"""
    if os.name == 'nt':
        return PackageManager.UNKNOWN
    
    # Check for each package manager
    pm_commands = {
        PackageManager.APT: 'apt',
        PackageManager.DNF: 'dnf',
        PackageManager.YUM: 'yum',
        PackageManager.PACMAN: 'pacman',
        PackageManager.BREW: 'brew',
    }
    
    for pm, cmd in pm_commands.items():
        if shutil.which(cmd):
            return pm
    
    return PackageManager.UNKNOWN


def is_root() -> bool:
    """Check if running as root/admin"""
    if os.name == 'nt':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0


def check_tool_installed(tool: ToolInfo) -> Tuple[bool, str]:
    """
    Check if a tool is installed
    Returns: (is_installed, version_or_error)
    """
    # First try shutil.which for simpler check
    tool_path = shutil.which(tool.name)
    if tool_path:
        # Try to get version
        try:
            result = subprocess.run(
                tool.check_cmd.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            # Extract version from output
            output = result.stdout + result.stderr
            if 'version' in output.lower():
                for line in output.split('\n'):
                    if 'version' in line.lower() or tool.name in line.lower():
                        return True, line.strip()[:50]
            return True, f"Found at {tool_path}"
        except:
            return True, f"Found at {tool_path}"
    
    # Alternative check using 'which' on Linux
    if os.name != 'nt':
        try:
            result = subprocess.run(
                ['which', tool.name],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, result.stdout.strip()
        except:
            pass
    
    return False, "Not installed"


def get_install_command(tool: ToolInfo, pm: PackageManager) -> Optional[str]:
    """Get the installation command for a tool"""
    package = tool.packages.get(pm.value, '')
    if not package:
        return None
    
    commands = {
        PackageManager.APT: f'sudo apt install -y {package}',
        PackageManager.DNF: f'sudo dnf install -y {package}',
        PackageManager.YUM: f'sudo yum install -y {package}',
        PackageManager.PACMAN: f'sudo pacman -S --noconfirm {package}',
        PackageManager.BREW: f'brew install {package}',
    }
    
    return commands.get(pm)


def install_tool(tool: ToolInfo, pm: PackageManager, 
                 log_callback: Optional[Callable] = None) -> bool:
    """
    Install a tool using the system package manager
    Returns: success status
    """
    def log(msg: str):
        if log_callback:
            log_callback(msg)
        else:
            print(msg)
    
    cmd = get_install_command(tool, pm)
    if not cmd:
        log(f"  [!] No package available for {tool.name} on {pm.value}")
        return False
    
    log(f"  [*] Installing {tool.name}...")
    log(f"      Command: {cmd}")
    
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            log(f"  [+] {tool.name} installed successfully!")
            return True
        else:
            log(f"  [-] Failed to install {tool.name}")
            if result.stderr:
                log(f"      Error: {result.stderr[:200]}")
            return False
            
    except subprocess.TimeoutExpired:
        log(f"  [-] Installation timed out for {tool.name}")
        return False
    except Exception as e:
        log(f"  [-] Error installing {tool.name}: {e}")
        return False


# ============================================================================
# MAIN INSTALLER CLASS
# ============================================================================

class ExternalToolInstaller:
    """
    Manages detection and installation of external tools
    """
    
    def __init__(self, log_callback: Optional[Callable] = None):
        self.log_callback = log_callback
        self.package_manager = detect_package_manager()
        self.is_windows = os.name == 'nt'
        self.is_linux = sys.platform.startswith('linux')
        self.is_macos = sys.platform == 'darwin'
        
    def log(self, message: str, color: str = '') -> None:
        """Log a message"""
        if self.log_callback:
            self.log_callback(message)
        else:
            print_colored(message, color)
    
    def check_all(self) -> Dict[str, Tuple[bool, str]]:
        """
        Check all tools and return their status
        Returns: {tool_name: (is_installed, version_or_path)}
        """
        results = {}
        
        print_header("PyAirgeddon - External Tools Check")
        
        # System info
        self.log(f"  Platform: {platform.system()} {platform.release()}")
        self.log(f"  Package Manager: {self.package_manager.value}")
        self.log(f"  Running as root: {is_root()}")
        print()
        
        # Required tools
        self.log("Required Tools:", Color.YELLOW)
        for tool in REQUIRED_TOOLS:
            installed, info = check_tool_installed(tool)
            results[tool.name] = (installed, info)
            print_status(tool.name, installed, info if installed else tool.description)
            
            if not installed and self.is_windows and tool.windows_note:
                print_colored(f"      Note: {tool.windows_note}", Color.BLUE)
        
        print()
        
        # Optional tools
        self.log("Optional Tools:", Color.YELLOW)
        for tool in OPTIONAL_TOOLS:
            installed, info = check_tool_installed(tool)
            results[tool.name] = (installed, info)
            print_status(tool.name, installed, info if installed else tool.description)
            
            if not installed and self.is_windows and tool.windows_note:
                print_colored(f"      Note: {tool.windows_note}", Color.BLUE)
        
        # Summary
        print()
        required_ok = sum(1 for t in REQUIRED_TOOLS if results.get(t.name, (False,))[0])
        optional_ok = sum(1 for t in OPTIONAL_TOOLS if results.get(t.name, (False,))[0])
        
        self.log(f"Summary: {required_ok}/{len(REQUIRED_TOOLS)} required, "
                f"{optional_ok}/{len(OPTIONAL_TOOLS)} optional tools installed")
        
        return results
    
    def install_missing(self, required_only: bool = False, 
                        interactive: bool = True) -> bool:
        """
        Install missing tools
        Args:
            required_only: If True, only install required tools
            interactive: If True, ask before each installation
        Returns: success status
        """
        if self.is_windows:
            print_header("Windows Detected")
            self.log("External tool installation requires Linux or WSL.", Color.YELLOW)
            self.log("For Windows, please:")
            self.log("  1. Install WSL2 with Kali Linux or Ubuntu")
            self.log("  2. Or use a Linux VM")
            self.log("  3. Download Windows-compatible tools manually:")
            self.log("     - Aircrack-ng: https://www.aircrack-ng.org/")
            self.log("     - Hashcat: https://hashcat.net/hashcat/")
            return False
        
        if self.package_manager == PackageManager.UNKNOWN:
            self.log("Could not detect package manager!", Color.RED)
            return False
        
        if not is_root() and self.package_manager != PackageManager.BREW:
            self.log("Warning: Installation may require sudo privileges.", Color.YELLOW)
        
        print_header("Installing Missing Tools")
        
        tools_to_install = REQUIRED_TOOLS if required_only else REQUIRED_TOOLS + OPTIONAL_TOOLS
        
        # Collect unique packages to install
        packages_to_install: Dict[str, List[str]] = {}  # package -> [tools]
        
        for tool in tools_to_install:
            installed, _ = check_tool_installed(tool)
            if not installed:
                package = tool.packages.get(self.package_manager.value, '')
                if package:
                    if package not in packages_to_install:
                        packages_to_install[package] = []
                    packages_to_install[package].append(tool.name)
        
        if not packages_to_install:
            self.log("All tools are already installed!", Color.GREEN)
            return True
        
        self.log(f"Packages to install: {', '.join(packages_to_install.keys())}")
        print()
        
        if interactive:
            response = input("Proceed with installation? [Y/n]: ").strip().lower()
            if response and response not in ('y', 'yes'):
                self.log("Installation cancelled.")
                return False
        
        # Install packages
        success_count = 0
        for package, tools in packages_to_install.items():
            self.log(f"\n[*] Installing {package} (provides: {', '.join(tools)})...")
            
            # Create a dummy tool info for installation
            dummy_tool = ToolInfo(
                name=package,
                description='',
                check_cmd='',
                packages={self.package_manager.value: package}
            )
            
            if install_tool(dummy_tool, self.package_manager, self.log_callback):
                success_count += 1
        
        print()
        self.log(f"Installation complete: {success_count}/{len(packages_to_install)} packages")
        
        return success_count == len(packages_to_install)
    
    def generate_install_script(self, output_path: str = 'install_deps.sh') -> str:
        """
        Generate a shell script to install all dependencies
        Returns: path to generated script
        """
        if self.package_manager == PackageManager.UNKNOWN:
            self.log("Cannot generate script: unknown package manager", Color.RED)
            return ''
        
        packages = set()
        for tool in REQUIRED_TOOLS + OPTIONAL_TOOLS:
            pkg = tool.packages.get(self.package_manager.value, '')
            if pkg:
                packages.add(pkg)
        
        install_cmds = {
            PackageManager.APT: f'apt update && apt install -y {" ".join(packages)}',
            PackageManager.DNF: f'dnf install -y {" ".join(packages)}',
            PackageManager.YUM: f'yum install -y {" ".join(packages)}',
            PackageManager.PACMAN: f'pacman -Sy --noconfirm {" ".join(packages)}',
            PackageManager.BREW: f'brew install {" ".join(packages)}',
        }
        
        script = f'''#!/bin/bash
# PyAirgeddon Dependency Installer
# Generated for: {self.package_manager.value}
# Run with: sudo bash {output_path}

echo "========================================"
echo "  PyAirgeddon Dependency Installer"
echo "========================================"

# Check root
if [ "$EUID" -ne 0 ] && [ "{self.package_manager.value}" != "brew" ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

echo "[*] Installing required packages..."
{install_cmds.get(self.package_manager, '# Unknown package manager')}

echo "[+] Installation complete!"
echo "[*] You can now run: python pyairgeddon.py"
'''
        
        with open(output_path, 'w') as f:
            f.write(script)
        
        os.chmod(output_path, 0o755)
        self.log(f"Generated install script: {output_path}", Color.GREEN)
        
        return output_path


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='PyAirgeddon External Tools Installer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python install_tools.py              # Interactive mode
  python install_tools.py --check      # Check tools only
  python install_tools.py --all        # Install all tools
  python install_tools.py --generate   # Generate install script
        '''
    )
    
    parser.add_argument('--check', action='store_true',
                        help='Check tool availability only')
    parser.add_argument('--all', action='store_true',
                        help='Install all missing tools (non-interactive)')
    parser.add_argument('--required', action='store_true',
                        help='Install only required tools')
    parser.add_argument('--generate', action='store_true',
                        help='Generate installation script')
    
    args = parser.parse_args()
    
    installer = ExternalToolInstaller()
    
    if args.check:
        installer.check_all()
    elif args.generate:
        installer.check_all()
        installer.generate_install_script()
    elif args.all:
        installer.check_all()
        installer.install_missing(required_only=args.required, interactive=False)
    else:
        # Interactive mode
        installer.check_all()
        print()
        
        if os.name != 'nt':
            response = input("Would you like to install missing tools? [Y/n]: ").strip().lower()
            if not response or response in ('y', 'yes'):
                installer.install_missing(interactive=True)


if __name__ == '__main__':
    main()
