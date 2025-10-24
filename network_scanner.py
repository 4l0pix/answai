#!/usr/bin/env python3
"""
A.N.S.W.A.I ===== Advanced Network Scan With Artificial Intelligence

Date: October 24, 2025
"""

import subprocess
import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
import logging
import socket
import threading
from threading import Thread, Lock
import time
import re
import os
import sys
import getpass
from ipaddress import ip_network, ip_address
import argparse
import platform

# Import nmap utilities
from nmaputils import NmapProfileManager, get_nmap_commands, get_fallback_config, ProgressBar

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

CONFIG_FILE = "config.json"


class NetworkScanner:
    def __init__(self, config_file=CONFIG_FILE):
        self.results = []
        self.lock = Lock()
        self.scan_progress = {'scanned': 0, 'total': 0, 'found': 0}
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.csv_file = f"answai_results_{self.timestamp}.csv"
        self.json_file = f"answai_results_{self.timestamp}.json"
        self.has_sudo = False
        self.sudo_password = None
        
        # Color codes for different message types
        self.colors = {
            'red': '\033[91m',      # Errors
            'orange': '\033[93m',   # Warnings  
            'green': '\033[92m',    # Success/Completed
            'blue': '\033[94m',     # Info
            'reset': '\033[0m'      # Reset color
        }
        
        # Initialize nmap configuration manager
        try:
            self.nmap_manager = NmapProfileManager(config_file)
            logger.info(f"Loaded nmap configuration from {config_file}")
        except Exception as e:
            logger.warning(f"Could not load nmap config: {e}, using defaults")
            self.nmap_manager = None
        
        # CSV headers for comprehensive scan results
        self.csv_headers = [
            'IP Address', 'Hostname', 'MAC Address', 'Vendor', 'OS Detection',
            'Open Ports', 'Services', 'Vulnerabilities', 'Response Time',
            'Last Boot', 'Scan Timestamp', 'Status', 'Notes'
        ]
        
        # Progress tracking
        self.current_progress_bar = None
        self.scan_stages = []
        self.current_stage = 0

    def create_progress_bar(self, total, description="Progress"):
        """Create a new progress bar"""
        if self.current_progress_bar:
            self.current_progress_bar.close()
        self.current_progress_bar = ProgressBar(total, description)
        return self.current_progress_bar
        
    def update_progress(self, amount=1):
        """Update current progress bar"""
        if self.current_progress_bar:
            self.current_progress_bar.update(amount)
            
    def close_progress_bar(self):
        """Close current progress bar"""
        if self.current_progress_bar:
            self.current_progress_bar.close()
            self.current_progress_bar = None

    def print_error(self, message):
        """Print error message in red"""
        print(f"{self.colors['red']}{message}{self.colors['reset']}")

    def print_warning(self, message):
        """Print warning message in orange"""
        print(f"{self.colors['orange']}{message}{self.colors['reset']}")

    def print_success(self, message):
        """Print success message in green"""
        print(f"{self.colors['green']}{message}{self.colors['reset']}")

    def print_info(self, message):
        """Print info message in blue"""
        print(f"{self.colors['blue']}{message}{self.colors['reset']}")

    def check_sudo_access(self):
        """Check and handle sudo permissions with fallback mechanisms"""
        self.print_info("\nChecking administrative privileges...")
        
        # Check if running on Windows
        if platform.system() == "Windows":
            try:
                # Check if running as administrator
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if is_admin:
                    self.print_success("SUDO RIGHTS GRANTED--- Running with Administrator privileges")
                    self.has_sudo = True
                    return True
                else:
                    self.print_warning("NO SUDO RIGHTS GRANTED --- Not running as Administrator")
                    self.print_info("For best results, run as Super User/Administrator")
                    self.print_warning("Continuing with limited privileges...")
                    return False
            except:
                self.print_error("Could not determine privilege level.")
                return False
        
        # Unix-like systems (Linux, macOS)
        try:
            # Check if already root
            if os.geteuid() == 0:
                self.print_success("SUDO RIGHTS GRANTED --- Already running as root")
                self.has_sudo = True
                return True
        except AttributeError:
            # Windows doesn't have geteuid
            pass
        
        # Try to get sudo password
        try:
            self.print_info("This script requires sudo privileges for comprehensive scanning.")
            self.print_info("Advanced features like SYN scanning, OS detection, and service enumeration need elevated privileges.")
            
            choice = input("Do you want to provide sudo password? (y/n) [y]: ").strip().lower()
            
            if choice in ['', 'y', 'yes']:
                password = getpass.getpass("Enter sudo password (will be hidden and not stored by this software): ")
                
                # Test sudo access
                test_cmd = ["sudo", "-S", "-p", "", "nmap", "--version"]
                process = subprocess.Popen(
                    test_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                stdout, stderr = process.communicate(input=password + '\n')
                
                if process.returncode == 0:
                    self.print_success("Sudo access verified!")
                    self.has_sudo = True
                    self.sudo_password = password
                    return True
                else:
                    self.print_error("Invalid sudo password or sudo access denied")
                    self.print_warning("Continuing with fallback scanning methods...")
                    return False
            else:
                self.print_warning("Continuing without sudo privileges")
                self.print_warning("Some advanced features will be unavailable")
                return False
                
        except Exception as e:
            logger.error(f"Error checking sudo access: {e}")
            self.print_error("Error checking sudo access, continuing with fallback methods...")
            return False

    def run_command_with_sudo(self, cmd):
        """Run command with sudo if available, otherwise run normally"""
        try:
            if self.has_sudo and self.sudo_password and platform.system() != "Windows":
                # Unix with sudo
                full_cmd = ["sudo", "-S", "-p", ""] + cmd
                process = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                stdout, stderr = process.communicate(input=self.sudo_password + '\n')
                return subprocess.CompletedProcess(full_cmd, process.returncode, stdout, stderr)
            else:
                # No sudo or Windows
                return subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
        except Exception as e:
            logger.error(f"Error running command with sudo: {e}")
            # Fallback to normal execution
            return subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    def run_command_with_sudo_with_progress(self, cmd, timeout=300, scan_name="scan"):
        """Run command with sudo and show progress during execution"""
        try:
            if self.has_sudo and self.sudo_password and platform.system() != "Windows":
                # Unix with sudo
                full_cmd = ["sudo", "-S", "-p", ""] + cmd
                process = subprocess.Popen(
                    full_cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Send password
                process.stdin.write(self.sudo_password + '\n')
                process.stdin.flush()
                
                # Monitor progress with timeout
                start_time = time.time()
                while process.poll() is None:
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        process.terminate()
                        raise subprocess.TimeoutExpired(full_cmd, timeout)
                    
                    # Update progress description with elapsed time
                    if self.current_progress_bar:
                        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
                        self.current_progress_bar.set_description(f"{scan_name} (Running {elapsed_str})")
                    
                    time.sleep(0.5)
                
                stdout, stderr = process.communicate()
                return subprocess.CompletedProcess(full_cmd, process.returncode, stdout, stderr)
            else:
                # No sudo or Windows - use regular run with progress monitoring
                start_time = time.time()
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Monitor progress with timeout
                while process.poll() is None:
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        process.terminate()
                        raise subprocess.TimeoutExpired(cmd, timeout)
                    
                    # Update progress description with elapsed time
                    if self.current_progress_bar:
                        elapsed_str = f"{int(elapsed//60):02d}:{int(elapsed%60):02d}"
                        self.current_progress_bar.set_description(f"{scan_name} (Running {elapsed_str})")
                    
                    time.sleep(0.5)
                
                stdout, stderr = process.communicate()
                return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
                
        except Exception as e:
            logger.error(f"Error running command with sudo: {e}")
            # Fallback to normal execution
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def get_network_gateway(self):
        """Automatically detect network gateway"""
        try:
            system = platform.system()
            
            if system == "Windows":
                # Windows: use ipconfig
                result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if 'Default Gateway' in line or 'Standardgateway' in line:
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                gateway = match.group(1)
                                logger.info(f"Detected gateway (Windows): {gateway}")
                                return gateway
                
                # Fallback: route command on Windows
                result = subprocess.run(['route', 'print', '0.0.0.0'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if '0.0.0.0' in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                gateway = parts[2]
                                if re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
                                    logger.info(f"Detected gateway (Windows route): {gateway}")
                                    return gateway
            
            else:
                # Linux/Unix: use ip route
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('default via '):
                            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', line)
                            if match:
                                gateway = match.group(1)
                                logger.info(f"Detected gateway (Linux): {gateway}")
                                return gateway
                
                # Fallback: netstat
                result = subprocess.run(['netstat', '-rn'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.startswith('0.0.0.0') or line.startswith('default'):
                            parts = line.split()
                            if len(parts) >= 2:
                                gateway = parts[1]
                                if re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
                                    logger.info(f"Detected gateway (netstat): {gateway}")
                                    return gateway

            logger.warning("Could not automatically detect gateway")
            return None

        except Exception as e:
            logger.error(f"Error detecting gateway: {e}")
            return None

    def get_local_ip(self):
        """Get local IP address to determine network"""
        try:
            # Connect to a remote address to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                logger.info(f"Detected local IP: {local_ip}")
                return local_ip
        except Exception as e:
            logger.error(f"Error detecting local IP: {e}")
            return None

    def suggest_network_ranges(self):
        """Suggest network ranges based on gateway and local IP"""
        gateway = self.get_network_gateway()
        local_ip = self.get_local_ip()
        
        suggestions = []
        
        if gateway:
            base_ip = '.'.join(gateway.split('.')[:3])
            suggestions.append(f"{base_ip}.0/24")
        
        if local_ip:
            base_ip = '.'.join(local_ip.split('.')[:3])
            suggestions.append(f"{base_ip}.0/24")
        
        # Common network ranges
        common_ranges = [
            "192.168.1.0/24",
            "192.168.0.0/24",
            "10.0.0.0/24",
            "172.16.0.0/24",
            "192.168.31.0/24"
        ]
        
        # Remove duplicates
        all_suggestions = suggestions + common_ranges
        unique_suggestions = []
        for suggestion in all_suggestions:
            if suggestion not in unique_suggestions:
                unique_suggestions.append(suggestion)
        
        return unique_suggestions[:5]

    def comprehensive_nmap_scan(self, network_range, profile_name=None):
        """Perform comprehensive nmap scan using configuration"""
        self.print_info(f"\nStarting comprehensive nmap scan on {network_range}")
        
        # Get scan commands from configuration
        scan_commands = []
        
        if self.nmap_manager:
            try:
                # Get commands from configuration
                cmd_configs = self.nmap_manager.get_scan_commands(
                    network_range, 
                    has_sudo=self.has_sudo, 
                    profile_name=profile_name
                )
                
                if self.has_sudo:
                    self.print_info("Using advanced scanning with elevated privileges...")
                else:
                    self.print_info("Using standard scanning without elevated privileges...")
                
                # Convert to the format expected by the rest of the code
                for cmd_config in cmd_configs:
                    scan_commands.append({
                        'command': cmd_config['command'],
                        'timeout': cmd_config['timeout'],
                        'description': cmd_config['description'],
                        'name': cmd_config['name']
                    })
                    
                self.print_info(f"Loaded {len(scan_commands)} scan commands from configuration")
                
            except Exception as e:
                logger.error(f"Error loading scan commands from config: {e}")
                self.print_warning("Falling back to hardcoded scan commands...")
                scan_commands = self._get_fallback_scan_commands(network_range)
        else:
            self.print_warning("No nmap configuration available, using fallback commands...")
            scan_commands = self._get_fallback_scan_commands(network_range)
        
        all_results = []
        
        # Create progress bar for nmap scans
        if scan_commands:
            progress_bar = self.create_progress_bar(len(scan_commands), "Nmap Scans")
        
        for i, cmd_info in enumerate(scan_commands, 1):
            try:
                # Handle both old format (list) and new format (dict)
                if isinstance(cmd_info, dict):
                    command = cmd_info['command']
                    timeout = cmd_info.get('timeout', 300)
                    description = cmd_info.get('description', 'Nmap scan')
                    name = cmd_info.get('name', f'scan_{i}')
                else:
                    # Fallback for old format
                    command = cmd_info
                    timeout = 300
                    description = 'Nmap scan'
                    name = f'scan_{i}'
                
                # Update progress bar description
                if self.current_progress_bar:
                    self.current_progress_bar.set_description(f"Scan {i}/{len(scan_commands)} ({name})")
                
                self.print_info(f"\nRunning scan {i}/{len(scan_commands)} ({name}): {description}")
                self.print_info(f"Command: {' '.join(command[:6])}...")
                
                # Run the command with timeout tracking
                result = self.run_command_with_sudo_with_progress(command, timeout, name)
                
                if result.returncode == 0:
                    hosts = self.parse_nmap_xml(result.stdout)
                    if hosts:
                        all_results.extend(hosts)
                        self.print_success(f"Scan {i} ({name}) completed: found {len(hosts)} hosts")
                    else:
                        self.print_warning(f"Scan {i} ({name}) completed: no hosts found")
                else:
                    self.print_error(f"Scan {i} ({name}) failed: {result.stderr.strip()}")
                    logger.warning(f"Nmap scan {i} failed: {result.stderr}")
                
                # Update progress
                self.update_progress(1)
                
            except subprocess.TimeoutExpired:
                self.print_error(f"Scan {i} ({name}) timed out")
                logger.error(f"Nmap scan {i} timed out")
                self.update_progress(1)
            except Exception as e:
                self.print_error(f"Scan {i} ({name}) error: {str(e)}")
                logger.error(f"Error in nmap scan {i}: {e}")
        
        # Close progress bar
        self.close_progress_bar()
        
        # Merge and deduplicate results
        merged_results = self.merge_scan_results(all_results)
        
        if not merged_results:
            self.print_warning("No hosts found via nmap scanning, trying fallback methods...")
            return self.fallback_network_scan(network_range)
        
        return merged_results

    def _get_fallback_scan_commands(self, network_range):
        """Get hardcoded fallback scan commands when configuration is not available"""
        if self.has_sudo:
            return [
                {
                    'name': 'syn_stealth_comprehensive',
                    'command': ["nmap", "-sS", "-sV", "-O", "-A", "-T4", "--open", 
                               "--script=default,discovery,safe", "-oX", "-", network_range],
                    'timeout': 600,
                    'description': 'SYN stealth scan with OS detection and service enumeration'
                },
                {
                    'name': 'udp_common_ports',
                    'command': ["nmap", "-sU", "-T4", "--top-ports", "100", "-oX", "-", network_range],
                    'timeout': 300,
                    'description': 'UDP scan for common services'
                }
            ]
        else:
            return [
                {
                    'name': 'tcp_connect_comprehensive',
                    'command': ["nmap", "-sT", "-sV", "-T4", "--open", 
                               "--script=default,discovery,safe", "-oX", "-", network_range],
                    'timeout': 600,
                    'description': 'TCP connect scan with service detection'
                },
                {
                    'name': 'host_discovery',
                    'command': ["nmap", "-sn", "-T4", "-oX", "-", network_range],
                    'timeout': 180,
                    'description': 'Host discovery only (ping scan)'
                }
            ]

    def merge_scan_results(self, all_results):
        """Merge results from multiple scans, combining data for same IPs"""
        merged = {}
        
        for host in all_results:
            ip = host['ip']
            
            if ip not in merged:
                merged[ip] = host.copy()
            else:
                # Merge additional information
                existing = merged[ip]
                
                # Merge ports
                existing_ports = {str(port['port']): port for port in existing.get('ports', [])}
                for port in host.get('ports', []):
                    port_key = str(port['port'])
                    if port_key not in existing_ports or not existing_ports[port_key].get('service'):
                        existing_ports[port_key] = port
                
                existing['ports'] = list(existing_ports.values())
                
                # Update other fields if not present
                if not existing.get('hostname') and host.get('hostname'):
                    existing['hostname'] = host['hostname']
                
                if not existing.get('os') and host.get('os'):
                    existing['os'] = host['os']
                
                if not existing.get('mac_address') and host.get('mac_address'):
                    existing['mac_address'] = host['mac_address']
                
                if not existing.get('vendor') and host.get('vendor'):
                    existing['vendor'] = host['vendor']
        
        return list(merged.values())

    def parse_nmap_xml(self, xml_output):
        """Parse comprehensive nmap XML output"""
        try:
            root = ET.fromstring(xml_output)
            hosts = []

            for host in root.findall(".//host"):
                # Skip hosts that are down
                status = host.find("status")
                if status is None or status.get("state") != "up":
                    continue

                host_info = {
                    'ip': None,
                    'hostname': None,
                    'mac_address': None,
                    'vendor': None,
                    'os': None,
                    'ports': [],
                    'response_time': None,
                    'last_boot': None,
                    'vulnerabilities': [],
                    'status': 'up'
                }

                # Get IP address
                for address in host.findall("address"):
                    if address.get("addrtype") == "ipv4":
                        host_info['ip'] = address.get("addr")
                    elif address.get("addrtype") == "mac":
                        host_info['mac_address'] = address.get("addr")
                        host_info['vendor'] = address.get("vendor", "")

                if not host_info['ip']:
                    continue

                # Get hostname
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    hostname_elem = hostnames_elem.find("hostname")
                    if hostname_elem is not None:
                        host_info['hostname'] = hostname_elem.get("name")

                # Get OS information
                os_elem = host.find("os")
                if os_elem is not None:
                    osmatch = os_elem.find("osmatch")
                    if osmatch is not None:
                        host_info['os'] = osmatch.get("name", "")

                # Get timing information
                times = host.find("times")
                if times is not None:
                    host_info['response_time'] = times.get("rttvar")

                # Get open ports and services
                ports = host.find("ports")
                if ports is not None:
                    for port in ports.findall("port"):
                        state = port.find("state")
                        if state is None or state.get("state") != "open":
                            continue

                        port_info = {
                            'port': int(port.get("portid")),
                            'protocol': port.get("protocol"),
                            'service': None,
                            'version': None,
                            'product': None,
                            'extrainfo': None
                        }

                        # Get service information
                        service = port.find("service")
                        if service is not None:
                            port_info['service'] = service.get("name", "")
                            port_info['version'] = service.get("version", "")
                            port_info['product'] = service.get("product", "")
                            port_info['extrainfo'] = service.get("extrainfo", "")

                        # Get script results (for vulnerability detection)
                        for script in port.findall("script"):
                            script_id = script.get("id", "")
                            script_output = script.get("output", "")
                            if "vuln" in script_id.lower() or "cve" in script_output.lower():
                                host_info['vulnerabilities'].append({
                                    'port': port_info['port'],
                                    'script': script_id,
                                    'details': script_output
                                })

                        host_info['ports'].append(port_info)

                # Get host script results
                hostscript = host.find("hostscript")
                if hostscript is not None:
                    for script in hostscript.findall("script"):
                        script_id = script.get("id", "")
                        script_output = script.get("output", "")
                        
                        # Look for interesting information
                        if "smb-os-discovery" in script_id:
                            if not host_info['os']:
                                # Extract OS from SMB discovery
                                os_match = re.search(r'OS: ([^|]+)', script_output)
                                if os_match:
                                    host_info['os'] = os_match.group(1).strip()
                        
                        # Check for vulnerabilities
                        if "vuln" in script_id.lower() or "cve" in script_output.lower():
                            host_info['vulnerabilities'].append({
                                'port': 'host',
                                'script': script_id,
                                'details': script_output
                            })

                hosts.append(host_info)
                logger.info(f"Parsed host: {host_info['ip']} with {len(host_info['ports'])} open ports")

            return hosts

        except Exception as e:
            logger.error(f"Error parsing nmap XML: {e}")
            return []

    def fallback_network_scan(self, network_range):
        """Fallback scanning methods when nmap fails"""
        self.print_info("Using fallback scanning methods...")
        
        methods = [
            ("TCP Port Scan", self.tcp_port_scan),
            ("Ping Sweep", self.ping_sweep),
            ("ARP Scan", self.arp_scan)
        ]
        
        all_results = []
        
        for method_name, method_func in methods:
            try:
                self.print_info(f"Trying {method_name}...")
                results = method_func(network_range)
                if results:
                    all_results.extend(results)
                    self.print_success(f"{method_name} found {len(results)} hosts")
                else:
                    self.print_warning(f"{method_name} found no hosts")
            except Exception as e:
                self.print_error(f"{method_name} failed: {e}")
                logger.error(f"{method_name} error: {e}")
        
        return self.merge_scan_results(all_results)

    def tcp_port_scan(self, network_range):
        """TCP port scanning for host discovery and service detection"""
        hosts = []
        
        # Get configuration for TCP port scan
        if self.nmap_manager:
            tcp_config = self.nmap_manager.get_fallback_config('tcp_port_scan')
            if tcp_config:
                common_ports = tcp_config.get('common_ports', [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3389, 5900])
                timeout_per_port = tcp_config.get('timeout_per_port', 2)
                max_threads = tcp_config.get('max_threads', 50)
                max_hosts_to_test = tcp_config.get('max_hosts_to_test', 100)
            else:
                # Fallback defaults
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3389, 5900]
                timeout_per_port = 2
                max_threads = 50
                max_hosts_to_test = 100
        else:
            # Fallback defaults
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3389, 5900]
            timeout_per_port = 2
            max_threads = 50
            max_hosts_to_test = 100
        
        try:
            network = ip_network(network_range, strict=False)
            test_hosts = list(network.hosts())[:max_hosts_to_test]
            
            # Create progress bar for TCP port scanning
            progress_bar = self.create_progress_bar(len(test_hosts), "TCP Port Scan")
            
            def scan_host(ip):
                host_info = {
                    'ip': str(ip),
                    'hostname': None,
                    'mac_address': None,
                    'vendor': None,
                    'os': None,
                    'ports': [],
                    'response_time': None,
                    'last_boot': None,
                    'vulnerabilities': [],
                    'status': 'down'
                }
                
                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(str(ip))[0]
                    host_info['hostname'] = hostname
                except:
                    pass
                
                # Scan common ports
                open_ports = []
                for port in common_ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(timeout_per_port)
                        result = sock.connect_ex((str(ip), port))
                        sock.close()
                        
                        if result == 0:
                            open_ports.append({
                                'port': port,
                                'protocol': 'tcp',
                                'service': self.get_service_name(port),
                                'version': None,
                                'product': None,
                                'extrainfo': None
                            })
                    except:
                        pass
                
                if open_ports:
                    host_info['ports'] = open_ports
                    host_info['status'] = 'up'
                    with self.lock:
                        hosts.append(host_info)
                        logger.info(f"TCP scan found active host: {ip} ({len(open_ports)} open ports)")
                
                # Update progress
                with self.lock:
                    self.update_progress(1)
            
            # Use threading for faster scanning
            threads = []
            for ip in test_hosts:
                thread = Thread(target=scan_host, args=(ip,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
                # Limit concurrent threads
                if len(threads) >= max_threads:
                    for t in threads:
                        t.join(timeout=10)
                    threads = [t for t in threads if t.is_alive()]
            
            # Wait for remaining threads
            for t in threads:
                t.join(timeout=10)
            
            # Close progress bar
            self.close_progress_bar()
        
        except Exception as e:
            logger.error(f"Error in TCP port scan: {e}")
        
        return hosts

    def get_service_name(self, port):
        """Get common service names for ports"""
        services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
            993: 'imaps', 995: 'pop3s', 8080: 'http-proxy', 8443: 'https-alt',
            3389: 'rdp', 5900: 'vnc'
        }
        return services.get(port, 'unknown')

    def ping_sweep(self, network_range):
        """Basic ping sweep for host discovery"""
        hosts = []
        
        # Get configuration for ping sweep
        if self.nmap_manager:
            ping_config = self.nmap_manager.get_fallback_config('ping_sweep')
            if ping_config:
                ping_timeout = ping_config.get('ping_timeout', 1)
                max_threads = ping_config.get('max_threads', 50)
                max_hosts_to_test = ping_config.get('max_hosts_to_test', 100)
            else:
                ping_timeout = 1
                max_threads = 50
                max_hosts_to_test = 100
        else:
            ping_timeout = 1
            max_threads = 50
            max_hosts_to_test = 100
        
        try:
            network = ip_network(network_range, strict=False)
            test_hosts = list(network.hosts())[:max_hosts_to_test]
            
            # Create progress bar for ping sweep
            progress_bar = self.create_progress_bar(len(test_hosts), "Ping Sweep")
            
            def ping_host(ip):
                try:
                    # Use appropriate ping command for the OS
                    if platform.system() == "Windows":
                        cmd = ["ping", "-n", "1", "-w", str(ping_timeout * 1000), str(ip)]
                    else:
                        cmd = ["ping", "-c", "1", "-W", str(ping_timeout), str(ip)]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=ping_timeout + 2)
                    
                    if result.returncode == 0:
                        host_info = {
                            'ip': str(ip),
                            'hostname': None,
                            'mac_address': None,
                            'vendor': None,
                            'os': None,
                            'ports': [],
                            'response_time': None,
                            'last_boot': None,
                            'vulnerabilities': [],
                            'status': 'up'
                        }
                        
                        # Try to get response time from ping output
                        if platform.system() == "Windows":
                            time_match = re.search(r'time[<=](\d+)ms', result.stdout)
                        else:
                            time_match = re.search(r'time=(\d+\.?\d*)\s*ms', result.stdout)
                        
                        if time_match:
                            host_info['response_time'] = time_match.group(1)
                        
                        with self.lock:
                            hosts.append(host_info)
                            logger.info(f"Ping found active host: {ip}")
                
                except Exception as e:
                    pass
                finally:
                    # Update progress
                    with self.lock:
                        self.update_progress(1)
            
            # Ping all hosts in the network
            threads = []
            for ip in test_hosts:
                thread = Thread(target=ping_host, args=(ip,))
                thread.daemon = True
                thread.start()
                threads.append(thread)
                
                # Limit concurrent threads
                if len(threads) >= max_threads:
                    for t in threads:
                        t.join(timeout=10)
                    threads = [t for t in threads if t.is_alive()]
            
            # Wait for remaining threads
            for t in threads:
                t.join(timeout=10)
            
            # Close progress bar
            self.close_progress_bar()
        
        except Exception as e:
            logger.error(f"Error in ping sweep: {e}")
        
        return hosts

    def arp_scan(self, network_range):
        """ARP scanning for host discovery (works only on local network)"""
        hosts = []
        
        # Get configuration for ARP scan
        if self.nmap_manager:
            arp_config = self.nmap_manager.get_fallback_config('arp_scan')
            if arp_config:
                timeout = arp_config.get('timeout', 30)
            else:
                timeout = 30
        else:
            timeout = 30
        
        try:
            if platform.system() == "Windows":
                # Windows: use arp -a
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=timeout)
                if result.returncode == 0:
                    network = ip_network(network_range, strict=False)
                    
                    for line in result.stdout.split('\n'):
                        # Parse Windows ARP output: IP address (192.168.1.1) at 00-11-22-33-44-55 [ether] on eth0
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})', line)
                        if match:
                            ip_str, mac = match.groups()
                            ip = ip_address(ip_str)
                            
                            if ip in network:
                                hosts.append({
                                    'ip': str(ip),
                                    'hostname': None,
                                    'mac_address': mac.replace('-', ':'),
                                    'vendor': None,
                                    'os': None,
                                    'ports': [],
                                    'response_time': None,
                                    'last_boot': None,
                                    'vulnerabilities': [],
                                    'status': 'up'
                                })
                                logger.info(f"ARP found host: {ip} ({mac})")
            
            else:
                # Linux: try arp-scan or arp command
                try:
                    # Try arp-scan first
                    result = subprocess.run(['arp-scan', '--local', '--quiet'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        network = ip_network(network_range, strict=False)
                        
                        for line in result.stdout.split('\n'):
                            # Parse arp-scan output: 192.168.1.1    00:11:22:33:44:55    Vendor
                            parts = line.split()
                            if len(parts) >= 2:
                                ip_str, mac = parts[0], parts[1]
                                vendor = ' '.join(parts[2:]) if len(parts) > 2 else None
                                
                                try:
                                    ip = ip_address(ip_str)
                                    if ip in network:
                                        hosts.append({
                                            'ip': str(ip),
                                            'hostname': None,
                                            'mac_address': mac,
                                            'vendor': vendor,
                                            'os': None,
                                            'ports': [],
                                            'response_time': None,
                                            'last_boot': None,
                                            'vulnerabilities': [],
                                            'status': 'up'
                                        })
                                        logger.info(f"ARP-scan found host: {ip} ({mac})")
                                except ValueError:
                                    continue
                    
                except FileNotFoundError:
                    # arp-scan not available, try regular arp
                    result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        network = ip_network(network_range, strict=False)
                        
                        for line in result.stdout.split('\n'):
                            # Parse arp output: hostname (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
                            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})', line)
                            if match:
                                ip_str, mac = match.groups()
                                ip = ip_address(ip_str)
                                
                                if ip in network:
                                    hosts.append({
                                        'ip': str(ip),
                                        'hostname': None,
                                        'mac_address': mac,
                                        'vendor': None,
                                        'os': None,
                                        'ports': [],
                                        'response_time': None,
                                        'last_boot': None,
                                        'vulnerabilities': [],
                                        'status': 'up'
                                    })
                                    logger.info(f"ARP found host: {ip} ({mac})")
        
        except Exception as e:
            logger.error(f"Error in ARP scan: {e}")
        
        return hosts

    def save_to_csv(self, results):
        """Save scan results to CSV file"""
        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.csv_headers)
                writer.writeheader()
                
                for host in results:
                    # Format ports and services
                    ports_list = []
                    services_list = []
                    
                    for port in host.get('ports', []):
                        port_str = f"{port['port']}/{port['protocol']}"
                        ports_list.append(port_str)
                        
                        service = port.get('service', 'unknown')
                        if port.get('product'):
                            service += f" ({port['product']})"
                        if port.get('version'):
                            service += f" {port['version']}"
                        services_list.append(f"{port['port']}: {service}")
                    
                    # Format vulnerabilities
                    vulns = []
                    for vuln in host.get('vulnerabilities', []):
                        vulns.append(f"Port {vuln['port']}: {vuln['script']}")
                    
                    csv_row = {
                        'IP Address': host.get('ip', ''),
                        'Hostname': host.get('hostname', ''),
                        'MAC Address': host.get('mac_address', ''),
                        'Vendor': host.get('vendor', ''),
                        'OS Detection': host.get('os', ''),
                        'Open Ports': '; '.join(ports_list),
                        'Services': '; '.join(services_list),
                        'Vulnerabilities': '; '.join(vulns),
                        'Response Time': host.get('response_time', ''),
                        'Last Boot': host.get('last_boot', ''),
                        'Scan Timestamp': self.timestamp,
                        'Status': host.get('status', 'unknown'),
                        'Notes': f"Ports: {len(host.get('ports', []))}"
                    }
                    
                    writer.writerow(csv_row)
            
            self.print_success(f"Results saved to CSV: {self.csv_file}")
            
        except Exception as e:
            logger.error(f"Error saving to CSV: {e}")
            self.print_error(f"Error saving to CSV: {e}")

    def save_to_json(self, results):
        """Save detailed results to JSON file"""
        try:
            detailed_results = {
                'scan_info': {
                    'timestamp': self.timestamp,
                    'scan_type': 'comprehensive_network_scan',
                    'total_hosts': len(results),
                    'has_sudo': self.has_sudo
                },
                'hosts': results
            }
            
            with open(self.json_file, 'w', encoding='utf-8') as jsonfile:
                json.dump(detailed_results, jsonfile, indent=2, default=str)

            self.print_success(f"Detailed results saved to JSON: {self.json_file}")
            
        except Exception as e:
            logger.error(f"Error saving to JSON: {e}")
            self.print_error(f"Error saving to JSON: {e}")

    def print_summary(self, results):
        """Print comprehensive scan summary"""
        print("\n" + "="*80)
        self.print_success("COMPREHENSIVE NETWORK SCAN SUMMARY")
        print("="*80)
        
        if not results:
            self.print_error("No hosts found in the scan")
            return
        
        self.print_success(f"Total hosts discovered: {len(results)}")
        
        # Count statistics
        hosts_with_ports = len([h for h in results if h.get('ports')])
        total_open_ports = sum(len(h.get('ports', [])) for h in results)
        hosts_with_os = len([h for h in results if h.get('os')])
        hosts_with_vulns = len([h for h in results if h.get('vulnerabilities')])
        
        self.print_info(f"Hosts with open ports: {hosts_with_ports}")
        self.print_info(f"Total open ports: {total_open_ports}")
        self.print_info(f"Hosts with OS detection: {hosts_with_os}")
        if hosts_with_vulns > 0:
            self.print_warning(f"Hosts with vulnerabilities: {hosts_with_vulns}")
        else:
            self.print_info(f"Hosts with vulnerabilities: {hosts_with_vulns}")
        
        print("\nDETAILED HOST LIST:")
        print("-" * 80)
        
        for i, host in enumerate(results, 1):
            self.print_info(f"\n{i}. Host: {host['ip']}")
            
            if host.get('hostname'):
                print(f"   Hostname: {host['hostname']}")
            if host.get('mac_address'):
                print(f"   MAC: {host['mac_address']}")
                if host.get('vendor'):
                    print(f"   Vendor: {host['vendor']}")

            if host.get('os'):
                print(f"   OS: {host['os']}")

            if host.get('response_time'):
                print(f"   Response Time: {host['response_time']} ms")

            ports = host.get('ports', [])
            if ports:
                self.print_success(f"   Open Ports ({len(ports)}):")
                for port in ports[:10]:  # Show first 10 ports
                    service_info = port.get('service', 'unknown')
                    if port.get('product'):
                        service_info += f" ({port['product']})"
                    if port.get('version'):
                        service_info += f" v{port['version']}"
                    
                    print(f"      - {port['port']}/{port['protocol']} - {service_info}")
                
                if len(ports) > 10:
                    print(f"      ... and {len(ports) - 10} more ports")
            
            vulns = host.get('vulnerabilities', [])
            if vulns:
                self.print_warning(f"   Vulnerabilities ({len(vulns)}):")
                for vuln in vulns[:3]:  # Show first 3 vulnerabilities
                    print(f"      - Port {vuln['port']}: {vuln['script']}")
                
                if len(vulns) > 3:
                    print(f"      ... and {len(vulns) - 3} more vulnerabilities")
        
        print("\n" + "="*80)
        self.print_success(f"Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.print_success(f"Results saved to: {self.csv_file}")
        self.print_success(f"Detailed data: {self.json_file}")
        print("="*80)

    def scan_network(self, network_range, profile_name=None):
        """Main scanning function"""
        self.print_info(f"\nStarting comprehensive network scan...")
        self.print_info(f"Target: {network_range}")
        if profile_name:
            self.print_info(f"Using scan profile: {profile_name}")
        self.print_info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        start_time = time.time()
        
        # Perform comprehensive scan
        try:
            results = self.comprehensive_nmap_scan(network_range, profile_name)
        finally:
            # Ensure progress bars are closed
            self.close_progress_bar()
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Save results
        if results:
            self.print_success(f"\nScan completed! Processing results...")
            self.save_to_csv(results)
            self.save_to_json(results)
            self.print_summary(results)
        else:
            self.print_error("No hosts found. This could be due to:")
            self.print_error("   -Network is empty or isolated")
            self.print_error("   -Firewall blocking scans")
            self.print_error("   -Incorrect network range")
            self.print_error("   -Insufficient privileges")
        
        self.print_info(f"\nTotal scan time: {scan_duration:.2f} seconds")
        
        return results

    def list_available_profiles(self):
        """List available scan profiles"""
        if not self.nmap_manager:
            self.print_warning("No nmap configuration available")
            return
        
        try:
            profiles = self.nmap_manager.list_available_profiles()
            
            self.print_info("\nAvailable scan profiles:")
            print("-" * 50)
            
            for profile_name, description in profiles.items():
                print(f"  {profile_name}: {description}")
            
            print("-" * 50)
            
        except Exception as e:
            self.print_error(f"Error listing profiles: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Comprehensive Network Scanner - Discover and analyze network hosts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python network_scanner.py                          # Auto-detect network and scan
  python network_scanner.py -n 192.168.1.0/24       # Scan specific network
  python network_scanner.py -n 10.0.0.0/24 --no-sudo # Scan without sudo
        """
    )
    
    parser.add_argument(
        '-n', '--network',
        help='Network range to scan (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--no-sudo',
        action='store_true',
        help='Skip sudo password prompt and use fallback methods'
    )
    
    parser.add_argument(
        '-p', '--profile',
        help='Specify scan profile to use (use --list-profiles to see available profiles)'
    )
    
    parser.add_argument(
        '--list-profiles',
        action='store_true',
        help='List available scan profiles and exit'
    )
    
    parser.add_argument(
        '-c', '--config',
        default=CONFIG_FILE,
        help=f'Path to nmap configuration file (default: {CONFIG_FILE})'
    )
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = NetworkScanner(config_file=args.config)
    
    print("Comprehensive Network Scanner")
    print("=" * 50)
    
    # Handle list-profiles request
    if args.list_profiles:
        scanner.list_available_profiles()
        return 0
    
    # Validate profile if specified
    if args.profile and scanner.nmap_manager:
        if not scanner.nmap_manager.validate_profile(args.profile):
            scanner.print_error(f"Invalid profile: {args.profile}")
            scanner.print_info("Use --list-profiles to see available profiles")
            return 1
    
    # Handle sudo permissions
    if not args.no_sudo:
        scanner.check_sudo_access()
    else:
        scanner.print_warning("Skipping sudo access check (--no-sudo flag)")
    
    # Determine network range
    if args.network:
        network_range = args.network
        scanner.print_info(f"Using provided network range: {network_range}")
    else:
        # Auto-detect or ask user
        suggestions = scanner.suggest_network_ranges()
        
        scanner.print_info("\nNetwork Detection:")
        if suggestions:
            print("Suggested network ranges:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"  {i}. {suggestion}")
            
            print(f"\nPress Enter for default ({suggestions[0]}) or type a custom range:")
            user_input = input("Network range: ").strip()
            
            if not user_input:
                network_range = suggestions[0]
            elif user_input.isdigit() and 1 <= int(user_input) <= len(suggestions):
                network_range = suggestions[int(user_input) - 1]
            else:
                network_range = user_input
        else:
            network_range = input("Enter network range (e.g., 192.168.1.0/24): ").strip()
            if not network_range:
                network_range = "192.168.1.0/24"  # Default fallback
    
    scanner.print_info(f"Target network: {network_range}")
    
    # Show selected profile
    if args.profile:
        scanner.print_info(f"Using scan profile: {args.profile}")
    
    # Validate network range
    try:
        ip_network(network_range, strict=False)
    except ValueError as e:
        scanner.print_error(f"Invalid network range: {e}")
        return 1
    
    # Run the scan
    try:
        results = scanner.scan_network(network_range, profile_name=args.profile)
        
        if results:
            scanner.print_success(f"\nScan completed successfully!")
            scanner.print_success(f"Found {len(results)} hosts")
            return 0
        else:
            scanner.print_warning(f"\nScan completed but no hosts found")
            return 1
            
    except KeyboardInterrupt:
        scanner.print_warning(f"\nScan interrupted by user")
        return 1
    except Exception as e:
        scanner.print_error(f"\nScan failed with error: {e}")
        logger.error(f"Scan failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())