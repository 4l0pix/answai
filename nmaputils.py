"""
NMap Utilities Module
Handles nmap configuration loading and command generation
"""

import json
import os
import logging
import time
from typing import List, Dict, Any, Optional

# Configuration file constants
CONFIG_FILE = "config.json"

logger = logging.getLogger(__name__)


class ProgressBar:
    """Simple progress bar implementation"""
    
    def __init__(self, total, description="Progress", width=50):
        self.total = total
        self.current = 0
        self.description = description
        self.width = width
        self.start_time = time.time()
        self.last_update = 0
        
    def update(self, amount=1):
        """Update progress by specified amount"""
        self.current += amount
        if self.current > self.total:
            self.current = self.total
        self._display()
        
    def set_description(self, description):
        """Update the progress description"""
        self.description = description
        self._display()
        
    def _display(self):
        """Display the progress bar"""
        if self.total == 0:
            return
            
        percent = (self.current / self.total) * 100
        filled_width = int(self.width * self.current / self.total)
        
        # Create progress bar
        bar = '█' * filled_width + '░' * (self.width - filled_width)
        
        # Calculate timing info
        elapsed = time.time() - self.start_time
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            if rate > 0:
                eta = (self.total - self.current) / rate
                eta_str = f"ETA: {int(eta//60):02d}:{int(eta%60):02d}"
            else:
                eta_str = "ETA: --:--"
        else:
            eta_str = "ETA: --:--"
        
        # Display progress
        progress_line = f"\r{self.description}: |{bar}| {self.current}/{self.total} ({percent:.1f}%) {eta_str}"
        print(progress_line, end='', flush=True)
        
        # Add newline when complete
        if self.current >= self.total:
            print()
            
    def close(self):
        """Close the progress bar"""
        if self.current < self.total:
            self.current = self.total
            self._display()


class NmapConfig:
    """Handles loading and managing nmap configuration"""
    
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.config = {}
        self.load_config()
    
    def load_config(self):
        """Load nmap configuration from JSON file"""
        try:
            config_path = os.path.join(os.path.dirname(__file__), self.config_file)
            if not os.path.exists(config_path):
                # Try current directory
                config_path = self.config_file
            
            with open(config_path, 'r') as f:
                self.config = json.load(f)
                logger.info(f"Loaded nmap configuration from {config_path}")
                
        except FileNotFoundError:
            logger.error(f"Configuration file {self.config_file} not found")
            self._create_default_config()
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in configuration file: {e}")
            self._create_default_config()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create a minimal default configuration"""
        self.config = {
            "scan_profiles": {
                "basic": {
                    "description": "Basic scan",
                    "commands": [
                        {
                            "name": "basic_scan",
                            "description": "Basic TCP scan",
                            "command": ["nmap", "-sT", "-T4", "--open", "-oX", "-"],
                            "timeout": 300,
                            "requires_sudo": False
                        }
                    ]
                }
            },
            "general_settings": {
                "default_profile": "basic",
                "fallback_profile": "basic"
            }
        }
    
    def get_scan_profile(self, profile_name: str) -> Optional[Dict[str, Any]]:
        """Get scan profile by name"""
        return self.config.get("scan_profiles", {}).get(profile_name)
    
    def get_available_profiles(self) -> List[str]:
        """Get list of available scan profiles"""
        return list(self.config.get("scan_profiles", {}).keys())
    
    def get_commands_for_profile(self, profile_name: str, has_sudo: bool = False) -> List[Dict[str, Any]]:
        """Get nmap commands for a specific profile, filtered by sudo requirements"""
        profile = self.get_scan_profile(profile_name)
        if not profile:
            return []
        
        commands = profile.get("commands", [])
        
        # Filter commands based on sudo availability
        filtered_commands = []
        for cmd in commands:
            requires_sudo = cmd.get("requires_sudo", False)
            if requires_sudo and not has_sudo:
                continue  # Skip commands that require sudo when we don't have it
            filtered_commands.append(cmd)
        
        return filtered_commands
    
    def get_fallback_methods_config(self) -> Dict[str, Any]:
        """Get fallback methods configuration"""
        return self.config.get("fallback_methods", {})
    
    def get_general_settings(self) -> Dict[str, Any]:
        """Get general settings"""
        return self.config.get("general_settings", {})
    
    def get_default_profile(self, has_sudo: bool = False) -> str:
        """Get the appropriate default profile based on sudo availability"""
        settings = self.get_general_settings()
        
        if has_sudo:
            return settings.get("default_profile", "comprehensive_with_sudo")
        else:
            return settings.get("fallback_profile", "comprehensive_no_sudo")


class NmapCommandBuilder:
    """Builds nmap commands from configuration"""
    
    def __init__(self, config: NmapConfig):
        self.config = config
    
    def build_command(self, command_config: Dict[str, Any], network_range: str) -> List[str]:
        """Build complete nmap command with network range"""
        base_command = command_config.get("command", [])
        
        # Create a copy and append the network range
        full_command = base_command.copy()
        full_command.append(network_range)
        
        return full_command
    
    def get_command_timeout(self, command_config: Dict[str, Any]) -> int:
        """Get timeout for a command"""
        return command_config.get("timeout", 300)  # Default 5 minutes
    
    def get_command_description(self, command_config: Dict[str, Any]) -> str:
        """Get human-readable description of a command"""
        return command_config.get("description", "Nmap scan")


class NmapProfileManager:
    """High-level manager for nmap profiles and commands"""
    
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config = NmapConfig(config_file)
        self.builder = NmapCommandBuilder(self.config)
    
    def get_scan_commands(self, network_range: str, has_sudo: bool = False, 
                         profile_name: str = None) -> List[Dict[str, Any]]:
        """
        Get all scan commands for a network range
        
        Returns list of dictionaries with:
        - command: List of command arguments
        - timeout: Timeout in seconds
        - description: Human-readable description
        - name: Command name
        """
        if profile_name is None:
            profile_name = self.config.get_default_profile(has_sudo)
        
        command_configs = self.config.get_commands_for_profile(profile_name, has_sudo)
        
        scan_commands = []
        for cmd_config in command_configs:
            scan_commands.append({
                "name": cmd_config.get("name", "unknown"),
                "command": self.builder.build_command(cmd_config, network_range),
                "timeout": self.builder.get_command_timeout(cmd_config),
                "description": self.builder.get_command_description(cmd_config),
                "requires_sudo": cmd_config.get("requires_sudo", False)
            })
        
        return scan_commands
    
    def get_fallback_config(self, method_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration for fallback scanning methods"""
        fallback_methods = self.config.get_fallback_methods_config()
        return fallback_methods.get(method_name)
    
    def list_available_profiles(self) -> Dict[str, str]:
        """Get available profiles with descriptions"""
        profiles = {}
        for profile_name in self.config.get_available_profiles():
            profile = self.config.get_scan_profile(profile_name)
            if profile:
                profiles[profile_name] = profile.get("description", "No description")
        return profiles
    
    def validate_profile(self, profile_name: str) -> bool:
        """Check if a profile exists and is valid"""
        return profile_name in self.config.get_available_profiles()


# Convenience functions for easy usage
def get_nmap_commands(network_range: str, has_sudo: bool = False, 
                     profile: str = None, config_file: str = CONFIG_FILE) -> List[Dict[str, Any]]:
    """
    Convenience function to get nmap commands
    
    Args:
        network_range: Network to scan (e.g., "192.168.1.0/24")
        has_sudo: Whether sudo privileges are available
        profile: Specific profile to use (optional)
        config_file: Path to configuration file
    
    Returns:
        List of command dictionaries ready for execution
    """
    manager = NmapProfileManager(config_file)
    return manager.get_scan_commands(network_range, has_sudo, profile)


def get_fallback_config(method_name: str, config_file: str = CONFIG_FILE) -> Optional[Dict[str, Any]]:
    """
    Convenience function to get fallback method configuration
    
    Args:
        method_name: Name of fallback method (tcp_port_scan, ping_sweep, arp_scan)
        config_file: Path to configuration file
    
    Returns:
        Configuration dictionary for the method
    """
    manager = NmapProfileManager(config_file)
    return manager.get_fallback_config(method_name)


def list_scan_profiles(config_file: str = CONFIG_FILE) -> Dict[str, str]:
    """
    Convenience function to list available scan profiles
    
    Returns:
        Dictionary of {profile_name: description}
    """
    manager = NmapProfileManager(config_file)
    return manager.list_available_profiles()