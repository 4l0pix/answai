# Network Scanner Configuration Guide

## Overview

The network scanner now uses a modular configuration system that separates nmap parameters from the main code. This makes it easy to customize scanning behavior without modifying the source code.

## Files

- **`network_scanner.py`** - Main scanner application
- **`nmaputils.py`** - Nmap configuration management utilities
- **`config.json`** - Configuration file with scan profiles and settings

## Configuration File Structure

The `config.json` file contains:

### 1. Scan Profiles
Different scanning strategies for various use cases:

- **`comprehensive_with_sudo`** - Full scan with elevated privileges (SYN stealth, OS detection, service enumeration)
- **`comprehensive_no_sudo`** - Comprehensive scan without sudo (TCP connect, safe scripts)
- **`fast_scan`** - Quick basic scan for rapid discovery
- **`intensive_scan`** - Very thorough scan (all ports, vulnerability detection)

### 2. Fallback Methods
Configuration for non-nmap scanning methods:
- TCP port scanning parameters
- Ping sweep settings
- ARP scan timeouts

### 3. General Settings
- Default profile selection
- Timeout values
- Thread limits

## Usage Examples

### List Available Profiles
```bash
python network_scanner.py --list-profiles
```

### Use Specific Profile
```bash
python network_scanner.py -n 192.168.1.0/24 -p fast_scan
python network_scanner.py -n 10.0.0.0/24 -p intensive_scan
```

### Use Custom Configuration File
```bash
python network_scanner.py -c custom_config.json -n 192.168.1.0/24
```

### Standard Usage
```bash
# Auto-detect network and use default profile
python network_scanner.py

# Specify network with default profile
python network_scanner.py -n 192.168.1.0/24

# Skip sudo and use fallback profile
python network_scanner.py --no-sudo -n 192.168.1.0/24
```

## Customizing Scan Profiles

You can modify `config.json` to customize scanning behavior:

### Adding a New Profile
```json
{
  "scan_profiles": {
    "custom_profile": {
      "description": "Custom scan for my environment",
      "commands": [
        {
          "name": "custom_scan",
          "description": "My custom nmap scan",
          "command": ["nmap", "-sS", "-p", "80,443,22", "-T4", "-oX", "-"],
          "timeout": 300,
          "requires_sudo": true
        }
      ]
    }
  }
}
```

### Modifying Existing Profiles
Edit the `command` arrays to change nmap parameters:
- Add/remove ports: `"-p", "80,443,22,3389"`
- Change timing: `"-T3"` (slower) or `"-T5"` (faster)
- Add scripts: `"--script=smb-enum-shares,smb-os-discovery"`
- Modify output: Change `-oX` to `-oG` for greppable output

### Adjusting Fallback Methods
Modify fallback scanning parameters:

```json
{
  "fallback_methods": {
    "tcp_port_scan": {
      "common_ports": [21, 22, 80, 443, 3389, 5900],
      "timeout_per_port": 3,
      "max_threads": 100,
      "max_hosts_to_test": 254
    }
  }
}
```

## Configuration Parameters

### Scan Command Parameters
- **`name`** - Internal identifier for the command
- **`description`** - Human-readable description
- **`command`** - Array of nmap command arguments
- **`timeout`** - Maximum execution time in seconds
- **`requires_sudo`** - Whether the command needs elevated privileges

### Common Nmap Parameters
- **`-sS`** - SYN stealth scan (requires sudo)
- **`-sT`** - TCP connect scan (no sudo required)
- **`-sU`** - UDP scan
- **`-sV`** - Service version detection
- **`-O`** - OS fingerprinting
- **`-A`** - Aggressive scan (combines -sV, -O, -sC, --traceroute)
- **`-T4`** - Timing template (0-5, higher is faster)
- **`--open`** - Show only open ports
- **`--top-ports N`** - Scan most common N ports
- **`-p`** - Port specification (e.g., "80,443" or "1-1000")
- **`--script`** - NSE script categories or names

### Timing Templates
- **`-T0`** - Paranoid (very slow, evades IDS)
- **`-T1`** - Sneaky (slow, evades IDS)
- **`-T2`** - Polite (slower, less bandwidth)
- **`-T3`** - Normal (default)
- **`-T4`** - Aggressive (faster, assumes reliable network)
- **`-T5`** - Insane (very fast, may miss results)

## Security Considerations

- **Privileged scans**: SYN scans (`-sS`) require sudo/admin privileges
- **Script safety**: Use `safe` script category to avoid potentially harmful scripts
- **Network impact**: Aggressive timing (`-T4`, `-T5`) can impact network performance
- **Detection**: Stealth scans may still be detected by modern IDS/IPS systems

## Troubleshooting

### Configuration Not Loading
- Ensure `config.json` is in the same directory as the scanner
- Use `-c` flag to specify custom config file path
- Check JSON syntax with a validator

### Profile Not Found
- Use `--list-profiles` to see available profiles
- Check spelling of profile name
- Ensure profile exists in configuration file

### Permission Issues
- Use `--no-sudo` for scanning without elevated privileges
- Run as administrator on Windows or with sudo on Unix systems
- Check that nmap is installed and accessible

### Scan Failures
- Verify target network is reachable
- Check firewall settings
- Reduce scan timing with `-T2` or `-T1`
- Try fallback methods if nmap fails

## Advanced Configuration

### Multiple Configuration Files
You can maintain different configuration files for different environments:

```bash
# Development environment
python network_scanner.py -c config_dev.json -n 192.168.1.0/24

# Production environment  
python network_scanner.py -c config_prod.json -n 10.0.0.0/24
```

### Performance Tuning
Adjust these parameters based on your network and requirements:

- **Timeout values**: Increase for slow networks, decrease for fast local networks
- **Thread limits**: Higher values = faster scanning but more resource usage
- **Port ranges**: Scan fewer ports for faster results or more ports for potentially richer results
- **Timing templates**: Balance speed vs. accuracy

