"""
Utility Functions

Helper utilities for network operations, validation,
and common functionality used across the toolkit.
"""

import socket
import ipaddress
import re
import logging
from typing import List, Tuple, Optional, Union
from functools import lru_cache

logger = logging.getLogger(__name__)


# === IP Address Utilities ===

def is_valid_ip(ip: str) -> bool:
    """
    Check if string is a valid IP address.
    
    Args:
        ip: String to validate
        
    Returns:
        True if valid IPv4 or IPv6 address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_network(network: str) -> bool:
    """
    Check if string is a valid network in CIDR notation.
    
    Args:
        network: String to validate (e.g., "192.168.1.0/24")
        
    Returns:
        True if valid network
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is in private range.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private IP
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def expand_cidr(network: str) -> List[str]:
    """
    Expand CIDR notation to list of IP addresses.
    
    Args:
        network: Network in CIDR notation
        
    Returns:
        List of IP address strings
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError as e:
        logger.error(f"Invalid CIDR notation: {e}")
        return []


def ip_to_int(ip: str) -> int:
    """
    Convert IP address to integer for sorting.
    
    Args:
        ip: IP address string
        
    Returns:
        Integer representation
    """
    return int(ipaddress.ip_address(ip))


def int_to_ip(ip_int: int) -> str:
    """
    Convert integer to IP address.
    
    Args:
        ip_int: Integer representation
        
    Returns:
        IP address string
    """
    return str(ipaddress.ip_address(ip_int))


# === Hostname Utilities ===

@lru_cache(maxsize=1000)
def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address with caching.
    
    Args:
        hostname: Hostname to resolve
        
    Returns:
        IP address or None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


@lru_cache(maxsize=1000)
def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup with caching.
    
    Args:
        ip: IP address
        
    Returns:
        Hostname or None
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def is_valid_hostname(hostname: str) -> bool:
    """
    Validate hostname format.
    
    Args:
        hostname: Hostname to validate
        
    Returns:
        True if valid hostname format
    """
    if len(hostname) > 253:
        return False
    
    # Remove trailing dot if present
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    
    # Check each label
    labels = hostname.split('.')
    pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
    
    return all(pattern.match(label) for label in labels)


# === Port Utilities ===

def parse_ports(port_spec: str) -> List[int]:
    """
    Parse port specification string.
    
    Supports:
    - Single ports: "80"
    - Comma-separated: "22,80,443"
    - Ranges: "1-1000"
    - Mixed: "22,80,100-200,443,8000-9000"
    
    Args:
        port_spec: Port specification string
        
    Returns:
        List of port numbers
    """
    ports = set()
    
    for part in port_spec.split(','):
        part = part.strip()
        
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                if 0 < start <= end <= 65535:
                    ports.update(range(start, end + 1))
                else:
                    logger.warning(f"Invalid port range: {part}")
            except ValueError:
                logger.warning(f"Invalid port specification: {part}")
        else:
            try:
                port = int(part)
                if 0 < port <= 65535:
                    ports.add(port)
                else:
                    logger.warning(f"Port out of range: {port}")
            except ValueError:
                logger.warning(f"Invalid port: {part}")
    
    return sorted(ports)


def is_valid_port(port: Union[int, str]) -> bool:
    """
    Check if port number is valid.
    
    Args:
        port: Port number to check
        
    Returns:
        True if valid (1-65535)
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def get_port_category(port: int) -> str:
    """
    Get port category (well-known, registered, dynamic).
    
    Args:
        port: Port number
        
    Returns:
        Category string
    """
    if port < 1024:
        return "well-known"
    elif port < 49152:
        return "registered"
    else:
        return "dynamic"


# === Network Utilities ===

def get_local_ip() -> Optional[str]:
    """
    Get local machine's IP address.
    
    Returns:
        Local IP address or None
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Doesn't actually connect, just gets local interface
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None


def get_default_gateway() -> Optional[str]:
    """
    Attempt to get default gateway IP.
    
    Returns:
        Gateway IP or None
    """
    local_ip = get_local_ip()
    if local_ip:
        parts = local_ip.split('.')
        # Common gateway addresses
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"
    return None


def calculate_network(ip: str, netmask: str = "255.255.255.0") -> str:
    """
    Calculate network address from IP and netmask.
    
    Args:
        ip: IP address
        netmask: Network mask
        
    Returns:
        Network in CIDR notation
    """
    try:
        interface = ipaddress.ip_interface(f"{ip}/{netmask}")
        return str(interface.network)
    except ValueError:
        # Assume /24 if invalid mask
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# === Timing Utilities ===

class Timer:
    """Simple timer for measuring execution time."""
    
    def __init__(self):
        self._start = None
        self._end = None
    
    def start(self):
        """Start the timer."""
        from datetime import datetime
        self._start = datetime.now()
        return self
    
    def stop(self):
        """Stop the timer."""
        from datetime import datetime
        self._end = datetime.now()
        return self
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds."""
        if self._start is None:
            return 0.0
        from datetime import datetime
        end = self._end or datetime.now()
        return (end - self._start).total_seconds()
    
    @property
    def elapsed_ms(self) -> float:
        """Get elapsed time in milliseconds."""
        return self.elapsed * 1000


# === Validation Utilities ===

def validate_target(target: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validate and classify target.
    
    Args:
        target: Target to validate
        
    Returns:
        Tuple of (is_valid, target_type, resolved_ip)
        target_type: 'ip', 'hostname', 'network'
    """
    # Check if it's a network
    if '/' in target:
        if is_valid_network(target):
            return True, 'network', None
        return False, 'invalid', None
    
    # Check if it's an IP
    if is_valid_ip(target):
        return True, 'ip', target
    
    # Try to resolve as hostname
    if is_valid_hostname(target):
        resolved = resolve_hostname(target)
        if resolved:
            return True, 'hostname', resolved
        return False, 'unresolvable', None
    
    return False, 'invalid', None


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters.
    
    Args:
        filename: Original filename
        
    Returns:
        Safe filename
    """
    # Replace invalid characters
    safe = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    safe = safe.strip(' .')
    return safe or 'output'


# === Logging Utilities ===

def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None
):
    """
    Setup logging configuration.
    
    Args:
        level: Logging level
        log_file: Optional file to log to
    """
    format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    logging.basicConfig(
        level=level,
        format=format_str,
        handlers=handlers
    )


if __name__ == "__main__":
    # Demo utilities
    print("=== IP Utilities ===")
    print(f"Valid IP: {is_valid_ip('192.168.1.1')}")
    print(f"Private IP: {is_private_ip('192.168.1.1')}")
    print(f"Public IP: {is_private_ip('8.8.8.8')}")
    
    print("\n=== Port Parsing ===")
    print(f"Parse '22,80,443': {parse_ports('22,80,443')}")
    print(f"Parse '1-10': {parse_ports('1-10')}")
    print(f"Parse '22,80,100-105': {parse_ports('22,80,100-105')}")
    
    print("\n=== Network Info ===")
    print(f"Local IP: {get_local_ip()}")
    print(f"Default Gateway: {get_default_gateway()}")
    
    print("\n=== Validation ===")
    for target in ['192.168.1.1', 'google.com', '192.168.1.0/24', 'invalid..host']:
        valid, target_type, resolved = validate_target(target)
        print(f"  {target}: valid={valid}, type={target_type}, resolved={resolved}")
