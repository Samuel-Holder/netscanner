"""
Network Discovery Module

Provides host discovery capabilities using various techniques
including ICMP ping, TCP ping, and ARP scanning.
"""

import socket
import struct
import subprocess
import platform
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional, Dict, Generator
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class HostInfo:
    """Information about a discovered host."""
    
    ip: str
    hostname: Optional[str] = None
    is_alive: bool = False
    response_time: Optional[float] = None
    mac_address: Optional[str] = None
    discovery_method: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self) -> Dict:
        """Convert to dictionary."""
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "is_alive": self.is_alive,
            "response_time": self.response_time,
            "mac_address": self.mac_address,
            "discovery_method": self.discovery_method,
            "timestamp": self.timestamp.isoformat()
        }


class NetworkDiscovery:
    """
    Network Host Discovery.
    
    Discovers live hosts on a network using multiple techniques:
    - ICMP Echo (ping)
    - TCP SYN to common ports
    - ARP requests (local network)
    
    Example:
        >>> discovery = NetworkDiscovery()
        >>> hosts = discovery.discover_network("192.168.1.0/24")
        >>> for host in hosts:
        ...     print(f"{host.ip} - {host.hostname}")
    """
    
    # Ports to probe for TCP ping
    TCP_PROBE_PORTS = [80, 443, 22, 445, 139, 21, 23, 25, 3389]
    
    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 50,
        ping_count: int = 1
    ):
        """
        Initialize network discovery.
        
        Args:
            timeout: Timeout for probes in seconds
            threads: Maximum concurrent threads
            ping_count: Number of ICMP pings to send
        """
        self.timeout = timeout
        self.threads = threads
        self.ping_count = ping_count
        self._stop_discovery = False
        
        # Detect OS for ping command
        self.os_type = platform.system().lower()
        
        logger.info(f"NetworkDiscovery initialized (timeout={timeout}s)")
    
    @staticmethod
    def parse_network(network: str) -> Generator[str, None, None]:
        """
        Parse CIDR notation and generate IP addresses.
        
        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            
        Yields:
            IP addresses as strings
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
            for ip in net.hosts():
                yield str(ip)
        except ValueError as e:
            logger.error(f"Invalid network: {e}")
            raise
    
    def icmp_ping(self, target: str) -> HostInfo:
        """
        Ping a host using ICMP echo.
        
        Args:
            target: IP address to ping
            
        Returns:
            HostInfo with ping results
        """
        # Build ping command based on OS
        if self.os_type == "windows":
            cmd = ["ping", "-n", str(self.ping_count), "-w", str(int(self.timeout * 1000)), target]
        else:
            cmd = ["ping", "-c", str(self.ping_count), "-W", str(int(self.timeout)), target]
        
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 2
            )
            
            response_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Check if ping was successful
            is_alive = result.returncode == 0
            
            # Try to extract RTT from output
            if is_alive:
                # Parse average RTT (varies by OS)
                import re
                if self.os_type == "windows":
                    match = re.search(r"Average = (\d+)ms", result.stdout)
                else:
                    match = re.search(r"avg.*?(\d+\.?\d*)", result.stdout)
                
                if match:
                    response_time = float(match.group(1))
            
            return HostInfo(
                ip=target,
                is_alive=is_alive,
                response_time=response_time if is_alive else None,
                discovery_method="icmp"
            )
            
        except subprocess.TimeoutExpired:
            logger.debug(f"Ping timeout for {target}")
            return HostInfo(ip=target, is_alive=False, discovery_method="icmp")
        except Exception as e:
            logger.debug(f"Ping error for {target}: {e}")
            return HostInfo(ip=target, is_alive=False, discovery_method="icmp")
    
    def tcp_ping(self, target: str, ports: Optional[List[int]] = None) -> HostInfo:
        """
        Probe a host using TCP connections.
        
        Args:
            target: IP address to probe
            ports: Ports to try (default: common ports)
            
        Returns:
            HostInfo with probe results
        """
        if ports is None:
            ports = self.TCP_PROBE_PORTS
        
        start_time = datetime.now()
        
        for port in ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    
                    result = sock.connect_ex((target, port))
                    
                    if result == 0:
                        response_time = (datetime.now() - start_time).total_seconds() * 1000
                        
                        return HostInfo(
                            ip=target,
                            is_alive=True,
                            response_time=response_time,
                            discovery_method=f"tcp:{port}"
                        )
                        
            except socket.error:
                continue
        
        return HostInfo(ip=target, is_alive=False, discovery_method="tcp")
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """
        Resolve IP address to hostname.
        
        Args:
            ip: IP address to resolve
            
        Returns:
            Hostname or None
        """
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def _probe_host(
        self,
        target: str,
        methods: List[str] = None
    ) -> HostInfo:
        """
        Probe a host using multiple methods.
        
        Args:
            target: IP address to probe
            methods: Discovery methods to use
            
        Returns:
            HostInfo with combined results
        """
        if methods is None:
            methods = ["icmp", "tcp"]
        
        result = None
        
        for method in methods:
            if self._stop_discovery:
                break
                
            if method == "icmp":
                result = self.icmp_ping(target)
            elif method == "tcp":
                result = self.tcp_ping(target)
            
            if result and result.is_alive:
                break
        
        if result is None:
            result = HostInfo(ip=target, is_alive=False)
        
        # Try to resolve hostname for live hosts
        if result.is_alive:
            result.hostname = self.resolve_hostname(target)
            logger.info(f"Host discovered: {target} ({result.hostname})")
        
        return result
    
    def discover_network(
        self,
        network: str,
        methods: List[str] = None,
        resolve_dns: bool = True
    ) -> List[HostInfo]:
        """
        Discover live hosts on a network.
        
        Args:
            network: Network in CIDR notation
            methods: Discovery methods to use
            resolve_dns: Whether to resolve hostnames
            
        Returns:
            List of discovered hosts
        """
        self._stop_discovery = False
        
        # Generate target IPs
        targets = list(self.parse_network(network))
        
        logger.info(f"Starting discovery of {len(targets)} hosts in {network}")
        
        results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._probe_host, ip, methods): ip
                for ip in targets
            }
            
            for future in as_completed(futures):
                if self._stop_discovery:
                    break
                    
                try:
                    result = future.result()
                    if result.is_alive:
                        results.append(result)
                except Exception as e:
                    ip = futures[future]
                    logger.error(f"Error probing {ip}: {e}")
        
        # Sort by IP address
        results.sort(key=lambda h: ipaddress.ip_address(h.ip))
        
        logger.info(f"Discovery complete: {len(results)} hosts found")
        
        return results
    
    def stop(self):
        """Stop ongoing discovery."""
        self._stop_discovery = True
        logger.info("Discovery stop requested")
    
    def get_local_network(self) -> Optional[str]:
        """
        Get the local network in CIDR notation.
        
        Returns:
            Network string (e.g., "192.168.1.0/24") or None
        """
        try:
            # Get local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            # Assume /24 for simplicity
            ip_parts = local_ip.split(".")
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            logger.info(f"Local network detected: {network}")
            return network
            
        except Exception as e:
            logger.error(f"Could not detect local network: {e}")
            return None
    
    def get_local_ip(self) -> Optional[str]:
        """
        Get the local IP address.
        
        Returns:
            Local IP address string or None
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return None


def discover_hosts(network: str) -> List[HostInfo]:
    """
    Convenience function for network discovery.
    
    Args:
        network: Network in CIDR notation
        
    Returns:
        List of live hosts
    """
    discovery = NetworkDiscovery()
    return discovery.discover_network(network)


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.INFO)
    
    discovery = NetworkDiscovery(timeout=0.5, threads=100)
    
    # Try to discover local network
    local_net = discovery.get_local_network()
    
    if local_net:
        print(f"\nDiscovering hosts on {local_net}...")
        hosts = discovery.discover_network(local_net)
        
        print(f"\nFound {len(hosts)} live hosts:")
        for host in hosts:
            hostname = f" ({host.hostname})" if host.hostname else ""
            print(f"  {host.ip}{hostname} - {host.response_time:.1f}ms via {host.discovery_method}")
