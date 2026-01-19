"""
Core Port Scanner Module

Provides multi-threaded TCP port scanning capabilities with
configurable timeout, thread count, and port ranges.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Union, Callable
from datetime import datetime
import ipaddress

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Represents the result of a port scan."""
    
    target: str
    port: int
    state: str  # 'open', 'closed', 'filtered'
    service: Optional[str] = None
    banner: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    response_time: Optional[float] = None
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary format."""
        return {
            "target": self.target,
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "timestamp": self.timestamp.isoformat(),
            "response_time": self.response_time
        }


class PortScanner:
    """
    Multi-threaded TCP Port Scanner.
    
    Performs TCP connect scans to identify open ports on target hosts.
    Supports configurable timeouts, thread pools, and port ranges.
    
    Attributes:
        timeout: Socket connection timeout in seconds
        threads: Maximum number of concurrent scanning threads
        
    Example:
        >>> scanner = PortScanner(timeout=1.0, threads=100)
        >>> results = scanner.scan("192.168.1.1", ports=[22, 80, 443])
        >>> for result in results:
        ...     if result.state == 'open':
        ...         print(f"Port {result.port} is open")
    """
    
    # Common ports for quick scans
    COMMON_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888
    ]
    
    # Well-known port to service mapping
    PORT_SERVICES = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
        25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
        69: "tftp", 80: "http", 110: "pop3", 119: "nntp",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap",
        389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
        514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps",
        995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
        6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        27017: "mongodb"
    }
    
    def __init__(
        self,
        timeout: float = 1.0,
        threads: int = 100,
        callback: Optional[Callable[[ScanResult], None]] = None
    ):
        """
        Initialize the port scanner.
        
        Args:
            timeout: Connection timeout in seconds (default: 1.0)
            threads: Max concurrent threads (default: 100)
            callback: Optional callback function for real-time results
        """
        self.timeout = timeout
        self.threads = threads
        self.callback = callback
        self._stop_scan = False
        
        logger.info(f"PortScanner initialized (timeout={timeout}s, threads={threads})")
    
    def _validate_target(self, target: str) -> str:
        """
        Validate and resolve target to IP address.
        
        Args:
            target: Hostname or IP address
            
        Returns:
            Resolved IP address string
            
        Raises:
            ValueError: If target cannot be resolved
        """
        try:
            # Check if it's already a valid IP
            ipaddress.ip_address(target)
            return target
        except ValueError:
            pass
        
        # Try to resolve hostname
        try:
            resolved = socket.gethostbyname(target)
            logger.debug(f"Resolved {target} to {resolved}")
            return resolved
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{target}': {e}")
    
    def _parse_ports(self, ports: Union[str, List[int], range, None]) -> List[int]:
        """
        Parse port specification into list of port numbers.
        
        Args:
            ports: Port specification (e.g., "22,80,443" or "1-1000" or [22, 80])
            
        Returns:
            List of port numbers to scan
        """
        if ports is None:
            return self.COMMON_PORTS.copy()
        
        if isinstance(ports, (list, range)):
            return list(ports)
        
        if isinstance(ports, str):
            result = []
            for part in ports.split(","):
                part = part.strip()
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    result.extend(range(start, end + 1))
                else:
                    result.append(int(part))
            return result
        
        raise ValueError(f"Invalid port specification: {ports}")
    
    def _scan_port(self, target: str, port: int) -> ScanResult:
        """
        Scan a single port on the target.
        
        Args:
            target: Target IP address
            port: Port number to scan
            
        Returns:
            ScanResult with port state
        """
        start_time = datetime.now()
        state = "closed"
        response_time = None
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                
                conn_start = datetime.now()
                result = sock.connect_ex((target, port))
                conn_end = datetime.now()
                
                response_time = (conn_end - conn_start).total_seconds() * 1000
                
                if result == 0:
                    state = "open"
                    logger.debug(f"Port {port} is open on {target}")
                    
        except socket.timeout:
            state = "filtered"
            logger.debug(f"Port {port} timed out on {target}")
            
        except socket.error as e:
            logger.debug(f"Socket error on port {port}: {e}")
            state = "filtered"
        
        service = self.PORT_SERVICES.get(port) if state == "open" else None
        
        return ScanResult(
            target=target,
            port=port,
            state=state,
            service=service,
            response_time=response_time
        )
    
    def scan(
        self,
        target: str,
        ports: Union[str, List[int], range, None] = None,
        show_closed: bool = False
    ) -> List[ScanResult]:
        """
        Perform a port scan on the target.
        
        Args:
            target: Target hostname or IP address
            ports: Ports to scan (default: common ports)
            show_closed: Include closed ports in results
            
        Returns:
            List of ScanResult objects
        """
        self._stop_scan = False
        
        # Validate target
        resolved_target = self._validate_target(target)
        
        # Parse ports
        port_list = self._parse_ports(ports)
        
        logger.info(f"Starting scan of {target} ({resolved_target})")
        logger.info(f"Scanning {len(port_list)} ports with {self.threads} threads")
        
        results = []
        scan_start = datetime.now()
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scans
            futures = {
                executor.submit(self._scan_port, resolved_target, port): port
                for port in port_list
            }
            
            # Collect results as they complete
            for future in as_completed(futures):
                if self._stop_scan:
                    break
                    
                try:
                    result = future.result()
                    
                    if show_closed or result.state != "closed":
                        results.append(result)
                    
                    # Call callback if provided
                    if self.callback and result.state == "open":
                        self.callback(result)
                        
                except Exception as e:
                    port = futures[future]
                    logger.error(f"Error scanning port {port}: {e}")
        
        scan_duration = (datetime.now() - scan_start).total_seconds()
        
        # Sort results by port number
        results.sort(key=lambda r: r.port)
        
        open_count = sum(1 for r in results if r.state == "open")
        logger.info(f"Scan complete: {open_count} open ports found in {scan_duration:.2f}s")
        
        return results
    
    def stop(self):
        """Stop an ongoing scan."""
        self._stop_scan = True
        logger.info("Scan stop requested")
    
    def scan_range(
        self,
        targets: Union[str, List[str]],
        ports: Union[str, List[int], range, None] = None
    ) -> Dict[str, List[ScanResult]]:
        """
        Scan multiple targets.
        
        Args:
            targets: CIDR notation or list of targets
            ports: Ports to scan
            
        Returns:
            Dictionary mapping targets to their results
        """
        if isinstance(targets, str):
            # Parse CIDR notation
            try:
                network = ipaddress.ip_network(targets, strict=False)
                target_list = [str(ip) for ip in network.hosts()]
            except ValueError:
                target_list = [targets]
        else:
            target_list = targets
        
        logger.info(f"Scanning {len(target_list)} targets")
        
        all_results = {}
        for target in target_list:
            if self._stop_scan:
                break
            all_results[target] = self.scan(target, ports)
        
        return all_results


def quick_scan(target: str, ports: Optional[List[int]] = None) -> List[ScanResult]:
    """
    Convenience function for quick port scans.
    
    Args:
        target: Target to scan
        ports: Optional port list
        
    Returns:
        List of open port results
    """
    scanner = PortScanner()
    return [r for r in scanner.scan(target, ports) if r.state == "open"]


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.INFO)
    
    scanner = PortScanner(timeout=0.5, threads=50)
    results = scanner.scan("127.0.0.1", ports="1-1000")
    
    print(f"\nFound {len(results)} open ports:")
    for result in results:
        print(f"  {result.port}/tcp - {result.service or 'unknown'}")
