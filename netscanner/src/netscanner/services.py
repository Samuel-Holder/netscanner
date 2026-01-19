"""
Service Detection Module

Provides service identification through banner grabbing,
protocol fingerprinting, and service enumeration.
"""

import socket
import ssl
import re
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class Protocol(Enum):
    """Supported protocols for service detection."""
    TCP = "tcp"
    UDP = "udp"
    SSL = "ssl"


@dataclass
class ServiceInfo:
    """Detailed information about a detected service."""
    
    port: int
    protocol: Protocol
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    product: Optional[str] = None
    os_info: Optional[str] = None
    extra_info: Optional[Dict] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary format."""
        return {
            "port": self.port,
            "protocol": self.protocol.value,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
            "product": self.product,
            "os_info": self.os_info,
            "extra_info": self.extra_info
        }


class ServiceDetector:
    """
    Service Detection and Banner Grabbing.
    
    Identifies services running on open ports by connecting
    and analyzing response banners or sending protocol-specific probes.
    
    Example:
        >>> detector = ServiceDetector(timeout=2.0)
        >>> info = detector.detect("192.168.1.1", 22)
        >>> print(f"Service: {info.service}, Version: {info.version}")
    """
    
    # Protocol probes - data to send to elicit a response
    PROBES = {
        "http": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "https": b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        "ftp": b"",  # FTP sends banner automatically
        "ssh": b"",  # SSH sends banner automatically
        "smtp": b"",  # SMTP sends banner automatically
        "pop3": b"",  # POP3 sends banner automatically
        "imap": b"",  # IMAP sends banner automatically
        "mysql": b"",  # MySQL sends banner automatically
        "redis": b"INFO\r\n",
        "mongodb": b"\x3a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\x01\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00",
    }
    
    # Service signature patterns
    SIGNATURES = {
        "ssh": [
            (r"SSH-(\d+\.\d+)-OpenSSH[_-](\S+)", "OpenSSH", 2),
            (r"SSH-(\d+\.\d+)-dropbear[_-]?(\S*)", "Dropbear", 2),
            (r"SSH-(\d+\.\d+)", "SSH", 1),
        ],
        "http": [
            (r"Server:\s*Apache/(\S+)", "Apache", 1),
            (r"Server:\s*nginx/(\S+)", "nginx", 1),
            (r"Server:\s*Microsoft-IIS/(\S+)", "Microsoft IIS", 1),
            (r"HTTP/1\.[01]", "HTTP", None),
        ],
        "ftp": [
            (r"220[- ].*vsftpd (\S+)", "vsftpd", 1),
            (r"220[- ].*ProFTPD (\S+)", "ProFTPD", 1),
            (r"220[- ].*FileZilla Server (\S+)", "FileZilla", 1),
            (r"220[- ]", "FTP", None),
        ],
        "smtp": [
            (r"220.*Postfix", "Postfix", None),
            (r"220.*Exim (\S+)", "Exim", 1),
            (r"220.*Microsoft ESMTP", "Microsoft Exchange", None),
            (r"220", "SMTP", None),
        ],
        "mysql": [
            (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB", 1),
            (r"(\d+\.\d+\.\d+)", "MySQL", 1),
        ],
        "redis": [
            (r"redis_version:(\S+)", "Redis", 1),
        ],
        "postgresql": [
            (r"PostgreSQL", "PostgreSQL", None),
        ],
    }
    
    # Port to likely service mapping
    PORT_HINTS = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "https", 465: "smtps", 587: "smtp", 993: "imaps",
        995: "pop3s", 1433: "mssql", 3306: "mysql", 5432: "postgresql",
        6379: "redis", 8080: "http", 27017: "mongodb"
    }
    
    def __init__(self, timeout: float = 3.0):
        """
        Initialize the service detector.
        
        Args:
            timeout: Connection and read timeout in seconds
        """
        self.timeout = timeout
        logger.info(f"ServiceDetector initialized (timeout={timeout}s)")
    
    def grab_banner(
        self,
        target: str,
        port: int,
        probe: Optional[bytes] = None
    ) -> Optional[str]:
        """
        Grab banner from a service.
        
        Args:
            target: Target IP or hostname
            port: Port number
            probe: Optional data to send
            
        Returns:
            Banner string or None
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                
                # Send probe if provided
                if probe:
                    sock.send(probe)
                
                # Try to receive banner
                banner = sock.recv(4096)
                
                if banner:
                    # Decode and clean banner
                    try:
                        decoded = banner.decode('utf-8', errors='replace')
                    except:
                        decoded = banner.decode('latin-1', errors='replace')
                    
                    # Remove null bytes and clean up
                    cleaned = decoded.replace('\x00', '').strip()
                    logger.debug(f"Banner from {target}:{port}: {cleaned[:100]}")
                    return cleaned
                    
        except socket.timeout:
            logger.debug(f"Timeout grabbing banner from {target}:{port}")
        except socket.error as e:
            logger.debug(f"Error grabbing banner from {target}:{port}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        
        return None
    
    def grab_ssl_banner(
        self,
        target: str,
        port: int,
        probe: Optional[bytes] = None
    ) -> Tuple[Optional[str], Optional[Dict]]:
        """
        Grab banner from an SSL/TLS service.
        
        Args:
            target: Target IP or hostname
            port: Port number
            probe: Optional data to send after SSL handshake
            
        Returns:
            Tuple of (banner, ssl_info)
        """
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    ssock.connect((target, port))
                    
                    # Get SSL certificate info
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        ssl_info['cert'] = cert
                    
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()
                    
                    # Send probe if provided
                    if probe:
                        ssock.send(probe)
                    
                    # Receive response
                    banner = ssock.recv(4096)
                    
                    if banner:
                        decoded = banner.decode('utf-8', errors='replace')
                        return decoded.strip(), ssl_info
                        
        except ssl.SSLError as e:
            logger.debug(f"SSL error on {target}:{port}: {e}")
            ssl_info['error'] = str(e)
        except socket.error as e:
            logger.debug(f"Socket error on {target}:{port}: {e}")
        except Exception as e:
            logger.debug(f"Error on {target}:{port}: {e}")
        
        return None, ssl_info if ssl_info else None
    
    def _identify_service(
        self,
        banner: str,
        service_hint: Optional[str] = None
    ) -> Tuple[str, Optional[str], Optional[str]]:
        """
        Identify service from banner using signatures.
        
        Args:
            banner: Banner text to analyze
            service_hint: Suggested service type
            
        Returns:
            Tuple of (service, version, product)
        """
        # Try hinted service first
        services_to_check = []
        if service_hint and service_hint in self.SIGNATURES:
            services_to_check.append(service_hint)
        
        # Add all other services
        services_to_check.extend(
            s for s in self.SIGNATURES if s not in services_to_check
        )
        
        for service in services_to_check:
            for pattern, product, version_group in self.SIGNATURES[service]:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(version_group) if version_group else None
                    logger.debug(f"Identified as {product} {version}")
                    return service, version, product
        
        return "unknown", None, None
    
    def detect(
        self,
        target: str,
        port: int,
        protocol: Protocol = Protocol.TCP
    ) -> ServiceInfo:
        """
        Detect service running on a port.
        
        Args:
            target: Target IP or hostname
            port: Port number
            protocol: Protocol to use
            
        Returns:
            ServiceInfo with detected service details
        """
        service_hint = self.PORT_HINTS.get(port)
        probe = self.PROBES.get(service_hint, b"")
        
        # Determine if we should try SSL
        use_ssl = port in (443, 465, 636, 993, 995, 8443) or service_hint == "https"
        
        banner = None
        ssl_info = None
        
        if use_ssl or protocol == Protocol.SSL:
            banner, ssl_info = self.grab_ssl_banner(target, port, probe)
            protocol = Protocol.SSL
        else:
            banner = self.grab_banner(target, port, probe)
        
        # Identify service from banner
        if banner:
            service, version, product = self._identify_service(banner, service_hint)
        else:
            service = service_hint or "unknown"
            version = None
            product = None
        
        return ServiceInfo(
            port=port,
            protocol=protocol,
            service=service,
            version=version,
            banner=banner[:500] if banner else None,  # Truncate long banners
            product=product,
            extra_info=ssl_info
        )
    
    def detect_multiple(
        self,
        target: str,
        ports: list
    ) -> Dict[int, ServiceInfo]:
        """
        Detect services on multiple ports.
        
        Args:
            target: Target IP or hostname
            ports: List of port numbers
            
        Returns:
            Dictionary mapping port to ServiceInfo
        """
        results = {}
        
        for port in ports:
            logger.info(f"Detecting service on {target}:{port}")
            results[port] = self.detect(target, port)
        
        return results


def identify_service(target: str, port: int) -> ServiceInfo:
    """
    Convenience function to identify a service.
    
    Args:
        target: Target to scan
        port: Port number
        
    Returns:
        ServiceInfo object
    """
    detector = ServiceDetector()
    return detector.detect(target, port)


if __name__ == "__main__":
    # Demo usage
    logging.basicConfig(level=logging.DEBUG)
    
    detector = ServiceDetector(timeout=2.0)
    
    # Test on localhost
    test_ports = [22, 80, 443]
    for port in test_ports:
        info = detector.detect("127.0.0.1", port)
        print(f"\nPort {port}:")
        print(f"  Service: {info.service}")
        print(f"  Product: {info.product}")
        print(f"  Version: {info.version}")
        if info.banner:
            print(f"  Banner: {info.banner[:80]}...")
