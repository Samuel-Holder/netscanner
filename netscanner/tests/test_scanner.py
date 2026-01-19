"""
Unit Tests for Port Scanner Module

Tests covering port scanning functionality, validation,
and result handling.
"""

import pytest
import socket
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from netscanner.scanner import PortScanner, ScanResult, quick_scan


class TestScanResult:
    """Tests for ScanResult dataclass."""
    
    def test_scan_result_creation(self):
        """Test basic ScanResult creation."""
        result = ScanResult(
            target="192.168.1.1",
            port=80,
            state="open",
            service="http"
        )
        
        assert result.target == "192.168.1.1"
        assert result.port == 80
        assert result.state == "open"
        assert result.service == "http"
        assert isinstance(result.timestamp, datetime)
    
    def test_scan_result_to_dict(self):
        """Test ScanResult dictionary conversion."""
        result = ScanResult(
            target="192.168.1.1",
            port=22,
            state="open",
            service="ssh",
            banner="OpenSSH",
            response_time=5.5
        )
        
        data = result.to_dict()
        
        assert data["target"] == "192.168.1.1"
        assert data["port"] == 22
        assert data["state"] == "open"
        assert data["service"] == "ssh"
        assert data["banner"] == "OpenSSH"
        assert data["response_time"] == 5.5
        assert "timestamp" in data


class TestPortScanner:
    """Tests for PortScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization with default values."""
        scanner = PortScanner()
        
        assert scanner.timeout == 1.0
        assert scanner.threads == 100
        assert scanner.callback is None
    
    def test_scanner_custom_initialization(self):
        """Test scanner initialization with custom values."""
        callback = Mock()
        scanner = PortScanner(timeout=2.0, threads=50, callback=callback)
        
        assert scanner.timeout == 2.0
        assert scanner.threads == 50
        assert scanner.callback == callback
    
    def test_validate_target_ip(self):
        """Test target validation with IP address."""
        scanner = PortScanner()
        
        result = scanner._validate_target("192.168.1.1")
        assert result == "192.168.1.1"
    
    def test_validate_target_invalid(self):
        """Test target validation with invalid input."""
        scanner = PortScanner()
        
        with pytest.raises(ValueError):
            scanner._validate_target("invalid..hostname")
    
    @patch('socket.gethostbyname')
    def test_validate_target_hostname(self, mock_resolve):
        """Test target validation with hostname."""
        mock_resolve.return_value = "93.184.216.34"
        
        scanner = PortScanner()
        result = scanner._validate_target("example.com")
        
        assert result == "93.184.216.34"
        mock_resolve.assert_called_once_with("example.com")
    
    def test_parse_ports_list(self):
        """Test port parsing with list input."""
        scanner = PortScanner()
        
        result = scanner._parse_ports([22, 80, 443])
        assert result == [22, 80, 443]
    
    def test_parse_ports_string_single(self):
        """Test port parsing with single port string."""
        scanner = PortScanner()
        
        result = scanner._parse_ports("80")
        assert result == [80]
    
    def test_parse_ports_string_comma(self):
        """Test port parsing with comma-separated string."""
        scanner = PortScanner()
        
        result = scanner._parse_ports("22, 80, 443")
        assert result == [22, 80, 443]
    
    def test_parse_ports_string_range(self):
        """Test port parsing with range string."""
        scanner = PortScanner()
        
        result = scanner._parse_ports("20-25")
        assert result == [20, 21, 22, 23, 24, 25]
    
    def test_parse_ports_string_mixed(self):
        """Test port parsing with mixed format string."""
        scanner = PortScanner()
        
        result = scanner._parse_ports("22, 80-82, 443")
        assert result == [22, 80, 81, 82, 443]
    
    def test_parse_ports_none(self):
        """Test port parsing with None returns common ports."""
        scanner = PortScanner()
        
        result = scanner._parse_ports(None)
        assert result == scanner.COMMON_PORTS
    
    @patch('socket.socket')
    def test_scan_port_open(self, mock_socket_class):
        """Test scanning an open port."""
        mock_socket = MagicMock()
        mock_socket.__enter__ = Mock(return_value=mock_socket)
        mock_socket.__exit__ = Mock(return_value=False)
        mock_socket.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_socket
        
        scanner = PortScanner()
        result = scanner._scan_port("192.168.1.1", 80)
        
        assert result.state == "open"
        assert result.port == 80
        assert result.service == "http"
    
    @patch('socket.socket')
    def test_scan_port_closed(self, mock_socket_class):
        """Test scanning a closed port."""
        mock_socket = MagicMock()
        mock_socket.__enter__ = Mock(return_value=mock_socket)
        mock_socket.__exit__ = Mock(return_value=False)
        mock_socket.connect_ex.return_value = 111  # Connection refused
        mock_socket_class.return_value = mock_socket
        
        scanner = PortScanner()
        result = scanner._scan_port("192.168.1.1", 12345)
        
        assert result.state == "closed"
        assert result.port == 12345
    
    @patch('socket.socket')
    def test_scan_port_timeout(self, mock_socket_class):
        """Test scanning a filtered port (timeout)."""
        mock_socket = MagicMock()
        mock_socket.__enter__ = Mock(return_value=mock_socket)
        mock_socket.__exit__ = Mock(return_value=False)
        mock_socket.connect_ex.side_effect = socket.timeout()
        mock_socket_class.return_value = mock_socket
        
        scanner = PortScanner()
        result = scanner._scan_port("192.168.1.1", 80)
        
        assert result.state == "filtered"
    
    def test_port_service_mapping(self):
        """Test well-known port to service mapping."""
        scanner = PortScanner()
        
        assert scanner.PORT_SERVICES[22] == "ssh"
        assert scanner.PORT_SERVICES[80] == "http"
        assert scanner.PORT_SERVICES[443] == "https"
        assert scanner.PORT_SERVICES[3306] == "mysql"
    
    def test_stop_scan(self):
        """Test stopping a scan."""
        scanner = PortScanner()
        assert not scanner._stop_scan
        
        scanner.stop()
        assert scanner._stop_scan
    
    @patch.object(PortScanner, '_scan_port')
    @patch.object(PortScanner, '_validate_target')
    def test_scan_with_callback(self, mock_validate, mock_scan_port):
        """Test that callback is called for open ports."""
        mock_validate.return_value = "192.168.1.1"
        mock_scan_port.return_value = ScanResult(
            target="192.168.1.1",
            port=80,
            state="open",
            service="http"
        )
        
        callback = Mock()
        scanner = PortScanner(callback=callback)
        
        results = scanner.scan("192.168.1.1", ports=[80])
        
        assert callback.called


class TestQuickScan:
    """Tests for quick_scan convenience function."""
    
    @patch.object(PortScanner, 'scan')
    def test_quick_scan_filters_open(self, mock_scan):
        """Test that quick_scan only returns open ports."""
        mock_scan.return_value = [
            ScanResult(target="192.168.1.1", port=22, state="open"),
            ScanResult(target="192.168.1.1", port=23, state="closed"),
            ScanResult(target="192.168.1.1", port=80, state="open"),
        ]
        
        results = quick_scan("192.168.1.1")
        
        assert len(results) == 2
        assert all(r.state == "open" for r in results)


class TestPortScannerIntegration:
    """Integration tests (require network, marked for optional skip)."""
    
    @pytest.mark.integration
    def test_scan_localhost(self):
        """Test scanning localhost."""
        scanner = PortScanner(timeout=0.5, threads=10)
        results = scanner.scan("127.0.0.1", ports="1-100")
        
        # Should complete without error
        assert isinstance(results, list)
    
    @pytest.mark.integration  
    def test_scan_invalid_host(self):
        """Test scanning non-existent host."""
        scanner = PortScanner(timeout=0.1, threads=10)
        results = scanner.scan("192.0.2.1", ports=[80])  # TEST-NET-1
        
        # Should return results (likely all closed/filtered)
        assert isinstance(results, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
