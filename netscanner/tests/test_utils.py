"""
Unit Tests for Utility Functions
"""

import pytest
from netscanner.utils import (
    is_valid_ip, is_valid_network, is_private_ip,
    expand_cidr, parse_ports, is_valid_port,
    is_valid_hostname, validate_target, sanitize_filename
)


class TestIPValidation:
    """Tests for IP address validation."""
    
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("10.0.0.1") is True
        assert is_valid_ip("8.8.8.8") is True
    
    def test_invalid_ip(self):
        assert is_valid_ip("256.1.1.1") is False
        assert is_valid_ip("not.an.ip") is False
        assert is_valid_ip("") is False
    
    def test_private_ip(self):
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("8.8.8.8") is False


class TestNetworkValidation:
    """Tests for network CIDR validation."""
    
    def test_valid_network(self):
        assert is_valid_network("192.168.1.0/24") is True
        assert is_valid_network("10.0.0.0/8") is True
    
    def test_invalid_network(self):
        assert is_valid_network("192.168.1.0") is False
        assert is_valid_network("invalid/24") is False


class TestPortParsing:
    """Tests for port specification parsing."""
    
    def test_single_port(self):
        assert parse_ports("80") == [80]
    
    def test_comma_separated(self):
        assert parse_ports("22,80,443") == [22, 80, 443]
    
    def test_range(self):
        assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]
    
    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]
    
    def test_invalid_port_ignored(self):
        result = parse_ports("80,99999")
        assert 80 in result
        assert 99999 not in result


class TestHostnameValidation:
    """Tests for hostname validation."""
    
    def test_valid_hostnames(self):
        assert is_valid_hostname("example.com") is True
        assert is_valid_hostname("sub.example.com") is True
        assert is_valid_hostname("my-server.local") is True
    
    def test_invalid_hostnames(self):
        assert is_valid_hostname("-invalid.com") is False
        assert is_valid_hostname("a" * 300) is False


class TestTargetValidation:
    """Tests for target validation."""
    
    def test_ip_target(self):
        valid, target_type, resolved = validate_target("192.168.1.1")
        assert valid is True
        assert target_type == "ip"
    
    def test_network_target(self):
        valid, target_type, resolved = validate_target("192.168.1.0/24")
        assert valid is True
        assert target_type == "network"


class TestSanitizeFilename:
    """Tests for filename sanitization."""
    
    def test_clean_filename(self):
        assert sanitize_filename("report.json") == "report.json"
    
    def test_removes_invalid_chars(self):
        result = sanitize_filename("file<>:\"/\\|?*.txt")
        assert "<" not in result
        assert ">" not in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
