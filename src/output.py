"""
Output Formatting Module

Provides multiple output formats for scan results including
JSON, CSV, and formatted console output.
"""

import json
import csv
import io
import logging
from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from pathlib import Path

from scanner import ScanResult
from services import ServiceInfo
from discovery import HostInfo

logger = logging.getLogger(__name__)


class OutputFormatter:
    """
    Output Formatter for scan results.
    
    Supports multiple output formats:
    - JSON: Machine-readable format
    - CSV: Spreadsheet-compatible format
    - Console: Human-readable formatted output
    - Markdown: Documentation-friendly format
    
    Example:
        >>> formatter = OutputFormatter()
        >>> results = [ScanResult(...), ...]
        >>> print(formatter.to_console(results))
        >>> formatter.to_file(results, "results.json", format="json")
    """
    
    # ANSI color codes for console output
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "cyan": "\033[96m",
    }
    
    def __init__(self, use_colors: bool = True):
        """
        Initialize the formatter.
        
        Args:
            use_colors: Whether to use ANSI colors in console output
        """
        self.use_colors = use_colors
    
    def _color(self, text: str, color: str) -> str:
        """Apply ANSI color to text."""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"
    
    def _state_color(self, state: str) -> str:
        """Get color for port state."""
        colors = {
            "open": "green",
            "closed": "red",
            "filtered": "yellow"
        }
        return colors.get(state, "reset")
    
    # === JSON Output ===
    
    def to_json(
        self,
        results: List[Union[ScanResult, ServiceInfo, HostInfo]],
        pretty: bool = True
    ) -> str:
        """
        Convert results to JSON format.
        
        Args:
            results: List of result objects
            pretty: Whether to format with indentation
            
        Returns:
            JSON string
        """
        data = {
            "scan_time": datetime.now().isoformat(),
            "total_results": len(results),
            "results": [r.to_dict() for r in results]
        }
        
        indent = 2 if pretty else None
        return json.dumps(data, indent=indent, default=str)
    
    # === CSV Output ===
    
    def to_csv(
        self,
        results: List[Union[ScanResult, ServiceInfo, HostInfo]]
    ) -> str:
        """
        Convert results to CSV format.
        
        Args:
            results: List of result objects
            
        Returns:
            CSV string
        """
        if not results:
            return ""
        
        output = io.StringIO()
        
        # Get fields from first result
        sample = results[0].to_dict()
        fieldnames = list(sample.keys())
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for result in results:
            writer.writerow(result.to_dict())
        
        return output.getvalue()
    
    # === Console Output ===
    
    def to_console(
        self,
        results: List[ScanResult],
        target: Optional[str] = None,
        show_closed: bool = False
    ) -> str:
        """
        Format port scan results for console display.
        
        Args:
            results: List of ScanResult objects
            target: Target that was scanned
            show_closed: Whether to show closed ports
            
        Returns:
            Formatted string
        """
        lines = []
        
        # Header
        lines.append("")
        lines.append(self._color("=" * 60, "cyan"))
        
        if target:
            lines.append(self._color(f"  Scan Results for {target}", "bold"))
        else:
            lines.append(self._color("  Port Scan Results", "bold"))
        
        lines.append(self._color("=" * 60, "cyan"))
        lines.append("")
        
        # Filter results
        filtered = results if show_closed else [r for r in results if r.state != "closed"]
        
        if not filtered:
            lines.append("  No open ports found.")
            lines.append("")
            return "\n".join(lines)
        
        # Table header
        lines.append(f"  {'PORT':<10} {'STATE':<12} {'SERVICE':<20} {'RESPONSE':<12}")
        lines.append("  " + "-" * 54)
        
        # Results
        open_count = 0
        for result in filtered:
            state_colored = self._color(result.state.upper(), self._state_color(result.state))
            service = result.service or "unknown"
            response = f"{result.response_time:.1f}ms" if result.response_time else "-"
            
            lines.append(f"  {result.port:<10} {state_colored:<21} {service:<20} {response:<12}")
            
            if result.state == "open":
                open_count += 1
        
        # Summary
        lines.append("")
        lines.append(self._color(f"  Summary: {open_count} open ports found", "green"))
        lines.append("")
        
        return "\n".join(lines)
    
    def services_to_console(
        self,
        services: Dict[int, ServiceInfo]
    ) -> str:
        """
        Format service detection results for console.
        
        Args:
            services: Dictionary mapping port to ServiceInfo
            
        Returns:
            Formatted string
        """
        lines = []
        
        lines.append("")
        lines.append(self._color("=" * 70, "cyan"))
        lines.append(self._color("  Service Detection Results", "bold"))
        lines.append(self._color("=" * 70, "cyan"))
        lines.append("")
        
        lines.append(f"  {'PORT':<10} {'SERVICE':<15} {'PRODUCT':<20} {'VERSION':<15}")
        lines.append("  " + "-" * 66)
        
        for port, info in sorted(services.items()):
            service = info.service or "unknown"
            product = info.product or "-"
            version = info.version or "-"
            
            service_colored = self._color(service, "green")
            lines.append(f"  {port:<10} {service_colored:<24} {product:<20} {version:<15}")
            
            if info.banner:
                banner_preview = info.banner[:50] + "..." if len(info.banner) > 50 else info.banner
                lines.append(f"             {self._color('Banner:', 'yellow')} {banner_preview}")
        
        lines.append("")
        
        return "\n".join(lines)
    
    def hosts_to_console(
        self,
        hosts: List[HostInfo]
    ) -> str:
        """
        Format host discovery results for console.
        
        Args:
            hosts: List of HostInfo objects
            
        Returns:
            Formatted string
        """
        lines = []
        
        lines.append("")
        lines.append(self._color("=" * 70, "cyan"))
        lines.append(self._color("  Network Discovery Results", "bold"))
        lines.append(self._color("=" * 70, "cyan"))
        lines.append("")
        
        lines.append(f"  {'IP ADDRESS':<18} {'HOSTNAME':<30} {'RESPONSE':<12} {'METHOD'}")
        lines.append("  " + "-" * 70)
        
        for host in hosts:
            hostname = host.hostname or "-"
            if len(hostname) > 28:
                hostname = hostname[:25] + "..."
            
            response = f"{host.response_time:.1f}ms" if host.response_time else "-"
            method = host.discovery_method or "-"
            
            ip_colored = self._color(host.ip, "green")
            lines.append(f"  {ip_colored:<27} {hostname:<30} {response:<12} {method}")
        
        lines.append("")
        lines.append(self._color(f"  Total: {len(hosts)} hosts discovered", "green"))
        lines.append("")
        
        return "\n".join(lines)
    
    # === Markdown Output ===
    
    def to_markdown(
        self,
        results: List[ScanResult],
        target: Optional[str] = None
    ) -> str:
        """
        Format results as Markdown.
        
        Args:
            results: List of ScanResult objects
            target: Target that was scanned
            
        Returns:
            Markdown string
        """
        lines = []
        
        lines.append(f"# Port Scan Results")
        lines.append("")
        
        if target:
            lines.append(f"**Target:** `{target}`")
            lines.append("")
        
        lines.append(f"**Scan Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Table
        lines.append("| Port | State | Service | Response Time |")
        lines.append("|------|-------|---------|---------------|")
        
        for result in results:
            if result.state == "open":
                service = result.service or "unknown"
                response = f"{result.response_time:.1f}ms" if result.response_time else "-"
                lines.append(f"| {result.port} | {result.state} | {service} | {response} |")
        
        lines.append("")
        
        open_count = sum(1 for r in results if r.state == "open")
        lines.append(f"**Summary:** {open_count} open ports found")
        lines.append("")
        
        return "\n".join(lines)
    
    # === File Output ===
    
    def to_file(
        self,
        results: List[Union[ScanResult, ServiceInfo, HostInfo]],
        filepath: str,
        format: str = "json"
    ) -> bool:
        """
        Save results to a file.
        
        Args:
            results: List of result objects
            filepath: Output file path
            format: Output format (json, csv, md)
            
        Returns:
            True if successful
        """
        path = Path(filepath)
        
        try:
            if format == "json":
                content = self.to_json(results)
            elif format == "csv":
                content = self.to_csv(results)
            elif format in ("md", "markdown"):
                content = self.to_markdown(results)
            else:
                logger.error(f"Unsupported format: {format}")
                return False
            
            path.write_text(content)
            logger.info(f"Results saved to {filepath}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving to {filepath}: {e}")
            return False
    
    def export_all(
        self,
        results: List[Union[ScanResult, ServiceInfo, HostInfo]],
        base_path: str
    ) -> Dict[str, bool]:
        """
        Export results in all formats.
        
        Args:
            results: List of result objects
            base_path: Base path without extension
            
        Returns:
            Dictionary mapping format to success status
        """
        formats = {
            "json": f"{base_path}.json",
            "csv": f"{base_path}.csv",
            "md": f"{base_path}.md"
        }
        
        return {
            fmt: self.to_file(results, path, fmt)
            for fmt, path in formats.items()
        }


# Convenience functions

def print_results(results: List[ScanResult], target: str = None):
    """Print scan results to console."""
    formatter = OutputFormatter()
    print(formatter.to_console(results, target))


def save_json(results: List, filepath: str) -> bool:
    """Save results as JSON."""
    formatter = OutputFormatter()
    return formatter.to_file(results, filepath, "json")


def save_csv(results: List, filepath: str) -> bool:
    """Save results as CSV."""
    formatter = OutputFormatter()
    return formatter.to_file(results, filepath, "csv")


if __name__ == "__main__":
    # Demo with sample data
    from datetime import datetime
    
    sample_results = [
        ScanResult(target="192.168.1.1", port=22, state="open", service="ssh", response_time=5.2),
        ScanResult(target="192.168.1.1", port=80, state="open", service="http", response_time=3.1),
        ScanResult(target="192.168.1.1", port=443, state="open", service="https", response_time=4.5),
        ScanResult(target="192.168.1.1", port=8080, state="filtered", service=None, response_time=None),
    ]
    
    formatter = OutputFormatter()
    
    print(formatter.to_console(sample_results, "192.168.1.1"))
    print("\n--- JSON Output ---")
    print(formatter.to_json(sample_results))
    print("\n--- CSV Output ---")
    print(formatter.to_csv(sample_results))
