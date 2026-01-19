"""
NetScanner CLI Entry Point

Command-line interface for the network security toolkit.
Provides commands for port scanning, service detection, and network discovery.
"""

import argparse
import sys
import logging
from typing import Optional

from scanner import PortScanner
from services import ServiceDetector
from discovery import NetworkDiscovery
from output import OutputFormatter
from utils import validate_target, parse_ports, setup_logging


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    
    parser = argparse.ArgumentParser(
        prog="netscanner",
        description="Network Security Toolkit - Port scanning, service detection, and network discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netscanner scan 192.168.1.1                    # Scan common ports
  netscanner scan 192.168.1.1 -p 1-1000          # Scan port range
  netscanner scan target.com -p 22,80,443 -sV    # Scan with service detection
  netscanner discover 192.168.1.0/24             # Discover hosts
  netscanner discover 192.168.1.0/24 --tcp       # TCP ping discovery

⚠️  Only scan networks you own or have permission to test.
        """
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help="Increase verbosity (use -vv for debug)"
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help="Disable colored output"
    )
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # === Scan Command ===
    scan_parser = subparsers.add_parser(
        'scan',
        help='Perform port scan on target'
    )
    
    scan_parser.add_argument(
        'target',
        help="Target IP address or hostname"
    )
    
    scan_parser.add_argument(
        '-p', '--ports',
        default=None,
        help="Ports to scan (e.g., '22,80,443' or '1-1000')"
    )
    
    scan_parser.add_argument(
        '-t', '--threads',
        type=int,
        default=100,
        help="Number of concurrent threads (default: 100)"
    )
    
    scan_parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )
    
    scan_parser.add_argument(
        '-sV', '--service-detection',
        action='store_true',
        help="Enable service version detection"
    )
    
    scan_parser.add_argument(
        '-o', '--output',
        help="Output file path"
    )
    
    scan_parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'md', 'all'],
        default='json',
        help="Output format (default: json)"
    )
    
    scan_parser.add_argument(
        '--show-closed',
        action='store_true',
        help="Show closed ports in output"
    )
    
    # === Discover Command ===
    discover_parser = subparsers.add_parser(
        'discover',
        help='Discover live hosts on network'
    )
    
    discover_parser.add_argument(
        'network',
        nargs='?',
        help="Network in CIDR notation (e.g., 192.168.1.0/24)"
    )
    
    discover_parser.add_argument(
        '--tcp',
        action='store_true',
        help="Use TCP ping instead of ICMP"
    )
    
    discover_parser.add_argument(
        '-t', '--threads',
        type=int,
        default=50,
        help="Number of concurrent threads (default: 50)"
    )
    
    discover_parser.add_argument(
        '--timeout',
        type=float,
        default=1.0,
        help="Probe timeout in seconds (default: 1.0)"
    )
    
    discover_parser.add_argument(
        '-o', '--output',
        help="Output file path"
    )
    
    discover_parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'md'],
        default='json',
        help="Output format (default: json)"
    )
    
    # === Service Command ===
    service_parser = subparsers.add_parser(
        'service',
        help='Detect services on specific ports'
    )
    
    service_parser.add_argument(
        'target',
        help="Target IP address or hostname"
    )
    
    service_parser.add_argument(
        '-p', '--ports',
        required=True,
        help="Ports to probe (e.g., '22,80,443')"
    )
    
    service_parser.add_argument(
        '--timeout',
        type=float,
        default=3.0,
        help="Banner grab timeout in seconds (default: 3.0)"
    )
    
    return parser


def run_scan(args, formatter: OutputFormatter) -> int:
    """Execute port scan command."""
    
    # Validate target
    is_valid, target_type, resolved = validate_target(args.target)
    
    if not is_valid:
        print(f"Error: Invalid target '{args.target}'")
        return 1
    
    target_display = args.target
    if resolved and resolved != args.target:
        target_display = f"{args.target} ({resolved})"
    
    print(f"\nStarting scan of {target_display}")
    
    # Create scanner
    scanner = PortScanner(
        timeout=args.timeout,
        threads=args.threads
    )
    
    # Parse ports
    ports = args.ports
    
    # Perform scan
    print(f"Scanning ports: {ports if ports else 'common ports'}")
    print(f"Threads: {args.threads}, Timeout: {args.timeout}s\n")
    
    results = scanner.scan(
        resolved or args.target,
        ports=ports,
        show_closed=args.show_closed
    )
    
    # Service detection if requested
    if args.service_detection:
        print("\nPerforming service detection...")
        detector = ServiceDetector(timeout=args.timeout + 1)
        
        open_ports = [r.port for r in results if r.state == 'open']
        services = detector.detect_multiple(resolved or args.target, open_ports)
        
        # Update results with service info
        for result in results:
            if result.port in services:
                info = services[result.port]
                result.service = f"{info.product or info.service}"
                if info.version:
                    result.service += f" {info.version}"
                result.banner = info.banner
        
        print(formatter.services_to_console(services))
    
    # Output results
    print(formatter.to_console(results, args.target, args.show_closed))
    
    # Save to file if requested
    if args.output:
        if args.format == 'all':
            formatter.export_all(results, args.output)
            print(f"Results saved to {args.output}.{{json,csv,md}}")
        else:
            output_file = f"{args.output}.{args.format}" if '.' not in args.output else args.output
            formatter.to_file(results, output_file, args.format)
            print(f"Results saved to {output_file}")
    
    return 0


def run_discover(args, formatter: OutputFormatter) -> int:
    """Execute network discovery command."""
    
    discovery = NetworkDiscovery(
        timeout=args.timeout,
        threads=args.threads
    )
    
    # Get network to scan
    network = args.network
    
    if not network:
        network = discovery.get_local_network()
        if not network:
            print("Error: Could not detect local network. Please specify a network.")
            return 1
        print(f"Auto-detected local network: {network}")
    
    print(f"\nDiscovering hosts on {network}")
    print(f"Threads: {args.threads}, Timeout: {args.timeout}s")
    print(f"Method: {'TCP ping' if args.tcp else 'ICMP ping'}\n")
    
    # Determine discovery method
    methods = ['tcp'] if args.tcp else ['icmp', 'tcp']
    
    # Perform discovery
    hosts = discovery.discover_network(network, methods=methods)
    
    # Output results
    print(formatter.hosts_to_console(hosts))
    
    # Save to file if requested
    if args.output:
        output_file = f"{args.output}.{args.format}" if '.' not in args.output else args.output
        formatter.to_file(hosts, output_file, args.format)
        print(f"Results saved to {output_file}")
    
    return 0


def run_service(args, formatter: OutputFormatter) -> int:
    """Execute service detection command."""
    
    # Validate target
    is_valid, target_type, resolved = validate_target(args.target)
    
    if not is_valid:
        print(f"Error: Invalid target '{args.target}'")
        return 1
    
    print(f"\nDetecting services on {args.target}")
    print(f"Ports: {args.ports}")
    print(f"Timeout: {args.timeout}s\n")
    
    detector = ServiceDetector(timeout=args.timeout)
    
    ports = parse_ports(args.ports)
    services = detector.detect_multiple(resolved or args.target, ports)
    
    print(formatter.services_to_console(services))
    
    return 0


def main(argv: Optional[list] = None) -> int:
    """Main entry point."""
    
    parser = create_parser()
    args = parser.parse_args(argv)
    
    # Setup logging
    log_level = logging.WARNING
    if args.verbose == 1:
        log_level = logging.INFO
    elif args.verbose >= 2:
        log_level = logging.DEBUG
    
    setup_logging(log_level)
    
    # Create formatter
    formatter = OutputFormatter(use_colors=not args.no_color)
    
    # Handle commands
    if args.command == 'scan':
        return run_scan(args, formatter)
    elif args.command == 'discover':
        return run_discover(args, formatter)
    elif args.command == 'service':
        return run_service(args, formatter)
    else:
        parser.print_help()
        return 0


if __name__ == '__main__':
    sys.exit(main())
