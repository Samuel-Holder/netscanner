#!/usr/bin/env python3
"""
NetScanner Example Usage

Demonstrates various ways to use the NetScanner toolkit
programmatically in your own scripts.
"""

import sys
sys.path.insert(0, '../src')

from netscanner import (
    PortScanner,
    ServiceDetector, 
    NetworkDiscovery,
    OutputFormatter
)


def example_basic_scan():
    """Basic port scanning example."""
    print("\n" + "="*60)
    print("Example 1: Basic Port Scan")
    print("="*60)
    
    # Create scanner with custom settings
    scanner = PortScanner(
        timeout=1.0,    # 1 second timeout
        threads=50      # 50 concurrent threads
    )
    
    # Scan localhost on common ports
    results = scanner.scan(
        target="127.0.0.1",
        ports=[22, 80, 443, 8080, 3306, 5432]
    )
    
    # Process results
    print(f"\nScanned 127.0.0.1")
    print(f"Found {len([r for r in results if r.state == 'open'])} open ports:\n")
    
    for result in results:
        if result.state == "open":
            print(f"  Port {result.port}/tcp - {result.service or 'unknown'}")


def example_with_callback():
    """Real-time scanning with callback."""
    print("\n" + "="*60)
    print("Example 2: Real-time Callback")
    print("="*60)
    
    def on_port_found(result):
        """Called when an open port is found."""
        print(f"  [FOUND] Port {result.port} is {result.state}")
    
    scanner = PortScanner(
        timeout=0.5,
        threads=100,
        callback=on_port_found
    )
    
    print("\nScanning ports 1-100 with real-time output...")
    scanner.scan("127.0.0.1", ports="1-100")
    print("Scan complete!")


def example_service_detection():
    """Service detection with banner grabbing."""
    print("\n" + "="*60)
    print("Example 3: Service Detection")
    print("="*60)
    
    detector = ServiceDetector(timeout=3.0)
    
    # Common ports to check
    ports_to_check = [22, 80, 443]
    
    print(f"\nDetecting services on localhost...")
    
    services = detector.detect_multiple("127.0.0.1", ports_to_check)
    
    for port, info in services.items():
        print(f"\n  Port {port}:")
        print(f"    Service: {info.service}")
        print(f"    Product: {info.product or 'unknown'}")
        print(f"    Version: {info.version or 'unknown'}")
        if info.banner:
            banner_preview = info.banner[:60] + "..." if len(info.banner) > 60 else info.banner
            print(f"    Banner: {banner_preview}")


def example_network_discovery():
    """Network host discovery."""
    print("\n" + "="*60)
    print("Example 4: Network Discovery")
    print("="*60)
    
    discovery = NetworkDiscovery(
        timeout=0.5,
        threads=50
    )
    
    # Get local network
    local_net = discovery.get_local_network()
    
    if local_net:
        print(f"\nDiscovering hosts on {local_net}...")
        print("(This may take a moment)\n")
        
        # Limit to first 10 IPs for demo
        hosts = discovery.discover_network(local_net)[:10]
        
        print(f"Found {len(hosts)} hosts:")
        for host in hosts:
            hostname = f" ({host.hostname})" if host.hostname else ""
            print(f"  {host.ip}{hostname}")
    else:
        print("\nCould not detect local network")


def example_output_formats():
    """Different output format examples."""
    print("\n" + "="*60)
    print("Example 5: Output Formats")
    print("="*60)
    
    # Create some sample results
    scanner = PortScanner(timeout=0.5, threads=20)
    results = scanner.scan("127.0.0.1", ports="20-25,80,443")
    
    formatter = OutputFormatter(use_colors=True)
    
    # Console output
    print("\n--- Console Format ---")
    print(formatter.to_console(results, "127.0.0.1"))
    
    # JSON output (truncated)
    print("\n--- JSON Format (preview) ---")
    json_output = formatter.to_json(results)
    print(json_output[:500] + "...")
    
    # CSV output
    print("\n--- CSV Format ---")
    csv_output = formatter.to_csv(results)
    print(csv_output[:300] + "..." if len(csv_output) > 300 else csv_output)


def example_full_workflow():
    """Complete scanning workflow."""
    print("\n" + "="*60)
    print("Example 6: Full Workflow")
    print("="*60)
    
    target = "127.0.0.1"
    
    print(f"\n[1] Port Scanning {target}...")
    scanner = PortScanner(timeout=0.5, threads=100)
    scan_results = scanner.scan(target, ports="1-1024")
    
    open_ports = [r for r in scan_results if r.state == "open"]
    print(f"    Found {len(open_ports)} open ports")
    
    if open_ports:
        print(f"\n[2] Service Detection...")
        detector = ServiceDetector(timeout=2.0)
        
        port_list = [r.port for r in open_ports]
        services = detector.detect_multiple(target, port_list)
        
        print(f"    Identified {len(services)} services")
        
        print(f"\n[3] Results Summary:")
        for port, info in services.items():
            service_str = info.product or info.service
            version_str = f" {info.version}" if info.version else ""
            print(f"    {port}/tcp: {service_str}{version_str}")


def main():
    """Run all examples."""
    print("\n" + "#"*60)
    print("#  NetScanner Usage Examples")
    print("#"*60)
    
    try:
        example_basic_scan()
        example_with_callback()
        example_service_detection()
        # example_network_discovery()  # Uncomment to run (may be slow)
        example_output_formats()
        example_full_workflow()
        
    except KeyboardInterrupt:
        print("\n\nExamples interrupted by user")
    except Exception as e:
        print(f"\nError: {e}")
    
    print("\n" + "="*60)
    print("Examples complete!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
