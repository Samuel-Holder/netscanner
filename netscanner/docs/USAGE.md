# NetScanner Usage Guide

## Installation

### From Source

```bash
git clone https://github.com/yourusername/netscanner.git
cd netscanner
pip install -e .
```

### Development Setup

```bash
pip install -e ".[dev]"
```

## Command Line Usage

### Port Scanning

#### Basic Scan
```bash
# Scan common ports on a target
netscanner scan 192.168.1.1

# Scan a hostname
netscanner scan example.com
```

#### Specify Ports
```bash
# Single port
netscanner scan 192.168.1.1 -p 80

# Multiple ports
netscanner scan 192.168.1.1 -p 22,80,443,8080

# Port range
netscanner scan 192.168.1.1 -p 1-1000

# Mixed
netscanner scan 192.168.1.1 -p 22,80-100,443,8000-9000
```

#### Service Detection
```bash
# Enable service version detection
netscanner scan 192.168.1.1 -p 22,80,443 -sV
```

#### Performance Tuning
```bash
# Increase threads for faster scanning
netscanner scan 192.168.1.1 -p 1-65535 -t 200

# Adjust timeout for slow networks
netscanner scan 192.168.1.1 --timeout 2.0
```

#### Output Options
```bash
# Save as JSON
netscanner scan 192.168.1.1 -o results -f json

# Save as CSV
netscanner scan 192.168.1.1 -o results -f csv

# Save all formats
netscanner scan 192.168.1.1 -o results -f all

# Include closed ports
netscanner scan 192.168.1.1 --show-closed
```

### Network Discovery

#### Discover Hosts
```bash
# Scan a network (auto-detect local network if not specified)
netscanner discover

# Scan specific network
netscanner discover 192.168.1.0/24

# Use TCP ping instead of ICMP
netscanner discover 192.168.1.0/24 --tcp
```

### Service Detection

```bash
# Detect services on specific ports
netscanner service 192.168.1.1 -p 22,80,443
```

## Python API Usage

### Basic Port Scanning

```python
from netscanner import PortScanner

# Create scanner
scanner = PortScanner(timeout=1.0, threads=100)

# Scan target
results = scanner.scan("192.168.1.1", ports=[22, 80, 443])

# Process results
for result in results:
    if result.state == "open":
        print(f"Port {result.port}: {result.service}")
```

### Service Detection

```python
from netscanner import ServiceDetector

detector = ServiceDetector(timeout=3.0)

# Detect single port
info = detector.detect("192.168.1.1", 22)
print(f"Service: {info.service}")
print(f"Version: {info.version}")
print(f"Banner: {info.banner}")

# Detect multiple ports
services = detector.detect_multiple("192.168.1.1", [22, 80, 443])
for port, info in services.items():
    print(f"{port}: {info.product} {info.version}")
```

### Network Discovery

```python
from netscanner import NetworkDiscovery

discovery = NetworkDiscovery(timeout=1.0, threads=50)

# Discover hosts
hosts = discovery.discover_network("192.168.1.0/24")

for host in hosts:
    print(f"{host.ip} - {host.hostname} ({host.response_time}ms)")
```

### Output Formatting

```python
from netscanner import PortScanner, OutputFormatter

scanner = PortScanner()
results = scanner.scan("192.168.1.1")

formatter = OutputFormatter()

# Console output
print(formatter.to_console(results))

# JSON output
json_data = formatter.to_json(results)

# Save to file
formatter.to_file(results, "results.json", format="json")
formatter.to_file(results, "results.csv", format="csv")
```

### Real-time Callback

```python
from netscanner import PortScanner

def on_port_found(result):
    print(f"Found open port: {result.port}")

scanner = PortScanner(callback=on_port_found)
scanner.scan("192.168.1.1", ports="1-1000")
```

## Common Use Cases

### Security Audit
```bash
# Full port scan with service detection
netscanner scan target.com -p 1-65535 -sV -o audit_results -f all
```

### Quick Check
```bash
# Check if common services are running
netscanner scan 192.168.1.1 -p 22,80,443,3306,5432
```

### Network Inventory
```bash
# Discover all hosts and scan common ports
netscanner discover 10.0.0.0/24 -o network_hosts
```

## Troubleshooting

### Permission Errors
- ICMP ping may require elevated privileges on some systems
- Use `--tcp` flag for TCP-based host discovery

### Slow Scans
- Increase thread count: `-t 200`
- Reduce timeout: `--timeout 0.5`
- Scan fewer ports

### No Results
- Verify target is reachable: `ping target`
- Check firewall settings
- Try different ports
