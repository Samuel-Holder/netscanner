# NetScanner - Network Security Toolkit

A Python-based network security toolkit demonstrating practical cybersecurity skills including port scanning, service detection, and network reconnaissance.

## Features

- **TCP Port Scanner** - Multi-threaded scanning with configurable timeout and port ranges
- **Service Detection** - Banner grabbing and service fingerprinting
- **Network Discovery** - Host discovery via ICMP and ARP
- **Output Formats** - JSON, CSV, and formatted console output
- **Logging** - Comprehensive logging for audit trails

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/netscanner.git
cd netscanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Quick Start

```bash
# Basic port scan
python -m netscanner scan 192.168.1.1

# Scan specific ports
python -m netscanner scan 192.168.1.1 -p 22,80,443,8080

# Scan port range with service detection
python -m netscanner scan 192.168.1.1 -p 1-1000 --service-detection

# Output to JSON
python -m netscanner scan 192.168.1.1 -o results.json --format json

# Network sweep
python -m netscanner discover 192.168.1.0/24
```

## Project Structure

```
netscanner/
├── src/
│   └── netscanner/
│       ├── __init__.py
│       ├── __main__.py        # CLI entry point
│       ├── scanner.py         # Core port scanning logic
│       ├── services.py        # Service detection & banner grabbing
│       ├── discovery.py       # Network/host discovery
│       ├── utils.py           # Helper utilities
│       └── output.py          # Output formatting
├── tests/
│   ├── __init__.py
│   ├── test_scanner.py
│   ├── test_services.py
│   └── test_utils.py
├── docs/
│   ├── USAGE.md
│   └── ARCHITECTURE.md
├── examples/
│   └── example_scans.py
├── requirements.txt
├── setup.py
├── pyproject.toml
├── .gitignore
├── LICENSE
└── README.md
```

## Usage Examples

### Python API

```python
from netscanner import PortScanner, ServiceDetector

# Initialize scanner
scanner = PortScanner(timeout=1.0, threads=100)

# Scan common ports
results = scanner.scan("192.168.1.1", ports=[22, 80, 443, 8080])

# Process results
for port, status in results.items():
    if status['state'] == 'open':
        print(f"Port {port}: {status['service']}")

# Service detection
detector = ServiceDetector()
banner = detector.grab_banner("192.168.1.1", 22)
```

### Command Line

```bash
# Verbose scan with timing
python -m netscanner scan 10.0.0.1 -p 1-65535 -t 50 -v

# Export multiple formats
python -m netscanner scan target.com -p 1-1000 -o scan_results --format all
```

## Legal Disclaimer

⚠️ **This tool is intended for authorized security testing and educational purposes only.**

- Only scan networks and systems you own or have explicit written permission to test
- Unauthorized port scanning may violate computer crime laws in your jurisdiction
- The author assumes no liability for misuse of this software

## Technical Skills Demonstrated

- **Network Programming** - Socket programming, TCP/IP fundamentals
- **Concurrency** - Multi-threading for performance optimization
- **Security Concepts** - Port scanning techniques, service enumeration
- **Software Engineering** - Clean architecture, testing, documentation
- **Python Best Practices** - Type hints, logging, error handling

## Contributing

Contributions welcome! Please read the contributing guidelines and submit pull requests.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Author

Built as a portfolio project demonstrating cybersecurity and Python development skills.
