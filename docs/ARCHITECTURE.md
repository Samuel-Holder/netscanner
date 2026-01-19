# NetScanner Architecture

## Overview

NetScanner is designed with a modular architecture that separates concerns into distinct components, making the codebase maintainable, testable, and extensible.

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                             │
│                     (__main__.py)                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                      Core Modules                            │
├─────────────────┬─────────────────┬─────────────────────────┤
│   PortScanner   │ ServiceDetector │   NetworkDiscovery      │
│   (scanner.py)  │  (services.py)  │    (discovery.py)       │
└────────┬────────┴────────┬────────┴────────┬────────────────┘
         │                 │                  │
┌────────┴─────────────────┴──────────────────┴───────────────┐
│                    Utility Layer                             │
│              (utils.py, output.py)                           │
└─────────────────────────────────────────────────────────────┘
```

## Module Descriptions

### scanner.py - Port Scanner

The core scanning engine using multi-threaded TCP connect scanning.

**Key Classes:**
- `PortScanner`: Main scanner class with configurable threads/timeout
- `ScanResult`: Dataclass representing scan results

**Design Decisions:**
- Uses `ThreadPoolExecutor` for concurrent scanning
- TCP connect scan (full 3-way handshake) for reliability
- Callback support for real-time results

```python
# Internal flow
scan() -> _validate_target() -> _parse_ports() -> ThreadPool(_scan_port)
```

### services.py - Service Detection

Banner grabbing and service fingerprinting.

**Key Classes:**
- `ServiceDetector`: Banner grabbing and protocol detection
- `ServiceInfo`: Detailed service information

**Design Decisions:**
- Regex-based signature matching
- SSL/TLS support for encrypted services
- Protocol-specific probes for better detection

### discovery.py - Network Discovery

Host discovery using multiple techniques.

**Key Classes:**
- `NetworkDiscovery`: Multi-method host discovery
- `HostInfo`: Discovered host information

**Design Decisions:**
- Falls back through methods (ICMP → TCP)
- Cross-platform ping implementation
- Optional reverse DNS resolution

### output.py - Output Formatting

Multiple output format support.

**Key Classes:**
- `OutputFormatter`: Handles JSON, CSV, console, Markdown

**Design Decisions:**
- ANSI color support with disable option
- Consistent dictionary conversion for all result types
- File export with automatic format detection

### utils.py - Utilities

Shared helper functions.

**Key Functions:**
- IP/hostname validation
- Port parsing
- Network calculations
- Logging setup

## Data Flow

```
User Input
    │
    ▼
┌─────────────────┐
│  CLI Parser     │  Parse arguments, validate input
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Core Module     │  Execute scan/discovery/detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Result Objects  │  ScanResult, ServiceInfo, HostInfo
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ OutputFormatter │  Format for display/export
└────────┬────────┘
         │
         ▼
    User Output
```

## Threading Model

```
Main Thread
    │
    ├── Creates ThreadPoolExecutor(max_workers=N)
    │
    ├── Submits scan tasks ──────┬─── Worker 1: scan_port(host, port1)
    │                            ├─── Worker 2: scan_port(host, port2)
    │                            ├─── Worker 3: scan_port(host, port3)
    │                            └─── Worker N: scan_port(host, portN)
    │
    └── Collects results via as_completed()
```

## Error Handling

- Socket timeouts → "filtered" state
- Connection refused → "closed" state
- Name resolution failure → ValueError
- All errors logged with appropriate level

## Extensibility Points

1. **New Scan Types**: Add methods to `PortScanner`
2. **Service Signatures**: Extend `SIGNATURES` dict
3. **Output Formats**: Add methods to `OutputFormatter`
4. **Discovery Methods**: Add to `NetworkDiscovery`

## Security Considerations

- No raw sockets (no root required)
- Respects system rate limits
- Clear disclaimer about authorized use only
- No credential handling
