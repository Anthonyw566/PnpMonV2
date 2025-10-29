# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**PNPmon Enhanced** is a live PMCP (ProfiNet Communication Protocol) switch monitor with advanced viewing and plotting capabilities. It combines real-time network packet monitoring with historical data analysis from `.pmcp` capture files.

### Core Functionality
- **Live Monitoring**: Direct UDP connection to PMCP switches (default: 192.168.15.4:55554)
- **File Viewing**: Load and analyze `.pmcp` XML capture files
- **Packet Analysis**: Display packet table with source/destination mapping and payload inspection
- **Data Visualization**: Plot selected hex bytes over time with interactive tooltips
- **Time Modes**: Switch between elapsed time (seconds) and absolute date/time with NSW DST adjustment

## Development Commands

### Running the Application
```bash
python main.py
```

### Virtual Environment
The project uses a Python virtual environment in `.venv/`:
```bash
# Activate (Linux/WSL)
source .venv/bin/activate

# Activate (Windows)
.venv\Scripts\activate
```

### Dependencies
Install required packages:
```bash
pip install customtkinter matplotlib pyshark psutil
```

Required libraries:
- `customtkinter` - Modern UI framework with dark theme
- `matplotlib` - Plotting and data visualization
- `pyshark` - Packet capture using tshark (requires tshark/Wireshark installed)
- `psutil` - Network interface detection
- Standard library: `socket`, `threading`, `xml.etree.ElementTree`, `struct`, `datetime`, `tkinter`, `queue`

**Note:** pyshark requires tshark to be installed on the system:
- Windows: Install Wireshark (includes tshark)
- Linux: `apt-get install tshark`

## Architecture & Code Structure

### Single-File Application
All code is in `main.py` (~2000 lines). The file is organized in clear sections with comment dividers:

1. **Imports** (lines 15-49) - All imports including pyshark and psutil
2. **Control Protocol Constants** (lines 51-77) - PMCP protocol definitions, ports, message types
3. **Control Protocol Structures** (lines 83-175) - Binary packet formats (`ControlMessageHeader`, `ShortControlResponse`, `MessageInfo`)
4. **Utility Functions** (lines 179-342) - Hex conversion, `.pmcp` file parsing, network interface detection
5. **ISSwitchMonitor Class** (lines 348-644) - Live switch connection handler with pyshark capture
6. **SimplePNPMon Application** (lines 650+) - Main GUI and logic

### Critical Implementation Details

#### Packet Parsing (`_parse_packet` at line 463)
Live packets require special handling:
1. Check for `MessageInfo` header (16 bytes) if extended protocol is enabled
2. **Strip first 16 bytes** (Ethernet/IP/UDP headers) - this is critical and user-specified
3. Parse remainder using 6-byte PMCP header format: `[00] [protocol] [dest_id] [dest_ch] [src_id] [src_ch] [payload...]`
4. If byte 0 is `0x00`, extract header fields and strip it to get payload
5. Size calculation MUST match `parse_pmcp()` behavior (line 249) - total length before stripping 6-byte header

#### Time Handling
- **File mode**: Uses `time_base` from XML and `offs_units` (offset in microseconds)
- **Live mode**: First packet sets `live_base_time` and `file_base_time`, subsequent packets are relative
- **NSW DST**: Automatically adds 1 hour between first Sunday in October and first Sunday in April
- Conversion factor: `units_per_sec = 1000000.0` (microseconds to seconds)

#### Network Interface Detection (lines 285-333)
- `get_network_interfaces()`: Returns dict mapping IP addresses to interface names
- `get_default_interface_ip()`: Auto-selects default interface (prioritizes 192.168.x.x, 10.x.x.x)
- Uses psutil to enumerate network interfaces
- Filters out loopback addresses (127.x.x.x)

#### Live Connection Protocol with Pyshark (lines 384-487)
**START Command (UNCHANGED):**
1. Create control socket (UDP) for command communication
2. Create data socket (UDP) to get local port number - NOT used for receiving
3. Start pyshark capture thread with BPF filter: `udp and src host {switch_ip} and dst port {local_port}`
4. Start processing thread to read from packet queue
5. Send START command (12-byte header + 12-byte address) with incrementing counter
6. Send dummy packet for NAT hole-punching
7. Wait for response on control socket

**STOP Command (UNCHANGED):**
- Uses different constant bytes (line 493-500)
- Sends via control socket

**Pyshark Capture Architecture:**
- `_capture_loop()`: Pyshark captures packets from network interface, puts in queue (max 10000 packets)
- `_process_loop()`: Reads from queue, extracts raw UDP payload, parses using existing `_parse_packet()`
- `_extract_raw_data()`: Extracts raw bytes from pyshark packet UDP layer
- Queue decouples packet capture (fast) from packet processing (slower)
- No packet loss even under high traffic due to pyshark's efficient buffering

#### Node Mapping (lines 620-630)
Friendly names for node IDs:
- 11: PMC-R, 12: Shearer, 20: PLC, 31: VShield, 60: I/O, 71: ??, 72: PPD, 1: Provider, 88: MG PAM

### Data Flow

**File Loading:**
```
load_file() → parse_pmcp() → _populate_table() → on_packet_selected() → plot_selection()
```

**Live Monitoring:**
```
connect_to_switch() → ISSwitchMonitor.connect() → _capture_loop() (pyshark) → packet_queue → _process_loop() → _extract_raw_data() → _parse_packet() → on_packet_received() → _add_packet_to_table()
```

**Plotting:**
```
plot_selection() → _get_selected_byte_indices() → _draw_plot() → on_hover (tooltip)
```

## UI Components

### Layout (top to bottom)
1. **Connection Controls** - Interface/IP selector dropdown (auto-detects), Switch IP/Port entry, Connect/Disconnect buttons
2. **File Controls** - Load button, file info, time mode toggle (Elapsed/Full Date)
3. **Middle Section** (horizontal split)
   - Left: Packet table (Time, Source, Dest, Bytes)
   - Right: Hex viewer (8+8 compact format) + Plot button
4. **Plot Area** - Matplotlib canvas with hover tooltips

### Styling
- Dark theme (`#141414` background, `#2b7cc7` accent blue)
- CustomTkinter modern widgets with minimal borders
- Seamless card-based layout with transparent frames

## Testing & Debugging

### Test Files
Example capture file: `192.168.15.4_test_4.pmcp` (29KB)

### Common Issues
1. **Packet loss**: Now handled by pyshark with queue buffering (max 10000 packets). If queue fills, older packets are dropped
2. **Wrong packet format**: Verify 16-byte strip is applied in `_parse_packet()`
3. **Time display errors**: Check `file_base_time` is set and DST calculation is correct
4. **Connection timeout**: Switch must respond within 2 seconds
5. **Pyshark not working**: Ensure tshark is installed and accessible in PATH
6. **Permission errors**: On Linux, may need to run `sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap` or run with sudo
7. **No interfaces found**: Check that psutil can enumerate network interfaces correctly
8. **Wrong interface selected**: Use dropdown to manually select correct local IP address

### Protocol Version
Must use `PMCN_CTRL_VERSION = 0x0101` to match real PnpMon behavior (from Wireshark analysis).

## Important Notes

- **Byte order**: Little-endian for multi-byte values in plotting
- **Hex format**: Display uses 8+8 format (16 bytes per line) with double space separator
- **Threading**: Two daemon threads for live capture: `_capture_loop()` (pyshark) and `_process_loop()` (processing). UI updates use `after(0, ...)` for thread safety
- **Table limit**: Live monitoring keeps max 1000 packets in UI table
- **Queue size**: Packet queue can buffer up to 10000 packets between capture and processing
- **Pyshark capture**: Uses BPF filter to only capture UDP packets from switch IP to local port, minimizing CPU usage
- **Interface selection**: User can select which local network interface to capture on via dropdown
- **Git**: Project is version controlled, `.idea/` PyCharm configs are tracked

## Why Pyshark?

The original implementation used raw Python sockets (`socket.recvfrom()`) for packet capture. This was changed to pyshark for the following reasons:

1. **No packet loss**: Pyshark uses tshark/libpcap which has kernel-level buffering, preventing packet loss even under high traffic
2. **Better performance**: Packet capture happens in separate thread with queue buffering, decoupling from Python processing
3. **More reliable**: Tested and proven packet capture library used by Wireshark
4. **START/STOP protocol unchanged**: Control commands remain identical, only data reception method changed

**Trade-offs:**
- Requires tshark to be installed on system
- Slightly more complex setup (interface selection)
- Additional dependency (pyshark, psutil)
