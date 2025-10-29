"""
PNPmon Enhanced - Live PMCP Switch Monitor with Advanced Viewer
================================================================
This version combines live switch monitoring with advanced viewing/plotting:
1. Connect directly to PMCP switch (live monitoring)
2. View packet table with real-time updates
3. Select hex bytes from payload
4. Plot selected bytes over time
5. Advanced features: time modes, DST handling, hex display

Author: Merged from PNPmon_V3 and Testing_PnpMon
Date: 2025-10-28
"""

# ============================================================================
# IMPORTS
# ============================================================================
import re
import socket
import struct
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional
from queue import Queue, Empty
import psutil  # For network interface detection
import asyncio  # For pyshark event loop handling

# CustomTkinter for modern UI (install: pip install customtkinter)
import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

# Matplotlib for plott
try:
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

    MPL_OK = True
except ImportError:
    MPL_OK = False

# Pyshark for packet capture (install: pip install pyshark)
try:
    import pyshark
    PYSHARK_OK = True
except ImportError:
    PYSHARK_OK = False

# ============================================================================
# CONTROL PROTOCOL CONSTANTS (for live switch connection)
# ============================================================================
# Based on Testing_PnpMon.py and C++ MoniThread.cpp analysis

# Protocol version
PMCN_CTRL_VERSION = 0x0101  # Match real PnpMon (from Wireshark capture)

# Message types
PMCN_CTRL_REQUEST = 1
PMCN_CTRL_RESPONSE = 2

# Commands
PMCN_CTRL_SET_TRAFFIC_MONITOR = 2  # Match real PnpMon
PMCN_CTRL_RESET_TRAFFIC_MONITOR = 2

# Parameters (bit flags for SET_TRAFFIC_MONITOR command)
PMCN_CTRL_PARAM_SENDER_ADDR = 0x0001  # Use sender address
PMCN_CTRL_PARAM_EXT_PROT = 0x0002  # Extended protocol
PMCN_CTRL_PARAM_BOTH = 0x0003  # Both flags (typical)

# Ports
SWITCH_DATA_PORT = 55555  # Port where switch sends packet data
SWITCH_CONTROL_PORT = 55554  # Default control port

# Buffer sizes
MAX_PACKET_SIZE = 2048  # Maximum packet size to receive


# ============================================================================
# CONTROL PROTOCOL STRUCTURES (for live switch connection)
# ============================================================================

class ControlMessageHeader:
    """
    Control message header structure for START command.
    Based on Wireshark analysis of real PnpMon behavior.

    Format (12 bytes):
    - Bytes 0-1: Version (hardcoded 01 01)
    - Bytes 2-3: Counter (increments by 2)
    - Bytes 4-7: Constant (0a 00 03 00)
    - Bytes 8-9: Constant (02 00)
    - Bytes 10-11: Port in big-endian
    """
    STRUCT_SIZE = 12

    def __init__(self, counter=0, port=0):
        self.counter = counter
        self.port = port

    def pack(self) -> bytes:
        """Pack structure into bytes for transmission."""
        version_bytes = bytes([0x01, 0x01])
        counter_bytes = struct.pack('<H', self.counter)
        constant1_bytes = bytes([0x0a, 0x00, 0x03, 0x00])
        constant2_bytes = bytes([0x02, 0x00])
        port_bytes = struct.pack('!H', self.port)

        return (version_bytes + counter_bytes + constant1_bytes +
                constant2_bytes + port_bytes)

    @classmethod
    def unpack(cls, data: bytes) -> 'ControlMessageHeader':
        """Unpack bytes into structure."""
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError("Insufficient data for control header")
        return cls(counter=0, port=0)


class ShortControlResponse:
    """
    Shortened control response structure (8 bytes).
    Some switches use this simplified format.

    Format: version(2), msgtype(2), seqcnt(4)
    """
    STRUCT_FORMAT = '!HHI'  # Network byte order (big-endian)
    STRUCT_SIZE = struct.calcsize(STRUCT_FORMAT)

    def __init__(self, version=PMCN_CTRL_VERSION, msgtype=PMCN_CTRL_RESPONSE, seqcnt=0):
        self.version = version
        self.msgtype = msgtype
        self.seqcnt = seqcnt
        self.command = 0
        self.param = 0

    @classmethod
    def unpack(cls, data: bytes) -> 'ShortControlResponse':
        """Unpack bytes into structure."""
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError("Insufficient data for short control response")
        version, msgtype, seqcnt = struct.unpack(cls.STRUCT_FORMAT, data[:cls.STRUCT_SIZE])
        return cls(version, msgtype, seqcnt)


class MessageInfo:
    """
    Extended message info structure (16 bytes).
    Equivalent to pmcnk_msginfo in C++

    Format: timestamp_sec(4), timestamp_usec(4), status(1), pad(3),
            data_offs(2), data_len(2)
    """
    STRUCT_FORMAT = '!IIBBBBHH'  # Network byte order
    STRUCT_SIZE = struct.calcsize(STRUCT_FORMAT)

    def __init__(self):
        self.timestamp_sec = 0
        self.timestamp_usec = 0
        self.status = 0
        self.data_offs = 0
        self.data_len = 0

    @classmethod
    def unpack(cls, data: bytes) -> 'MessageInfo':
        """Unpack bytes into structure."""
        if len(data) < cls.STRUCT_SIZE:
            raise ValueError("Insufficient data for message info")

        info = cls()
        (info.timestamp_sec, info.timestamp_usec, info.status,
         _, _, _, info.data_offs, info.data_len) = struct.unpack(
            cls.STRUCT_FORMAT, data[:cls.STRUCT_SIZE])
        return info


# ============================================================================
# UTILITY FUNCTIONS (reused from V2, these work well)
# ============================================================================

# Regular expression to find hex bytes (e.g., "A3", "FF", "00")
HEX_RE = re.compile(r"(?i)\b[0-9a-f]{2}\b")


def bytes_to_hex(b: bytes) -> str:
    """
    Convert bytes to hex string representation.
    Example: b'\x01\xa3\xff' -> "01 A3 FF"
    """
    return " ".join(f"{x:02X}" for x in b)


def hex_to_bytes(s: str) -> bytes:
    """
    Convert hex string to bytes.
    Example: "01 A3 FF" -> b'\x01\xa3\xff'
    """
    return bytes(int(h, 16) for h in HEX_RE.findall(s))


def _from_iso(ts: str) -> datetime:
    """Parse ISO format timestamp string to datetime object."""
    return datetime.fromisoformat(ts)


def parse_pmcp(path: str) -> Iterable[Dict[str, Any]]:
    """
    Parse .pmcp file and yield packet dictionaries.

    PMCP files are XML-based captures from PnpMon switches.
    Each packet has a 6-byte header:
        [00] [protocol] [dest_id] [dest_ch] [src_id] [src_ch] [payload...]

    Returns:
        Iterator of dicts with keys:
        - time_base: datetime of capture start
        - offs_units: offset in time units from start
        - size: total packet size in bytes
        - src_id, src_ch: source node ID and channel
        - dst_id, dst_ch: destination node ID and channel
        - payload: payload bytes (header stripped)
        - status: packet status string
    """
    base_time: Optional[datetime] = None

    # Parse XML iteratively (memory efficient for large files)
    for event, elem in ET.iterparse(path, events=("start", "end")):
        # Extract base timestamp (first timestamp in file)
        if event == "end" and elem.tag == "timestamp":
            if base_time is None:
                t = elem.get("time")
                if t:
                    try:
                        base_time = _from_iso(t)
                    except Exception:
                        pass
            elem.clear()

        # Extract packet data from <raw> tags
        if event == "end" and elem.tag == "raw":
            offs_s = elem.get("offs", "")  # time offset
            status = elem.get("status", "")  # packet status
            text = (elem.text or "").strip()  # hex data
            elem.clear()

            if not text:
                continue

            # Parse time offset
            try:
                offs_units = int(float(offs_s))
            except Exception:
                offs_units = None

            # Convert hex string to bytes
            b = hex_to_bytes(text)
            size = len(b)

            # Parse 6-byte header (if present)
            src_id = src_ch = dst_id = dst_ch = None
            payload = b  # default: all bytes
            prot = None

            if size >= 6 and b[0] == 0x00:
                prot = b[1]
                dst_id, dst_ch = b[2], b[3]
                src_id, src_ch = b[4], b[5]
                payload = b[6:]  # Strip 6-byte header

            yield {
                "time_base": base_time,
                "offs_units": offs_units,
                "size": size,
                "prot": prot,
                "src_id": src_id,
                "src_ch": src_ch,
                "dst_id": dst_id,
                "dst_ch": dst_ch,
                "status": status,
                "payload": payload,
            }


def get_network_interfaces() -> Dict[str, str]:
    """
    Get all network interfaces with their IP addresses.

    Returns:
        Dictionary mapping IP addresses to interface names
        Format: {"192.168.1.100": "Ethernet", "10.0.0.5": "Wi-Fi", ...}
    """
    interfaces = {}

    try:
        # Get all network interface addresses
        for interface_name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                # Only include IPv4 addresses (AF_INET)
                if addr.family == socket.AF_INET:
                    ip = addr.address
                    # Skip loopback addresses
                    if not ip.startswith("127."):
                        interfaces[ip] = interface_name
    except Exception as e:
        print(f"Error getting network interfaces: {e}")

    return interfaces


def get_default_interface_ip() -> Optional[str]:
    """
    Get the default network interface IP address.

    Returns:
        IP address of default interface, or None if not found
    """
    try:
        # Get all interfaces
        interfaces = get_network_interfaces()

        if not interfaces:
            return None

        # Try to find an interface that matches common patterns (192.168.x.x, 10.x.x.x)
        for ip in interfaces.keys():
            if ip.startswith("192.168.") or ip.startswith("10."):
                return ip

        # If no match, return first available IP
        return next(iter(interfaces.keys()))
    except Exception:
        return None


# ============================================================================
# IS SWITCH MONITOR CLASS (for live connection)
# ============================================================================

class ISSwitchMonitor:
    """
    Handles live connection to IS switch and packet reception using pyshark.
    Parses packets by stripping first 32 bytes (16 hex pairs) then processing remainder.
    """

    def __init__(self, callback_func, interface_name: Optional[str] = None):
        """
        Initialize monitor.

        Args:
            callback_func: Function to call when packet is received.
                          Signature: callback(packet_dict)
            interface_name: Network interface name to capture on (e.g., "Ethernet", "Wi-Fi")
        """
        self.callback = callback_func

        # Sockets
        self.control_sock: Optional[socket.socket] = None
        self.data_sock: Optional[socket.socket] = None  # Keep for START command dummy packet

        # Pyshark capture
        self.capture: Optional[pyshark.LiveCapture] = None
        self.interface_name = interface_name

        # Packet queue (pyshark -> processing thread)
        self.packet_queue: Queue = Queue(maxsize=10000)  # Buffer up to 10000 packets

        # Connection state
        self.is_monitoring = False
        self.sequence_counter = 9  # Start at 9, increments by 2 each command
        self.switch_ip = ""
        self.control_port = SWITCH_CONTROL_PORT
        self.use_extended_protocol = True
        self.local_port = 0  # Port we're listening on (from data socket)

        # Threading
        self.capture_thread: Optional[threading.Thread] = None
        self.process_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

        # Statistics
        self.packet_count = 0

    def connect(self, switch_ip: str, control_port: int) -> bool:
        """
        Connect to IS switch and start monitoring using pyshark.

        Args:
            switch_ip: IP address of the switch
            control_port: Control port of the switch

        Returns:
            True if connection successful, False otherwise
        """
        try:
            if not PYSHARK_OK:
                print("ERROR: pyshark is not installed. Install with: pip install pyshark")
                return False

            if not self.interface_name:
                print("ERROR: No network interface selected")
                return False

            self.switch_ip = switch_ip
            self.control_port = control_port

            # Create control socket (same as before)
            self.control_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.control_sock.bind(('', 0))
            self.control_sock.settimeout(2.0)

            # Create data socket (only for dummy packet - not for receiving)
            self.data_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.data_sock.bind(('', 0))
            self.data_sock.setblocking(True)

            self.local_port = self.data_sock.getsockname()[1]

            # Start monitoring
            self.is_monitoring = True
            self.packet_count = 0
            self.stop_event.clear()

            # Create pyshark capture filter
            # Filter: UDP packets from switch IP to local port (data port)
            capture_filter = f"udp and src host {switch_ip} and dst port {self.local_port}"

            # Start pyshark capture thread
            self.capture_thread = threading.Thread(
                target=self._capture_loop,
                args=(capture_filter,),
                daemon=True
            )
            self.capture_thread.start()

            # Start processing thread (reads from queue and processes packets)
            self.process_thread = threading.Thread(target=self._process_loop, daemon=True)
            self.process_thread.start()

            # Send START command (EXACTLY THE SAME AS BEFORE)
            self.sequence_counter += 2

            ctrl_msg = ControlMessageHeader(counter=self.sequence_counter, port=self.local_port)

            # Address data (12 bytes: IP + padding)
            local_addr_data = (
                    bytes([0xc0, 0xa8, 0x00, 0x01]) +  # IP: 192.168.0.1 (placeholder)
                    b'\x00' * 8  # Padding
            )

            message = ctrl_msg.pack() + local_addr_data

            # Send START command
            self.control_sock.sendto(message, (switch_ip, control_port))

            # Wait for response
            start_time = time.time()
            while (time.time() - start_time) < 2.0:
                self.control_sock.settimeout(0.1)
                try:
                    data, addr = self.control_sock.recvfrom(MAX_PACKET_SIZE)

                    if addr[0] != switch_ip:
                        continue

                    # Try to parse response (accept 8-byte or 12-byte format)
                    if len(data) >= ShortControlResponse.STRUCT_SIZE:
                        self.use_extended_protocol = True

                        # Send dummy packet for NAT hole-punching (SAME AS BEFORE)
                        self.data_sock.sendto(b'', (switch_ip, SWITCH_DATA_PORT))

                        return True

                except socket.timeout:
                    continue
                except Exception:
                    continue

            return False

        except Exception as e:
            print(f"Connection error: {e}")
            import traceback
            traceback.print_exc()
            self.disconnect()
            return False

    def disconnect(self):
        """Disconnect from switch and stop monitoring."""
        if self.is_monitoring:
            try:
                # Send STOP command (EXACTLY THE SAME AS BEFORE)
                self.sequence_counter += 2

                version_bytes = bytes([0x01, 0x01])
                counter_bytes = struct.pack('<H', self.sequence_counter)
                constant_bytes = bytes([0x0b, 0x00, 0x00, 0x00])

                stop_payload = version_bytes + counter_bytes + constant_bytes

                self.control_sock.sendto(stop_payload, (self.switch_ip, self.control_port))

                try:
                    self.control_sock.recvfrom(MAX_PACKET_SIZE)
                except socket.timeout:
                    pass

            except Exception:
                pass

        # Stop monitoring threads
        self.is_monitoring = False
        self.stop_event.set()

        # Stop pyshark capture
        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass
            self.capture = None

        # Wait for threads to finish
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)

        if self.process_thread and self.process_thread.is_alive():
            self.process_thread.join(timeout=2.0)

        # Close sockets
        if self.control_sock:
            self.control_sock.close()
            self.control_sock = None

        if self.data_sock:
            self.data_sock.close()
            self.data_sock = None

        # Clear packet queue
        while not self.packet_queue.empty():
            try:
                self.packet_queue.get_nowait()
            except Empty:
                break

    def _capture_loop(self, capture_filter: str):
        """
        Pyshark capture loop (runs in separate thread).
        Captures packets from network interface and puts them in queue.

        Args:
            capture_filter: BPF filter string for packet capture
        """
        try:
            # CRITICAL FIX for Python 3.10+ threading with asyncio:
            # Create a new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Create pyshark live capture
            # MUST use use_json=True when include_raw=True (pyshark requirement)
            self.capture = pyshark.LiveCapture(
                interface=self.interface_name,
                bpf_filter=capture_filter,
                use_json=True,
                include_raw=True
            )

            # Capture packets and add to queue
            for packet in self.capture.sniff_continuously():
                if not self.is_monitoring or self.stop_event.is_set():
                    break

                try:
                    # Put packet in queue (non-blocking with timeout)
                    self.packet_queue.put(packet, timeout=0.1)
                except Exception as e:
                    # Queue full or other error - skip this packet
                    if self.is_monitoring:
                        print(f"Queue put error: {e}")
                    continue

        except Exception as e:
            if self.is_monitoring:
                print(f"Capture error: {e}")
                import traceback
                traceback.print_exc()
        finally:
            # Clean up event loop
            try:
                loop.close()
            except Exception:
                pass

    def _process_loop(self):
        """
        Processing loop (runs in separate thread).
        Reads packets from queue and processes them.
        """
        while self.is_monitoring and not self.stop_event.is_set():
            try:
                # Get packet from queue (blocking with timeout)
                packet = self.packet_queue.get(timeout=0.5)

                # Extract raw packet data from pyshark packet
                raw_data = self._extract_raw_data(packet)

                if raw_data and len(raw_data) > 0:
                    # Parse packet (same logic as before)
                    parsed_packet = self._parse_packet(raw_data)

                    if parsed_packet:
                        self.packet_count += 1
                        if self.callback:
                            self.callback(parsed_packet)

            except Empty:
                # Queue empty, continue waiting
                continue
            except Exception as e:
                if self.is_monitoring:
                    print(f"Process error: {e}")
                continue

    def _extract_raw_data(self, packet) -> Optional[bytes]:
        """
        Extract raw packet data from pyshark packet.

        Args:
            packet: Pyshark packet object

        Returns:
            Raw packet bytes (full UDP payload), or None if extraction fails
        """
        try:
            # Method 1: Try to get UDP payload directly
            if hasattr(packet, 'udp'):
                # Try getting payload field
                if hasattr(packet.udp, 'payload'):
                    try:
                        payload_hex = str(packet.udp.payload).replace(':', '').replace(' ', '')
                        if payload_hex:
                            return bytes.fromhex(payload_hex)
                    except Exception:
                        pass

                # Method 2: Try getting data field from UDP layer
                if hasattr(packet.udp, 'data'):
                    try:
                        data_hex = str(packet.udp.data).replace(':', '').replace(' ', '')
                        if data_hex:
                            return bytes.fromhex(data_hex)
                    except Exception:
                        pass

            # Method 3: Get raw packet and extract UDP payload manually
            # UDP header is typically after Ethernet (14) + IP (20) = 34 bytes + UDP header (8) = 42 bytes
            if hasattr(packet, 'get_raw_packet'):
                try:
                    raw = packet.get_raw_packet()
                    # Skip Ethernet (14) + IP header (20) + UDP header (8) = 42 bytes
                    # This gets us to the UDP payload
                    return raw[42:]
                except Exception:
                    pass

            return None

        except Exception as e:
            if self.is_monitoring:
                print(f"Raw data extraction error: {e}")
            return None

    def _parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse received packet data.
        CRITICAL: Strips first 32 bytes (16 hex pairs) before processing.

        Process:
        1. Check if extended protocol (MessageInfo header present)
        2. Extract timestamp and payload from MessageInfo if present
        3. Strip first 32 bytes (Ethernet/IP/UDP headers) from payload
        4. Parse remainder using standard 6-byte header format
        5. Return packet dict compatible with SimplePNPMon UI

        Args:
            data: Raw packet bytes from switch

        Returns:
            Packet dictionary compatible with SimplePNPMon UI
        """
        try:
            timestamp_sec = None
            timestamp_usec = None
            actual_payload = data

            # STEP 1: Check if extended protocol (with MessageInfo header)
            if self.use_extended_protocol and len(data) >= MessageInfo.STRUCT_SIZE:
                try:
                    # Parse MessageInfo structure
                    msg_info = MessageInfo.unpack(data)

                    # Extract timestamp from MessageInfo
                    timestamp_sec = msg_info.timestamp_sec
                    timestamp_usec = msg_info.timestamp_usec

                    # Extract actual payload from offset
                    if msg_info.data_offs + msg_info.data_len <= len(data):
                        actual_payload = data[msg_info.data_offs:msg_info.data_offs + msg_info.data_len]
                    else:
                        # Invalid MessageInfo, fall back to using entire data
                        actual_payload = data
                        timestamp_sec = None
                        timestamp_usec = None
                except Exception:
                    # Failed to parse MessageInfo, use entire data
                    actual_payload = data
                    timestamp_sec = None
                    timestamp_usec = None

            # STEP 2: Strip first 16 bytes (32 hex numbers = 16 hex pairs) - Ethernet/IP/UDP headers
            # User wants to remove 32 hex numbers, which equals 16 bytes (since 2 hex digits = 1 byte)
            if len(actual_payload) < 16:
                return None

            actual_payload = actual_payload[16:]

            # STEP 3: Now parse using standard 6-byte header format
            # Format: [00] [protocol] [dest_id] [dest_ch] [src_id] [src_ch] [payload...]
            # This matches the parse_pmcp() function format EXACTLY
            #
            # Key: After stripping first 32 bytes (Ethernet/IP/UDP headers),
            # the remainder is processed exactly like parse_pmcp() processes file data:
            # - Check if it has a 6-byte header (starts with 0x00)
            # - Extract header fields (protocol, dest_id, dest_ch, src_id, src_ch)
            # - Strip the 6-byte header from payload
            # - size = total length BEFORE stripping 6-byte header (matches parse_pmcp line 247)

            size = len(actual_payload)  # Total size (includes 6-byte header if present)
            src_id = src_ch = dst_id = dst_ch = None
            payload = actual_payload  # default: all bytes if no header found
            prot = None

            if size >= 6 and actual_payload[0] == 0x00:
                prot = actual_payload[1]
                dst_id, dst_ch = actual_payload[2], actual_payload[3]
                src_id, src_ch = actual_payload[4], actual_payload[5]
                payload = actual_payload[6:]  # Strip 6-byte header, matches parse_pmcp line 258

            # STEP 4: Calculate timestamp for packet
            # Use MessageInfo timestamp if available, otherwise use current time
            if timestamp_sec is not None and timestamp_usec is not None:
                # Convert to microseconds offset (like Testing_PnpMon does)
                offs_units = timestamp_sec * 1000000 + timestamp_usec
                time_base = None  # Will be set by UI when first packet arrives
            else:
                # Fallback: use current time
                offs_units = int(time.time() * 1000000)
                time_base = None

            # Create packet dictionary compatible with SimplePNPMon
            return {
                "time_base": time_base,
                "offs_units": offs_units,
                "size": size,
                "prot": prot,
                "src_id": src_id,
                "src_ch": src_ch,
                "dst_id": dst_id,
                "dst_ch": dst_ch,
                "status": "",
                "payload": payload,
            }

        except Exception as e:
            print(f"Parse error: {e}")
            import traceback
            traceback.print_exc()
            return None


# ============================================================================
# MAIN APPLICATION CLASS
# ============================================================================

class SimplePNPMon(ctk.CTk):
    """
    Main application window for PNPmon V3.

    This class handles:
    - UI layout and widgets
    - File loading
    - Table display
    - Hex selection
    - Plotting functionality
    """

    def __init__(self):
        super().__init__()

        # ====================================================================
        # WINDOW CONFIGURATION
        # ====================================================================
        self.title("PNPmon Enhanced - PMCP Viewer")
        self.geometry("1400x900")

        # Set modern dark theme with smooth appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Configure window background for seamless look
        self.configure(fg_color=("#f0f0f0", "#0a0a0a"))  # Light/Dark mode colors

        # ====================================================================
        # DATA STORAGE
        # ====================================================================
        self.packets = []  # List of all parsed packets
        self.selected_packet_idx = None  # Index of currently selected packet
        self.file_path = None  # Path to loaded file
        self.file_base_time = None  # Base timestamp from file (for absolute time mode)
        self.units_per_sec = 1000000.0  # Conversion factor for time units to seconds (divide by 1000000.0)
        self.time_mode = tk.StringVar(value="elapsed")  # Time display mode: "elapsed" or "absolute"
        self.is_live_data = False  # Track if data is from live monitoring (True) or file (False)

        # Plot data storage (for refreshing when time mode changes)
        self.plot_times = []  # Time values for current plot (in seconds)
        self.plot_values = []  # Y-axis values for current plot
        self.plot_byte_indices = []  # Which byte indices are being plotted
        self.plot_datetimes = []  # Datetime objects for tooltips (with DST applied)
        self.plot_filter_src_id = None  # Source node ID for plot filtering
        self.plot_filter_src_ch = None  # Source channel for plot filtering
        self.plot_filter_dst_id = None  # Destination node ID for plot filtering
        self.plot_filter_dst_ch = None  # Destination channel for plot filtering
        self.live_plot_timer_id = None  # Timer ID for live plot updates
        self.live_plot_update_interval = 100  # Update plot every 100ms (0.1 seconds)

        # Pause tracking for red line visualization
        self.pause_ranges = []  # List of (start_packet_idx, end_packet_idx) tuples for pause periods
        self.pause_start_idx = None  # Packet index when pause was pressed
        self.waiting_for_resume_packet = False  # Flag to capture first packet after resume

        # Node mapping (friendly names for node IDs)
        self.node_map = {
            11: "PMC-R",
            12: "Shearer",
            20: "PLC",
            31: "VShield",
            60: "I/O",
            71: "??",
            72: "PPD",
            1: "Provider",
            88: "MG PAM",  # Added from Testing_PnpMon
        }

        # ====================================================================
        # LIVE MONITORING (for switch connection)
        # ====================================================================
        self.monitor: Optional[ISSwitchMonitor] = None
        self.is_connected = False
        self.live_base_time = None  # Base timestamp for live monitoring (first packet time)
        self.auto_scroll_enabled = True  # Auto-scroll to newest packets in live mode
        self.is_paused = False  # Pause state for monitoring

        # Network interface selection
        self.available_interfaces = get_network_interfaces()  # Dict: {ip: interface_name}
        self.selected_interface_ip = get_default_interface_ip()  # Default IP
        self.selected_interface_name = None
        if self.selected_interface_ip and self.selected_interface_ip in self.available_interfaces:
            self.selected_interface_name = self.available_interfaces[self.selected_interface_ip]

        # ====================================================================
        # BUILD UI
        # ====================================================================
        self._build_ui()

        # Initialize monitor (callback will be set after UI is built)
        self.monitor = ISSwitchMonitor(
            callback_func=self.on_packet_received,
            interface_name=self.selected_interface_name
        )

        # Handle window close event
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Display welcome message
        self._set_status("Ready - Load a .pmcp file or connect to switch")

    def _build_ui(self):
        """
        Build the seamless modern user interface.
        Single-column flow with minimal visual separation.
        """

        # ====================================================================
        # CONNECTION CONTROLS (at very top)
        # ====================================================================
        conn_frame = ctk.CTkFrame(self, fg_color="transparent")
        conn_frame.pack(side=tk.TOP, fill=tk.X, padx=15, pady=(15, 8))

        # Title label
        ctk.CTkLabel(
            conn_frame,
            text="Live Connection:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#666666", "#999999")
        ).pack(side=tk.LEFT, padx=(0, 12))

        # Network Interface selection
        ctk.CTkLabel(
            conn_frame,
            text="Local IP:",
            font=ctk.CTkFont(size=11),
            text_color=("#666666", "#999999")
        ).pack(side=tk.LEFT, padx=(0, 6))

        # Create dropdown with available IPs
        interface_ips = list(self.available_interfaces.keys()) if self.available_interfaces else ["No interfaces found"]
        default_value = self.selected_interface_ip if self.selected_interface_ip else (interface_ips[0] if interface_ips else "No interfaces")

        self.interface_dropdown = ctk.CTkComboBox(
            conn_frame,
            values=interface_ips,
            command=self._on_interface_changed,
            width=140,
            font=ctk.CTkFont(size=11),
            height=32,
            state="readonly"
        )
        self.interface_dropdown.set(default_value)
        self.interface_dropdown.pack(side=tk.LEFT, padx=(0, 12))

        # IP Address input
        ctk.CTkLabel(
            conn_frame,
            text="Switch IP:",
            font=ctk.CTkFont(size=11),
            text_color=("#666666", "#999999")
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.ip_entry = ctk.CTkEntry(
            conn_frame,
            width=130,
            placeholder_text="192.168.15.4",
            font=ctk.CTkFont(size=11),
            height=32
        )
        self.ip_entry.insert(0, "192.168.15.4")
        self.ip_entry.pack(side=tk.LEFT, padx=(0, 12))

        # Port input
        ctk.CTkLabel(
            conn_frame,
            text="Port:",
            font=ctk.CTkFont(size=11),
            text_color=("#666666", "#999999")
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.port_entry = ctk.CTkEntry(
            conn_frame,
            width=70,
            placeholder_text="55554",
            font=ctk.CTkFont(size=11),
            height=32
        )
        self.port_entry.insert(0, "55554")
        self.port_entry.pack(side=tk.LEFT, padx=(0, 12))

        # Connect button
        self.connect_btn = ctk.CTkButton(
            conn_frame,
            text="🔌 Connect",
            command=self.connect_to_switch,
            width=100,
            height=32,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
            fg_color=("#2b7cc7", "#1a5a9e"),
            hover_color=("#3a7ebf", "#1f538d")
        )
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Disconnect button
        self.disconnect_btn = ctk.CTkButton(
            conn_frame,
            text="❌ Disconnect",
            command=self.disconnect_from_switch,
            width=100,
            height=32,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
            fg_color=("#cc6666", "#994444"),
            hover_color=("#dd7777", "#aa5555"),
            state="disabled"
        )
        self.disconnect_btn.pack(side=tk.LEFT, padx=(0, 12))

        # Auto-scroll toggle button
        self.autoscroll_btn = ctk.CTkButton(
            conn_frame,
            text="📜 Auto-Scroll: ON",
            command=self._toggle_autoscroll,
            width=140,
            height=32,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
            fg_color=("#2b7cc7", "#1a5a9e"),
            hover_color=("#3a7ebf", "#1f538d")
        )
        self.autoscroll_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Pause/Resume button for monitoring
        self.pause_btn = ctk.CTkButton(
            conn_frame,
            text="⏸ Pause",
            command=self._toggle_pause,
            width=100,
            height=32,
            font=ctk.CTkFont(size=11, weight="bold"),
            corner_radius=6,
            fg_color=("#cc8800", "#aa6600"),
            hover_color=("#dd9900", "#bb7700"),
            state="disabled"
        )
        self.pause_btn.pack(side=tk.LEFT)

        # ====================================================================
        # FILE LOADING AREA (integrated below connection)
        # ====================================================================
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(side=tk.TOP, fill=tk.X, padx=15, pady=(8, 8))

        # Modern load button with integrated status
        self.load_btn = ctk.CTkButton(
            top_frame,
            text="📁 Load PMCP File",
            command=self.load_file,
            height=42,
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=8,
            hover_color=("#3a7ebf", "#1f538d"),
            fg_color=("#2b7cc7", "#1a5a9e")
        )
        self.load_btn.pack(side=tk.LEFT, padx=(0, 12), fill=tk.X, expand=True)

        # File info integrated inline (replaces separate status bar)
        self.file_label = ctk.CTkLabel(
            top_frame,
            text="No file loaded",
            font=ctk.CTkFont(size=12),
            text_color=("#999999", "#666666"),
            anchor="w"
        )
        self.file_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Time mode toggle (seamlessly integrated)
        time_mode_frame = ctk.CTkFrame(top_frame, fg_color="transparent")
        time_mode_frame.pack(side=tk.LEFT, padx=(12, 0))

        ctk.CTkLabel(
            time_mode_frame,
            text="Time:",
            font=ctk.CTkFont(size=11),
            text_color=("#888888", "#666666")
        ).pack(side=tk.LEFT, padx=(0, 6))

        self.time_mode_segmented = ctk.CTkSegmentedButton(
            time_mode_frame,
            values=["Elapsed", "Full Date"],
            command=self._on_time_mode_changed,
            font=ctk.CTkFont(size=11),
            height=32,
            corner_radius=6,
            fg_color=("#2a2a2a", "#1a1a1a"),
            selected_color=("#2b7cc7", "#1a5a9e"),
            selected_hover_color=("#3a7ebf", "#1f538d"),
            unselected_color=("#1a1a1a", "#0f0f0f"),
            unselected_hover_color=("#2a2a2a", "#1a1a1a")
        )
        self.time_mode_segmented.set("Elapsed")
        self.time_mode_segmented.pack(side=tk.LEFT)

        # ====================================================================
        # MIDDLE SECTION - TABLE (LEFT) + OVERVIEW (RIGHT)
        # ====================================================================
        middle_container = ctk.CTkFrame(self, fg_color="transparent")
        middle_container.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=15, pady=(0, 8))

        # Configure grid layout for horizontal split
        middle_container.grid_columnconfigure(0, weight=3, minsize=400)  # Table takes 60% (weight=3)
        middle_container.grid_columnconfigure(1, weight=2, minsize=300)  # Overview takes 40% (weight=2)
        middle_container.grid_rowconfigure(0, weight=1)

        # ====================================================================
        # LEFT SIDE - PACKET TABLE
        # ====================================================================
        table_frame = ctk.CTkFrame(middle_container, fg_color="transparent")
        table_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        # Subtle card container with minimal elevation
        tree_card = tk.Frame(table_frame, bg="#141414", highlightthickness=0)
        tree_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        columns = ("time", "source", "dest", "size")

        # Modern minimal styling for table
        style = ttk.Style()
        style.theme_use("clam")

        # Ultra-minimal scrollbar styling (thin, low contrast)
        style.configure("Minimal.Vertical.TScrollbar",
                        background="#1a1a1a",
                        troughcolor="#0f0f0f",
                        borderwidth=0,
                        arrowsize=0,
                        width=8)
        style.configure("Minimal.Horizontal.TScrollbar",
                        background="#1a1a1a",
                        troughcolor="#0f0f0f",
                        borderwidth=0,
                        arrowsize=0,
                        width=8)
        style.map("Minimal.Vertical.TScrollbar",
                  background=[("active", "#2a2a2a"), ("!active", "#1a1a1a")])
        style.map("Minimal.Horizontal.TScrollbar",
                  background=[("active", "#2a2a2a"), ("!active", "#1a1a1a")])

        # Seamless table styling
        style.configure("Treeview",
                        background="#141414",
                        foreground="#d0d0d0",
                        fieldbackground="#141414",
                        borderwidth=0,
                        relief="flat",
                        rowheight=28)
        style.configure("Treeview.Heading",
                        background="#1a1a1a",
                        foreground="#999999",
                        borderwidth=0,
                        relief="flat",
                        font=("Segoe UI", 9))
        style.map("Treeview",
                  background=[("selected", "#2b5a8e")],
                  foreground=[("selected", "#ffffff")])
        style.map("Treeview.Heading",
                  background=[("active", "#222222")])

        self.tree = ttk.Treeview(
            tree_card,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        # Column configuration
        self.tree.heading("time", text="Time (s)")
        self.tree.heading("source", text="Source")
        self.tree.heading("dest", text="Destination")
        self.tree.heading("size", text="Bytes")

        self.tree.column("time", width=200, anchor=tk.CENTER)
        self.tree.column("source", width=180, anchor=tk.CENTER)
        self.tree.column("dest", width=180, anchor=tk.CENTER)
        self.tree.column("size", width=90, anchor=tk.CENTER)

        # Minimal scrollbars
        vsb = ttk.Scrollbar(tree_card, orient="vertical", command=self.tree.yview, style="Minimal.Vertical.TScrollbar")
        hsb = ttk.Scrollbar(tree_card, orient="horizontal", command=self.tree.xview,
                            style="Minimal.Horizontal.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_card.rowconfigure(0, weight=1)
        tree_card.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self.on_packet_selected)

        # ====================================================================
        # RIGHT SIDE - OVERVIEW SECTION
        # ====================================================================
        overview_frame = ctk.CTkFrame(middle_container, fg_color="transparent")
        overview_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        # Overview label
        overview_label = ctk.CTkLabel(
            overview_frame,
            text="Overview",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#999999", "#888888"),
            anchor="w"
        )
        overview_label.pack(side=tk.TOP, anchor="w", padx=0, pady=(0, 8))

        # Hex card container
        hex_card = tk.Frame(overview_frame, bg="#141414", highlightthickness=0)
        hex_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        self.hex_text = tk.Text(
            hex_card,
            wrap="word",  # Enable wrapping for compact display
            font=("Consolas", 10),
            bg="#141414",
            fg="#b8b8b8",
            insertbackground="#888888",
            selectbackground="#2b5a8e",
            selectforeground="#ffffff",
            borderwidth=0,
            highlightthickness=0,
            padx=8,
            pady=6
        )

        # Minimal scrollbar for hex (vertical only, wrapping handles horizontal)
        hex_vsb = ttk.Scrollbar(hex_card, orient="vertical", command=self.hex_text.yview,
                                style="Minimal.Vertical.TScrollbar")
        self.hex_text.configure(yscrollcommand=hex_vsb.set)

        self.hex_text.grid(row=0, column=0, sticky="nsew")
        hex_vsb.grid(row=0, column=1, sticky="ns")
        hex_card.rowconfigure(0, weight=1)
        hex_card.columnconfigure(0, weight=1)

        # Plot button (integrated seamlessly)
        self.plot_btn = ctk.CTkButton(
            overview_frame,
            text="📊 Plot Selection",
            command=self.plot_selection,
            height=38,
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
            hover_color=("#3a7ebf", "#1f538d"),
            fg_color=("#2b7cc7", "#1a5a9e")
        )
        self.plot_btn.pack(side=tk.BOTTOM, padx=0, pady=(8, 0), fill=tk.X)

        # ====================================================================
        # PLOT AREA (seamless integration)
        # ====================================================================
        plot_frame = ctk.CTkFrame(self, fg_color="transparent")
        plot_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        # Plot card container
        if MPL_OK:
            plot_card = tk.Frame(plot_frame, bg="#141414", highlightthickness=0)
            plot_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

            # Increase height and add padding for tooltips at top
            self.plot_fig = Figure(figsize=(10, 5.0), facecolor='#141414')
            self.plot_ax = self.plot_fig.add_subplot(111)
            # Add extra top padding to prevent tooltip from squishing plot
            self.plot_fig.subplots_adjust(top=0.85, bottom=0.15, left=0.10, right=0.95)
            self.plot_ax.set_facecolor('#141414')
            self.plot_ax.set_xlabel("Time (seconds)", fontsize=10, color="#999999")
            self.plot_ax.set_ylabel("Value", fontsize=10, color="#999999")
            self.plot_ax.set_title("Select bytes in hex area above, then click Plot", fontsize=9, color="#666666",
                                   pad=8)
            self.plot_ax.tick_params(colors="#888888", labelsize=8)
            self.plot_ax.grid(True, alpha=0.12, color="#2a2a2a", linewidth=0.5)

            for spine in self.plot_ax.spines.values():
                spine.set_edgecolor('#2a2a2a')
                spine.set_linewidth(0.5)

            self.plot_canvas = FigureCanvasTkAgg(self.plot_fig, master=plot_card)
            self.plot_canvas.get_tk_widget().configure(bg='#141414', highlightthickness=0)
            self.plot_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        else:
            error_label = ctk.CTkLabel(
                plot_frame,
                text="⚠️ Matplotlib not installed. Run: pip install matplotlib",
                font=ctk.CTkFont(size=11),
                text_color="#cc6666"
            )
            error_label.pack(fill=tk.BOTH, expand=True)
            self.plot_ax = None
            self.plot_canvas = None

    # ========================================================================
    # FILE LOADING
    # ========================================================================

    def load_file(self):
        """
        Open file dialog and load selected .pmcp file.
        This parses the file and populates the packet table.
        """
        # Show file picker dialog
        path = filedialog.askopenfilename(
            title="Select PMCP File",
            filetypes=[("PMCP Files", "*.pmcp"), ("All Files", "*.*")]
        )

        if not path:
            return  # User cancelled

        try:
            # Parse the file
            self._set_status(f"Loading {path}...")
            self.packets = list(parse_pmcp(path))
            self.file_path = path
            self.is_live_data = False  # File data (DST adjustment will be applied)

            # Clear pause ranges (only relevant for live data)
            self.pause_ranges = []
            self.pause_start_idx = None
            self.waiting_for_resume_packet = False

            # Extract base time from first packet (for absolute time mode)
            if self.packets and self.packets[0].get("time_base"):
                self.file_base_time = self.packets[0]["time_base"]
            else:
                self.file_base_time = None

            # Update UI
            import os
            filename = os.path.basename(path)
            self.file_label.configure(text=f"Loaded: {filename} ({len(self.packets)} packets)")

            # Populate table
            self._populate_table()

            # Clear hex display and plot
            self.hex_text.delete("1.0", tk.END)
            if self.plot_ax:
                self.plot_ax.clear()
                self.plot_ax.set_facecolor('#141414')
                self.plot_ax.set_xlabel("Time (seconds)", fontsize=10, color="#999999")
                self.plot_ax.set_ylabel("Value", fontsize=10, color="#999999")
                self.plot_ax.set_title("Select bytes in hex area above, then click Plot", fontsize=9, color="#666666",
                                       pad=8)
                self.plot_ax.tick_params(colors="#888888", labelsize=8)
                self.plot_ax.grid(True, alpha=0.12, color="#2a2a2a", linewidth=0.5)
                for spine in self.plot_ax.spines.values():
                    spine.set_edgecolor('#2a2a2a')
                    spine.set_linewidth(0.5)
                self.plot_canvas.draw()

            self._set_status(f"Loaded {len(self.packets)} packets from {filename}")

        except Exception as e:
            messagebox.showerror("Load Error", f"Failed to load file:\n{str(e)}")
            self._set_status("Load failed")

    def _populate_table(self):
        """
        Fill the packet table with data from loaded packets.
        Displays: Time (elapsed or absolute), Source, Destination, Size
        """
        # Clear existing rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add rows for each packet
        for idx, packet in enumerate(self.packets):
            # Format time based on selected mode
            if self.time_mode.get() == "elapsed":
                # Elapsed time in seconds
                time_sec = self._offs_to_seconds(packet["offs_units"])
                time_str = f"{time_sec:.6f}" if time_sec is not None else "N/A"
            else:
                # Absolute datetime
                dt = self._offs_to_datetime(packet["offs_units"])
                time_str = self._fmt_time_abs(dt) if dt else "N/A"

            # Format source and destination (e.g., "60:12")
            src = self._format_node(packet["src_id"], packet["src_ch"])
            dst = self._format_node(packet["dst_id"], packet["dst_ch"])

            # Payload size
            size = len(packet["payload"])

            # Insert row (store index as iid for later retrieval)
            self.tree.insert("", tk.END, iid=str(idx), values=(time_str, src, dst, size))

    def _offs_to_seconds(self, offs_units: Optional[int]) -> Optional[float]:
        """
        Convert offset units to seconds.

        Args:
            offs_units: Time offset in arbitrary units

        Returns:
            Time in seconds, or None if offs_units is None
        """
        if offs_units is None:
            return None
        return offs_units / self.units_per_sec

    def _format_node(self, node_id: Optional[int], channel: Optional[int]) -> str:
        """
        Format node ID and channel with friendly name.
        Format: "id:channel Name" (e.g., "11:1 PMC-R", "60:12 I/O")
        The name is determined by the node_id (first number), but both numbers are always shown.

        Args:
            node_id: Node ID number
            channel: Channel number

        Returns:
            Formatted string, or "—" if data missing
        """
        if node_id is None or channel is None:
            return "—"

        # Get friendly name from node_map (if available)
        name = self.node_map.get(node_id, "")

        # Format: "id:channel Name" or just "id:channel" if no name
        if name:
            return f"{node_id}:{channel} {name}"
        else:
            return f"{node_id}:{channel}"

    def _is_dst_nsw(self, dt: datetime) -> bool:
        """
        Check if a given date falls within NSW Australia Daylight Saving Time period.

        Simplified date-only check:
        - Starts: First Sunday in October
        - Ends: First Sunday in April (next year)
        - If date is within this range, return True

        Args:
            dt: Datetime object to check

        Returns:
            True if date is within DST period, False otherwise
        """
        from datetime import timedelta, date

        # Extract just the date (ignoring time component to avoid timezone issues)
        check_date = dt.date() if hasattr(dt, 'date') else dt

        # Find first Sunday in October for this year
        october_1st = date(check_date.year, 10, 1)
        days_until_sunday = (6 - october_1st.weekday()) % 7
        dst_start_date = october_1st + timedelta(days=days_until_sunday)

        # Find first Sunday in April for the NEXT year (DST ends in following year)
        april_1st_next = date(check_date.year + 1, 4, 1)
        days_until_sunday_april = (6 - april_1st_next.weekday()) % 7
        dst_end_date_next = april_1st_next + timedelta(days=days_until_sunday_april)

        # Also check if we're in DST from previous year (before April of current year)
        april_1st_current = date(check_date.year, 4, 1)
        days_until_sunday_april_current = (6 - april_1st_current.weekday()) % 7
        dst_end_date_current = april_1st_current + timedelta(days=days_until_sunday_april_current)

        # Simple date comparison (no time/timezone issues)
        # Check if we're before April DST end (meaning we're in DST from previous October)
        if check_date < dst_end_date_current:
            return True

        # Check if we're after October DST start (meaning we're in DST until next April)
        if check_date >= dst_start_date:
            return True

        return False

    def _apply_dst_adjustment(self, dt: Optional[datetime]) -> Optional[datetime]:
        """
        Apply NSW Australia DST adjustment to a datetime if it falls within DST period.

        Args:
            dt: Datetime object to adjust

        Returns:
            Adjusted datetime (+1 hour if in DST), or None if input is None
        """
        if dt is None:
            return None

        from datetime import timedelta

        # Check if datetime falls within DST period
        if self._is_dst_nsw(dt):
            # Add 1 hour for DST
            return dt + timedelta(hours=1)

        return dt

    def _offs_to_datetime(self, offs_units: Optional[int]) -> Optional[datetime]:
        """
        Convert offset units to absolute datetime with NSW DST adjustment.
        DST adjustment is ONLY applied to file data, not live monitoring data.

        Args:
            offs_units: Time offset in arbitrary units

        Returns:
            Absolute datetime (with DST applied for file data only), or None if base_time not available
        """
        if self.file_base_time is None or offs_units is None:
            return None
        from datetime import timedelta
        seconds = self._offs_to_seconds(offs_units)
        if seconds is None:
            return None
        dt = self.file_base_time + timedelta(seconds=seconds)
        # Apply DST adjustment ONLY for file data (live monitoring already has correct time)
        if not self.is_live_data:
            return self._apply_dst_adjustment(dt)
        return dt

    def _fmt_time_abs(self, dt: Optional[datetime]) -> str:
        """
        Format datetime as string for display with 24-hour format.

        Args:
            dt: Datetime object

        Returns:
            Formatted string "YYYY-MM-DD HH:MM:SS.mmm" or empty string
        """
        if dt is None:
            return ""
        # Use %H for 24-hour format (00-23)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def _format_hex_compact(self, payload: bytes) -> str:
        """
        Format hex bytes in compact 8+8 format for display.
        Format: 8 hex pairs, space, 8 hex pairs, newline
        Example:
            01 A3 FF 2C 00 00 1E 4A  5B 3D 88 91 CC 45 12 90
            AB CD EF 01 23 45 67 89  ...

        Args:
            payload: Bytes to format

        Returns:
            Formatted hex string with newlines
        """
        if not payload:
            return ""

        lines = []
        for i in range(0, len(payload), 16):  # 16 bytes per line
            chunk = payload[i:i + 16]

            # Split into two groups of 8
            first_8 = chunk[:8]
            second_8 = chunk[8:16]

            # Format each group
            first_str = " ".join(f"{b:02X}" for b in first_8)
            second_str = " ".join(f"{b:02X}" for b in second_8)

            # Combine with double space separator
            if second_str:
                line = f"{first_str}  {second_str}"
            else:
                line = first_str

            lines.append(line)

        return "\n".join(lines)

    # ========================================================================
    # PACKET SELECTION
    # ========================================================================

    def on_packet_selected(self, event):
        """
        Called when user clicks a row in the packet table.
        Displays the hex payload of the selected packet in compact 8+8 format.
        Also disables auto-scroll so user can browse packets.
        """
        selection = self.tree.selection()
        if not selection:
            return

        # Disable auto-scroll when user manually selects a packet
        if self.is_connected:
            if self.auto_scroll_enabled:
                self.auto_scroll_enabled = False
            # Always update button to ensure UI stays in sync
            self._update_autoscroll_button()

        # Get packet index from selection
        try:
            self.selected_packet_idx = int(selection[0])
        except (ValueError, IndexError):
            return

        # Get packet data
        packet = self.packets[self.selected_packet_idx]
        payload = packet["payload"]

        # Display hex bytes in compact 8+8 format
        hex_str = self._format_hex_compact(payload)

        # Clear and update hex display
        self.hex_text.delete("1.0", tk.END)
        self.hex_text.insert("1.0", hex_str)

        # Update status
        self._set_status(
            f"Selected packet {self.selected_packet_idx + 1}/{len(self.packets)} - "
            f"Payload: {len(payload)} bytes"
        )

    # ========================================================================
    # HEX SELECTION AND PLOTTING
    # ========================================================================

    def _draw_plot(self):
        """
        Draw or refresh the plot with current plot data.
        Handles time formatting based on current time mode:
        - Elapsed mode: Show seconds
        - Full Date mode: Show time only (HH:MM:SS.mmm), not full date

        Also adds interactive tooltips that show on hover.
        """
        if not self.plot_times or not self.plot_values or not MPL_OK:
            return

        # Clear and setup plot
        self.plot_ax.clear()
        self.plot_ax.set_facecolor('#141414')

        # Prepare time values based on mode
        if self.time_mode.get() == "elapsed":
            # Use seconds directly
            x_values = self.plot_times
            x_label = "Time (seconds)"
        else:
            # Convert to datetime objects and format as time only
            from datetime import timedelta
            if self.file_base_time:
                # Convert datetime objects to matplotlib date numbers explicitly
                # Apply 10-hour correction to fix matplotlib timezone interpretation issue
                from matplotlib.dates import date2num, DateFormatter
                x_values = [date2num(dt - timedelta(hours=10)) for dt in self.plot_datetimes if dt is not None]
                x_label = "Time (24-hour format)"

                # Format x-axis to show time only (no date) with 24-hour format
                time_formatter = DateFormatter('%H:%M:%S')
                self.plot_ax.xaxis.set_major_formatter(time_formatter)
                # Rotate labels for better readability
                self.plot_fig.autofmt_xdate(rotation=45)
            else:
                # Fallback to seconds if no base time
                x_values = self.plot_times
                x_label = "Time (seconds)"

        # Draw all points in blue first
        line, = self.plot_ax.plot(x_values, self.plot_values, marker='o', linestyle='-',
                                  linewidth=1.8, markersize=4,
                                  color='#3a7ebf', markerfacecolor='#5da3e8', markeredgecolor='#5da3e8',
                                  zorder=1)

        # Draw red line segments for pause gaps
        # Each pause range is (start_idx, end_idx) where:
        # - start_idx = last packet before pause
        # - end_idx = first packet after resume
        # We only draw the line segment connecting these two points in red
        for start_idx, end_idx in self.pause_ranges:
            if start_idx < len(self.plot_values) and end_idx < len(self.plot_values):
                # Draw red line from last point before pause to first point after resume
                self.plot_ax.plot([x_values[start_idx], x_values[end_idx]],
                                 [self.plot_values[start_idx], self.plot_values[end_idx]],
                                 color='#ff4444', linewidth=2.5, linestyle='-', zorder=2)
                # Draw red markers on these two points
                self.plot_ax.plot(x_values[start_idx], self.plot_values[start_idx], marker='o',
                                 markersize=5, color='#ff4444', markerfacecolor='#ff6666',
                                 markeredgecolor='#ff6666', zorder=3)
                self.plot_ax.plot(x_values[end_idx], self.plot_values[end_idx], marker='o',
                                 markersize=5, color='#ff4444', markerfacecolor='#ff6666',
                                 markeredgecolor='#ff6666', zorder=3)

        # Set labels and styling
        self.plot_ax.set_xlabel(x_label, fontsize=10, color="#999999")
        self.plot_ax.set_ylabel("Value", fontsize=10, color="#999999")
        self.plot_ax.tick_params(colors="#888888", labelsize=8)

        # Create title showing which bytes are plotted
        byte_range = f"bytes [{self.plot_byte_indices[0]}"
        if len(self.plot_byte_indices) > 1:
            byte_range += f"-{self.plot_byte_indices[-1]}"
        byte_range += "]"

        self.plot_ax.set_title(
            f"Value of Bytes Over Time",
            fontsize=9,
            color="#666666",
            pad=8
        )

        # Grid and spines
        self.plot_ax.grid(True, alpha=0.12, color="#2a2a2a", linewidth=0.5)
        for spine in self.plot_ax.spines.values():
            spine.set_edgecolor('#2a2a2a')
            spine.set_linewidth(0.5)

        # CRITICAL: Lock plot limits to prevent tooltip from moving points
        self.plot_ax.set_xlim(self.plot_ax.get_xlim())
        self.plot_ax.set_ylim(self.plot_ax.get_ylim())

        # Create tooltip annotation (initially invisible)
        annot = self.plot_ax.annotate(
            "",
            xy=(0, 0),
            xytext=(15, 15),
            textcoords="offset points",
            bbox=dict(boxstyle="round,pad=0.5", fc="#2a2a2a", ec="#5da3e8", lw=1.5, alpha=0.95),
            arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=0", color="#5da3e8", lw=1.5),
            fontsize=9,
            color="#ffffff",
            visible=False,
            zorder=100,
            clip_on=False  # Prevent annotation from affecting plot bounds
        )

        # Event handler for mouse hover
        def on_hover(event):
            """Show tooltip when hovering over a data point."""
            if event.inaxes != self.plot_ax:
                if annot.get_visible():
                    annot.set_visible(False)
                    self.plot_canvas.draw_idle()
                return

            # Check if mouse is near any data point
            cont, ind = line.contains(event)
            if cont:
                # Get the index of the nearest point
                point_index = ind["ind"][0]

                # Get value at this point
                value = self.plot_values[point_index]

                # Format time based on current mode
                if self.time_mode.get() == "elapsed":
                    time_str = f"{self.plot_times[point_index]:.6f}s"
                else:
                    # Use datetime with DST applied, formatted with 24-hour format
                    if self.plot_datetimes and point_index < len(self.plot_datetimes):
                        dt = self.plot_datetimes[point_index]
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    else:
                        time_str = f"{self.plot_times[point_index]:.6f}s"

                # Update annotation text and position
                annot.xy = (x_values[point_index], value)
                text = f"Value: {value}\nTime: {time_str}"
                annot.set_text(text)
                annot.set_visible(True)
                self.plot_canvas.draw_idle()
            else:
                if annot.get_visible():
                    annot.set_visible(False)
                    self.plot_canvas.draw_idle()

        # Connect the hover event
        self.plot_canvas.mpl_connect("motion_notify_event", on_hover)

        # Redraw canvas
        self.plot_canvas.draw()

    def plot_selection(self):
        """
        Plot the selected hex bytes across all packets over time.

        How it works:
        1. User selects hex bytes in the hex display (by dragging)
        2. This method extracts which byte positions were selected
        3. For each packet, extract the value at those byte positions
        4. Plot the values vs time

        Byte order: Little-endian (LSB first)
        Example: bytes [A3 FF] -> value = 0xFFA3 = 65443
        """
        if not self.packets:
            messagebox.showinfo("No Data", "Please load a .pmcp file first")
            return

        if not MPL_OK:
            messagebox.showerror("Plot Error", "Matplotlib not installed")
            return

        # Get selected text range
        try:
            sel_start = self.hex_text.index(tk.SEL_FIRST)
            sel_end = self.hex_text.index(tk.SEL_LAST)
        except tk.TclError:
            messagebox.showinfo("No Selection", "Please select hex bytes to plot")
            return

        # Get selected text
        selected_text = self.hex_text.get(sel_start, sel_end)

        # Extract byte positions from selection
        # Hex bytes are displayed as "AA BB CC DD" with spaces
        # We need to figure out which byte indices were selected
        byte_indices = self._get_selected_byte_indices(sel_start, sel_end)

        if not byte_indices:
            messagebox.showinfo("Invalid Selection", "Please select complete hex bytes (e.g., 'A3 FF')")
            return

        # Get the currently selected packet's routing info to filter by exact src:ch -> dest:ch
        if self.selected_packet_idx is None or self.selected_packet_idx >= len(self.packets):
            self._set_status("❌ Error: Please select a packet from the table first")
            messagebox.showinfo("No Packet Selected", "Please click a packet in the table first to see its hex bytes, then select (click and drag) the hex bytes you want to plot.")
            return

        selected_packet = self.packets[self.selected_packet_idx]
        filter_src_id = selected_packet["src_id"]
        filter_src_ch = selected_packet["src_ch"]
        filter_dst_id = selected_packet["dst_id"]
        filter_dst_ch = selected_packet["dst_ch"]

        # Store filter values for live plot updates
        self.plot_filter_src_id = filter_src_id
        self.plot_filter_src_ch = filter_src_ch
        self.plot_filter_dst_id = filter_dst_id
        self.plot_filter_dst_ch = filter_dst_ch

        # Show what we're filtering for
        src_str = self._format_node(filter_src_id, filter_src_ch)
        dest_str = self._format_node(filter_dst_id, filter_dst_ch)
        self._set_status(f"🔍 Filtering packets from {src_str} → {dest_str} at byte positions {byte_indices}...")

        # Extract values from packets with EXACT same source:channel -> dest:channel
        times = []
        values = []
        datetimes = []
        matched_count = 0  # Track how many packets match the routing filter

        for packet in self.packets:
            # Only plot packets with exact same routing (src_id:src_ch -> dst_id:dst_ch)
            if (packet["src_id"] != filter_src_id or
                packet["src_ch"] != filter_src_ch or
                packet["dst_id"] != filter_dst_id or
                packet["dst_ch"] != filter_dst_ch):
                continue  # Skip packets with different routing

            matched_count += 1  # This packet matches the routing filter

            time_sec = self._offs_to_seconds(packet["offs_units"])
            if time_sec is None:
                continue

            # Extract bytes at selected indices (same positions across all matching packets)
            payload = packet["payload"]
            try:
                selected_bytes = [payload[i] for i in byte_indices if i < len(payload)]
                if len(selected_bytes) != len(byte_indices):
                    continue  # Skip if payload too short

                # Convert to integer (little-endian)
                value = int.from_bytes(bytes(selected_bytes), byteorder='little')

                # Convert to datetime with DST applied (for tooltips)
                dt = self._offs_to_datetime(packet["offs_units"])

                times.append(time_sec)
                values.append(value)
                datetimes.append(dt)
            except (IndexError, ValueError):
                continue

        if not times:
            # Show detailed error message
            if matched_count == 0:
                self._set_status(f"❌ No packets found with routing {src_str} → {dest_str}")
                messagebox.showinfo("No Matching Packets",
                    f"No packets found with exact routing:\n{src_str} → {dest_str}\n\n"
                    f"Total packets: {len(self.packets)}")
            else:
                self._set_status(f"❌ Found {matched_count} packets with matching routing, but none had valid data at byte positions {byte_indices}")
                messagebox.showinfo("No Valid Data",
                    f"Found {matched_count} packets with routing {src_str} → {dest_str}\n"
                    f"but none had valid data at byte positions {byte_indices}.\n\n"
                    f"The payload might be too short in those packets.")
            return

        # Store plot data for refreshing when time mode changes
        self.plot_times = times
        self.plot_values = values
        self.plot_byte_indices = byte_indices
        self.plot_datetimes = datetimes

        # Draw the plot using the helper method
        self._draw_plot()

        # Start live plot updates if monitoring live data
        if self.is_connected and self.is_live_data:
            self._start_live_plot_updates()

        # Update status with routing filter info
        byte_range = f"bytes [{byte_indices[0]}"
        if len(byte_indices) > 1:
            byte_range += f"-{byte_indices[-1]}"
        byte_range += "]"

        src_str = self._format_node(filter_src_id, filter_src_ch)
        dest_str = self._format_node(filter_dst_id, filter_dst_ch)

        self._set_status(
            f"Plotted {len(times)} points for {byte_range} from {src_str} → {dest_str} "
            f"(range: {min(values)} to {max(values)})"
        )

    def _get_selected_byte_indices(self, sel_start: str, sel_end: str) -> List[int]:
        """
        Convert text selection to byte indices.

        Args:
            sel_start: Start position in text widget (format: "line.col")
            sel_end: End position in text widget

        Returns:
            List of byte indices (0-based) that were selected
        """
        # Get all text
        all_text = self.hex_text.get("1.0", tk.END).strip()

        # Get character positions of selection
        start_line, start_col = map(int, sel_start.split('.'))
        end_line, end_col = map(int, sel_end.split('.'))

        # Convert to absolute character position
        # (For simplicity, assume single line - hex display is typically one line or wraps nicely)
        lines = all_text.split('\n')

        # Calculate absolute positions
        start_pos = sum(len(lines[i]) + 1 for i in range(start_line - 1)) + start_col
        end_pos = sum(len(lines[i]) + 1 for i in range(end_line - 1)) + end_col

        # Get selected text
        selected = all_text[start_pos:end_pos]

        # Find which bytes were selected
        # Hex format: "AA BB CC DD" (3 chars per byte including space)
        # Strategy: Find start and end byte indices

        byte_indices = []
        current_byte_idx = 0
        current_pos = 0

        for match in HEX_RE.finditer(all_text):
            match_start = match.start()
            match_end = match.end()

            # Check if this byte overlaps with selection
            if match_start < end_pos and match_end > start_pos:
                # Check if FULLY selected (both digits)
                if match_start >= start_pos and match_end <= end_pos:
                    byte_indices.append(current_byte_idx)

            current_byte_idx += 1

        return byte_indices

    # ========================================================================
    # LIVE PLOT UPDATES
    # ========================================================================

    def _start_live_plot_updates(self):
        """Start periodic plot updates for live monitoring."""
        # Cancel existing timer if any
        self._stop_live_plot_updates()

        # Schedule first update
        self.live_plot_timer_id = self.after(self.live_plot_update_interval, self._update_live_plot)

    def _stop_live_plot_updates(self):
        """Stop periodic plot updates."""
        if self.live_plot_timer_id is not None:
            self.after_cancel(self.live_plot_timer_id)
            self.live_plot_timer_id = None

    def _update_live_plot(self):
        """
        Update plot with latest data during live monitoring.
        Called periodically by timer.
        """
        # Only continue if still monitoring, not paused, and have byte indices selected
        if not self.is_connected or not self.is_live_data or not self.plot_byte_indices or self.is_paused:
            self._stop_live_plot_updates()
            return

        # Re-extract values from all packets (including new ones)
        # Filter by exact routing if filter is set
        times = []
        values = []
        datetimes = []

        for packet in self.packets:
            # Apply routing filter if set (only plot exact src:ch -> dst:ch match)
            if (self.plot_filter_src_id is not None and
                (packet["src_id"] != self.plot_filter_src_id or
                 packet["src_ch"] != self.plot_filter_src_ch or
                 packet["dst_id"] != self.plot_filter_dst_id or
                 packet["dst_ch"] != self.plot_filter_dst_ch)):
                continue  # Skip packets with different routing

            time_sec = self._offs_to_seconds(packet["offs_units"])
            if time_sec is None:
                continue

            # Extract bytes at selected indices
            payload = packet["payload"]
            try:
                selected_bytes = [payload[i] for i in self.plot_byte_indices if i < len(payload)]
                if len(selected_bytes) != len(self.plot_byte_indices):
                    continue  # Skip if payload too short

                # Convert to integer (little-endian)
                value = int.from_bytes(bytes(selected_bytes), byteorder='little')

                # Convert to datetime with DST applied (for tooltips)
                dt = self._offs_to_datetime(packet["offs_units"])

                times.append(time_sec)
                values.append(value)
                datetimes.append(dt)
            except (IndexError, ValueError):
                continue

        if not times:
            # No data, but keep trying
            self.live_plot_timer_id = self.after(self.live_plot_update_interval, self._update_live_plot)
            return

        # Update stored plot data
        self.plot_times = times
        self.plot_values = values
        self.plot_datetimes = datetimes

        # Redraw plot
        self._draw_plot()

        # Schedule next update
        self.live_plot_timer_id = self.after(self.live_plot_update_interval, self._update_live_plot)

    # ========================================================================
    # TIME MODE TOGGLE
    # ========================================================================

    def _on_time_mode_changed(self, value: str):
        """
        Called when user changes time display mode.

        Args:
            value: Selected value from segmented button ("Elapsed" or "Full Date")
        """
        # Update internal time mode variable
        if value == "Elapsed":
            self.time_mode.set("elapsed")
        else:  # "Full Date"
            self.time_mode.set("absolute")

        # Update table header text
        if self.time_mode.get() == "elapsed":
            self.tree.heading("time", text="Time (s)")
        else:
            self.tree.heading("time", text="Date & Time")

        # Refresh table with new time format
        if self.packets:
            self._populate_table()

        # Refresh plot with new time format (if plot data exists)
        if self.plot_times and self.plot_values:
            self._draw_plot()

    # ========================================================================
    # AUTO-SCROLL TOGGLE
    # ========================================================================

    def _toggle_autoscroll(self):
        """Toggle auto-scroll on/off."""
        self.auto_scroll_enabled = not self.auto_scroll_enabled
        self._update_autoscroll_button()

    def _update_autoscroll_button(self):
        """Update auto-scroll button text and color based on state."""
        if self.auto_scroll_enabled:
            self.autoscroll_btn.configure(
                text="📜 Auto-Scroll: ON",
                fg_color=("#2b7cc7", "#1a5a9e"),
                hover_color=("#3a7ebf", "#1f538d")
            )
        else:
            self.autoscroll_btn.configure(
                text="📜 Auto-Scroll: OFF",
                fg_color=("#666666", "#444444"),
                hover_color=("#777777", "#555555")
            )

    # ========================================================================
    # PAUSE/RESUME TOGGLE
    # ========================================================================

    def _toggle_pause(self):
        """Toggle pause/resume for live monitoring."""
        self.is_paused = not self.is_paused
        self._update_pause_button()

        if self.is_paused:
            self._set_status("⏸ Monitoring paused")
            # Track pause start: last packet before pause
            self.pause_start_idx = len(self.packets) - 1 if self.packets else None
            # Stop live plot updates
            self._stop_live_plot_updates()
        else:
            self._set_status("▶ Monitoring resumed")
            # Wait for first packet after resume to complete the pause range
            self.waiting_for_resume_packet = True
            # Restart live plot updates if we have byte indices selected
            if self.is_connected and self.is_live_data and self.plot_byte_indices:
                self._start_live_plot_updates()

    def _update_pause_button(self):
        """Update pause button text and color based on state."""
        if self.is_paused:
            self.pause_btn.configure(
                text="▶ Resume",
                fg_color=("#66cc66", "#55aa55"),
                hover_color=("#77dd77", "#66bb66")
            )
        else:
            self.pause_btn.configure(
                text="⏸ Pause",
                fg_color=("#cc8800", "#aa6600"),
                hover_color=("#dd9900", "#bb7700")
            )

    # ========================================================================
    # INTERFACE SELECTION
    # ========================================================================

    def _on_interface_changed(self, selected_ip: str):
        """
        Called when user changes the network interface selection.

        Args:
            selected_ip: IP address selected from dropdown
        """
        if selected_ip in self.available_interfaces:
            self.selected_interface_ip = selected_ip
            self.selected_interface_name = self.available_interfaces[selected_ip]

            # Update monitor's interface
            if self.monitor:
                self.monitor.interface_name = self.selected_interface_name

            self._set_status(f"Selected interface: {selected_ip} ({self.selected_interface_name})")

    # ========================================================================
    # LIVE CONNECTION METHODS
    # ========================================================================

    def on_packet_received(self, packet: Dict[str, Any]):
        """
        Called when a packet is received from the live switch connection.
        Updates UI in real-time (unless paused).

        Handles time tracking for live packets:
        - First packet: Sets live_base_time and file_base_time
        - Subsequent packets: Makes offs_units relative to first packet

        Args:
            packet: Packet dictionary from ISSwitchMonitor
        """
        # Skip packet processing if paused
        if self.is_paused:
            return

        # Store packet first
        # Track first packet timestamp as base time
        if self.live_base_time is None and packet["offs_units"] is not None:
            # First packet - set base time
            self.live_base_time = packet["offs_units"]

            # Convert to datetime (offs_units is in microseconds since epoch)
            self.file_base_time = datetime.fromtimestamp(packet["offs_units"] / 1000000.0)

            # Make first packet's offs_units = 0 (relative to itself)
            packet["offs_units"] = 0
            packet["time_base"] = self.file_base_time
        elif self.live_base_time is not None and packet["offs_units"] is not None:
            # Subsequent packets - make relative to first packet
            packet["offs_units"] = packet["offs_units"] - self.live_base_time
            packet["time_base"] = self.file_base_time

        # Store packet
        self.packets.append(packet)

        # Check if this is the first packet after resume (for red line visualization)
        if self.waiting_for_resume_packet and self.pause_start_idx is not None:
            # This is the first packet after resume
            pause_end_idx = len(self.packets) - 1
            self.pause_ranges.append((self.pause_start_idx, pause_end_idx))
            self.pause_start_idx = None
            self.waiting_for_resume_packet = False

        # Update UI (must be done in main thread)
        self.after(0, self._add_packet_to_table, len(self.packets) - 1)

    def _add_packet_to_table(self, packet_idx: int):
        """
        Add a single packet to the table (runs in main thread).

        Args:
            packet_idx: Index of packet in self.packets list
        """
        # Get packet from list
        if packet_idx >= len(self.packets):
            return

        packet = self.packets[packet_idx]

        # Get time
        time_sec = self._offs_to_seconds(packet["offs_units"])
        if time_sec is None:
            return

        # Format time based on mode
        if self.time_mode.get() == "elapsed":
            time_str = f"{time_sec:.6f}"
        else:
            dt = self._offs_to_datetime(packet["offs_units"])
            time_str = self._fmt_time_abs(dt) if dt else "—"

        # Format source/dest
        src = self._format_node(packet["src_id"], packet["src_ch"])
        dst = self._format_node(packet["dst_id"], packet["dst_ch"])

        # Size - use payload length (matches file loading behavior)
        size = len(packet["payload"])

        # CRITICAL: Preserve scroll position when auto-scroll is disabled
        # When inserting at position 0, we need to compensate for the new item added above
        if not self.auto_scroll_enabled:
            try:
                # Save current scroll position (fraction of total height)
                saved_yview = self.tree.yview()

                # Get current number of items before insertion
                num_items_before = len(self.tree.get_children())

                # Insert at top (newest first) with proper iid for row selection
                self.tree.insert("", 0, iid=str(packet_idx), values=(time_str, src, dst, size))

                # Get new number of items after insertion
                num_items_after = len(self.tree.get_children())

                # Calculate adjustment needed to stay at the same absolute position
                # Since we added 1 item at the top, scroll down by 1 item to compensate
                if num_items_before > 0 and num_items_after > num_items_before:
                    # Scroll down by 1 unit (1 item) to compensate for the new item added above
                    self.tree.yview_scroll(1, "units")

            except Exception as e:
                # If adjustment fails, just insert normally
                self.tree.insert("", 0, iid=str(packet_idx), values=(time_str, src, dst, size))
        else:
            # Auto-scroll is enabled - just insert normally
            # Insert at top (newest first) with proper iid for row selection
            self.tree.insert("", 0, iid=str(packet_idx), values=(time_str, src, dst, size))

        # Auto-scroll to top (only if auto-scroll is enabled)
        if self.auto_scroll_enabled:
            children = self.tree.get_children()
            if children:
                self.tree.see(children[0])

        # Limit table size (keep last 1000 packets)
        children = self.tree.get_children()
        if len(children) > 1000:
            # Remove oldest row
            self.tree.delete(children[-1])

        # Update status
        self._set_status(f"Connected - {len(self.packets)} packets received")

    def connect_to_switch(self):
        """Connect to the IS switch."""
        switch_ip = self.ip_entry.get().strip()
        control_port_str = self.port_entry.get().strip()

        if not switch_ip:
            messagebox.showerror("Invalid Input", "Please enter a switch IP address")
            return

        try:
            control_port = int(control_port_str)
            if control_port <= 0 or control_port > 65535:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Invalid Input", "Please enter a valid port number (1-65535)")
            return

        # Update status
        self._set_status(f"Connecting to {switch_ip}:{control_port}...")
        self.connect_btn.configure(state="disabled")
        self.update()

        # Try to connect
        success = self.monitor.connect(switch_ip, control_port)

        if success:
            self.is_connected = True
            self._set_status(f"✅ Connected to {switch_ip}:{control_port} - Monitoring active")
            self.connect_btn.configure(state="disabled")
            self.disconnect_btn.configure(state="normal")
            self.interface_dropdown.configure(state="disabled")
            self.ip_entry.configure(state="disabled")
            self.port_entry.configure(state="disabled")
            self.pause_btn.configure(state="normal")  # Enable pause button

            # Clear existing packets and reset time tracking when connecting live
            self.packets.clear()
            self.tree.delete(*self.tree.get_children())
            self.live_base_time = None  # Reset live time tracking
            self.file_base_time = None  # Will be set by first packet
            self.is_live_data = True  # Live monitoring (NO DST adjustment)
            self.auto_scroll_enabled = True  # Enable auto-scroll for live monitoring
            self.is_paused = False  # Reset pause state
            self.pause_ranges = []  # Clear pause tracking
            self.pause_start_idx = None
            self._update_autoscroll_button()
            self._update_pause_button()
        else:
            self._set_status("❌ Connection failed - Check IP/port and try again")
            self.connect_btn.configure(state="normal")
            messagebox.showerror(
                "Connection Failed",
                f"Could not connect to switch at {switch_ip}:{control_port}\n\n"
                "Please check:\n"
                "- Switch IP address is correct\n"
                "- Switch is powered on and accessible\n"
                "- Control port is correct (default: 55554)\n"
                "- Network connection is working\n"
                "- Network interface is correct"
            )

    def disconnect_from_switch(self):
        """Disconnect from the IS switch."""
        self._set_status("Disconnecting...")
        self.update()

        # Stop live plot updates
        self._stop_live_plot_updates()

        # Disconnect
        self.monitor.disconnect()

        # Update UI
        self.is_connected = False
        self._set_status("Disconnected")
        self.connect_btn.configure(state="normal")
        self.disconnect_btn.configure(state="disabled")
        self.interface_dropdown.configure(state="readonly")
        self.ip_entry.configure(state="normal")
        self.port_entry.configure(state="normal")
        self.pause_btn.configure(state="disabled")  # Disable pause button

        # Reset live time tracking and pause state
        self.live_base_time = None
        self.is_paused = False
        self.pause_ranges = []
        self.pause_start_idx = None
        self._update_pause_button()

    def on_closing(self):
        """Handle window close event."""
        if self.is_connected:
            self.disconnect_from_switch()

        self.destroy()

    # ========================================================================
    # STATUS BAR
    # ========================================================================

    def _set_status(self, message: str):
        """Update status display with message (integrated into file_label)."""
        self.file_label.configure(text=message)


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Create and run the application
    app = SimplePNPMon()
    app.mainloop()
