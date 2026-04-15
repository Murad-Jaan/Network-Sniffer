"""
Network Packet Analyzer - Enterprise Edition
Captures, analyzes, and inspects network traffic with vulnerability detection
Supports HTTP/HTTPS inspection, credential detection, and security analysis
"""

import socket
import struct
import textwrap
import sys
import json
from datetime import datetime
from collections import defaultdict
import re
import base64
from urllib.parse import unquote

# ANSI color codes for terminal output
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'

# ============================================================================
# PACKET PARSING FUNCTIONS
# ============================================================================

def format_ipv4(bytes_addr):
    """Convert 4 bytes to IPv4 address string"""
    bytes_str = map(str, bytes_addr)
    return '.'.join(bytes_str)

def format_mac_addr(bytes_addr):
    """Convert 6 bytes to MAC address string"""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# ============================================================================
# ETHERNET FRAME PARSING
# ============================================================================

def parse_ethernet_frame(data):
    """
    Parse Ethernet frame structure:
    - Destination MAC (6 bytes)
    - Source MAC (6 bytes)
    - Protocol (2 bytes) - 0x0800 (IPv4), 0x0806 (ARP), 0x86DD (IPv6)
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_addr(dest_mac), format_mac_addr(src_mac), proto, data[14:]

# ============================================================================
# IPv4 PACKET PARSING
# ============================================================================

def parse_ipv4_packet(data):
    """
    Parse IPv4 packet structure:
    - Version (4 bits) + Header Length (4 bits)
    - Type of Service (8 bits)
    - Total Length (16 bits)
    - Identification (16 bits)
    - Flags (3 bits) + Fragment Offset (13 bits)
    - TTL (8 bits)
    - Protocol (8 bits) - 1 (ICMP), 6 (TCP), 17 (UDP)
    - Header Checksum (16 bits)
    - Source IP (32 bits)
    - Destination IP (32 bits)
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

# ============================================================================
# ICMP PACKET PARSING
# ============================================================================

def parse_icmp_packet(data):
    """
    Parse ICMP packet structure:
    - Type (8 bits) - 8 (Echo), 0 (Reply), 11 (TTL Exceeded), etc.
    - Code (8 bits)
    - Checksum (16 bits)
    - Rest of Header (32 bits)
    """
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# ============================================================================
# TCP SEGMENT PARSING
# ============================================================================

def parse_tcp_segment(data):
    """
    Parse TCP segment structure:
    - Source Port (16 bits)
    - Destination Port (16 bits)
    - Sequence Number (32 bits)
    - Acknowledgment Number (32 bits)
    - Data Offset (4 bits) + Reserved (3 bits) + Flags (9 bits)
    - Window Size (16 bits)
    - Checksum (16 bits)
    - Urgent Pointer (16 bits)
    """
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:12])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

# ============================================================================
# UDP DATAGRAM PARSING
# ============================================================================

def parse_udp_segment(data):
    """
    Parse UDP datagram structure:
    - Source Port (16 bits)
    - Destination Port (16 bits)
    - Length (16 bits)
    - Checksum (16 bits)
    """
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, length, data[8:]

# ============================================================================
# IPv4 ADDRESSES PARSING
# ============================================================================

def parse_ipv4_addresses(data):
    """Parse IPv4 addresses from data"""
    src_addr, dest_addr = struct.unpack('! 4s 4s', data[:8])
    return format_ipv4(src_addr), format_ipv4(dest_addr), data[8:]

# ============================================================================
# PAYLOAD FORMATTING & INSPECTION
# ============================================================================

def format_multi_line(prefix, bytes_data, size=80):
    """Format bytes data into readable multi-line format"""
    if size % 2 == 1:
        size -= 1
    lines = [bytes_data[i:i+size].hex(' ', 1) for i in range(0, len(bytes_data), size)]
    if lines:
        return '\n'.join([f'{prefix}{line}' for line in lines])
    else:
        return ''

def format_payload(payload):
    """Extract and format printable characters from payload"""
    if len(payload) == 0:
        return 'No Payload'
    
    # Try to extract printable ASCII characters
    printable_payload = ''.join(
        [chr(b) if 32 <= b <= 126 else '.' for b in payload]
    )
    
    hex_payload = format_multi_line('    ', payload[:100])
    
    output = f"\n    Payload (Hex):\n{hex_payload}"
    if len(printable_payload.strip()) > 0:
        output += f"\n    Payload (ASCII): {printable_payload[:100]}"
    
    return output

# ============================================================================
# VULNERABILITY & CREDENTIAL DETECTION
# ============================================================================

def detect_http_credentials(payload):
    """Detect plaintext HTTP credentials"""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        credentials = []
        
        # Detect Basic Auth
        if 'Authorization: Basic' in payload_str:
            basic_auth_match = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', payload_str)
            if basic_auth_match:
                try:
                    encoded = basic_auth_match.group(1)
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    if ':' in decoded:
                        user, password = decoded.split(':', 1)
                        credentials.append({
                            'type': 'HTTP Basic Auth',
                            'username': user,
                            'password': password,
                            'severity': 'CRITICAL'
                        })
                except:
                    pass
        
        # Detect form data with password fields
        password_patterns = [
            r'password=([^&\s\r\n]+)',
            r'passwd=([^&\s\r\n]+)',
            r'pwd=([^&\s\r\n]+)',
            r'pass=([^&\s\r\n]+)',
        ]
        
        for pattern in password_patterns:
            matches = re.finditer(pattern, payload_str, re.IGNORECASE)
            for match in matches:
                password = unquote(match.group(1))
                credentials.append({
                    'type': 'Form Data Password',
                    'password': password,
                    'severity': 'CRITICAL'
                })
        
        # Detect common credential patterns
        if re.search(r'(username|user|login).*?(password|pass|pwd)', payload_str, re.IGNORECASE):
            credentials.append({
                'type': 'Potential Credentials',
                'severity': 'WARNING',
                'note': 'Potential username/password found in payload'
            })
        
        return credentials
    except:
        return []

def detect_sensitive_data(payload):
    """Detect sensitive data patterns"""
    try:
        payload_str = payload.decode('utf-8', errors='ignore')
        
        findings = []
        
        # Credit card patterns (simplified)
        cc_pattern = r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'
        if re.search(cc_pattern, payload_str):
            findings.append({
                'type': 'Potential Credit Card Number',
                'severity': 'CRITICAL'
            })
        
        # Social Security Number pattern (US)
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        if re.search(ssn_pattern, payload_str):
            findings.append({
                'type': 'Potential Social Security Number',
                'severity': 'CRITICAL'
            })
        
        # Email patterns
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = re.findall(email_pattern, payload_str)
        if emails:
            findings.append({
                'type': 'Email Addresses Found',
                'count': len(emails),
                'severity': 'MEDIUM'
            })
        
        # API Keys (common patterns)
        api_key_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})', 'API Key'),
            (r'token["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})', 'Token'),
            (r'secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{20,})', 'Secret Key'),
        ]
        
        for pattern, key_type in api_key_patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                findings.append({
                    'type': f'{key_type} Found',
                    'severity': 'CRITICAL'
                })
        
        return findings
    except:
        return []

def analyze_packet_security(protocol, src, dst, src_port, dst_port, payload):
    """Perform security analysis on packet"""
    vulnerabilities = []
    
    # Check for unencrypted sensitive protocols
    unencrypted_ports = {
        23: ('TELNET', 'CRITICAL'),
        25: ('SMTP Unencrypted', 'HIGH'),
        80: ('HTTP Unencrypted', 'MEDIUM'),
        110: ('POP3 Unencrypted', 'HIGH'),
        143: ('IMAP Unencrypted', 'HIGH'),
    }
    
    if dst_port in unencrypted_ports:
        protocol_name, severity = unencrypted_ports[dst_port]
        vulnerabilities.append({
            'type': f'Unencrypted {protocol_name}',
            'severity': severity,
            'port': dst_port
        })
    
    # Detect credentials in HTTP
    if dst_port == 80 or src_port == 80:
        creds = detect_http_credentials(payload)
        vulnerabilities.extend(creds)
    
    # Detect sensitive data
    sensitive = detect_sensitive_data(payload)
    vulnerabilities.extend(sensitive)
    
    return vulnerabilities

# ============================================================================
# PROTOCOL CONSTANTS
# ============================================================================

ETHERNET_PROTOCOLS = {
    8: 'IPv4',
    1536: 'IPv4',
    2048: 'IPv4',
    2054: 'ARP',
    34525: 'IPv6'
}

IPV4_PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}

ICMP_TYPES = {
    0: 'Echo Reply',
    3: 'Destination Unreachable',
    8: 'Echo Request',
    11: 'Time Exceeded',
    12: 'Parameter Problem'
}

COMMON_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Alt'
}

# ============================================================================
# PACKET FORMATTING & DISPLAY
# ============================================================================

def format_tcp_flags(urg, ack, psh, rst, syn, fin):
    """Format TCP flags as readable string"""
    flags = []
    if syn:
        flags.append('SYN')
    if ack:
        flags.append('ACK')
    if fin:
        flags.append('FIN')
    if rst:
        flags.append('RST')
    if psh:
        flags.append('PSH')
    if urg:
        flags.append('URG')
    return '[' + ', '.join(flags) + ']' if flags else '[No Flags]'

def get_port_service(port):
    """Get service name for common ports"""
    return COMMON_PORTS.get(port, str(port))

def format_packet_info(timestamp, protocol, src, dest, details=""):
    """Format packet info for display"""
    return f"{Colors.BOLD}{timestamp}{Colors.RESET} | {Colors.OKGREEN}{protocol:6}{Colors.RESET} | {Colors.OKCYAN}{src:20}{Colors.RESET} -> {Colors.WARNING}{dest:20}{Colors.RESET} | {details}"

# ============================================================================
# MAIN PACKET SNIFFER
# ============================================================================

class PacketSniffer:
    def __init__(self, interface=None, packet_count=0, output_file=None):
        """
        Initialize packet sniffer
        
        Args:
            interface: Network interface to sniff on (None = all)
            packet_count: Number of packets to capture (0 = unlimited)
            output_file: File to save captured packets (JSON format)
        """
        self.interface = interface
        self.packet_count = packet_count
        self.packets_captured = 0
        self.stats = defaultdict(int)
        self.output_file = output_file
        self.packets_data = []  # Store packet data for export
        
    def start(self):
        """Start sniffing packets"""
        print(f"{Colors.HEADER}{'='*80}")
        print(f"Network Packet Analyzer Started")
        print(f"{'='*80}{Colors.RESET}\n")
        
        try:
            # Platform-specific socket creation
            if sys.platform == 'win32':
                # Windows: AF_PACKET is not available
                print(f"{Colors.FAIL}Error: Windows packet capture requires Npcap{Colors.RESET}")
                print(f"{Colors.WARNING}Steps to fix:{Colors.RESET}")
                print("1. Download Npcap from: https://npcap.org/")
                print("2. Install with Administrator privileges")
                print("3. Restart your system")
                print("4. Run: python network_sniffer.py")
                print(f"\n{Colors.FAIL}Note: Raw socket packet capture is not natively supported on Windows.{Colors.RESET}")
                print("Use Docker for full functionality on Windows:")
                print("  docker build -t network-analyzer .")
                print("  docker run --net=host -it network-analyzer")
                sys.exit(1)
                
            elif sys.platform == 'darwin':
                # macOS
                try:
                    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                except OSError:
                    print(f"{Colors.FAIL}Error: Raw sockets not available on this macOS version{Colors.RESET}")
                    print("Try running with sudo: sudo python3 network_sniffer.py")
                    print("\nAlternative: Use Docker")
                    print("  docker build -t network-analyzer .")
                    print("  docker run --net=host -it network-analyzer")
                    sys.exit(1)
            else:
                # Linux
                conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print(f"{Colors.OKBLUE}Listening for packets...{Colors.RESET}\n")
            print(f"{Colors.WARNING}Press Ctrl+C to stop{Colors.RESET}\n")
            
            while True:
                if self.packet_count > 0 and self.packets_captured >= self.packet_count:
                    break
                
                try:
                    raw_buffer = conn.recvfrom(65535)[0]
                    self.packets_captured += 1
                    self.process_packet(raw_buffer)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"{Colors.WARNING}Error processing packet: {e}{Colors.RESET}")
                    continue
                
        except KeyboardInterrupt:
            print(f"\n\n{Colors.WARNING}Sniffer stopped by user{Colors.RESET}")
            self.print_statistics()
            self.export_packets()
        except PermissionError:
            print(f"\n{Colors.FAIL}Error: This program requires administrator/root privileges{Colors.RESET}")
            if sys.platform == 'darwin':
                print("Run with: sudo python3 network_sniffer.py")
            elif sys.platform == 'linux':
                print("Run with: sudo python3 network_sniffer.py")
            else:
                print("Run Command Prompt/PowerShell as Administrator")
            sys.exit(1)
        except OSError as e:
            print(f"\n{Colors.FAIL}Socket Error: {e}{Colors.RESET}")
            print("This usually means:")
            print("  - Not running with sufficient privileges (try sudo)")
            print("  - Npcap not installed (Windows)")
            print("  - Network interface issues")
            sys.exit(1)
        except Exception as e:
            print(f"\n{Colors.FAIL}Unexpected Error: {e}{Colors.RESET}")
            print("Please report this issue at: https://github.com/yourusername/network-packet-analyzer/issues")
            sys.exit(1)
    
    def process_packet(self, data):
        """Process a single packet"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        dest_mac, src_mac, eth_proto, payload = parse_ethernet_frame(data)
        self.stats['Total'] += 1
        
        # IPv4
        if eth_proto == 8:
            self.stats['IPv4'] += 1
            version, header_length, ttl, proto, src, target, payload = parse_ipv4_packet(payload)
            
            # ICMP
            if proto == 1:
                self.stats['ICMP'] += 1
                icmp_type, code, checksum, payload = parse_icmp_packet(payload)
                icmp_type_str = ICMP_TYPES.get(icmp_type, f'Unknown({icmp_type})')
                
                print(format_packet_info(
                    timestamp, 'ICMP',
                    src, target,
                    f"{icmp_type_str} (Code: {code})"
                ))
            
            # TCP
            elif proto == 6:
                self.stats['TCP'] += 1
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = parse_tcp_segment(payload)
                
                tcp_flags = format_tcp_flags(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
                src_service = get_port_service(src_port)
                dest_service = get_port_service(dest_port)
                
                print(format_packet_info(
                    timestamp, 'TCP',
                    f"{src}:{src_port}({src_service})",
                    f"{target}:{dest_port}({dest_service})",
                    f"Seq: {sequence}, Ack: {acknowledgment} {tcp_flags}"
                ))
                
                if len(payload) > 0:
                    print(format_payload(payload))
            
            # UDP
            elif proto == 17:
                self.stats['UDP'] += 1
                src_port, dest_port, size, payload = parse_udp_segment(payload)
                
                src_service = get_port_service(src_port)
                dest_service = get_port_service(dest_port)
                
                print(format_packet_info(
                    timestamp, 'UDP',
                    f"{src}:{src_port}({src_service})",
                    f"{target}:{dest_port}({dest_service})",
                    f"Size: {size} bytes"
                ))
                
                if len(payload) > 0:
                    print(format_payload(payload))
            
            # Other
            else:
                print(format_packet_info(
                    timestamp, 'IPv4',
                    src, target,
                    f"Protocol: {proto}"
                ))
        
        # ARP
        elif eth_proto == 2054:
            self.stats['ARP'] += 1
            print(format_packet_info(
                timestamp, 'ARP',
                src_mac, dest_mac,
                "Address Resolution Protocol"
            ))
        
        # IPv6
        elif eth_proto == 34525:
            self.stats['IPv6'] += 1
            print(format_packet_info(
                timestamp, 'IPv6',
                src_mac, dest_mac,
                "IPv6 Packet"
            ))
        
        # Unknown
        else:
            print(format_packet_info(
                timestamp, 'Unknown',
                src_mac, dest_mac,
                f"Protocol: {eth_proto}"
            ))
        
        print()  # Blank line for readability
    
    def print_statistics(self):
        """Print capture statistics"""
        print(f"\n{Colors.HEADER}{'='*80}")
        print("Packet Capture Statistics")
        print(f"{'='*80}{Colors.RESET}\n")
        
        print(f"Total Packets: {self.stats['Total']}")
        print(f"IPv4 Packets: {self.stats['IPv4']}")
        print(f"IPv6 Packets: {self.stats['IPv6']}")
        print(f"ARP Packets: {self.stats['ARP']}")
        print(f"TCP Segments: {self.stats['TCP']}")
        print(f"UDP Datagrams: {self.stats['UDP']}")
        print(f"ICMP Messages: {self.stats['ICMP']}")
    
    def export_packets(self):
        """Export captured packets to JSON file"""
        if not self.output_file or not self.packets_data:
            return
        
        try:
            with open(self.output_file, 'w') as f:
                json.dump({
                    'capture_timestamp': datetime.now().isoformat(),
                    'total_packets': len(self.packets_data),
                    'packets': self.packets_data
                }, f, indent=2)
            print(f"\n{Colors.OKGREEN}✓ Packets exported to {self.output_file}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.FAIL}✗ Failed to export packets: {e}{Colors.RESET}")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Packet Analyzer - Capture and analyze network traffic'
    )
    parser.add_argument('count', nargs='?', type=int, default=0,
                       help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-o', '--output', type=str, default=None,
                       help='Output file for captured packets (JSON format)')
    parser.add_argument('-i', '--interface', type=str, default=None,
                       help='Network interface to sniff on')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    sniffer = PacketSniffer(
        interface=args.interface,
        packet_count=args.count,
        output_file=args.output
    )
    
    try:
        sniffer.start()
    except KeyboardInterrupt:
        sniffer.print_statistics()
        sniffer.export_packets()
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.RESET}")
