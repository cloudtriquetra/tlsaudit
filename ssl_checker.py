#!/usr/bin/env python3
"""
TLS Version and Cipher Scanner
This script checks which TLS versions and ciphers are supported by a server.
Uses openssl s_client for maximum compatibility.
"""

import subprocess
import sys
import re
import json
import argparse
import csv
import os
from urllib.parse import urlparse
from datetime import datetime

# TLS versions to test (in order from oldest to newest)
TLS_VERSIONS = {
    'TLSv1.0': '-tls1',
    'TLSv1.1': '-tls1_1',
    'TLSv1.2': '-tls1_2',
    'TLSv1.3': '-tls1_3',
}

# Approved TLS protocol versions
APPROVED_PROTOCOLS = {
    'TLSv1.2': 'SECURE',
    'TLSv1.3': 'RECOMMENDED',
}

# Approved cipher suites (loaded from CSV)
APPROVED_CIPHERS = {}


def load_approved_ciphers(csv_file='approved_ciphers.csv'):
    """Load approved cipher suites from CSV file.
    
    CSV format: cipher_name,protocol,rating,format,key_exchange,signature_algorithm
    
    Each row represents one cipher that can be matched. Same cipher name can appear
    multiple times with different protocols (e.g., TLS 1.2 and TLS 1.3).
    Format column (OPENSSL or IANA) is for documentation purposes.
    Key_exchange column documents the key exchange method (e.g., X25519MLKEM768 for PQC).
    Signature_algorithm column documents the certificate signing algorithm (e.g., RSASSA-PSS).
    """
    global APPROVED_CIPHERS
    
    # Get the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, csv_file)
    
    if not os.path.exists(csv_path):
        print(f"Warning: Cipher config file not found: {csv_path}", file=sys.stderr)
        return False
    
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Skip empty rows and comments
                cipher_name = row['cipher_name'].strip()
                if not cipher_name or cipher_name.startswith('#'):
                    continue
                
                protocol = row['protocol'].strip()
                rating = row['rating'].strip()
                # Format column is optional, just for documentation
                cipher_format = row.get('format', 'UNKNOWN').strip()
                # Key exchange column is optional, for PQC tracking
                key_exchange = row.get('key_exchange', '').strip()
                # Signature algorithm column is optional, for certificate auth tracking
                signature_algorithm = row.get('signature_algorithm', '').strip()
                
                # Store cipher with protocol as part of the lookup key
                # This allows same cipher name with different protocols
                key = (cipher_name, protocol)
                APPROVED_CIPHERS[key] = (rating, cipher_name, cipher_format, key_exchange, signature_algorithm)
        
        return True
    except Exception as e:
        print(f"Error loading cipher config: {e}", file=sys.stderr)
        return False


def check_cipher_compliance(cipher, protocol):
    """Check if a cipher is approved according to compliance standards.
    
    Returns: (rating, cipher_name, format, key_exchange, signature_algorithm) where rating is 
    'PQC_RECOMMENDED', 'RECOMMENDED', 'SECURE', or 'NOT_APPROVED'
    """
    # Look up using both cipher name and protocol
    key = (cipher, protocol)
    if key in APPROVED_CIPHERS:
        rating, cipher_name, cipher_format, key_exchange, signature_algorithm = APPROVED_CIPHERS[key]
        return (rating, cipher_name, cipher_format, key_exchange, signature_algorithm)
    
    return ('NOT_APPROVED', 'Not in approved cipher list', 'N/A', '', '')


def extract_hostname_port(url):
    """Extract hostname and port from URL."""
    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    hostname = parsed.hostname or parsed.path.split('/')[0]
    port = parsed.port or 443
    return hostname, port


def get_available_ciphers(tls_flag):
    """Get list of ALL ciphers available for a specific TLS version from OpenSSL."""
    try:
        # Use 'ALL' to get every cipher OpenSSL knows about, not just DEFAULT
        # This ensures we don't miss weak/deprecated ciphers during testing
        if tls_flag == '-tls1':
            # For TLS 1.0, include weak ciphers and null ciphers
            cipher_spec = 'ALL:eNULL:@SECLEVEL=0'
        elif tls_flag == '-tls1_1':
            # For TLS 1.1, include weak ciphers and null ciphers
            cipher_spec = 'ALL:eNULL:@SECLEVEL=0'
        elif tls_flag == '-tls1_2':
            # For TLS 1.2, get all ciphers (including weak ones for security testing)
            cipher_spec = 'ALL:eNULL'
        elif tls_flag == '-tls1_3':
            # TLS 1.3 has limited cipher suites
            cipher_spec = 'ALL'
        else:
            cipher_spec = 'ALL:eNULL'
        
        cmd = ['openssl', 'ciphers', '-v', cipher_spec]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=5,
            text=True
        )
        
        ciphers = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    ciphers.append(parts[0])
        return ciphers
    except:
        return []


def find_supported_ciphers(hostname, port, tls_name, tls_flag, max_ciphers=None, proxy=None, socks_proxy=None):
    """Find all supported ciphers for a TLS version by iteratively testing.
    
    Args:
        max_ciphers: Limit cipher enumeration (None = no limit, test all)
                    Use with caution - full enumeration is slow but accurate for compliance
    """
    supported_ciphers = []
    seen = set()
    available_ciphers = get_available_ciphers(tls_flag)
    
    if not available_ciphers:
        return []
    
    # Map TLS flag to expected protocol name
    expected_map = {
        '-tls1': 'TLSv1',
        '-tls1_1': 'TLSv1.1',
        '-tls1_2': 'TLSv1.2',
        '-tls1_3': 'TLSv1.3'
    }
    expected_protocol = expected_map.get(tls_flag, tls_name)
    
    # Limit ciphers tested if specified (for performance)
    ciphers_to_test = available_ciphers if max_ciphers is None else available_ciphers[:max_ciphers]
    
    # Try each cipher individually
    for cipher in ciphers_to_test:
        try:
            cmd = [
                'openssl', 's_client',
                '-connect', f'{hostname}:{port}',
                tls_flag,
                '-cipher', cipher,
                '-servername', hostname
            ]
            
            # Add proxy support if specified
            if proxy:
                cmd.extend(['-proxy', proxy])
            elif socks_proxy:
                cmd.extend(['-socksport', socks_proxy])
            
            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True
            )
            
            output = result.stdout + result.stderr
            
            # CRITICAL: Verify both protocol AND cipher negotiated correctly
            # Extract protocol
            negotiated_protocol = None
            protocol_match = re.search(r'Protocol\s+:\s+([a-zA-Z0-9.]+)', output)
            if protocol_match:
                negotiated_protocol = protocol_match.group(1)
            else:
                protocol_match = re.search(r'New,\s+(TLSv[\d.]+),\s+Cipher', output)
                if protocol_match:
                    negotiated_protocol = protocol_match.group(1)
            
            # Extract cipher
            cipher_match = re.search(r'Cipher\s+is\s+(.+?)(?:\n|$)', output)
            if not cipher_match:
                cipher_match = re.search(r'Cipher\s+:\s+(.+?)(?:\n|$)', output)
            
            negotiated_cipher = None
            if cipher_match:
                negotiated_cipher = cipher_match.group(1).strip()
            
            # Validate: Both protocol AND cipher must match expectations
            # Protocol must equal expected (no downgrades)
            # Cipher must not be (NONE) or 0000
            if (negotiated_protocol == expected_protocol and 
                negotiated_cipher and 
                negotiated_cipher not in ['(NONE)', '0000'] and 
                negotiated_cipher not in seen):
                supported_ciphers.append(negotiated_cipher)
                seen.add(negotiated_cipher)
        except:
            pass
    
    return supported_ciphers


def check_tls_version(hostname, port, tls_name, tls_flag, max_ciphers=10, proxy=None, socks_proxy=None):
    """Check if a specific TLS version is supported and get cipher info."""
    try:
        # Run openssl s_client command
        cmd = [
            'openssl', 's_client',
            '-connect', f'{hostname}:{port}',
            tls_flag,
            '-servername', hostname  # SNI support
        ]
        
        # Add proxy support if specified
        if proxy:
            cmd.extend(['-proxy', proxy])
        elif socks_proxy:
            cmd.extend(['-socksport', socks_proxy])
        
        # For security testing: allow legacy ciphers for older TLS versions
        # This enables detection of weak protocols that may still be supported
        if tls_flag in ['-tls1', '-tls1_1']:
            cmd.extend(['-cipher', 'DEFAULT:@SECLEVEL=0'])
        
        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True
        )
        
        output = result.stdout + result.stderr
        
        # Extract actual negotiated protocol version
        negotiated_protocol = None
        # Handle both "Protocol : TLSv1.2" and "New, TLSv1.3, Cipher is ..."
        protocol_match = re.search(r'Protocol\s+:\s+([a-zA-Z0-9.]+)', output)
        if protocol_match:
            negotiated_protocol = protocol_match.group(1)
        else:
            # TLS 1.3 format: "New, TLSv1.3, Cipher is ..."
            protocol_match = re.search(r'New,\s+(TLSv[\d.]+),\s+Cipher', output)
            if protocol_match:
                negotiated_protocol = protocol_match.group(1)
        
        # Extract cipher - use flexible regex to capture all characters including lowercase
        cipher = 'Unknown'
        cipher_match = re.search(r'Cipher\s+is\s+(.+?)(?:\n|$)', output)
        if not cipher_match:
            cipher_match = re.search(r'Cipher\s+:\s+(.+?)(?:\n|$)', output)
        if cipher_match:
            cipher = cipher_match.group(1).strip()
        
        # Map what we requested to expected protocol
        expected_map = {
            '-tls1': 'TLSv1',
            '-tls1_1': 'TLSv1.1',
            '-tls1_2': 'TLSv1.2',
            '-tls1_3': 'TLSv1.3'
        }
        expected_protocol = expected_map.get(tls_flag, tls_name)
        
        # CLIENT UNSUPPORTED: OpenSSL doesn't support this protocol at all
        # Indicator: protocol-related error + no negotiated protocol
        # OpenSSL 1.x: "no protocols available"
        # OpenSSL 3.x: "unsupported protocol", "wrong version number", etc.
        error_indicators = ['no protocols available', 'unsupported protocol', 'wrong version number']
        if any(err in output.lower() for err in error_indicators) and not negotiated_protocol:
            return {'status': 'CLIENT_UNSUPPORTED', 'reason': 'OpenSSL does not support this protocol'}
        
        # SERVER UNSUPPORTED: Multiple indicators
        # 1. Protocol downgrade detected (only for legacy TLS versions)
        # If we requested TLS 1.0 but got TLS 1.2, server doesn't support TLS 1.0
        # BUT: If we request TLS 1.2 and get TLS 1.3, server DOES support 1.2 (just prefers 1.3)
        if negotiated_protocol and negotiated_protocol != expected_protocol:
            # Only treat as unsupported for legacy versions requesting upgrade
            if tls_flag in ['-tls1', '-tls1_1']:
                return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server negotiated different protocol (downgrade)'}
            # For TLS 1.2+, upgrade is normal behavior (server preference), not unsupported
        
        # 2. Non-zero exit code with no valid cipher AND protocol didn't negotiate
        # Only if both: exit failed AND no protocol negotiated = truly rejected
        if result.returncode != 0 and cipher in ['0000', '(NONE)', 'Unknown'] and not negotiated_protocol:
            return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server rejected this protocol'}
        
        # SUPPORTED: Valid cipher negotiated with correct protocol (reliable indicator)
        # A valid cipher means the handshake succeeded with the requested protocol
        if cipher not in ['0000', '(NONE)', 'Unknown'] and negotiated_protocol:
            protocol = negotiated_protocol
            # Validate cipher is appropriate for the protocol
            # TLS 1.3 ciphers start with "TLS_", older versions use traditional suite names
            is_tls13_cipher = 'TLS_' in cipher
            protocol_is_tls13 = 'TLSv1.3' in protocol or 'TLS 1.3' in protocol
            
            # Both must agree on TLS 1.3 or both not (prevents protocol/cipher mismatch)
            if is_tls13_cipher == protocol_is_tls13:
                # Find all supported ciphers for this protocol
                all_ciphers = find_supported_ciphers(hostname, port, tls_name, tls_flag, max_ciphers,
                                                     proxy=proxy, socks_proxy=socks_proxy)
                # Include the already-negotiated cipher if not in list
                if cipher not in all_ciphers:
                    all_ciphers.insert(0, cipher)
                
                return {
                    'status': 'SUPPORTED',
                    'protocol': protocol,
                    'ciphers': all_ciphers,
                    'cipher': cipher  # Keep for backward compatibility
                }
        
        # SERVER UNSUPPORTED: Cipher is 0000/(NONE) with negotiated protocol
        # Server sent certificate but rejected the handshake
        if cipher in ['0000', '(NONE)'] and negotiated_protocol:
            return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server rejected this protocol'}
        
        # Error cases
        if 'Connection refused' in output or 'connect:errno' in output:
            return {'status': 'ERROR', 'error': 'Connection refused'}
        
        error_match = re.search(r'error:([0-9A-F]+)', output)
        error = f"SSL Error {error_match.group(1)}" if error_match else "Connection failed"
        return {'status': 'ERROR', 'error': error}
    
    except subprocess.TimeoutExpired:
        return {'status': 'ERROR', 'error': 'Timeout'}
    except FileNotFoundError:
        return {'status': 'ERROR', 'error': 'OpenSSL not found'}
    except Exception as e:
        return {'status': 'ERROR', 'error': str(e)[:50]}


def check_tls_support(hostname, port):
    """Check which TLS versions are supported."""
    print(f"\n{'='*70}")
    print(f"SSL/TLS Scanner Results for: {hostname}:{port}")
    print(f"{'='*70}\n")
    
    results = {}
    
    for tls_name, tls_flag in TLS_VERSIONS.items():
        result = check_tls_version(hostname, port, tls_name, tls_flag)
        results[tls_name] = result
    
    # Display results
    for tls_name in TLS_VERSIONS.keys():
        result = results.get(tls_name, {})
        status = result.get('status', 'UNKNOWN')
        
        if status == 'SUPPORTED':
            print(f"✓ {tls_name:<15} - SUPPORTED")
            print(f"  Protocol Version: {result.get('protocol', 'Unknown')}")
            ciphers = result.get('ciphers', [result.get('cipher', 'Unknown')])
            print(f"  Ciphers ({len(ciphers)}):")
            for cipher in ciphers:
                print(f"    • {cipher}")
        elif status == 'SERVER_UNSUPPORTED':
            print(f"✗ {tls_name:<15} - NOT SUPPORTED (Server)")
            print(f"  Server does not support this protocol version")
        elif status == 'CLIENT_UNSUPPORTED':
            print(f"⊘ {tls_name:<15} - NOT SUPPORTED (Client)")
            print(f"  {result.get('reason', 'OpenSSL does not support this protocol')}")
            print(f"  Note: Install legacy OpenSSL to test this version")
        else:
            print(f"⚠ {tls_name:<15} - ERROR: {result.get('error', 'Unknown error')}")
        print()
    
    return results


def output_json_report(hostname, port, results):
    """Output results in JSON format."""
    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'target': {
            'hostname': hostname,
            'port': port
        },
        'protocols': {}
    }
    
    for tls_name, result in results.items():
        status = result.get('status', 'UNKNOWN')
        
        # Check protocol compliance
        protocol_compliance = APPROVED_PROTOCOLS.get(tls_name, 'NOT_APPROVED')
        
        protocol_info = {
            'status': status,
            'compliance': protocol_compliance,
        }
        
        if status == 'SUPPORTED':
            protocol_info.update({
                'protocol_version': result.get('protocol', 'Unknown'),
                'ciphers': []
            })
            # Add compliance info for each cipher
            for cipher in result.get('ciphers', []):
                compliance_rating, matched_cipher, cipher_format, key_exchange, signature_algorithm = check_cipher_compliance(cipher, result.get('protocol', ''))
                cipher_info = {
                    'name': cipher,
                    'format': cipher_format,
                    'compliance': compliance_rating
                }
                if key_exchange:
                    cipher_info['key_exchange'] = key_exchange
                if signature_algorithm:
                    cipher_info['signature_algorithm'] = signature_algorithm
                protocol_info['ciphers'].append(cipher_info)
        elif status == 'SERVER_UNSUPPORTED':
            protocol_info['reason'] = 'Server does not support this protocol version'
        elif status == 'CLIENT_UNSUPPORTED':
            protocol_info['reason'] = result.get('reason', 'OpenSSL does not support this protocol')
        else:
            protocol_info['error'] = result.get('error', 'Unknown error')
        
        report['protocols'][tls_name] = protocol_info
    
    return report


def main():
    parser = argparse.ArgumentParser(
        description='TLS Version and Cipher Scanner - Check which TLS versions and ciphers are supported by a server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --url google.com
  %(prog)s --url google.com --port 443
  %(prog)s --url https://google.com:8443
  %(prog)s --url google.com --port 8443 --json
  %(prog)s --url example.com --json > report.json
        '''
    )
    
    parser.add_argument('--url', '-u', 
                        required=True,
                        help='URL or FQDN to scan (with or without http/https scheme)')
    parser.add_argument('--port', '-p',
                        type=int,
                        default=None,
                        help='Port number (default: 443)')
    parser.add_argument('--json', '-j',
                        action='store_true',
                        help='Output results in JSON format')
    parser.add_argument('--ciphers', '-c',
                        type=int,
                        default=10,
                        help='Max ciphers to enumerate per protocol (default: 10, use 0 for unlimited). Warning: unlimited enumeration is slow and IDS-detectable')
    parser.add_argument('--proxy',
                        help='HTTP/HTTPS proxy (e.g., http://proxy.example.com:8080)')
    parser.add_argument('--socks-proxy',
                        help='SOCKS proxy (e.g., socks5://proxy.example.com:1080)')
    
    args = parser.parse_args()
    
    # Load approved ciphers from CSV
    if not load_approved_ciphers():
        print("Error: Could not load approved ciphers configuration", file=sys.stderr)
        sys.exit(1)
    
    try:
        hostname, default_port = extract_hostname_port(args.url)
        
        # Use provided port, otherwise use extracted port, otherwise default to 443
        port = args.port if args.port is not None else default_port
        
        # Convert cipher limit: 0 = unlimited (None), otherwise use specified value
        max_ciphers = None if args.ciphers == 0 else args.ciphers
        
        if max_ciphers is None:
            print("⚠️  WARNING: Unlimited cipher enumeration enabled - this will be SLOW and IDS-DETECTABLE", file=sys.stderr)
        
        results = {}
        
        for tls_name, tls_flag in TLS_VERSIONS.items():
            # Pass max_ciphers to check_tls_version for cipher enumeration
            result = check_tls_version(hostname, port, tls_name, tls_flag, max_ciphers, 
                                     proxy=args.proxy, socks_proxy=args.socks_proxy)
            results[tls_name] = result
        
        if args.json:
            report = output_json_report(hostname, port, results)
            print(json.dumps(report, indent=2))
        else:
            # Text format - display results
            print(f"\n{'='*70}")
            print(f"SSL/TLS Scanner Results for: {hostname}:{port}")
            print(f"{'='*70}\n")
            
            for tls_name in TLS_VERSIONS.keys():
                result = results.get(tls_name, {})
                status = result.get('status', 'UNKNOWN')
                protocol_compliance = APPROVED_PROTOCOLS.get(tls_name, 'NOT_APPROVED')
                
                if status == 'SUPPORTED':
                    compliance_icon = '✅' if protocol_compliance == 'RECOMMENDED' else '⚠️ ' if protocol_compliance == 'SECURE' else '❌'
                    print(f"{compliance_icon} {tls_name:<15} - SUPPORTED")
                    if protocol_compliance != 'RECOMMENDED':
                        print(f"   ℹ️  Protocol compliance: {protocol_compliance}")
                    print(f"  Protocol Version: {result.get('protocol', 'Unknown')}")
                    ciphers = result.get('ciphers', [result.get('cipher', 'Unknown')])
                    print(f"  Ciphers ({len(ciphers)}):")
                    for cipher in ciphers:
                        compliance_rating, cipher_name, cipher_format, key_exchange, signature_algorithm = check_cipher_compliance(cipher, result.get('protocol', ''))
                        status_icon = '✅' if compliance_rating in ('PQC_RECOMMENDED', 'RECOMMENDED') else '⚠️ ' if compliance_rating == 'SECURE' else '❓'
                        print(f"    {status_icon} {cipher}")
                        if cipher_format and cipher_format not in ['N/A', 'Not in approved cipher list']:
                            print(f"       Format: {cipher_format}")
                        if key_exchange:
                            print(f"       Key Exchange: {key_exchange}")
                        if signature_algorithm:
                            print(f"       Signature: {signature_algorithm}")
                elif status == 'SERVER_UNSUPPORTED':
                    print(f"✗ {tls_name:<15} - NOT SUPPORTED (Server)")
                    print(f"  Server does not support this protocol version")
                elif status == 'CLIENT_UNSUPPORTED':
                    print(f"⊘ {tls_name:<15} - NOT SUPPORTED (Client)")
                    print(f"  {result.get('reason', 'OpenSSL does not support this protocol')}")
                    print(f"  Note: Install legacy OpenSSL to test this version")
                else:
                    print(f"⚠ {tls_name:<15} - ERROR: {result.get('error', 'Unknown error')}")
                print()
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
