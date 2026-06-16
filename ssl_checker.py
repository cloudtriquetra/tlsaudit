#!/usr/bin/env python3
"""
TLS Version and Cipher Scanner
Uses nmap ssl-enum-ciphers for fast, comprehensive cipher enumeration.
"""

import subprocess
import sys
import xml.etree.ElementTree as ET
import json
import argparse
import csv
import os
from urllib.parse import urlparse
from datetime import datetime

# TLS versions tracked, in order oldest to newest
TLS_VERSIONS = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

# Approved TLS protocol versions
APPROVED_PROTOCOLS = {
    'TLSv1.2': 'SECURE',
    'TLSv1.3': 'RECOMMENDED',
}

# Approved cipher suites (loaded from CSV)
APPROVED_CIPHERS = {}


def load_approved_ciphers(csv_file='approved_ciphers.csv', compliance_standard=None):
    """Load approved cipher suites from CSV file.

    CSV format: cipher_name,protocol,rating,format,key_exchange,signature_algorithm,compliance_standard
    """
    global APPROVED_CIPHERS

    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, csv_file)

    if not os.path.exists(csv_path):
        print(f"Warning: Cipher config file not found: {csv_path}", file=sys.stderr)
        return False

    if compliance_standard == 'CHINA_GB/T_38636':
        print(
            "Warning: CHINA_GB/T_38636 SM cipher detection requires the openssl/tongsuo backend. "
            "The nmap backend will check discovered ciphers against the approved list but cannot "
            "enumerate SM-specific ciphers.",
            file=sys.stderr,
        )

    try:
        _load_csv_rows(csv_path, compliance_standard)
        return True
    except Exception as e:
        print(f"Error loading cipher config: {e}", file=sys.stderr)
        return False


def _load_csv_rows(csv_path, compliance_standard):
    """Read CSV rows and populate APPROVED_CIPHERS."""
    with open(csv_path, 'r') as f:
        for row in csv.DictReader(f):
            cipher_name = row['cipher_name'].strip()
            if not cipher_name or cipher_name.startswith('#'):
                continue
            std = row.get('compliance_standard', 'GLOBAL').strip()
            if compliance_standard and std != compliance_standard and std != 'GLOBAL':
                continue
            key = (cipher_name, row['protocol'].strip())
            APPROVED_CIPHERS[key] = (
                row['rating'].strip(),
                cipher_name,
                row.get('format', 'UNKNOWN').strip(),
                row.get('key_exchange', '').strip(),
                row.get('signature_algorithm', '').strip(),
                std,
            )


def check_cipher_compliance(cipher, protocol):
    """Return (rating, name, format, key_exchange, signature_algorithm, standard) for a cipher."""
    entry = APPROVED_CIPHERS.get((cipher, protocol))
    if entry:
        return entry
    return ('NOT_APPROVED', 'Not in approved cipher list', 'N/A', '', '', '')


def extract_hostname_port(url):
    """Extract hostname and port from URL."""
    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    hostname = parsed.hostname or parsed.path.split('/')[0]
    return hostname, parsed.port or 443


# ---------------------------------------------------------------------------
# nmap scanning
# ---------------------------------------------------------------------------

def _build_nmap_cmd(hostname, port, socks_proxy, proxy):
    cmd = ['nmap', '--script', 'ssl-enum-ciphers', '-p', str(port), hostname, '-oX', '-']
    if socks_proxy:
        cmd.extend(['--proxies', socks_proxy])
    elif proxy:
        print(
            "Warning: HTTP proxy is not supported by the nmap backend. "
            "Use --socks-proxy with a SOCKS4/5 proxy instead.",
            file=sys.stderr,
        )
    return cmd


def _run_nmap(cmd, hostname, port):
    """Execute nmap and return (stdout, error_dict). One of them is None."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        return None, {'_error': 'nmap executable not found. Install nmap: https://nmap.org/download.html'}
    except subprocess.TimeoutExpired:
        return None, {'_error': f'nmap scan timed out for {hostname}:{port}'}

    if not result.stdout.strip():
        msg = result.stderr.strip() or f'no output for {hostname}:{port}'
        return None, {'_error': f'nmap produced no output: {msg}'}

    return result.stdout, None


def _parse_port_state(port_elem, hostname, port):
    """Return an error dict if the port is closed/filtered, else None."""
    state_elem = port_elem.find('state')
    if state_elem is None:
        return None
    state = state_elem.get('state', '')
    if state == 'closed':
        return {'_error': f'Port {port} is closed on {hostname}'}
    if state == 'filtered':
        return {'_error': f'Port {port} is filtered on {hostname} — firewall may be blocking the probe'}
    return None


def _extract_ciphers_from_proto_table(proto_table):
    """Parse one <table key="TLSv1.x"> element and return list of cipher names."""
    ciphers = []
    ciphers_table = proto_table.find('table[@key="ciphers"]')
    if ciphers_table is None:
        return ciphers
    for entry in ciphers_table.findall('table'):
        name_elem = entry.find('elem[@key="name"]')
        if name_elem is not None and name_elem.text:
            ciphers.append(name_elem.text.strip())
    return ciphers


def _parse_nmap_xml(xml_text, hostname, port):
    """Parse nmap XML output and return per-protocol results dict."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {'_error': f'Failed to parse nmap XML output: {e}'}

    host = root.find('host')
    if host is None:
        return {'_error': f'Host {hostname} not found or not reachable'}

    port_elem = host.find(f'.//port[@portid="{port}"]')
    if port_elem is None:
        return {'_error': f'Port {port} not found in nmap scan results'}

    port_error = _parse_port_state(port_elem, hostname, port)
    if port_error:
        return port_error

    script = port_elem.find('.//script[@id="ssl-enum-ciphers"]')
    if script is None:
        return {'_no_tls': True}

    results = {}
    for proto_table in script.findall('table'):
        proto_name = proto_table.get('key', '')
        if not proto_name.startswith('TLS'):
            continue
        ciphers = _extract_ciphers_from_proto_table(proto_table)
        if ciphers:
            results[proto_name] = {
                'status': 'SUPPORTED',
                'protocol': proto_name,
                'ciphers': ciphers,
                'cipher': ciphers[0],
            }

    return results


def scan_with_nmap(hostname, port, socks_proxy=None, proxy=None):
    """Run nmap ssl-enum-ciphers and return per-protocol results dict."""
    cmd = _build_nmap_cmd(hostname, port, socks_proxy, proxy)
    stdout, error = _run_nmap(cmd, hostname, port)
    if error:
        return error
    return _parse_nmap_xml(stdout, hostname, port)


def build_full_results(nmap_results):
    """Expand nmap results to cover all TLS versions, marking absent ones as SERVER_UNSUPPORTED."""
    if '_error' in nmap_results:
        return {v: {'status': 'ERROR', 'error': nmap_results['_error']} for v in TLS_VERSIONS}

    if '_no_tls' in nmap_results:
        return {v: {'status': 'ERROR', 'error': 'No TLS detected on this port'} for v in TLS_VERSIONS}

    return {
        v: nmap_results.get(v, {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server does not support this protocol version'})
        for v in TLS_VERSIONS
    }


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _cipher_to_json(cipher, protocol):
    """Build the JSON dict for one cipher entry."""
    rating, _, fmt, kex, sig, std = check_cipher_compliance(cipher, protocol)
    info = {'name': cipher, 'format': fmt, 'compliance': rating, 'standard': std}
    if kex:
        info['key_exchange'] = kex
    if sig:
        info['signature_algorithm'] = sig
    return info


def output_json_report(hostname, port, results):
    """Return the full scan report as a JSON-serialisable dict."""
    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'target': {'hostname': hostname, 'port': port},
        'protocols': {},
    }

    for tls_name in TLS_VERSIONS:
        result = results.get(tls_name, {})
        status = result.get('status', 'UNKNOWN')
        protocol_compliance = APPROVED_PROTOCOLS.get(tls_name, 'NOT_APPROVED')

        protocol_info = {'status': status, 'compliance': protocol_compliance}

        if status == 'SUPPORTED':
            proto = result.get('protocol', 'Unknown')
            protocol_info['protocol_version'] = proto
            protocol_info['ciphers'] = [_cipher_to_json(c, proto) for c in result.get('ciphers', [])]
        elif status == 'SERVER_UNSUPPORTED':
            protocol_info['reason'] = 'Server does not support this protocol version'
        else:
            protocol_info['error'] = result.get('error', 'Unknown error')

        report['protocols'][tls_name] = protocol_info

    return report


# ---------------------------------------------------------------------------
# Text output
# ---------------------------------------------------------------------------

def _protocol_icon(protocol_compliance):
    if protocol_compliance == 'RECOMMENDED':
        return '✅'
    if protocol_compliance == 'SECURE':
        return '⚠️ '
    return '❌'


def _cipher_icon(rating):
    if rating in ('PQC_RECOMMENDED', 'RECOMMENDED', 'REQUIRED'):
        return '✅'
    if rating == 'SECURE':
        return '⚠️ '
    return '❓'


def _print_cipher_line(cipher, protocol):
    rating, _, fmt, kex, sig, std = check_cipher_compliance(cipher, protocol)
    print(f"    {_cipher_icon(rating)} {cipher}")
    if std and std != 'GLOBAL':
        print(f"       Standard: {std}")
    if fmt and fmt not in ('N/A', 'Not in approved cipher list'):
        print(f"       Format: {fmt}")
    if kex:
        print(f"       Key Exchange: {kex}")
    if sig:
        print(f"       Signature: {sig}")


def _print_protocol_block(tls_name, result):
    status = result.get('status', 'UNKNOWN')
    protocol_compliance = APPROVED_PROTOCOLS.get(tls_name, 'NOT_APPROVED')

    if status == 'SUPPORTED':
        icon = _protocol_icon(protocol_compliance)
        print(f"{icon} {tls_name:<15} - SUPPORTED")
        if protocol_compliance != 'RECOMMENDED':
            print(f"   ℹ️  Protocol compliance: {protocol_compliance}")
        proto = result.get('protocol', 'Unknown')
        print(f"  Protocol Version: {proto}")
        ciphers = result.get('ciphers', [])
        print(f"  Ciphers ({len(ciphers)}):")
        for cipher in ciphers:
            _print_cipher_line(cipher, proto)
    elif status == 'SERVER_UNSUPPORTED':
        print(f"✗ {tls_name:<15} - NOT SUPPORTED (Server)")
        print("  Server does not support this protocol version")
    else:
        print(f"⚠ {tls_name:<15} - ERROR: {result.get('error', 'Unknown error')}")


def _print_text_results(hostname, port, results):
    print(f"\n{'='*70}")
    print(f"SSL/TLS Scanner Results for: {hostname}:{port}")
    print(f"{'='*70}\n")
    for tls_name in TLS_VERSIONS:
        _print_protocol_block(tls_name, results.get(tls_name, {}))
        print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='TLS Version and Cipher Scanner - uses nmap ssl-enum-ciphers for fast enumeration',
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

    parser.add_argument('--url', '-u', required=True,
                        help='URL or FQDN to scan (with or without http/https scheme)')
    parser.add_argument('--port', '-p', type=int, default=None,
                        help='Port number (default: 443)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output results in JSON format')
    parser.add_argument('--proxy',
                        help='HTTP/HTTPS proxy — NOTE: not supported by nmap; use --socks-proxy instead')
    parser.add_argument('--socks-proxy',
                        help='SOCKS proxy passed to nmap --proxies (e.g., socks5://proxy.example.com:1080)')
    parser.add_argument('--compliance-standard', default='GLOBAL',
                        help='Compliance standard to enforce (default: GLOBAL, options: GLOBAL, CHINA_GB/T_38636, etc.)')

    args = parser.parse_args()

    if not load_approved_ciphers(compliance_standard=args.compliance_standard):
        print("Error: Could not load approved ciphers configuration", file=sys.stderr)
        sys.exit(1)

    try:
        hostname, default_port = extract_hostname_port(args.url)
        port = args.port if args.port is not None else default_port

        results = build_full_results(
            scan_with_nmap(hostname, port, socks_proxy=args.socks_proxy, proxy=args.proxy)
        )

        if args.json:
            print(json.dumps(output_json_report(hostname, port, results), indent=2))
        else:
            _print_text_results(hostname, port, results)

    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
