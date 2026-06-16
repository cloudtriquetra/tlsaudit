#!/usr/bin/env python3
"""
TLS Version and Cipher Scanner
Supports both nmap (fast, default) and openssl backends with automatic selection.
Cipher names are always normalised to IANA format in output.
"""

import subprocess
import sys
import re
import xml.etree.ElementTree as ET
import json
import argparse
import csv
import os
import shutil
from urllib.parse import urlparse
from datetime import datetime

# TLS versions tracked, in order oldest to newest
TLS_VERSIONS = ['TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3']

# TLS versions with their openssl flags (for openssl backend)
TLS_VERSION_FLAGS = {
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
# key: (cipher_name, protocol) -> (rating, name, format, kex, sig, std)
APPROVED_CIPHERS = {}

# Normalisation map: openssl_name -> iana_name (built from CSV iana_name column)
OPENSSL_TO_IANA = {}

# OpenSSL executable to use (can be 'openssl' or path to tongsuo)
OPENSSL_EXECUTABLE = 'openssl'

# ---------------------------------------------------------------------------
# Built-in normalisation tables (backend-agnostic, CSV-independent)
# ---------------------------------------------------------------------------

# nmap reports TLS 1.3 ciphers with a non-standard TLS_AKE_WITH_* prefix
# in some versions. Map to the correct IANA names.
_NMAP_TLS13_ALIAS = {
    'TLS_AKE_WITH_AES_128_GCM_SHA256':       'TLS_AES_128_GCM_SHA256',
    'TLS_AKE_WITH_AES_256_GCM_SHA384':       'TLS_AES_256_GCM_SHA384',
    'TLS_AKE_WITH_CHACHA20_POLY1305_SHA256': 'TLS_CHACHA20_POLY1305_SHA256',
}

# Comprehensive OpenSSL shorthand → IANA name mapping.
# Covers ciphers that may not appear in approved_ciphers.csv (e.g. NOT_APPROVED
# ones) so that both backends produce the same IANA name for every cipher,
# enabling accurate backend-consistency comparison in reports.
_BUILTIN_OPENSSL_TO_IANA = {
    # RSA key exchange (no forward secrecy)
    'AES128-SHA':                     'TLS_RSA_WITH_AES_128_CBC_SHA',
    'AES256-SHA':                     'TLS_RSA_WITH_AES_256_CBC_SHA',
    'AES128-SHA256':                  'TLS_RSA_WITH_AES_128_CBC_SHA256',
    'AES256-SHA256':                  'TLS_RSA_WITH_AES_256_CBC_SHA256',
    'AES128-GCM-SHA256':              'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'AES256-GCM-SHA384':              'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'AES128-CCM':                     'TLS_RSA_WITH_AES_128_CCM',
    'AES256-CCM':                     'TLS_RSA_WITH_AES_256_CCM',
    'AES128-CCM8':                    'TLS_RSA_WITH_AES_128_CCM_8',
    'AES256-CCM8':                    'TLS_RSA_WITH_AES_256_CCM_8',
    'CAMELLIA128-SHA':                'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
    'CAMELLIA256-SHA':                'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
    'CAMELLIA128-SHA256':             'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    'CAMELLIA256-SHA256':             'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    'DES-CBC3-SHA':                   'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    'RC4-SHA':                        'TLS_RSA_WITH_RC4_128_SHA',
    'RC4-MD5':                        'TLS_RSA_WITH_RC4_128_MD5',
    'NULL-SHA':                       'TLS_RSA_WITH_NULL_SHA',
    'NULL-SHA256':                    'TLS_RSA_WITH_NULL_SHA256',
    'NULL-MD5':                       'TLS_RSA_WITH_NULL_MD5',
    'SEED-SHA':                       'TLS_RSA_WITH_SEED_CBC_SHA',
    'ARIA128-GCM-SHA256':             'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
    'ARIA256-GCM-SHA384':             'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
    # ECDHE-RSA
    'ECDHE-RSA-AES128-SHA':           'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'ECDHE-RSA-AES256-SHA':           'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'ECDHE-RSA-AES128-SHA256':        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    'ECDHE-RSA-AES256-SHA384':        'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    'ECDHE-RSA-AES128-GCM-SHA256':    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384':    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305':    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'ECDHE-RSA-DES-CBC3-SHA':         'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'ECDHE-RSA-RC4-SHA':              'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    'ECDHE-RSA-NULL-SHA':             'TLS_ECDHE_RSA_WITH_NULL_SHA',
    'ECDHE-RSA-CAMELLIA128-SHA256':   'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    'ECDHE-RSA-CAMELLIA256-SHA384':   'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
    'ECDHE-RSA-ARIA128-GCM-SHA256':   'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
    'ECDHE-RSA-ARIA256-GCM-SHA384':   'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
    # ECDHE-ECDSA
    'ECDHE-ECDSA-AES128-SHA':         'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    'ECDHE-ECDSA-AES256-SHA':         'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    'ECDHE-ECDSA-AES128-SHA256':      'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    'ECDHE-ECDSA-AES256-SHA384':      'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    'ECDHE-ECDSA-AES128-GCM-SHA256':  'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384':  'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'ECDHE-ECDSA-CHACHA20-POLY1305':  'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-DES-CBC3-SHA':       'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    'ECDHE-ECDSA-RC4-SHA':            'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    'ECDHE-ECDSA-NULL-SHA':           'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
    'ECDHE-ECDSA-CAMELLIA128-SHA256': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
    'ECDHE-ECDSA-CAMELLIA256-SHA384': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
    'ECDHE-ECDSA-ARIA128-GCM-SHA256': 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
    'ECDHE-ECDSA-ARIA256-GCM-SHA384': 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
    # DHE-RSA
    'DHE-RSA-AES128-SHA':             'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    'DHE-RSA-AES256-SHA':             'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    'DHE-RSA-AES128-SHA256':          'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    'DHE-RSA-AES256-SHA256':          'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    'DHE-RSA-AES128-GCM-SHA256':      'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    'DHE-RSA-AES256-GCM-SHA384':      'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    'DHE-RSA-CHACHA20-POLY1305':      'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'DHE-RSA-DES-CBC3-SHA':           'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    'DHE-RSA-CAMELLIA128-SHA':        'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
    'DHE-RSA-CAMELLIA256-SHA':        'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
    'DHE-RSA-CAMELLIA128-SHA256':     'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
    'DHE-RSA-CAMELLIA256-SHA256':     'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
    'DHE-RSA-AES128-CCM':             'TLS_DHE_RSA_WITH_AES_128_CCM',
    'DHE-RSA-AES256-CCM':             'TLS_DHE_RSA_WITH_AES_256_CCM',
    'DHE-RSA-AES128-CCM8':            'TLS_DHE_RSA_WITH_AES_128_CCM_8',
    'DHE-RSA-AES256-CCM8':            'TLS_DHE_RSA_WITH_AES_256_CCM_8',
    'DHE-RSA-ARIA128-GCM-SHA256':     'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
    'DHE-RSA-ARIA256-GCM-SHA384':     'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
    'DHE-RSA-SEED-SHA':               'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
    # DHE-DSS
    'DHE-DSS-AES128-SHA':             'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
    'DHE-DSS-AES256-SHA':             'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
    'DHE-DSS-AES128-SHA256':          'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
    'DHE-DSS-AES256-SHA256':          'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
    'DHE-DSS-AES128-GCM-SHA256':      'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
    'DHE-DSS-AES256-GCM-SHA384':      'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
    'DHE-DSS-CAMELLIA128-SHA':        'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
    'DHE-DSS-CAMELLIA256-SHA':        'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
    # ECDH static (non-ephemeral)
    'ECDH-RSA-AES128-SHA':            'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
    'ECDH-RSA-AES256-SHA':            'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
    'ECDH-RSA-AES128-SHA256':         'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
    'ECDH-RSA-AES256-SHA384':         'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
    'ECDH-RSA-AES128-GCM-SHA256':     'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
    'ECDH-RSA-AES256-GCM-SHA384':     'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    'ECDH-ECDSA-AES128-SHA':          'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
    'ECDH-ECDSA-AES256-SHA':          'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
    'ECDH-ECDSA-AES128-SHA256':       'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
    'ECDH-ECDSA-AES256-SHA384':       'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
    'ECDH-ECDSA-AES128-GCM-SHA256':   'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
    'ECDH-ECDSA-AES256-GCM-SHA384':   'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
    # DH static
    'DH-RSA-AES128-SHA':              'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
    'DH-RSA-AES256-SHA':              'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
    'DH-RSA-AES128-SHA256':           'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
    'DH-RSA-AES256-SHA256':           'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
    'DH-RSA-AES128-GCM-SHA256':       'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
    'DH-RSA-AES256-GCM-SHA384':       'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
    'DH-DSS-AES128-SHA':              'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
    'DH-DSS-AES256-SHA':              'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
    # Anonymous (no authentication)
    'ADH-AES128-SHA':                 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
    'ADH-AES256-SHA':                 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
    'ADH-AES128-GCM-SHA256':          'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
    'ADH-AES256-GCM-SHA384':          'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
    'AECDH-AES128-SHA':               'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
    'AECDH-AES256-SHA':               'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
    'AECDH-NULL-SHA':                 'TLS_ECDH_anon_WITH_NULL_SHA',
}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

def normalise_to_iana(cipher_name):
    """Return the IANA name for a cipher, applying mappings in priority order:
    1. CSV-derived OPENSSL_TO_IANA (approved ciphers with iana_name column)
    2. nmap TLS 1.3 non-standard aliases (TLS_AKE_WITH_* → TLS_AES_*)
    3. Built-in comprehensive OpenSSL shorthand table
    4. Passthrough (name already in IANA format or genuinely unknown)
    """
    return (
        OPENSSL_TO_IANA.get(cipher_name)
        or _NMAP_TLS13_ALIAS.get(cipher_name)
        or _BUILTIN_OPENSSL_TO_IANA.get(cipher_name)
        or cipher_name
    )


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------

def select_backend(preferred):
    """Choose the scan backend.

    Args:
        preferred: 'auto', 'nmap', or 'openssl'

    Returns:
        'nmap' or 'openssl'
    """
    if preferred == 'nmap':
        return 'nmap'
    if preferred == 'openssl':
        return 'openssl'
    # auto: prefer nmap
    if shutil.which('nmap'):
        return 'nmap'
    print("nmap not found, falling back to openssl", file=sys.stderr)
    return 'openssl'


# ---------------------------------------------------------------------------
# CSV loading
# ---------------------------------------------------------------------------

def _load_csv_rows(csv_path, compliance_standard):
    """Read CSV rows and populate APPROVED_CIPHERS and OPENSSL_TO_IANA."""
    global OPENSSL_TO_IANA
    with open(csv_path, 'r') as f:
        for row in csv.DictReader(f):
            cipher_name = row['cipher_name'].strip()
            if not cipher_name or cipher_name.startswith('#'):
                continue
            std = row.get('compliance_standard', 'GLOBAL').strip()
            if compliance_standard and std != compliance_standard and std != 'GLOBAL':
                continue

            protocol = row['protocol'].strip()
            rating = row['rating'].strip()
            cipher_format = row.get('format', 'UNKNOWN').strip()
            key_exchange = row.get('key_exchange', '').strip()
            signature_algorithm = row.get('signature_algorithm', '').strip()
            iana_name = row.get('iana_name', '').strip()

            key = (cipher_name, protocol)
            APPROVED_CIPHERS[key] = (rating, cipher_name, cipher_format, key_exchange, signature_algorithm, std)

            # Build the normalisation map from OPENSSL rows with a populated iana_name
            if cipher_format == 'OPENSSL' and iana_name:
                OPENSSL_TO_IANA[cipher_name] = iana_name


def load_approved_ciphers(csv_file='approved_ciphers.csv', compliance_standard=None, tongsuo_path=None):
    """Load approved cipher suites from CSV file.

    Args:
        csv_file: Path to cipher configuration CSV
        compliance_standard: Compliance standard to use (GLOBAL, CHINA_GB/T_38636, etc.)
        tongsuo_path: Custom path to tongsuo/openssl binary (only used for CHINA_GB/T_38636)
    """
    global OPENSSL_EXECUTABLE

    # If China compliance standard is specified, try to use tongsuo
    if compliance_standard == 'CHINA_GB/T_38636':
        tongsuo_bin = find_tongsuo(custom_path=tongsuo_path)
        if tongsuo_bin:
            OPENSSL_EXECUTABLE = tongsuo_bin
            print(f"Using tongsuo for China standard compliance: {tongsuo_bin}", file=sys.stderr)
        else:
            if tongsuo_path:
                print(
                    f"Warning: Custom tongsuo path '{tongsuo_path}' not found or invalid. "
                    "Using standard openssl.",
                    file=sys.stderr,
                )
            else:
                print(
                    "Warning: China standard requested but tongsuo not found. "
                    "Using standard openssl.",
                    file=sys.stderr,
                )
            OPENSSL_EXECUTABLE = 'openssl'

    script_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(script_dir, csv_file)

    if not os.path.exists(csv_path):
        print(f"Warning: Cipher config file not found: {csv_path}", file=sys.stderr)
        return False

    try:
        _load_csv_rows(csv_path, compliance_standard)
        return True
    except Exception as e:
        print(f"Error loading cipher config: {e}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Compliance lookup
# ---------------------------------------------------------------------------

def check_cipher_compliance(cipher, protocol):
    """Check if a cipher is approved according to compliance standards.

    The cipher argument should be in IANA format (after normalisation).

    Returns: (rating, cipher_name, format, key_exchange, signature_algorithm, compliance_standard)
    where rating is 'PQC_RECOMMENDED', 'RECOMMENDED', 'SECURE', 'REQUIRED', or 'NOT_APPROVED'
    """
    entry = APPROVED_CIPHERS.get((cipher, protocol))
    if entry:
        return entry
    return ('NOT_APPROVED', 'Not in approved cipher list', 'N/A', '', '', '')


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def extract_hostname_port(url):
    """Extract hostname and port from URL."""
    parsed = urlparse(url if url.startswith('http') else f'https://{url}')
    hostname = parsed.hostname or parsed.path.split('/')[0]
    return hostname, parsed.port or 443


# ---------------------------------------------------------------------------
# openssl backend
# ---------------------------------------------------------------------------

def find_tongsuo(custom_path=None):
    """Try to find tongsuo/openssl executable in common locations.

    Args:
        custom_path: Custom path provided by user (takes precedence)
    """
    if custom_path:
        try:
            result = subprocess.run(
                [custom_path, 'version'],
                capture_output=True,
                timeout=2,
                text=True,
            )
            if result.returncode == 0 and (
                'tongsuo' in result.stdout.lower() or 'openssl' in result.stdout.lower()
            ):
                return custom_path
        except Exception:
            pass

    tongsuo_paths = [
        '/opt/tongsuo/bin/openssl',
        'tongsuo',
        '/usr/local/bin/tongsuo',
        '/opt/tongsuo/bin/tongsuo',
        '/opt/bin/tongsuo',
        '/usr/bin/tongsuo',
    ]

    for path in tongsuo_paths:
        try:
            result = subprocess.run(
                [path, 'version'],
                capture_output=True,
                timeout=2,
                text=True,
            )
            if result.returncode == 0 and (
                'tongsuo' in result.stdout.lower() or 'openssl' in result.stdout.lower()
            ):
                return path
        except Exception:
            pass

    return None


def get_available_ciphers(tls_flag):
    """Get list of ALL ciphers available for a specific TLS version from OpenSSL."""
    try:
        if tls_flag == '-tls1':
            cipher_spec = 'ALL:eNULL:@SECLEVEL=0'
        elif tls_flag == '-tls1_1':
            cipher_spec = 'ALL:eNULL:@SECLEVEL=0'
        elif tls_flag == '-tls1_2':
            cipher_spec = 'ALL:eNULL'
        elif tls_flag == '-tls1_3':
            cipher_spec = 'ALL'
        else:
            cipher_spec = 'ALL:eNULL'

        cmd = [OPENSSL_EXECUTABLE, 'ciphers', '-v', cipher_spec]
        result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)

        ciphers = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split()
                if parts:
                    ciphers.append(parts[0])
        return ciphers
    except Exception:
        return []


def find_supported_ciphers(hostname, port, tls_name, tls_flag, max_ciphers=None, proxy=None):
    """Find all supported ciphers for a TLS version by iteratively testing."""
    supported_ciphers = []
    seen = set()
    available_ciphers = get_available_ciphers(tls_flag)

    if not available_ciphers:
        return []

    expected_map = {
        '-tls1': 'TLSv1',
        '-tls1_1': 'TLSv1.1',
        '-tls1_2': 'TLSv1.2',
        '-tls1_3': 'TLSv1.3',
    }
    expected_protocol = expected_map.get(tls_flag, tls_name)

    ciphers_to_test = available_ciphers if max_ciphers is None else available_ciphers[:max_ciphers]

    for cipher in ciphers_to_test:
        try:
            cmd = [
                OPENSSL_EXECUTABLE, 's_client',
                '-connect', f'{hostname}:{port}',
                tls_flag,
                '-cipher', cipher,
                '-servername', hostname,
            ]

            if proxy:
                cmd.extend(['-proxy', proxy])

            result = subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                text=True,
            )

            output = result.stdout + result.stderr

            negotiated_protocol = None
            protocol_match = re.search(r'Protocol\s+:\s+([a-zA-Z0-9.]+)', output)
            if protocol_match:
                negotiated_protocol = protocol_match.group(1)
            else:
                protocol_match = re.search(r'New,\s+(TLSv[\d.]+),\s+Cipher', output)
                if protocol_match:
                    negotiated_protocol = protocol_match.group(1)

            cipher_match = re.search(r'Cipher\s+is\s+(.+?)(?:\n|$)', output)
            if not cipher_match:
                cipher_match = re.search(r'Cipher\s+:\s+(.+?)(?:\n|$)', output)

            negotiated_cipher = None
            if cipher_match:
                negotiated_cipher = cipher_match.group(1).strip()

            if (
                negotiated_protocol == expected_protocol
                and negotiated_cipher
                and negotiated_cipher not in ['(NONE)', '0000']
                and negotiated_cipher not in seen
            ):
                supported_ciphers.append(negotiated_cipher)
                seen.add(negotiated_cipher)
        except Exception:
            pass

    return supported_ciphers


def check_tls_version(hostname, port, tls_name, tls_flag, proxy=None):
    """Check if a specific TLS version is supported and get cipher info (openssl backend)."""
    try:
        cmd = [
            OPENSSL_EXECUTABLE, 's_client',
            '-connect', f'{hostname}:{port}',
            tls_flag,
            '-servername', hostname,
        ]

        if proxy:
            cmd.extend(['-proxy', proxy])
        if tls_flag in ['-tls1', '-tls1_1']:
            cmd.extend(['-cipher', 'DEFAULT:@SECLEVEL=0'])

        result = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )

        output = result.stdout + result.stderr

        negotiated_protocol = None
        protocol_match = re.search(r'Protocol\s+:\s+([a-zA-Z0-9.]+)', output)
        if protocol_match:
            negotiated_protocol = protocol_match.group(1)
        else:
            protocol_match = re.search(r'New,\s+(TLSv[\d.]+),\s+Cipher', output)
            if protocol_match:
                negotiated_protocol = protocol_match.group(1)

        cipher = 'Unknown'
        cipher_match = re.search(r'Cipher\s+is\s+(.+?)(?:\n|$)', output)
        if not cipher_match:
            cipher_match = re.search(r'Cipher\s+:\s+(.+?)(?:\n|$)', output)
        if cipher_match:
            cipher = cipher_match.group(1).strip()

        expected_map = {
            '-tls1': 'TLSv1',
            '-tls1_1': 'TLSv1.1',
            '-tls1_2': 'TLSv1.2',
            '-tls1_3': 'TLSv1.3',
        }
        expected_protocol = expected_map.get(tls_flag, tls_name)

        connection_established = 'CONNECTED' in output

        if not connection_established and result.returncode != 0:
            if 'Connection refused' in output or 'connect:errno' in output:
                return {'status': 'ERROR', 'error': f'Connection refused by {hostname}:{port}. Is the server running on this port?'}
            if 'getaddrinfo failed' in output or 'nodename nor servname provided' in output or 'Name or service not known' in output:
                return {'status': 'ERROR', 'error': f'DNS resolution failed for "{hostname}". Check hostname spelling and DNS availability.'}
            if 'Network is unreachable' in output or 'No route to host' in output or 'Unreachable' in output:
                return {'status': 'ERROR', 'error': f'Network unreachable to {hostname}:{port}. Check network connectivity and WiFi status.'}
            if 'Host is down' in output or 'host unreachable' in output.lower():
                return {'status': 'ERROR', 'error': f'Host unreachable: {hostname}:{port}. Target server is offline or network path unavailable.'}
            return {'status': 'ERROR', 'error': f'Unable to connect to {hostname}:{port}. Check network connectivity, WiFi status, and firewall rules.'}

        error_indicators = ['no protocols available', 'unsupported protocol', 'wrong version number']
        if any(err in output.lower() for err in error_indicators) and not negotiated_protocol:
            return {'status': 'CLIENT_UNSUPPORTED', 'reason': 'OpenSSL does not support this protocol'}

        if negotiated_protocol and negotiated_protocol != expected_protocol:
            if tls_flag in ['-tls1', '-tls1_1']:
                return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server negotiated different protocol (downgrade)'}

        if result.returncode != 0 and cipher in ['0000', '(NONE)', 'Unknown'] and not negotiated_protocol:
            return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server rejected this protocol'}

        if cipher not in ['0000', '(NONE)', 'Unknown'] and negotiated_protocol:
            protocol = negotiated_protocol
            is_tls13_cipher = 'TLS_' in cipher
            protocol_is_tls13 = 'TLSv1.3' in protocol or 'TLS 1.3' in protocol

            if is_tls13_cipher == protocol_is_tls13:
                all_ciphers = find_supported_ciphers(
                    hostname, port, tls_name, tls_flag,
                    proxy=proxy,
                )
                if cipher not in all_ciphers:
                    all_ciphers.insert(0, cipher)

                return {
                    'status': 'SUPPORTED',
                    'protocol': protocol,
                    'ciphers': all_ciphers,
                    'cipher': cipher,
                }

        if cipher in ['0000', '(NONE)'] and negotiated_protocol:
            return {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server rejected this protocol'}

        if 'timeout' in output.lower() or 'timed out' in output.lower():
            return {'status': 'ERROR', 'error': f'Connection timeout to {hostname}:{port}. Server not responding. Check network connectivity and firewall rules.'}

        if 'Permission denied' in output:
            return {'status': 'ERROR', 'error': f'Permission denied connecting to {hostname}:{port}. May require elevated privileges or port access.'}

        if 'Certificate_required' in output or 'certificate required' in output.lower():
            return {'status': 'ERROR', 'error': 'Server requires client certificate authentication. Not currently supported.'}

        error_match = re.search(r'error:([0-9A-F]+)', output)
        if error_match:
            error_code = error_match.group(1)
            error_desc = {
                '14094410': 'SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE - Server cannot negotiate a protocol/cipher',
                '1416D086': 'SSL_R_TLSV1_ALERT_INTERNAL_ERROR - Server internal error',
                '14077410': 'SSL_R_SSL_HANDSHAKE_FAILURE - General handshake failure',
            }.get(error_code, f'OpenSSL error {error_code}')
            return {'status': 'ERROR', 'error': f'SSL/TLS Error: {error_desc}'}

        return {'status': 'ERROR', 'error': f'Connection to {hostname}:{port} failed. Check server accessibility, port number, and proxy configuration.'}

    except subprocess.TimeoutExpired:
        return {'status': 'ERROR', 'error': f'Connection timeout to {hostname}:{port}. Server not responding within 10 seconds. Try with a longer timeout or check network connectivity.'}
    except FileNotFoundError:
        exe_name = 'Tongsuo' if 'tongsuo' in OPENSSL_EXECUTABLE else 'OpenSSL'
        return {'status': 'ERROR', 'error': f"{exe_name} executable not found. Install {exe_name} and ensure it's in your PATH."}
    except Exception as e:
        return {'status': 'ERROR', 'error': f'Unexpected error: {str(e)[:100]}'}


def scan_with_openssl(hostname, port, proxy=None):
    """Run openssl-based scan and return per-protocol results dict."""
    results = {}
    for tls_name, tls_flag in TLS_VERSION_FLAGS.items():
        results[tls_name] = check_tls_version(
            hostname, port, tls_name, tls_flag,
            proxy=proxy,
        )
    return results


# ---------------------------------------------------------------------------
# nmap backend
# ---------------------------------------------------------------------------

def _build_nmap_cmd(hostname, port, proxy):
    cmd = ['nmap', '--script', 'ssl-enum-ciphers', '-p', str(port), hostname, '-oX', '-']
    if proxy:
        cmd.extend(['--proxies', proxy])
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


def scan_with_nmap(hostname, port, proxy=None):
    """Run nmap ssl-enum-ciphers and return per-protocol raw results dict."""
    cmd = _build_nmap_cmd(hostname, port, proxy)
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
        v: nmap_results.get(
            v,
            {'status': 'SERVER_UNSUPPORTED', 'reason': 'Server does not support this protocol version'},
        )
        for v in TLS_VERSIONS
    }


# ---------------------------------------------------------------------------
# Output normalisation
# ---------------------------------------------------------------------------

def normalise_results(results):
    """Return a copy of results with cipher names normalised to IANA format.

    Each cipher is stored as a dict {'iana': <iana_name>, 'original': <reported_name>}.
    When the backend already reported an IANA name, both fields are identical.
    """
    normalised = {}
    for tls_name, result in results.items():
        if result.get('status') == 'SUPPORTED':
            new_result = dict(result)
            new_result['ciphers'] = [
                {'iana': normalise_to_iana(c), 'original': c}
                for c in result.get('ciphers', [])
            ]
            if 'cipher' in result:
                new_result['cipher'] = normalise_to_iana(result['cipher'])
            normalised[tls_name] = new_result
        else:
            normalised[tls_name] = result
    return normalised


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _cipher_to_json(cipher_entry, protocol):
    """Build the JSON dict for one cipher entry.

    cipher_entry is a dict {'iana': <iana_name>, 'original': <reported_name>}.
    The IANA name is used for the compliance lookup. Both names appear in the
    output so consumers can cross-reference regardless of which backend ran.
    """
    iana = cipher_entry['iana']
    original = cipher_entry['original']
    rating, _, _fmt, kex, sig, std = check_cipher_compliance(iana, protocol)
    info = {
        'iana_name': iana,
        'compliance': rating,
        'standard': std,
    }
    if original != iana:
        info['openssl_name'] = original
    if kex:
        info['key_exchange'] = kex
    if sig:
        info['signature_algorithm'] = sig
    return info


def output_json_report(hostname, port, results):
    """Return the full scan report as a JSON-serialisable dict.

    Cipher names in ``results`` must already be normalised to IANA format.
    """
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
            protocol_info['cipher_count'] = len(protocol_info['ciphers'])
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


def _print_cipher_line(cipher_entry, protocol):
    """Print one cipher line. cipher_entry is {'iana': str, 'original': str}."""
    iana = cipher_entry['iana']
    original = cipher_entry['original']
    rating, _, fmt, kex, sig, std = check_cipher_compliance(iana, protocol)
    label = iana if iana == original else f"{iana}  (openssl: {original})"
    print(f"    {_cipher_icon(rating)} {label}")
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
    elif status == 'CLIENT_UNSUPPORTED':
        print(f"⊘ {tls_name:<15} - NOT SUPPORTED (Client)")
        print(f"  {result.get('reason', 'OpenSSL does not support this protocol')}")
        print("  Note: Install legacy OpenSSL to test this version")
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
        description='TLS Version and Cipher Scanner - Check which TLS versions and ciphers are supported by a server',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s --url google.com
  %(prog)s --url google.com --port 443
  %(prog)s --url https://google.com:8443
  %(prog)s --url google.com --port 8443 --json
  %(prog)s --url example.com --json > report.json
        ''',
    )

    parser.add_argument('--url', '-u', required=True,
                        help='URL or FQDN to scan (with or without http/https scheme)')
    parser.add_argument('--port', '-p', type=int, default=None,
                        help='Port number (default: 443)')
    parser.add_argument('--json', '-j', action='store_true',
                        help='Output results in JSON format')
    parser.add_argument('--backend', default='auto',
                        choices=['auto', 'nmap', 'openssl'],
                        help=(
                            'Scan backend: auto (default, uses nmap if available, otherwise openssl), '
                            'nmap, or openssl. openssl required for CHINA_GB/T_38636 compliance.'
                        ))
    parser.add_argument('--proxy',
                        help='HTTP CONNECT proxy (e.g., http://proxy.example.com:8080). '
                             'Supported by both nmap and openssl backends.')
    parser.add_argument('--compliance-standard', default='GLOBAL',
                        help='Compliance standard to enforce (default: GLOBAL, options: GLOBAL, CHINA_GB/T_38636, etc.)')
    parser.add_argument('--tongsuo-path',
                        help='Custom path to tongsuo/openssl binary. '
                             'Only used with --compliance-standard CHINA_GB/T_38636')

    args = parser.parse_args()

    # Load approved ciphers from CSV (also sets up OPENSSL_TO_IANA and OPENSSL_EXECUTABLE)
    if not load_approved_ciphers(
        compliance_standard=args.compliance_standard,
        tongsuo_path=args.tongsuo_path,
    ):
        print("Error: Could not load approved ciphers configuration", file=sys.stderr)
        sys.exit(1)

    # Select backend
    backend = select_backend(args.backend)
    if args.backend != 'auto' or backend != 'nmap':
        # Print backend info when non-default or when fallback happened
        print(f"Using {backend} backend", file=sys.stderr)

    try:
        hostname, default_port = extract_hostname_port(args.url)
        port = args.port if args.port is not None else default_port

        # Run scan with chosen backend
        if backend == 'nmap':
            raw_results = build_full_results(
                scan_with_nmap(hostname, port, proxy=args.proxy)
            )
        else:
            raw_results = scan_with_openssl(hostname, port, proxy=args.proxy)

        # Normalise all cipher names to IANA format before output
        results = normalise_results(raw_results)

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
