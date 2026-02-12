# tlsaudit

Verify TLS/SSL compliance. Audit cipher suites and protocol versions against modern security standards. Get instant compliance ratings and format details.

**Repository:** https://github.com/cloudtriquetra/tlsaudit

> 🔒 **Secure by default** - Validates against TLS 1.2+ with RECOMMENDED/SECURE cipher filtering. Easy to customize for your compliance requirements.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/cloudtriquetra/tlsaudit.git
cd tlsaudit

# Scan a domain
python3 ssl_checker.py --url example.com

# Get JSON report
python3 ssl_checker.py --url example.com --json > report.json

# Custom cipher enumeration
python3 ssl_checker.py --url example.com --ciphers 50
```

## Features

- **TLS Version Detection**: Tests for support of TLS 1.0, 1.1, 1.2, and 1.3
- **Cipher Suite Enumeration**: Identifies all supported ciphers per protocol
- **Compliance Checking**: Validates ciphers and protocols against an approved security standards list
- **Multiple Output Formats**: Human-readable text and JSON output
- **IANA Cipher Naming**: Shows official IANA names for approved ciphers
- **Flexible Configuration**: Adjustable cipher enumeration depth for speed vs. accuracy

## Requirements

- Python 3.6+
- OpenSSL 1.1.1+ (for full TLS 1.3 support)
- Network access to target server

## Installation

```bash
# Clone or download the project
cd sslchecker

# No external dependencies required - uses standard library and system OpenSSL
```

## Configuration

### Customizing Approved Ciphers

The approved cipher suites are defined in `approved_ciphers.csv`. Users can easily update this file to match their organization's security policies.

**CSV Format:**
```
cipher_name,protocol,rating,format
```

**Columns:**
- `cipher_name`: The name as reported by servers (OpenSSL format, IANA format, or any other format)
- `protocol`: TLS version (TLSv1.2 or TLSv1.3)
- `rating`: Compliance rating (RECOMMENDED, SECURE, or custom values)
- `format`: Cipher name format (OPENSSL, IANA, or other) - optional, for documentation only

**Examples:**

OpenSSL format cipher:
```
ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,RECOMMENDED,OPENSSL
```

IANA format cipher:
```
TLS_CHACHA20_POLY1305_SHA256,TLSv1.3,RECOMMENDED,IANA
```

Custom/unknown format:
```
TLS_ECCPWD_WITH_AES_256_GCM_SHA256,TLSv1.2,SECURE,IANA
```

Same cipher with multiple reported names (add separate rows):
```
ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,RECOMMENDED,OPENSSL
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLSv1.2,RECOMMENDED,IANA
```

Same cipher name with different protocols (add separate rows):
```
TLS_AES_256_GCM_SHA384,TLSv1.2,SECURE,IANA
TLS_AES_256_GCM_SHA384,TLSv1.3,RECOMMENDED,IANA
```

**To customize:**
1. Open `approved_ciphers.csv`
2. Add/remove rows as needed
3. Use the exact name format that will be reported by servers
4. Optionally document the format (OPENSSL, IANA, etc.)
5. Save and re-run the scanner

Lines starting with `#` in the cipher_name column are treated as comments and ignored.

## Usage

### Basic Usage

```bash
# Scan a domain on default HTTPS port (443)
python3 ssl_checker.py --url google.com

# Scan with explicit port
python3 ssl_checker.py --url example.com --port 8443

# Scan with full URL
python3 ssl_checker.py --url https://api.example.com:8443
```

### Output Formats

```bash
# Text output (default)
python3 ssl_checker.py --url example.com

# JSON output
python3 ssl_checker.py --url example.com --json

# Save JSON report to file
python3 ssl_checker.py --url example.com --json > report.json
```

### Performance Options

```bash
# Quick scan: test only 10 ciphers per protocol (default)
python3 ssl_checker.py --url example.com --ciphers 10

# Thorough scan: test 50 ciphers per protocol
python3 ssl_checker.py --url example.com --ciphers 50

# Complete enumeration: test all available ciphers (slow and IDS-detectable)
python3 ssl_checker.py --url example.com --ciphers 0
```

## Compliance Standards

### TLS Protocol Versions

| Version | Status | Notes |
|---------|--------|-------|
| TLS 1.3 | ✅ RECOMMENDED | Modern, secure standard |
| TLS 1.2 | ⚠️ SECURE | Acceptable but older; TLS 1.3 preferred |
| TLS 1.1 | ❌ NOT APPROVED | Deprecated, cryptographically weak |
| TLS 1.0 | ❌ NOT APPROVED | Deprecated, cryptographically weak |

### Cipher Suite Ratings

- **✅ RECOMMENDED**: Modern ciphers meeting best practices (TLS 1.3 AEAD suites, ECDHE with strong authentication)
- **⚠️ SECURE**: Acceptable for compatibility (ECDHE, DHE with SHA256/384)
- **❌ NOT_APPROVED**: Weak or deprecated ciphers (anonymous DH, NULL ciphers, export-grade, DES, RC4, MD5, SHA1)

### Approved Ciphers

**TLS 1.3 Recommended:**
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_256_GCM_SHA384`
- `TLS_AES_128_GCM_SHA256`

**TLS 1.3 Secure:**
- `TLS_AES_128_CCM_SHA256`
- `TLS_AES_128_CCM_8_SHA256`

**TLS 1.2 ECDHE Ciphers:**
- ECDHE-ECDSA and ECDHE-RSA suites with AES-GCM (RECOMMENDED)
- ECDHE-ECDSA and ECDHE-RSA with SHA384/256 (SECURE)
- ECDHE with CAMELLIA (SECURE alternative)

**TLS 1.2 DHE Ciphers:**
- DHE-RSA with AES-GCM (SECURE, PFS but slower)

## Output Examples

### Text Format

```
======================================================================
SSL/TLS Scanner Results for: example.com:443
======================================================================

✅ TLSv1.3         - SUPPORTED
  Protocol Version: TLSv1.3
  Ciphers (3):
    ✅ TLS_AES_256_GCM_SHA384
       Format: IANA
    ✅ TLS_CHACHA20_POLY1305_SHA256
       Format: IANA
    ✅ TLS_AES_128_GCM_SHA256
       Format: IANA

⚠️  TLSv1.2         - SUPPORTED
   ℹ️  Protocol compliance: SECURE
  Protocol Version: TLSv1.2
  Ciphers (4):
    ✅ ECDHE-ECDSA-AES256-GCM-SHA384
       Format: OPENSSL
    ⚠️  ECDHE-RSA-AES256-SHA384
       Format: OPENSSL
    ...

✗ TLSv1.1          - NOT SUPPORTED (Server)
  Server does not support this protocol version

✗ TLSv1.0          - NOT SUPPORTED (Server)
  Server does not support this protocol version
```

### JSON Format

```json
{
  "scan_timestamp": "2026-02-11T10:30:45.123456",
  "target": {
    "hostname": "example.com",
    "port": 443
  },
  "protocols": {
    "TLSv1.3": {
      "status": "SUPPORTED",
      "compliance": "RECOMMENDED",
      "protocol_version": "TLSv1.3",
      "ciphers": [
        {
          "name": "TLS_AES_256_GCM_SHA384",
          "format": "IANA",
          "compliance": "RECOMMENDED"
        },
        {
          "name": "TLS_CHACHA20_POLY1305_SHA256",
          "format": "IANA",
          "compliance": "RECOMMENDED"
        }
      ]
    },
    "TLSv1.2": {
      "status": "SUPPORTED",
      "compliance": "SECURE",
      "protocol_version": "TLSv1.2",
      "ciphers": [...]
    }
  }
}
```

## Exit Codes

- `0`: Scan completed successfully
- `1`: Error during scan (connection failed, invalid input, etc.)

## Security Considerations

- **IDS Detection**: Unlimited cipher enumeration (`--ciphers 0`) may trigger security alerts
- **Rate Limiting**: Some servers may reject rapid connection attempts
- **Network Access**: Requires outbound connectivity to target server
- **Authentication**: No client certificates; suitable for public-facing services

## Troubleshooting

### "OpenSSL not found"
Ensure OpenSSL is installed and in your PATH:
```bash
openssl version
which openssl
```

### "Protocol not supported (Client)"
Your OpenSSL version doesn't support that protocol. Install a more recent version or compile OpenSSL with legacy support enabled.

### Timeout errors
Network connectivity issue or server rejecting connections. Verify the hostname/port and try again.

### No ciphers detected for supported protocol
The server may have restrictive cipher policies. Try with `--ciphers 0` for full enumeration.

## Technical Details

- Uses `openssl s_client` for TLS handshaking
- Validates both negotiated protocol AND cipher (prevents false positives)
- Per-protocol cipher enumeration with configurable depth
- SNI support for modern web servers
- Handles both IPv4 and IPv6 (via hostname resolution)

## License

MIT

## Contributing

Suggestions for improving the compliance standards or adding new features welcome.
