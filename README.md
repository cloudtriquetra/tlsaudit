# tlsaudit

Verify TLS/SSL compliance. Audit cipher suites and protocol versions against modern security standards. Get instant compliance ratings and format details.

> 🔒 **Secure by default** - Validates against TLS 1.2+ with RECOMMENDED/SECURE cipher filtering. Easy to customize for your compliance requirements.

## Quick Start

```bash
# Extract the project
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
- **Optional:** Tongsuo/BabaSSL (required for China GB/T 38636 SM4/SM3 cipher detection)

## Installation

```bash
# Extract or download the project
cd tlsaudit

# No external dependencies required - uses standard library and system OpenSSL
```

### Optional: Installing Tongsuo for China Compliance Scanning

To scan servers for China GB/T 38636 compliance (SM4/SM3 cipher support), install Tongsuo/BabaSSL:

**macOS:**
```bash
# Option 1: Build from source
git clone https://github.com/Tongsuo-Project/tongsuo.git
cd tongsuo
mkdir build && cd build
cmake ..
make
sudo make install

# Option 2: Install via homebrew (if available)
brew install tongsuo
```

**Linux:**
```bash
# Build from source
git clone https://github.com/Tongsuo-Project/tongsuo.git
cd tongsuo
./Configure
make
sudo make install
```

**Verification:**
```bash
tongsuo version
# or if installed in /opt/tongsuo/
/opt/tongsuo/bin/openssl version
```

**How it works:**
- When `--compliance-standard CHINA_GB/T_38636` is specified, the script automatically detects and uses Tongsuo
- If Tongsuo is not found, the script falls back to standard OpenSSL with a warning
- Standard OpenSSL is used for all other compliance standards (GLOBAL, etc.)
- Tongsuo provides SM4 encryption and SM3 hash algorithm support required by China's national cryptographic standards

## Configuration

### Customizing Approved Ciphers

The approved cipher suites are defined in `approved_ciphers.csv`. Users can easily update this file to match their organization's security policies.

**CSV Format:**
```
cipher_name,protocol,rating,format,key_exchange,signature_algorithm,compliance_standard
```

**Columns:**
- `cipher_name`: The name as reported by servers (OpenSSL format, IANA format, or any other format)
- `protocol`: TLS version (TLSv1.2 or TLSv1.3)
- `rating`: Compliance rating (RECOMMENDED, SECURE, REQUIRED, PQC_RECOMMENDED, or custom values)
- `format`: Cipher name format (OPENSSL, IANA, or other) - optional, for documentation only
- `key_exchange`: Key exchange method used (e.g., X25519MLKEM768 for post-quantum cryptography) - optional, for documentation/PQC tracking
- `signature_algorithm`: Certificate signing algorithm (e.g., RSASSA-PSS, ECDSA) - optional, for documentation
- `compliance_standard`: Compliance standard applicability (GLOBAL, CHINA_GB/T_38636, EU_TLS, etc.) - optional, defaults to GLOBAL if omitted. Ciphers with standard other than GLOBAL are only included when that standard is explicitly requested

**Examples:**

OpenSSL format cipher:
```
ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,RECOMMENDED,OPENSSL,,,GLOBAL
```

IANA format cipher:
```
TLS_CHACHA20_POLY1305_SHA256,TLSv1.3,RECOMMENDED,IANA,,,GLOBAL
```

Custom/unknown format:
```
TLS_ECCPWD_WITH_AES_256_GCM_SHA256,TLSv1.2,SECURE,IANA,,,GLOBAL
```

Same cipher with multiple reported names (add separate rows):
```
ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,RECOMMENDED,OPENSSL,,,GLOBAL
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLSv1.2,RECOMMENDED,IANA,,,GLOBAL
```

Same cipher name with different protocols (add separate rows):
```
TLS_AES_256_GCM_SHA384,TLSv1.2,SECURE,IANA,,,GLOBAL
TLS_AES_256_GCM_SHA384,TLSv1.3,RECOMMENDED,IANA,,,GLOBAL
```

Post-quantum cryptography cipher with key exchange method documented:
```
TLS_ECDHE_KYBER768_RSA_WITH_AES_256_GCM_SHA384,TLSv1.3,PQC_RECOMMENDED,IANA,X25519MLKEM768,RSASSA-PSS,GLOBAL
```

Regional/compliance-specific cipher (only used with --compliance-standard CHINA_GB/T_38636):
```
TLS_SM4_GCM_SM3,TLSv1.3,RECOMMENDED,IANA,,,CHINA_GB/T_38636
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

### Proxy Support

```bash
# Scan through HTTP/HTTPS proxy
python3 ssl_checker.py --url example.com --proxy http://proxy.corp.com:8080

# Scan through SOCKS proxy
python3 ssl_checker.py --url example.com --socks-proxy socks5://proxy.corp.com:1080

# Combine with other options
python3 ssl_checker.py --url example.com --proxy http://proxy:8080 --json
```

**Proxy Requirements:**
- HTTP proxy format: `http://hostname:port` or `https://hostname:port`
- SOCKS proxy format: `socks5://hostname:port`
- OpenSSL support required (modern versions include proxy support)

### Regulatory Compliance Standards

```bash
# Scan with global compliance standards (default)
python3 ssl_checker.py --url example.com

# Scan with China-specific requirements (SM4/SM3 ciphers)
python3 ssl_checker.py --url example.com --compliance-standard CHINA_GB/T_38636

# Specify custom tongsuo path (if installed in non-standard location)
python3 ssl_checker.py --url bank.example.com --compliance-standard CHINA_GB/T_38636 --tongsuo-path /custom/path/tongsuo

# Export compliance report
python3 ssl_checker.py --url example.com --compliance-standard CHINA_GB/T_38636 --json > china_audit.json
```

**Available Standards:**
- `GLOBAL` (default) - Global best practices and recommendations
- `CHINA_GB/T_38636` - China's national cryptographic standards (SM4-GCM-SM3, SM4-CCM-SM3)

**Tongsuo Path Options:**

The script automatically searches for Tongsuo in these locations (in order):
1. `/opt/tongsuo/bin/openssl` (recommended)
2. `tongsuo` (in system PATH)
3. `/usr/local/bin/tongsuo`
4. `/opt/tongsuo/bin/tongsuo`
5. `/opt/bin/tongsuo`
6. `/usr/bin/tongsuo`

If Tongsuo is installed in a different location, use `--tongsuo-path`:
```bash
# Explicit path to tongsuo or openssl binary
python3 ssl_checker.py --url bank.cn --compliance-standard CHINA_GB/T_38636 --tongsuo-path /usr/local/tongsuo/bin/openssl

# Or wherever your custom installation is
python3 ssl_checker.py --url bank.cn --compliance-standard CHINA_GB/T_38636 --tongsuo-path /opt/custom/tongsuo/bin/openssl
```

**Note:** 
- GLOBAL ciphers are always included
- Region-specific ciphers (SM4/SM3) are only added when that standard is selected
- The `--tongsuo-path` option is only used with `--compliance-standard CHINA_GB/T_38636`

**Automatic Tongsuo Selection:**
When you specify `--compliance-standard CHINA_GB/T_38636`:
1. The script searches for Tongsuo in standard locations (or uses your `--tongsuo-path`)
2. If found, it uses Tongsuo's `openssl` binary which supports SM4/SM3 algorithms
3. If not found, it falls back to standard OpenSSL and prints a warning
4. All standard ciphers and China-specific ciphers (SM4/SM3) are tested

**Example: China Compliance Scan**
```bash
# Comprehensive China compliance audit with full cipher enumeration
python3 ssl_checker.py --url bank.example.com.cn --compliance-standard CHINA_GB/T_38636 --ciphers 0 --json > audit_report.json

# With custom tongsuo path
python3 ssl_checker.py --url bank.example.com.cn --compliance-standard CHINA_GB/T_38636 --tongsuo-path /opt/tongsuo/bin/openssl --ciphers 0 --json > audit_report.json

# Output will include:
# - Standard international ciphers: ECDHE-RSA-AES256-GCM-SHA384 (GLOBAL)
# - China-specific ciphers if supported: TLS_SM4_GCM_SM3 (CHINA_GB/T_38636)
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

- **✅ PQC_RECOMMENDED**: Post-quantum cryptography ciphers meeting best practices
- **✅ RECOMMENDED**: Modern ciphers meeting best practices (TLS 1.3 AEAD suites, ECDHE with strong authentication)
- **⚠️ SECURE**: Acceptable for compatibility (ECDHE, DHE with SHA256/384)
- **⚠️ REQUIRED**: Mandatory ciphers for compliance with specific regulatory standards
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

### Network Connectivity Issues

The scanner now provides detailed diagnostics for network-level problems:

- **"Network unreachable to [host]:443. Check network connectivity and WiFi status."**
  - WiFi is off or network is unavailable
  - Solution: Check WiFi connection and network availability

- **"DNS resolution failed for [hostname]. Check hostname spelling and DNS availability."**
  - Hostname cannot be resolved
  - Solution: Verify the hostname spelling and DNS server availability

- **"Connection refused by [host]:443. Is the server running on this port?"**
  - Server is not listening on the specified port
  - Solution: Verify the correct port and check if the service is running

- **"Connection timeout to [host]:443. Server not responding within 10 seconds."**
  - Server is unreachable or not responding
  - Solution: Check network connectivity and firewall rules

- **"Host unreachable: [host]:443. Target server is offline or network path unavailable."**
  - Network path to the server is blocked
  - Solution: Verify the server is online and network/firewall rules allow access

### "OpenSSL not found"
Ensure OpenSSL is installed and in your PATH:
```bash
openssl version
which openssl
```

### "Tongsuo not found" (when using China compliance standard)
If you see: `Warning: China standard requested but tongsuo not found. Using standard openssl.`

This means:
- China compliance scanning (`--compliance-standard CHINA_GB/T_38636`) was requested
- Tongsuo/BabaSSL was not found in standard locations
- The script fell back to standard OpenSSL
- SM4/SM3 ciphers cannot be detected (standard OpenSSL doesn't support them)

**Solution:**
Install Tongsuo following the instructions in the "Optional: Installing Tongsuo for China Compliance Scanning" section above.

Common Tongsuo installation paths the script searches:
- `/opt/tongsuo/bin/openssl` (recommended)
- `/usr/local/bin/tongsuo`
- `/opt/tongsuo/bin/tongsuo`
- System PATH (`tongsuo` or `gmssl` command)

### "Protocol not supported (Client)"
Your OpenSSL version doesn't support that protocol. Install a more recent version or compile OpenSSL with legacy support enabled.

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
