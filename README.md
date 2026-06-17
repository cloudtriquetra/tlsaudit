# tlsaudit

Verify TLS/SSL compliance. Audit cipher suites and protocol versions against modern security standards. Get instant compliance ratings with official IANA cipher names.

> **Secure by default** - Validates against TLS 1.2+ with RECOMMENDED/SECURE cipher filtering. Easy to customize for your compliance requirements.

## Quick Start

```bash
# Scan a domain (uses nmap when available, openssl otherwise)
python3 ssl_checker.py --url example.com

# Get JSON report
python3 ssl_checker.py --url example.com --json > report.json

# Force a specific scanning backend
python3 ssl_checker.py --url example.com --backend nmap
python3 ssl_checker.py --url example.com --backend openssl
```

## Features

- **Dual Backend**: nmap `ssl-enum-ciphers` (fast, single session) with automatic OpenSSL fallback
- **TLS Version Detection**: Tests for support of TLS 1.0, 1.1, 1.2, and 1.3
- **Full Cipher Enumeration**: Identifies all supported ciphers per protocol version
- **IANA Cipher Naming**: Always reports official IANA names; JSON output includes original OpenSSL name when different
- **Compliance Checking**: Validates ciphers and protocols against an approved security standards whitelist
- **Multiple Output Formats**: Human-readable text and machine-readable JSON
- **China GB/T 38636 Compliance**: Optional Tongsuo/BabaSSL support for SM4/SM3 cipher detection

## Requirements

- Python 3.6+
- **nmap** with `ssl-enum-ciphers` script — primary backend (5.8× faster than OpenSSL full enumeration)
- OpenSSL 1.1.1+ — automatic fallback when nmap is unavailable, and required for China compliance scanning
- Network access to target server

### Installing nmap

```bash
# macOS
brew install nmap

# Debian/Ubuntu
apt install nmap

# RHEL/CentOS
yum install nmap
```

Verify nmap includes the ssl-enum-ciphers script:
```bash
nmap --script-help ssl-enum-ciphers
```

### Optional: Tongsuo for China Compliance Scanning

To scan servers for China GB/T 38636 compliance (SM4/SM3 cipher support), install Tongsuo/BabaSSL:

**macOS / Linux:**
```bash
git clone https://github.com/Tongsuo-Project/tongsuo.git
cd tongsuo && mkdir build && cd build
cmake ..
make && sudo make install
```

**Verification:**
```bash
/opt/tongsuo/bin/openssl version
```

## Performance

nmap enumerates all ciphers in a single TLS session, versus OpenSSL which opens one TCP connection per cipher tested. See [docs/performance_comparison.html](docs/performance_comparison.html) for a full comparison across five targets.

| Backend | Time (5 targets) | Notes |
|---------|-----------------|-------|
| nmap (full enumeration) | ~12 s | Single session per protocol per host |
| OpenSSL (unlimited) | ~70 s | One TCP connection per cipher |

## Configuration

### Customizing Approved Ciphers

The approved cipher suites are defined in `approved_ciphers.csv` — the security control whitelist. **Only add new approved entries; never remove rows.**

**CSV Format:**
```
cipher_name,protocol,rating,format,key_exchange,signature_algorithm,compliance_standard,iana_name
```

**Columns:**
- `cipher_name`: The cipher name (OpenSSL shorthand or IANA full name)
- `protocol`: TLS version (`TLSv1.2` or `TLSv1.3`)
- `rating`: Compliance rating — `PQC_RECOMMENDED`, `RECOMMENDED`, `SECURE`, `REQUIRED`
- `format`: `OPENSSL` or `IANA` — identifies the naming convention of `cipher_name`
- `key_exchange`: Key exchange method, e.g. `X25519MLKEM768` for post-quantum — optional
- `signature_algorithm`: Certificate signing algorithm, e.g. `ECDSA` — optional
- `compliance_standard`: `GLOBAL` (default) or `CHINA_GB/T_38636` — region-specific ciphers are only included when that standard is selected
- `iana_name`: **Required for OPENSSL-format rows.** The official IANA name corresponding to `cipher_name`. Must be empty for IANA-format rows. Used internally to normalise backend output to IANA names.

**Example rows:**

OpenSSL-format cipher (both `cipher_name` and `iana_name` provided):
```
ECDHE-RSA-AES256-GCM-SHA384,TLSv1.2,SECURE,OPENSSL,,,GLOBAL,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
```

IANA-format cipher (`iana_name` left empty):
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLSv1.2,SECURE,IANA,,,GLOBAL,
```

TLS 1.3 cipher:
```
TLS_AES_256_GCM_SHA384,TLSv1.3,RECOMMENDED,IANA,,,GLOBAL,
```

Post-quantum cipher:
```
TLS_ECDHE_KYBER768_RSA_WITH_AES_256_GCM_SHA384,TLSv1.3,PQC_RECOMMENDED,IANA,X25519MLKEM768,RSASSA-PSS,GLOBAL,
```

China-specific cipher (SM4/SM3):
```
TLS_SM4_GCM_SM3,TLSv1.3,RECOMMENDED,IANA,,,CHINA_GB/T_38636,
```

Lines with `#` in the `cipher_name` column are treated as comments.

**How to add a new approved cipher:**

1. Look up the cipher's official IANA name at [https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)

2. Decide the format you want to add:
   - **IANA format (recommended)** — use the full IANA name as `cipher_name`, leave `iana_name` empty:
     ```
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLSv1.2,SECURE,IANA,,,GLOBAL,
     ```
   - **OpenSSL format** — use the OpenSSL shorthand as `cipher_name`, and fill in the IANA name in `iana_name` (required so normalisation works):
     ```
     ECDHE-RSA-AES128-GCM-SHA256,TLSv1.2,SECURE,OPENSSL,,,GLOBAL,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
     ```

3. Choose the correct `rating`: `PQC_RECOMMENDED` > `RECOMMENDED` > `SECURE` > `REQUIRED`

4. Set `compliance_standard` to `GLOBAL` for universal ciphers, or a specific standard (e.g. `CHINA_GB/T_38636`) if the cipher only applies in that context.

5. Append the row to `approved_ciphers.csv`. **Never edit or remove existing rows** — the file is an append-only audit log of approved ciphers.

6. Verify the new entry is picked up:
   ```bash
   python3 ssl_checker.py --url example.com --json | python3 -m json.tool | grep -A3 "<your-cipher-name>"
   ```

## Usage

### Basic Usage

```bash
# Scan a single domain (default port 443)
python3 ssl_checker.py --url google.com

# Scan with explicit port
python3 ssl_checker.py --url example.com --port 8443

# Scan with full URL
python3 ssl_checker.py --url https://api.example.com:8443

# Scan multiple targets from a file (one URL or host:port per line)
python3 ssl_checker.py --url-file targets.txt
```

`targets.txt` format — one entry per line, optional `proxy=true`/`proxy=false` flag:
```
# host[:port]  [proxy=true|proxy=false]
api.example.com:443                    # use --proxy (default)
auth.example.com:8443   proxy=true     # use --proxy (explicit)
public.example.com      proxy=false    # bypass --proxy, connect directly
```

The proxy URL is supplied at runtime with `--proxy`. Targets with no flag default to `proxy=true` (use `--proxy` if set).

### Output Formats

```bash
# Text output (default)
python3 ssl_checker.py --url example.com

# JSON report — same schema for single target or batch
python3 ssl_checker.py --url example.com --json
python3 ssl_checker.py --url-file targets.txt --json > report.json
```

### Backend Selection

```bash
# Auto (default): use nmap when available, fall back to openssl
python3 ssl_checker.py --url example.com

# Force nmap backend
python3 ssl_checker.py --url example.com --backend nmap

# Force openssl backend
python3 ssl_checker.py --url example.com --backend openssl
```

The `--backend auto` mode (default) selects nmap automatically when it is installed. You never need to specify a backend explicitly unless troubleshooting or requiring the openssl backend for China compliance scanning.

### Proxy Support

```bash
# Single target through a proxy
python3 ssl_checker.py --url example.com --proxy http://proxy.corp.com:8080

# Batch scan — proxy applies to all targets marked true (or with no flag)
python3 ssl_checker.py --url-file targets.txt --proxy http://10.0.0.1:443 --json > report.json
```

In `targets.txt`, each line can opt in or out of the proxy:
```
api.internal.corp.com:443               # no flag → uses --proxy
auth.internal.corp.com:443  proxy=true  # explicit → uses --proxy
public.example.com          proxy=false # bypasses --proxy, connects directly
```

Both backends support HTTP CONNECT proxies. The nmap backend passes the proxy via `--proxies`; the openssl backend via `-proxy` to `s_client`.

**Proxy resolution order (per target):**
1. `--proxy` flag — always used when set; `NO_PROXY` does not override it
2. `HTTPS_PROXY` / `HTTP_PROXY` environment variable — used when `--proxy` is not set
3. Direct connection — when neither flag nor env var is present

`NO_PROXY` / `no_proxy` is respected for env-var proxies: hostnames matching any entry bypass the env proxy. `--proxy` is always applied regardless of `NO_PROXY`.

In `targets.txt`, `proxy=false` forces a direct connection for that target regardless of `--proxy` or env vars.

### Regulatory Compliance Standards

```bash
# Scan with global compliance standards (default)
python3 ssl_checker.py --url example.com

# Scan with China-specific requirements (SM4/SM3 ciphers) — requires openssl backend
python3 ssl_checker.py --url example.com --compliance-standard CHINA_GB/T_38636 --backend openssl

# Specify custom tongsuo path if installed in a non-standard location
python3 ssl_checker.py --url bank.cn --compliance-standard CHINA_GB/T_38636 --backend openssl --tongsuo-path /opt/tongsuo/bin/openssl

# Export compliance report
python3 ssl_checker.py --url example.com --compliance-standard CHINA_GB/T_38636 --backend openssl --json > china_audit.json
```

**Available Standards:**
- `GLOBAL` (default) — Global best practices and recommendations
- `CHINA_GB/T_38636` — China national cryptographic standards (SM4-GCM-SM3, SM4-CCM-SM3); requires Tongsuo and openssl backend

**Tongsuo auto-detection order:**
1. `--tongsuo-path` (if provided)
2. `/opt/tongsuo/bin/openssl`
3. `tongsuo` in system PATH
4. `/usr/local/bin/tongsuo`
5. `/opt/tongsuo/bin/tongsuo`

If Tongsuo is not found, the script falls back to standard OpenSSL with a warning. SM4/SM3 ciphers will not be detected.

## Compliance Standards

### TLS Protocol Versions

| Version | Status | Notes |
|---------|--------|-------|
| TLS 1.3 | RECOMMENDED | Modern, secure standard |
| TLS 1.2 | SECURE | Acceptable; TLS 1.3 preferred |
| TLS 1.1 | NOT_APPROVED | Deprecated, cryptographically weak |
| TLS 1.0 | NOT_APPROVED | Deprecated, cryptographically weak |

### Cipher Suite Ratings

- **PQC_RECOMMENDED**: Post-quantum cryptography ciphers
- **RECOMMENDED**: Modern ciphers meeting current best practices
- **SECURE**: Acceptable for compatibility
- **REQUIRED**: Mandatory for specific regulatory standards
- **NOT_APPROVED**: Weak or deprecated ciphers

## Output Examples

### Text Format

```
======================================================================
TLS Audit Results for: example.com:443
======================================================================

  TLSv1.3         - SUPPORTED
  Ciphers (3):
    TLS_AES_256_GCM_SHA384             [RECOMMENDED]
    TLS_CHACHA20_POLY1305_SHA256       [RECOMMENDED]
    TLS_AES_128_GCM_SHA256             [RECOMMENDED]

  TLSv1.2         - SUPPORTED  [SECURE]
  Ciphers (2):
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  (openssl: ECDHE-RSA-AES256-GCM-SHA384)  [SECURE]
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  (openssl: ECDHE-RSA-AES128-GCM-SHA256)  [SECURE]

  TLSv1.1         - NOT SUPPORTED
  TLSv1.0         - NOT SUPPORTED
```

### JSON Format

The JSON report uses the same schema whether you scan one target (`--url`) or many (`--url-file`). All cipher names are reported in IANA format; when the backend reports OpenSSL shorthand the original name is preserved in `openssl_name`.

```json
{
  "scan_timestamp": "2026-02-11T10:30:45.123456",
  "overall_compliance": "NON_COMPLIANT",
  "findings": [
    "api.example.com:8443 — TLSv1.0 is supported (deprecated protocol)",
    "api.example.com:8443 — NOT_APPROVED cipher on TLSv1.2: TLS_RSA_WITH_AES_128_CBC_SHA"
  ],
  "summary": {
    "targets_total": 2,
    "targets_compliant": 1,
    "targets_non_compliant": 1,
    "targets_error": 0
  },
  "targets": [
    {
      "hostname": "example.com",
      "port": 443,
      "overall_compliance": "COMPLIANT",
      "findings": [],
      "protocols": {
        "TLSv1.3": {
          "status": "SUPPORTED",
          "compliance": "RECOMMENDED",
          "protocol_version": "TLSv1.3",
          "cipher_count": 3,
          "ciphers": [
            { "iana_name": "TLS_AES_256_GCM_SHA384", "compliance": "RECOMMENDED", "standard": "GLOBAL" },
            { "iana_name": "TLS_CHACHA20_POLY1305_SHA256", "compliance": "RECOMMENDED", "standard": "GLOBAL" }
          ]
        },
        "TLSv1.2": {
          "status": "SUPPORTED",
          "compliance": "SECURE",
          "protocol_version": "TLSv1.2",
          "cipher_count": 1,
          "ciphers": [
            {
              "iana_name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
              "openssl_name": "ECDHE-RSA-AES256-GCM-SHA384",
              "compliance": "SECURE",
              "standard": "GLOBAL"
            }
          ]
        },
        "TLSv1.1": { "status": "SERVER_UNSUPPORTED" },
        "TLSv1.0": { "status": "SERVER_UNSUPPORTED" }
      }
    },
    {
      "hostname": "api.example.com",
      "port": 8443,
      "overall_compliance": "NON_COMPLIANT",
      "findings": [
        "TLSv1.0 is supported (deprecated protocol)",
        "NOT_APPROVED cipher on TLSv1.2: TLS_RSA_WITH_AES_128_CBC_SHA"
      ],
      "protocols": { "...": "..." }
    }
  ]
}
```

**Top-level fields:**
- `overall_compliance` — `COMPLIANT`, `NON_COMPLIANT`, or `ERROR` across all targets
- `findings` — all violations from all targets, each prefixed with `hostname:port —`
- `summary` — count of targets by compliance state
- `targets` — per-target results (one entry even for a single `--url` scan)

**Per-target fields (`targets[i]`):**
- `overall_compliance` — compliance status for this target
- `findings` — violations for this target only (no host prefix)
- `protocols` — per-protocol scan results

**Cipher fields (`protocols.TLSvX.Y.ciphers[i]`):**
- `iana_name` — official IANA cipher name (always present)
- `openssl_name` — OpenSSL shorthand (only present when different from `iana_name`)
- `compliance` — rating from `approved_ciphers.csv`
- `standard` — `GLOBAL`, `CHINA_GB/T_38636`, etc.
- `key_exchange` — key exchange method (when documented in the CSV)
- `signature_algorithm` — signature algorithm (when documented in the CSV)

## Exit Codes

- `0`: Scan completed — target is **COMPLIANT**
- `1`: Scan error — could not connect to target (DNS failure, connection refused, host unreachable, etc.)
- `2`: Scan completed — target is **NON_COMPLIANT**

Exit 1 is only returned when the tool could not reach the server at all. A server that responds but supports only deprecated protocols or weak ciphers exits 2, not 1.

This makes the tool pipeline-native:

```bash
# Fail the pipeline if the target is non-compliant
python3 ssl_checker.py --url api.example.com --json > report.json
# exit 0 = compliant, exit 2 = non-compliant, exit 1 = scan error

# One-liner gate
python3 ssl_checker.py --url api.example.com && echo "PASS" || echo "FAIL"
```

The top-level `overall_compliance` and `findings` fields are always present for easy pipeline parsing (see JSON Format section for the full schema). Even on a scan error (exit 1), a JSON report is written — `overall_compliance` is `ERROR` and the target entry includes an `error` field:

```json
{
  "overall_compliance": "ERROR",
  "summary": { "targets_total": 1, "targets_compliant": 0, "targets_non_compliant": 0, "targets_error": 1 },
  "targets": [{ "hostname": "bad-host.invalid", "port": 443, "overall_compliance": "ERROR",
                "error": "Host bad-host.invalid not found or not reachable", "findings": [], "protocols": {} }]
}
```

A target is NON_COMPLIANT if:
- Any deprecated protocol (TLS 1.0 or 1.1) is supported
- Any cipher is not in `approved_ciphers.csv` (defaults to NOT_APPROVED)

## Security Considerations

- **IDS Detection**: Full cipher enumeration may trigger security alerts on monitored networks
- **Rate Limiting**: Some servers may reject rapid connection attempts
- **Network Access**: Requires outbound connectivity to target server

## Troubleshooting

### "nmap not found, falling back to openssl"
Install nmap to use the faster primary backend:
```bash
brew install nmap   # macOS
apt install nmap    # Debian/Ubuntu
```

### Network Connectivity Issues

- **"Network unreachable"** — WiFi is off or network unavailable
- **"DNS resolution failed"** — Verify hostname spelling and DNS availability
- **"Connection refused"** — Server not listening on the specified port
- **"Connection timeout"** — Server unreachable; check network/firewall rules

### "Tongsuo not found" (China compliance)

If you see `Warning: China standard requested but tongsuo not found. Using standard openssl.`:
- Install Tongsuo following the steps in the Requirements section
- Or specify the path explicitly with `--tongsuo-path`

### "Protocol not supported (Client)"

Your OpenSSL version does not support that protocol. Install a more recent version or compile with legacy support.

## Technical Details

- **nmap backend**: runs `nmap --script ssl-enum-ciphers` and parses the XML output; enumerates all ciphers in one TLS session per protocol version
- **openssl backend**: calls `openssl s_client` once per cipher; required for Tongsuo/SM cipher testing
- **IANA normalisation — three-layer lookup** (applied to every cipher name before compliance check or output):
  1. `approved_ciphers.csv` `iana_name` column — highest priority; maps approved OpenSSL-format ciphers to their IANA names
  2. Built-in nmap TLS 1.3 alias table — corrects nmap's non-standard `TLS_AKE_WITH_*` names to proper `TLS_AES_*` IANA names
  3. Built-in comprehensive OpenSSL→IANA table — covers ~110 common ciphers (including NOT_APPROVED ones not in the CSV) so both backends always produce the same IANA name for comparison
- SNI support for modern web servers
- Handles IPv4 and IPv6 (via hostname resolution)

## License

MIT

## Contributing

Suggestions for improving the compliance standards or adding new features welcome.
