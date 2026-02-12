# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Improved
- **Network Error Detection**: Enhanced error handling to distinguish network connectivity issues from server protocol rejection
  - Added detection for WiFi/network unavailability (shows "Network unreachable" instead of "SERVER_UNSUPPORTED")
  - Added specific error messages for DNS resolution failures
  - Added diagnostics for connection refused, timeouts, and host unreachable conditions
  - Improved error messages with actionable troubleshooting steps

### Details
- When WiFi is off or network is unavailable, the scanner now correctly reports network errors instead of misidentifying them as server protocol incompatibility
- The fix detects whether `openssl s_client` successfully established a TCP connection before evaluating TLS handshake results
- If no connection is established AND the command exits with an error code, the code now properly categorizes it as a network issue with specific guidance

## [1.0.0] - 2026-02-11

### Added
- Initial release
- TLS version detection (1.0, 1.1, 1.2, 1.3)
- Cipher suite enumeration and compliance checking
- Support for approved cipher list (CSV-based configuration)
- JSON and text output formats
- Proxy support (HTTP and SOCKS)
- Regulatory compliance standards (GLOBAL and China GB/T 38636)
- SNI support for modern web servers
