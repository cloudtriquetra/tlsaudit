# Contributing to tlsaudit

Thanks for your interest in contributing! Here's how you can help:

## Adding New Ciphers

The easiest way to contribute is by updating the approved cipher list:

1. **Edit `approved_ciphers.csv`**
   - Add new ciphers with format: `cipher_name,protocol,rating,format`
   - Keep the file organized (group by protocol/rating)
   - Include the cipher name exactly as servers report it

2. **Example:**
   ```csv
   TLS_ECCPWD_WITH_AES_256_GCM_SHA256,TLSv1.2,RECOMMENDED,IANA
   ```

3. **Submit a Pull Request**
   - Include why you're adding/updating these ciphers
   - Reference any compliance standards (NIST, PCI-DSS, etc.)

## Reporting Issues

- **Scanning errors**: Include the target hostname/port, error message, and OpenSSL version (`openssl version`)
- **False positives/negatives**: Provide sample output and expected vs actual results
- **CSV format issues**: Describe the problem with clear examples

## Code Contributions

For code changes:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature`
3. **Keep changes focused** - one feature/fix per PR
4. **Test your changes** manually against real servers
5. **Maintain the existing code style**
6. **Submit a Pull Request** with clear description

## Coding Guidelines

- Python 3.6+ compatibility
- Use standard library only (no external dependencies)
- Add docstrings to new functions
- Keep functions focused and testable
- Follow existing code style (PEP 8)

## Questions?

Feel free to open an issue for discussions or questions about cipher compliance, TLS best practices, or feature requests.

## Compliance Standards

When suggesting ciphers, reference:
- NIST SP 800-52 Rev. 2 (TLS Guidelines)
- Mozilla SSL Configuration Generator
- PCI DSS Requirements
- OWASP Transport Layer Protection
