# Contributing to tlsaudit

Thanks for your interest in contributing! Here's how you can help:

## Adding New Ciphers

The easiest way to contribute is by updating the approved cipher list:

1. **Edit `approved_ciphers.csv`**
   - Add new ciphers with format: `cipher_name,protocol,rating,format,key_exchange,signature_algorithm,compliance_standard`
   - Keep the file organized (group by protocol/rating)
   - Include the cipher name exactly as servers report it

2. **Example:**
   ```csv
   TLS_SM4_GCM_SM3,TLSv1.3,REQUIRED,IANA,,SM3,CHINA_GB/T_38636
   ```

3. **Submit your updated file**
   - Include why you're adding/updating these ciphers
   - Reference any compliance standards (NIST, PCI-DSS, etc.)

## Reporting Issues

- **Scanning errors**: Include the target hostname/port, error message, and OpenSSL version (`openssl version`)
- **False positives/negatives**: Provide sample output and expected vs actual results
- **CSV format issues**: Describe the problem with clear examples

## Code Contributions

For code changes:

1. **Identify the issue or feature**
2. **Create your changes** locally
3. **Keep changes focused** - one feature/fix at a time
4. **Test your changes** manually against real servers
5. **Maintain the existing code style**
6. **Submit your changes** with clear description

## Coding Guidelines

- Python 3.6+ compatibility
- Use standard library only (no external dependencies)
- Add docstrings to new functions
- Keep functions focused and testable
- Follow existing code style (PEP 8)

## Questions?

Feel free to reach out with questions about cipher compliance, TLS best practices, or feature requests.

## Compliance Standards

When suggesting ciphers, reference:
- NIST SP 800-52 Rev. 2 (TLS Guidelines): https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf
- Mozilla SSL Configuration Generator: https://ssl-config.mozilla.org/
- PCI DSS Requirements
- OWASP Transport Layer Protection
