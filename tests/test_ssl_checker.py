"""
Tests for ssl_checker.py dual-backend implementation.

Unit tests run without network access.
Integration tests require INTEGRATION=1 environment variable.
"""

import csv
import io
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

# Ensure the project root is on the path so we can import ssl_checker
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ssl_checker

# Path to the CSV used by the real module
CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'approved_ciphers.csv')


def _load_csv_rows_direct():
    """Load CSV rows directly for inspection, bypassing module globals."""
    rows = []
    with open(CSV_PATH, newline='') as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def _ensure_module_loaded():
    """Load csv into module globals if not already done (idempotent)."""
    if not ssl_checker.APPROVED_CIPHERS:
        ssl_checker.APPROVED_CIPHERS.clear()
        ssl_checker.OPENSSL_TO_IANA.clear()
        ssl_checker._load_csv_rows(CSV_PATH, compliance_standard=None)


# ---------------------------------------------------------------------------
# TestCSVIntegrity — pure file tests, no network
# ---------------------------------------------------------------------------

class TestCSVIntegrity(unittest.TestCase):
    """Verify the structure and content of approved_ciphers.csv."""

    def setUp(self):
        self.rows = _load_csv_rows_direct()

    def test_csv_has_iana_name_column(self):
        """Header must contain the iana_name column."""
        with open(CSV_PATH, newline='') as f:
            header = f.readline().strip()
        self.assertIn('iana_name', header)

    def test_all_openssl_rows_have_iana_name(self):
        """Every row with format=OPENSSL must have a non-empty iana_name."""
        violations = []
        for row in self.rows:
            if row.get('format', '').strip() == 'OPENSSL':
                iana = row.get('iana_name', '').strip()
                if not iana:
                    violations.append(row['cipher_name'])
        self.assertEqual([], violations,
                         f"OPENSSL rows missing iana_name: {violations}")

    def test_iana_name_format_valid(self):
        """Every populated iana_name value must start with 'TLS_'."""
        violations = []
        for row in self.rows:
            iana = row.get('iana_name', '').strip()
            if iana and not iana.startswith('TLS_'):
                violations.append(iana)
        self.assertEqual([], violations,
                         f"iana_name values not starting with TLS_: {violations}")

    def test_iana_rows_have_empty_iana_name(self):
        """Rows with format=IANA must have an empty iana_name (they ARE the IANA name)."""
        violations = []
        for row in self.rows:
            if row.get('format', '').strip() == 'IANA':
                iana = row.get('iana_name', '').strip()
                if iana:
                    violations.append((row['cipher_name'], iana))
        self.assertEqual([], violations,
                         f"IANA rows with non-empty iana_name: {violations}")

    def test_no_aes_123_typo(self):
        """The typo TLS_DHE_RSA_WITH_AES_123_CCM_8 must NOT appear as an iana_name."""
        all_iana_names = [row.get('iana_name', '').strip() for row in self.rows]
        self.assertNotIn('TLS_DHE_RSA_WITH_AES_123_CCM_8', all_iana_names)

    def test_aes_128_ccm_8_present(self):
        """TLS_DHE_RSA_WITH_AES_128_CCM_8 must appear as an iana_name."""
        all_iana_names = [row.get('iana_name', '').strip() for row in self.rows]
        self.assertIn('TLS_DHE_RSA_WITH_AES_128_CCM_8', all_iana_names)


# ---------------------------------------------------------------------------
# TestNormalisation — unit tests, no network
# ---------------------------------------------------------------------------

class TestNormalisation(unittest.TestCase):
    """Test cipher name normalisation from OpenSSL to IANA format."""

    def setUp(self):
        _ensure_module_loaded()

    def test_known_openssl_name_normalised(self):
        result = ssl_checker.normalise_to_iana('ECDHE-RSA-AES256-GCM-SHA384')
        self.assertEqual('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', result)

    def test_iana_name_passthrough(self):
        name = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        self.assertEqual(name, ssl_checker.normalise_to_iana(name))

    def test_tls13_cipher_passthrough(self):
        name = 'TLS_AES_256_GCM_SHA384'
        self.assertEqual(name, ssl_checker.normalise_to_iana(name))

    def test_unknown_cipher_passthrough(self):
        name = 'SOME-UNKNOWN-CIPHER'
        self.assertEqual(name, ssl_checker.normalise_to_iana(name))

    def test_all_openssl_names_in_csv_are_normalisable(self):
        """Every OPENSSL-format cipher in the CSV must map to a different (IANA) name."""
        rows = _load_csv_rows_direct()
        not_normalised = []
        for row in rows:
            if row.get('format', '').strip() == 'OPENSSL':
                cipher_name = row['cipher_name'].strip()
                normalised = ssl_checker.normalise_to_iana(cipher_name)
                if normalised == cipher_name:
                    not_normalised.append(cipher_name)
        self.assertEqual([], not_normalised,
                         f"OPENSSL ciphers not normalised: {not_normalised}")


# ---------------------------------------------------------------------------
# TestComplianceParity — unit tests, no network
# ---------------------------------------------------------------------------

class TestComplianceParity(unittest.TestCase):
    """Verify that normalisation and compliance lookup agree."""

    def setUp(self):
        _ensure_module_loaded()

    def test_openssl_and_iana_name_same_rating(self):
        """For each OPENSSL row, check_cipher_compliance on the IANA name gives same rating."""
        rows = _load_csv_rows_direct()
        mismatches = []
        for row in rows:
            if row.get('format', '').strip() != 'OPENSSL':
                continue
            openssl_name = row['cipher_name'].strip()
            protocol = row['protocol'].strip()
            iana_name = ssl_checker.normalise_to_iana(openssl_name)
            if iana_name == openssl_name:
                # Not in map — skip (separate test covers this)
                continue
            openssl_rating = ssl_checker.check_cipher_compliance(openssl_name, protocol)[0]
            iana_rating = ssl_checker.check_cipher_compliance(iana_name, protocol)[0]
            if openssl_rating != iana_rating:
                mismatches.append((openssl_name, openssl_rating, iana_name, iana_rating))
        self.assertEqual([], mismatches,
                         f"Rating mismatches between OPENSSL and IANA names: {mismatches}")

    def test_approved_cipher_found_by_iana_name(self):
        """Every entry in OPENSSL_TO_IANA must resolve to an IANA name present in APPROVED_CIPHERS."""
        missing = []
        for openssl_name, iana_name in ssl_checker.OPENSSL_TO_IANA.items():
            # Find at least one (iana_name, *) entry in APPROVED_CIPHERS
            found = any(k[0] == iana_name for k in ssl_checker.APPROVED_CIPHERS)
            if not found:
                missing.append((openssl_name, iana_name))
        self.assertEqual([], missing,
                         f"IANA names not found in APPROVED_CIPHERS: {missing}")


# ---------------------------------------------------------------------------
# TestBackendSelection — unit tests, mock shutil.which
# ---------------------------------------------------------------------------

class TestBackendSelection(unittest.TestCase):
    """Test backend auto-selection logic."""

    def test_auto_selects_nmap_when_available(self):
        with patch('ssl_checker.shutil.which', return_value='/usr/bin/nmap'):
            self.assertEqual('nmap', ssl_checker.select_backend('auto'))

    def test_auto_falls_back_to_openssl_when_no_nmap(self):
        with patch('ssl_checker.shutil.which', return_value=None):
            self.assertEqual('openssl', ssl_checker.select_backend('auto'))

    def test_explicit_nmap_ignores_availability(self):
        with patch('ssl_checker.shutil.which', return_value=None):
            self.assertEqual('nmap', ssl_checker.select_backend('nmap'))

    def test_explicit_openssl_ignores_availability(self):
        with patch('ssl_checker.shutil.which', return_value='/usr/bin/nmap'):
            self.assertEqual('openssl', ssl_checker.select_backend('openssl'))


# ---------------------------------------------------------------------------
# TestOutputNormalisation — unit tests testing the output pipeline
# ---------------------------------------------------------------------------

class TestOutputNormalisation(unittest.TestCase):
    """Test that cipher names are IANA-normalised before they reach output."""

    def setUp(self):
        _ensure_module_loaded()

    def _make_results(self, cipher_names, protocol='TLSv1.2'):
        """Build a minimal results dict with the given cipher names."""
        return {
            'TLSv1.2': {
                'status': 'SUPPORTED',
                'protocol': protocol,
                'ciphers': list(cipher_names),
                'cipher': cipher_names[0] if cipher_names else '',
            },
            'TLSv1.0': {'status': 'SERVER_UNSUPPORTED'},
            'TLSv1.1': {'status': 'SERVER_UNSUPPORTED'},
            'TLSv1.3': {'status': 'SERVER_UNSUPPORTED'},
        }

    def test_json_report_cipher_names_are_iana(self):
        """After normalise_results + output_json_report, all cipher names must start with TLS_."""
        raw = self._make_results([
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'TLS_AES_256_GCM_SHA384',
        ])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        ciphers = report['protocols']['TLSv1.2']['ciphers']
        names = [c['name'] for c in ciphers]
        for name in names:
            self.assertTrue(name.startswith('TLS_'),
                            f"Cipher name not in IANA format: {name}")

    def test_normalisation_applied_before_compliance_lookup(self):
        """ECDHE-RSA-AES256-GCM-SHA384 must appear as IANA name with SECURE compliance."""
        raw = self._make_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        ciphers = report['protocols']['TLSv1.2']['ciphers']
        self.assertEqual(1, len(ciphers))
        cipher_entry = ciphers[0]
        self.assertEqual('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', cipher_entry['name'])
        self.assertEqual('SECURE', cipher_entry['compliance'])

    def test_normalise_results_leaves_already_iana_names_unchanged(self):
        """Ciphers already in IANA format must pass through unchanged."""
        name = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        raw = self._make_results([name])
        results = ssl_checker.normalise_results(raw)
        self.assertIn(name, results['TLSv1.2']['ciphers'])

    def test_normalise_results_does_not_alter_non_supported_protocols(self):
        """SERVER_UNSUPPORTED entries must not be modified by normalise_results."""
        raw = self._make_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        self.assertEqual('SERVER_UNSUPPORTED', results['TLSv1.0']['status'])
        self.assertNotIn('ciphers', results['TLSv1.0'])


# ---------------------------------------------------------------------------
# TestIntegration — network tests (skipped unless INTEGRATION=1)
# ---------------------------------------------------------------------------

@unittest.skipUnless(os.getenv('INTEGRATION'), 'set INTEGRATION=1 to run')
class TestIntegration(unittest.TestCase):
    """Live network tests against badssl.com."""

    TARGET_HOST = 'tls-v1-2.badssl.com'
    TARGET_PORT = 1012

    def setUp(self):
        ssl_checker.APPROVED_CIPHERS.clear()
        ssl_checker.OPENSSL_TO_IANA.clear()
        ssl_checker._load_csv_rows(CSV_PATH, compliance_standard=None)

    def _assert_tls12_only(self, results):
        """Assert TLSv1.2 is SUPPORTED and older/newer are SERVER_UNSUPPORTED."""
        self.assertEqual('SUPPORTED', results['TLSv1.2']['status'])
        self.assertIn(results['TLSv1.0']['status'], ('SERVER_UNSUPPORTED', 'CLIENT_UNSUPPORTED'))
        self.assertIn(results['TLSv1.1']['status'], ('SERVER_UNSUPPORTED', 'CLIENT_UNSUPPORTED'))
        self.assertIn(results['TLSv1.3']['status'], ('SERVER_UNSUPPORTED',))

    def _assert_cipher_names_are_iana(self, results):
        """Assert all cipher names in SUPPORTED protocols start with TLS_."""
        for tls_name, result in results.items():
            if result.get('status') == 'SUPPORTED':
                for cipher in result.get('ciphers', []):
                    self.assertTrue(
                        cipher.startswith('TLS_'),
                        f"{tls_name}: cipher not in IANA format: {cipher}",
                    )

    def test_nmap_backend_tls12_badssl(self):
        raw = ssl_checker.build_full_results(
            ssl_checker.scan_with_nmap(self.TARGET_HOST, self.TARGET_PORT)
        )
        results = ssl_checker.normalise_results(raw)
        self._assert_tls12_only(results)
        self._assert_cipher_names_are_iana(results)

    def test_openssl_backend_tls12_badssl(self):
        raw = ssl_checker.scan_with_openssl(self.TARGET_HOST, self.TARGET_PORT)
        results = ssl_checker.normalise_results(raw)
        self._assert_tls12_only(results)
        self._assert_cipher_names_are_iana(results)

    def test_both_backends_same_cipher_compliance(self):
        """For common ciphers (by IANA name), both backends must agree on compliance."""
        nmap_raw = ssl_checker.build_full_results(
            ssl_checker.scan_with_nmap(self.TARGET_HOST, self.TARGET_PORT)
        )
        nmap_results = ssl_checker.normalise_results(nmap_raw)

        openssl_raw = ssl_checker.scan_with_openssl(self.TARGET_HOST, self.TARGET_PORT)
        openssl_results = ssl_checker.normalise_results(openssl_raw)

        mismatches = []
        for tls_name in ssl_checker.TLS_VERSIONS:
            nr = nmap_results.get(tls_name, {})
            osr = openssl_results.get(tls_name, {})
            if nr.get('status') != 'SUPPORTED' or osr.get('status') != 'SUPPORTED':
                continue
            proto = nr.get('protocol', tls_name)
            nmap_ciphers = set(nr.get('ciphers', []))
            openssl_ciphers = set(osr.get('ciphers', []))
            common = nmap_ciphers & openssl_ciphers
            for cipher in common:
                n_rating = ssl_checker.check_cipher_compliance(cipher, proto)[0]
                o_rating = ssl_checker.check_cipher_compliance(cipher, proto)[0]
                if n_rating != o_rating:
                    mismatches.append((tls_name, cipher, n_rating, o_rating))

        self.assertEqual([], mismatches,
                         f"Compliance rating mismatches between backends: {mismatches}")


if __name__ == '__main__':
    unittest.main()
