"""
Tests for ssl_checker.py dual-backend implementation.

Unit tests run without network access.
Integration tests require INTEGRATION=1 environment variable.
"""

import csv
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ssl_checker

CSV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'approved_ciphers.csv')


def _load_csv_rows_direct():
    with open(CSV_PATH, newline='') as f:
        return list(csv.DictReader(f))


def _ensure_module_loaded():
    if not ssl_checker.APPROVED_CIPHERS:
        ssl_checker._load_csv_rows(CSV_PATH, compliance_standard=None)


# ---------------------------------------------------------------------------
# TestCSVIntegrity
# ---------------------------------------------------------------------------

class TestCSVIntegrity(unittest.TestCase):

    def setUp(self):
        self.rows = _load_csv_rows_direct()

    def test_csv_has_iana_name_column(self):
        with open(CSV_PATH, newline='') as f:
            header = f.readline().strip()
        self.assertIn('iana_name', header)

    def test_all_openssl_rows_have_iana_name(self):
        """Every row with format=OPENSSL must have a non-empty iana_name."""
        violations = [
            row['cipher_name'] for row in self.rows
            if row.get('format', '').strip() == 'OPENSSL'
            and not row.get('iana_name', '').strip()
        ]
        self.assertEqual([], violations, f"OPENSSL rows missing iana_name: {violations}")

    def test_iana_name_format_valid(self):
        """Every populated iana_name value must start with 'TLS_'."""
        violations = [
            row.get('iana_name', '').strip() for row in self.rows
            if row.get('iana_name', '').strip()
            and not row.get('iana_name', '').strip().startswith('TLS_')
        ]
        self.assertEqual([], violations, f"iana_name values not starting with TLS_: {violations}")

    def test_iana_rows_have_empty_iana_name(self):
        """Rows with format=IANA must have an empty iana_name."""
        violations = [
            (row['cipher_name'], row.get('iana_name', '').strip()) for row in self.rows
            if row.get('format', '').strip() == 'IANA'
            and row.get('iana_name', '').strip()
        ]
        self.assertEqual([], violations, f"IANA rows with non-empty iana_name: {violations}")

    def test_no_aes_123_typo(self):
        """The typo TLS_DHE_RSA_WITH_AES_123_CCM_8 must NOT appear as an iana_name."""
        all_iana = [row.get('iana_name', '').strip() for row in self.rows]
        self.assertNotIn('TLS_DHE_RSA_WITH_AES_123_CCM_8', all_iana)

    def test_aes_128_ccm_8_present(self):
        """TLS_DHE_RSA_WITH_AES_128_CCM_8 must appear as an iana_name."""
        all_iana = [row.get('iana_name', '').strip() for row in self.rows]
        self.assertIn('TLS_DHE_RSA_WITH_AES_128_CCM_8', all_iana)


# ---------------------------------------------------------------------------
# TestNormalisation
# ---------------------------------------------------------------------------

class TestNormalisation(unittest.TestCase):

    def setUp(self):
        _ensure_module_loaded()

    def test_known_openssl_name_normalised(self):
        self.assertEqual(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            ssl_checker.normalise_to_iana('ECDHE-RSA-AES256-GCM-SHA384'),
        )

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
        """Every OPENSSL-format cipher in the CSV must map to a different IANA name."""
        not_normalised = [
            row['cipher_name'].strip()
            for row in _load_csv_rows_direct()
            if row.get('format', '').strip() == 'OPENSSL'
            and ssl_checker.normalise_to_iana(row['cipher_name'].strip()) == row['cipher_name'].strip()
        ]
        self.assertEqual([], not_normalised, f"OPENSSL ciphers not normalised: {not_normalised}")

    def test_nmap_tls13_alias_normalised(self):
        """nmap TLS_AKE_WITH_* aliases must normalise to correct IANA TLS_AES_* names."""
        cases = {
            'TLS_AKE_WITH_AES_128_GCM_SHA256':       'TLS_AES_128_GCM_SHA256',
            'TLS_AKE_WITH_AES_256_GCM_SHA384':       'TLS_AES_256_GCM_SHA384',
            'TLS_AKE_WITH_CHACHA20_POLY1305_SHA256': 'TLS_CHACHA20_POLY1305_SHA256',
        }
        for alias, expected in cases.items():
            with self.subTest(alias=alias):
                self.assertEqual(expected, ssl_checker.normalise_to_iana(alias))

    def test_builtin_rsa_openssl_names_normalised(self):
        """Common RSA OpenSSL shorthand names not in CSV must normalise via built-in table."""
        cases = {
            'AES128-SHA':        'TLS_RSA_WITH_AES_128_CBC_SHA',
            'AES256-SHA':        'TLS_RSA_WITH_AES_256_CBC_SHA',
            'AES128-GCM-SHA256': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'AES256-GCM-SHA384': 'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'CAMELLIA128-SHA':   'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
            'DES-CBC3-SHA':      'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        }
        for openssl_name, expected in cases.items():
            with self.subTest(name=openssl_name):
                self.assertEqual(expected, ssl_checker.normalise_to_iana(openssl_name))

    def test_builtin_ecdhe_openssl_names_normalised(self):
        """Common ECDHE OpenSSL shorthand names must normalise via built-in table."""
        cases = {
            'ECDHE-RSA-AES128-SHA':        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'ECDHE-RSA-AES256-SHA384':     'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
            'ECDHE-ECDSA-AES128-SHA256':   'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
            'ECDHE-ECDSA-AES256-SHA384':   'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
            'ECDHE-RSA-CHACHA20-POLY1305': 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
        }
        for openssl_name, expected in cases.items():
            with self.subTest(name=openssl_name):
                self.assertEqual(expected, ssl_checker.normalise_to_iana(openssl_name))

    def test_builtin_dhe_openssl_names_normalised(self):
        """Common DHE OpenSSL shorthand names must normalise via built-in table."""
        cases = {
            'DHE-RSA-AES128-SHA':       'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
            'DHE-RSA-AES256-SHA256':    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
            'DHE-RSA-CAMELLIA128-SHA':  'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
            'DHE-RSA-CAMELLIA256-SHA':  'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
        }
        for openssl_name, expected in cases.items():
            with self.subTest(name=openssl_name):
                self.assertEqual(expected, ssl_checker.normalise_to_iana(openssl_name))

    def test_csv_mapping_takes_priority_over_builtin(self):
        """If a cipher appears in both CSV and built-in table, CSV wins."""
        # ECDHE-RSA-AES256-GCM-SHA384 is in the CSV; built-in agrees but CSV must win.
        result = ssl_checker.normalise_to_iana('ECDHE-RSA-AES256-GCM-SHA384')
        self.assertEqual('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', result)


# ---------------------------------------------------------------------------
# TestComplianceParity
# ---------------------------------------------------------------------------

class TestComplianceParity(unittest.TestCase):

    def setUp(self):
        _ensure_module_loaded()

    def test_openssl_and_iana_name_same_rating(self):
        """For each OPENSSL row, compliance on its IANA name must equal compliance on its OpenSSL name."""
        mismatches = []
        for row in _load_csv_rows_direct():
            if row.get('format', '').strip() != 'OPENSSL':
                continue
            openssl_name = row['cipher_name'].strip()
            protocol = row['protocol'].strip()
            iana_name = ssl_checker.normalise_to_iana(openssl_name)
            if iana_name == openssl_name:
                continue
            ossl_rating = ssl_checker.check_cipher_compliance(openssl_name, protocol)[0]
            iana_rating = ssl_checker.check_cipher_compliance(iana_name, protocol)[0]
            if ossl_rating != iana_rating:
                mismatches.append((openssl_name, ossl_rating, iana_name, iana_rating))
        self.assertEqual([], mismatches, f"Rating mismatches: {mismatches}")

    def test_approved_cipher_found_by_iana_name(self):
        """Every OPENSSL_TO_IANA value must appear as a key in APPROVED_CIPHERS."""
        missing = [
            (ossl, iana)
            for ossl, iana in ssl_checker.OPENSSL_TO_IANA.items()
            if not any(k[0] == iana for k in ssl_checker.APPROVED_CIPHERS)
        ]
        self.assertEqual([], missing, f"IANA names missing from APPROVED_CIPHERS: {missing}")


# ---------------------------------------------------------------------------
# TestBackendSelection
# ---------------------------------------------------------------------------

class TestBackendSelection(unittest.TestCase):

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
# TestOutputNormalisation
# ---------------------------------------------------------------------------

class TestOutputNormalisation(unittest.TestCase):

    def setUp(self):
        _ensure_module_loaded()

    def _make_raw_results(self, cipher_names, protocol='TLSv1.2'):
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

    def test_normalise_results_returns_cipher_dicts(self):
        """normalise_results must return ciphers as dicts with 'iana' and 'original' keys."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        ciphers = results['TLSv1.2']['ciphers']
        self.assertEqual(1, len(ciphers))
        self.assertIn('iana', ciphers[0])
        self.assertIn('original', ciphers[0])

    def test_normalise_results_iana_field_is_iana_name(self):
        """The 'iana' field must hold the normalised IANA name."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        self.assertEqual(
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            results['TLSv1.2']['ciphers'][0]['iana'],
        )

    def test_normalise_results_original_field_preserves_reported_name(self):
        """The 'original' field must hold the name as reported by the backend."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        self.assertEqual('ECDHE-RSA-AES256-GCM-SHA384', results['TLSv1.2']['ciphers'][0]['original'])

    def test_json_report_cipher_iana_name_field(self):
        """JSON output must have 'iana_name' field containing IANA name."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384', 'TLS_AES_256_GCM_SHA384'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        ciphers = report['protocols']['TLSv1.2']['ciphers']
        for c in ciphers:
            self.assertIn('iana_name', c)
            self.assertTrue(c['iana_name'].startswith('TLS_'),
                            f"iana_name not in IANA format: {c['iana_name']}")

    def test_json_report_openssl_name_present_when_different(self):
        """JSON must include 'openssl_name' when backend reported an OpenSSL shorthand."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        cipher_entry = report['protocols']['TLSv1.2']['ciphers'][0]
        self.assertIn('openssl_name', cipher_entry)
        self.assertEqual('ECDHE-RSA-AES256-GCM-SHA384', cipher_entry['openssl_name'])

    def test_json_report_no_openssl_name_when_already_iana(self):
        """JSON must NOT include 'openssl_name' when name was already in IANA format."""
        raw = self._make_raw_results(['TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        cipher_entry = report['protocols']['TLSv1.2']['ciphers'][0]
        self.assertNotIn('openssl_name', cipher_entry)

    def test_json_report_compliance_correct_after_normalisation(self):
        """ECDHE-RSA-AES256-GCM-SHA384 must yield iana_name=TLS_ECDHE_RSA... with SECURE compliance."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        entry = report['protocols']['TLSv1.2']['ciphers'][0]
        self.assertEqual('TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', entry['iana_name'])
        self.assertEqual('SECURE', entry['compliance'])

    def test_json_report_cipher_count_field(self):
        """JSON protocols must include a 'cipher_count' field."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256'])
        results = ssl_checker.normalise_results(raw)
        report = ssl_checker.output_json_report('example.com', 443, results)
        self.assertEqual(2, report['protocols']['TLSv1.2']['cipher_count'])

    def test_normalise_results_does_not_alter_unsupported_protocols(self):
        """SERVER_UNSUPPORTED entries must pass through normalise_results unchanged."""
        raw = self._make_raw_results(['ECDHE-RSA-AES256-GCM-SHA384'])
        results = ssl_checker.normalise_results(raw)
        self.assertEqual('SERVER_UNSUPPORTED', results['TLSv1.0']['status'])
        self.assertNotIn('ciphers', results['TLSv1.0'])

    def test_normalise_results_iana_name_passthrough(self):
        """A cipher already in IANA format must have iana == original in the dict."""
        name = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
        raw = self._make_raw_results([name])
        results = ssl_checker.normalise_results(raw)
        entry = results['TLSv1.2']['ciphers'][0]
        self.assertEqual(name, entry['iana'])
        self.assertEqual(name, entry['original'])


# ---------------------------------------------------------------------------
# TestIntegration — network tests (skipped unless INTEGRATION=1)
# ---------------------------------------------------------------------------

@unittest.skipUnless(os.getenv('INTEGRATION'), 'set INTEGRATION=1 to run')
class TestIntegration(unittest.TestCase):

    TARGET_HOST = 'tls-v1-2.badssl.com'
    TARGET_PORT = 1012

    def setUp(self):
        ssl_checker.APPROVED_CIPHERS.clear()
        ssl_checker.OPENSSL_TO_IANA.clear()
        ssl_checker._load_csv_rows(CSV_PATH, compliance_standard=None)

    def _assert_tls12_only(self, results):
        self.assertEqual('SUPPORTED', results['TLSv1.2']['status'])
        self.assertIn(results['TLSv1.0']['status'], ('SERVER_UNSUPPORTED', 'CLIENT_UNSUPPORTED'))
        self.assertIn(results['TLSv1.1']['status'], ('SERVER_UNSUPPORTED', 'CLIENT_UNSUPPORTED'))
        self.assertEqual('SERVER_UNSUPPORTED', results['TLSv1.3']['status'])

    def _assert_cipher_iana_names(self, results):
        """All cipher dicts must have iana field starting with TLS_."""
        for tls_name, result in results.items():
            if result.get('status') == 'SUPPORTED':
                for c in result.get('ciphers', []):
                    self.assertTrue(
                        c['iana'].startswith('TLS_'),
                        f"{tls_name}: iana field not in IANA format: {c['iana']}",
                    )

    def test_nmap_backend_tls12_badssl(self):
        raw = ssl_checker.build_full_results(
            ssl_checker.scan_with_nmap(self.TARGET_HOST, self.TARGET_PORT)
        )
        results = ssl_checker.normalise_results(raw)
        self._assert_tls12_only(results)
        self._assert_cipher_iana_names(results)

    def test_openssl_backend_tls12_badssl(self):
        raw = ssl_checker.scan_with_openssl(self.TARGET_HOST, self.TARGET_PORT)
        results = ssl_checker.normalise_results(raw)
        self._assert_tls12_only(results)
        self._assert_cipher_iana_names(results)

    def test_both_backends_same_cipher_compliance(self):
        """Common ciphers (by IANA name) must have same compliance rating from both backends."""
        nmap_results = ssl_checker.normalise_results(
            ssl_checker.build_full_results(
                ssl_checker.scan_with_nmap(self.TARGET_HOST, self.TARGET_PORT)
            )
        )
        openssl_results = ssl_checker.normalise_results(
            ssl_checker.scan_with_openssl(self.TARGET_HOST, self.TARGET_PORT)
        )

        mismatches = []
        for tls_name in ssl_checker.TLS_VERSIONS:
            nr = nmap_results.get(tls_name, {})
            osr = openssl_results.get(tls_name, {})
            if nr.get('status') != 'SUPPORTED' or osr.get('status') != 'SUPPORTED':
                continue
            proto = nr.get('protocol', tls_name)
            nmap_iana = {c['iana'] for c in nr.get('ciphers', [])}
            ossl_iana = {c['iana'] for c in osr.get('ciphers', [])}
            for cipher in nmap_iana & ossl_iana:
                n_rating = ssl_checker.check_cipher_compliance(cipher, proto)[0]
                o_rating = ssl_checker.check_cipher_compliance(cipher, proto)[0]
                if n_rating != o_rating:
                    mismatches.append((tls_name, cipher, n_rating, o_rating))

        self.assertEqual([], mismatches, f"Compliance mismatches: {mismatches}")


if __name__ == '__main__':
    unittest.main()
