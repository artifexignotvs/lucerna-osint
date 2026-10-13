"""Probationes limites extractionis et indicia examinant."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lucerna_osint.cli import analyze, normalize_url, csv_report, text_report, main


class InventoryTests(unittest.TestCase):
    def test_evidence_hash_and_lines(self):
        data = b'<title>Report</title>\n<a href="https://example.org/a">A</a>'
        result = analyze(data)
        self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(result['links'][0]['lines'], [2])
        self.assertEqual(result['title'], 'Report')

    def test_relative_base_and_external_host(self):
        result = analyze(b'<base href="/archive/"><a href="x">X</a><a href="//cdn.example.net/a">B</a>', 'https://example.org/home')
        self.assertEqual(result['links'][1]['url'], 'https://example.org/archive/x')
        self.assertFalse(result['links'][1]['external_host'])
        self.assertTrue(result['links'][0]['external_host'])

    def test_redaction_and_deduplication(self):
        result = analyze(b'<a href="https://user:password@example.org/a?token=secret#hidden"></a><img src="https://example.org/a?x=other">')
        encoded = json.dumps(result)
        for value in ['password', 'secret', 'hidden', 'token=']:
            self.assertNotIn(value, encoded)
        self.assertEqual(len(result['links']), 1)
        self.assertEqual(result['links'][0]['occurrences'], 2)
        self.assertTrue(result['links'][0]['credentials_removed'])

    def test_reject_unsafe_schemes(self):
        result = analyze(b'<a href="javascript:alert(1)"></a><img src="data:image/png;base64,AAA"><a href="file:///etc/passwd"></a><a href="#here"></a>')
        self.assertEqual(result['links'], [])
        self.assertEqual(result['skipped_references'], 4)

    def test_idna_ipv6_and_ports(self):
        self.assertEqual(normalize_url('https://b\u00fccher.example:443/a')['host'], 'xn--bcher-kva.example')
        self.assertEqual(normalize_url('http://[::1]:8080/a')['url'], 'http://[::1]:8080/a')
        self.assertIsNone(normalize_url('https://example.org:bad/'))

    def test_invalid_hosts_and_backslash(self):
        for url in ['https://bad host/a', 'https://-bad.example/a', 'https://example.org\\@evil.example/a', 'https://example.org/\x1b[31m']:
            self.assertIsNone(normalize_url(url))

    def test_no_network_and_no_script_execution(self):
        with patch('socket.socket', side_effect=AssertionError('Network forbidden')):
            result = analyze(b'<script>throw new Error("fail");</script><img src="https://example.org/a">')
        self.assertEqual(result['network_requests'], 0)

    def test_relative_without_base(self):
        result = analyze(b'<a href="/x"></a>')
        self.assertEqual(result['skipped_references'], 1)

    def test_empty_attributes_and_invalid_base(self):
        result = analyze(b'<base href="javascript:x"><link href="a" rel>', 'https://example.org/')
        self.assertEqual(result['links'][0]['url'], 'https://example.org/a')
        self.assertEqual(result['links'][0]['relations'], [])

    def test_encoding_errors_and_limits(self):
        with self.assertRaises(ValueError):
            analyze(b'\xff')
        with self.assertRaises(ValueError):
            analyze(b'a', encoding='not-an-encoding')
        with patch('lucerna_osint.cli.MAX_BYTES', 2):
            with self.assertRaises(ValueError):
                analyze(b'abc')
        with patch('lucerna_osint.cli.MAX_ITEMS', 1):
            with self.assertRaises(ValueError):
                analyze(b'<a><a>')

    def test_deterministic_reports(self):
        data = b'<a href="https://example.org/a"></a>'
        self.assertEqual(analyze(data), analyze(data))
        self.assertIn('https://example.org/a', csv_report(analyze(data)))
        self.assertIn('0 network requests', text_report(analyze(data)))

    def test_control_characters_in_title_and_metadata(self):
        result = analyze('<title>\x1b[31m\u202eText</title><meta name="description" content="\x1bTEST">'.encode())
        self.assertNotIn('\x1b', result['title'])
        self.assertNotIn('\u202e', result['title'])
        self.assertNotIn('\x1b', result['metadata'][0]['content'])

    def test_source_and_base_secrets_removed(self):
        result = analyze(b'<base href="https://a:b@example.org/x/?secret=123">', 'https://c:d@example.net/path?secret=456')
        self.assertNotIn('secret', json.dumps(result))
        self.assertEqual(result['effective_base']['url'], 'https://example.org/x/')

    def test_duplicate_attributes_use_first_value(self):
        result = analyze(b'<base href="https://first.example/" href="https://last.example/"><a href="first" href="last"></a>')
        self.assertEqual(result['links'][0]['url'], 'https://first.example/first')
        self.assertEqual(result['links'][0]['occurrences'], 1)

    def test_text_containers_do_not_create_false_references(self):
        result = analyze(b'<title>A &amp; B <a href="https://false.example/">text</a></title><textarea><img src="https://false.example/x"></textarea><iframe src="https://real.example/"><a href="https://false.example/y"></a></iframe>')
        self.assertEqual([link['url'] for link in result['links']], ['https://real.example/'])
        self.assertEqual(result['title'], 'A & B <a href="https://false.example/">text</a>')

    def test_paths_are_encoded_without_changing_existing_escapes(self):
        self.assertEqual(normalize_url('https://example.org/café x/%2F')['url'], 'https://example.org/caf%C3%A9%20x/%2F')
        self.assertIsNone(normalize_url('https://example.org/\u202eevil'))
        self.assertIsNone(normalize_url('https://[fe80::1%private-interface]/'))

    def test_cli_failures_are_structured_without_file_path_disclosure(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / 'private-missing-filename'
            errors = io.StringIO()
            output = io.StringIO()
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                status = main([str(missing), '--format', 'json'])
            self.assertEqual(status, 2)
            self.assertEqual(json.loads(errors.getvalue()), {'error': 'Cannot read input file'})
            self.assertNotIn('private-missing-filename', errors.getvalue())
            self.assertEqual(output.getvalue(), '')
            fixture = Path(temporary) / 'page.html'
            fixture.write_bytes(b'<title>Example</title>')
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                status = main([str(fixture), '--source-url', 'https://private-token@bad host/', '--format', 'json'])
            self.assertEqual(status, 2)
            self.assertNotIn('private-token', errors.getvalue())
            self.assertEqual(json.loads(errors.getvalue())['error'], 'Source must be an absolute HTTP or HTTPS URL')


if __name__ == '__main__':
    unittest.main()
