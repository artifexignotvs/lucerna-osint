"""Mutationes, limites et secreta in relationibus probantur."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
from lucerna_osint.cli import analyze, main, read_html
from lucerna_osint.compare import compare_reports, load_report, markdown_report, validate_report


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.before = analyze(b'<title>First</title><meta name="description" content="One"><a href="https://example.org/a">A</a><a href="https://old.example/x">X</a>', 'https://example.org/')
        self.after = analyze(b'<title>Second</title><meta name="description" content="Two"><img src="https://example.org/a"><img src="https://example.org/a"><a href="https://new.example/x">X</a>', 'https://example.org/')

    def test_identical_and_changed_reports(self):
        self.assertEqual(compare_reports(self.before, copy.deepcopy(self.before))["status"], "clean")
        diff = compare_reports(self.before, self.after)
        self.assertEqual(diff['status'], 'different')
        self.assertEqual(diff['links']['added'][0]['host'], 'new.example')
        self.assertEqual(diff['links']['removed'][0]['host'], 'old.example')
        self.assertEqual(diff['links']['changed'][0]['fields'], ['occurrences', 'tags'])
        self.assertEqual(diff['hosts']['changed'][0]['after']['occurrences'], 2)
        self.assertEqual(diff['metadata']['changed'][0]['name'], 'description')
        self.assertEqual(diff['title'], {'before': 'First', 'after': 'Second'})
        self.assertEqual(diff['before']['html_sha256'], self.before['sha256'])

    def test_same_inventory_different_source_bytes_is_not_clean(self):
        before = analyze(b'<a href="https://example.org/">One</a>')
        after = analyze(b'<a href="https://example.org/">Two</a>')
        diff = compare_reports(before, after)
        self.assertEqual(diff['status'], 'different')
        self.assertTrue(diff['provenance_changed'])
        self.assertEqual(diff['links'], {'added': [], 'removed': [], 'changed': []})

    def test_source_context_changes_resolution(self):
        first = analyze(b'<a href="/item">Item</a>', 'https://first.example/')
        second = analyze(b'<a href="/item">Item</a>', 'https://second.example/')
        self.assertEqual(first['sha256'], second['sha256'])
        self.assertTrue(compare_reports(first, second)['provenance_changed'])

    def test_no_network_and_no_new_secret_fields(self):
        with patch('socket.socket', side_effect=AssertionError('network')):
            first = analyze(b'<a href="https://user:credential@example.org/a?token=hidden#private">A</a>')
            diff = compare_reports(first, first)
        encoded = json.dumps(diff)
        for token in ['credential@', 'hidden', '#private']:
            self.assertNotIn(token, encoded)

    def test_strict_fields_types_counts_and_hosts(self):
        mutations = [lambda r: r.update(extra='secret'), lambda r: r.update(schema_version=True), lambda r: r.update(network_requests=1), lambda r: r.update(sha256='x'), lambda r: r['hosts'][0].update(occurrences=999), lambda r: r['links'][0].update(occurrences=True), lambda r: r['links'][0].update(external_host=0), lambda r: r['links'].append(r['links'][0]), lambda r: r['metadata'][0].update(content='\x1b[31m')]
        for mutate in mutations:
            value = copy.deepcopy(self.before)
            mutate(value)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                validate_report(value)

    def test_saved_reports_cannot_reintroduce_url_secrets(self):
        for url in ['https://user:password@example.org/a', 'https://example.org/a?token=private', 'https://example.org/a#private', 'javascript:secret']:
            value = copy.deepcopy(self.before)
            value['links'][0]['url'] = url
            with self.assertRaises(ValueError):
                validate_report(value)

    def test_item_and_text_bounds(self):
        with patch('lucerna_osint.compare.MAX_ITEMS', 1), self.assertRaises(ValueError):
            validate_report(self.before)
        value = copy.deepcopy(self.before)
        value['title'] = 'x' * 2001
        with self.assertRaises(ValueError):
            validate_report(value)

    def test_malformed_json_duplicates_nonfinite_depth_and_size(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            for data in [b'{"tool":"a","tool":"b"}', b'{"value":NaN}', b'\xff', b'[' * 2000 + b']' * 2000]:
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, '^Cannot read a valid bounded saved inventory$'):
                    load_report(path)
            path.write_text(json.dumps(self.before))
            with patch('lucerna_osint.compare.MAX_REPORT_BYTES', 8), self.assertRaises(ValueError):
                load_report(path)

    @unittest.skipUnless(hasattr(os, 'O_NOFOLLOW'), 'No no-follow file support')
    def test_symlink_and_special_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'target'
            target.write_text(json.dumps(self.before))
            link = Path(folder) / 'link'
            link.symlink_to(target)
            with self.assertRaises(ValueError):
                load_report(link)
            pipe = Path(folder) / 'pipe'
            os.mkfifo(pipe)
            with self.assertRaises(ValueError):
                load_report(pipe)

    @unittest.skipUnless(hasattr(os, 'mkfifo') and hasattr(os, 'O_NOFOLLOW'), 'Requires POSIX special files')
    def test_inventory_cli_rejects_special_files_without_waiting(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / 'saved.html'
            target.write_bytes(b'<title>Synthetic page</title>')
            pipe = root / 'private-pipe'
            os.mkfifo(pipe)
            link = root / 'private-link'
            link.symlink_to(target)
            for path in (pipe, link, root):
                with self.subTest(kind=path.name):
                    result = subprocess.run([sys.executable, '-m', 'lucerna_osint', str(path), '--format', 'json'], capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')
                    self.assertIn('error', json.loads(result.stderr))
                    self.assertNotIn(folder, result.stderr)

    def test_inventory_regular_file_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'saved.html'
            path.write_bytes(b'<title>Synthetic page</title>')
            self.assertEqual(read_html(path), path.read_bytes())
            with patch('lucerna_osint.cli.MAX_BYTES', 8), self.assertRaisesRegex(ValueError, 'Input exceeds'):
                read_html(path)

    def test_markdown_cannot_close_json_fence(self):
        value = copy.deepcopy(self.after)
        value['title'] = '``` </script><script>test</script> ````'
        text = markdown_report(compare_reports(self.before, value))
        self.assertIn('`````json', text)
        self.assertTrue(text.endswith('`````\n'))

    def test_cli_json_markdown_exit_codes_and_path_privacy(self):
        with tempfile.TemporaryDirectory() as folder:
            first, second = Path(folder) / 'before.json', Path(folder) / 'after.json'
            first.write_text(json.dumps(self.before))
            second.write_text(json.dumps(self.after))
            for fmt in ('json', 'markdown'):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    code = main(['diff', str(first), str(second), '--format', fmt])
                self.assertEqual(code, 1)
                self.assertNotIn(folder, out.getvalue())
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(['diff', str(first), str(first)]), 0)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(main(['diff', str(Path(folder) / 'private-path'), str(second)]), 2)
            self.assertNotIn(folder, err.getvalue())
            self.assertNotIn('private-path', err.getvalue())


if __name__ == '__main__':
    unittest.main()
