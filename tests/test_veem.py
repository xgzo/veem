import contextlib
import io
import json
from pathlib import Path
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import veem

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        location = {'/loop': '/loop', '/outside': 'http://example.invalid/', '/redirect': '/good'}.get(self.path)
        self.send_response(302 if location else 200)
        if location: self.send_header('Location', location)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Set-Cookie', 'sid=TOPSECRET; Path=/; HttpOnly; SameSite=Lax')
        self.send_header('Set-Cookie', 'prefs=SECRET2; SameSite=None')
        if self.path == '/good':
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        if self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin', self.headers['Origin'])
            self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers()

class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = 'http://127.0.0.1:%d' % cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
    def audit(self, path='', *flags):
        return veem.audit(self.url + path, veem.parser().parse_args(list(flags)))
    def test_redirect_cookies(self):
        r = self.audit('/redirect')
        self.assertTrue(r['complete'])
        self.assertEqual(len(r['hops']), 2)
        self.assertEqual(len(r['hops'][1]['cookies']), 2)
        self.assertNotIn('TOPSECRET', json.dumps(r))
        self.assertNotIn('SECRET2', json.dumps(r))
        checks = [f['check'] for f in r['findings'] if f['url'].endswith('/good')]
        self.assertNotIn('csp.missing', checks)
        self.assertNotIn('framing.policy', checks)
        self.assertIn('cookie.none_without_secure', checks)
    def test_loop(self):
        r = self.audit('/loop')
        self.assertFalse(r['complete'])
        self.assertIn('loop', r['errors'][0])
    def test_scope(self):
        r = self.audit('/outside')
        self.assertEqual(len(r['hops']), 1)
        self.assertIn('Cross-host', r['errors'][0])
    def test_cors(self):
        r = self.audit('/good', '--cors')
        self.assertEqual(sum(f['check'] == 'cors.reflection' for f in r['findings']), 2)
    def test_query_redaction(self):
        self.assertNotIn('SECRET', json.dumps(self.audit('/?token=SECRET')))
    def test_cli_json_save(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'report.json'
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                status = veem.main([self.url, '--json', '-o', str(path), '--fail-on', 'medium'])
            self.assertEqual(status, 1)
            self.assertEqual(json.loads(buf.getvalue()), json.loads(path.read_text()))
    def test_connection_exit(self):
        with patch('veem.request', side_effect=ConnectionRefusedError()):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(veem.main([self.url, '--json']), 2)
    def test_tls_failure(self):
        with patch('veem.request', side_effect=ssl.SSLCertVerificationError()) as req:
            r = self.audit()
            self.assertEqual(req.call_count, 1)
            self.assertIn('TLS certificate', r['errors'][0])
    def test_inputs(self):
        self.assertEqual(veem.normalize('example.com'), 'https://example.com/')
        self.assertEqual(veem.normalize('http://[::1]:8080'), 'http://[::1]:8080/')
        for bad in ('ftp://example.com', 'https://u:p@example.com', 'https://example.com:99999', 'https://foo\r\nbar'):
            with self.assertRaises(ValueError): veem.normalize(bad)
        self.assertNotIn('\x1b', veem.clean('\x1b[31mserver'))
    def test_json_not_html(self):
        f, _ = veem.analyze({'url': 'https://example.com/', 'status': 200, 'tls': None, 'headers': [('Content-Type', 'application/json')]})
        self.assertNotIn('csp.missing', [x['check'] for x in f])
    def test_nonce(self):
        f, _ = veem.analyze({'url': 'https://example.com/', 'status': 200, 'tls': None, 'headers': [('Content-Type', 'text/html'), ('Content-Security-Policy', "script-src 'nonce-abc' 'unsafe-inline'")]})
        self.assertNotIn('csp.inline', [x['check'] for x in f])

class MenuTests(unittest.TestCase):
    def test_invalid_choice_then_exit(self):
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', side_effect=['bad', '0']), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(veem.main(['--no-color']), 0)
            self.assertIn('Choose 01', out.getvalue())
    def test_missing_file_returns_to_menu(self):
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', side_effect=['2', '/missing/targets.txt', 'n', '', '', '0']), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(veem.main(['--no-color']), 0)
    def test_bad_extension_returns_to_menu(self):
        with patch('sys.stdin.isatty', return_value=True), patch('builtins.input', side_effect=['1', 'example.com', 'n', 'report.exe', '0']), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(veem.main(['--no-color']), 0)
            self.assertIn('Use .json', out.getvalue())

if __name__ == '__main__': unittest.main()
