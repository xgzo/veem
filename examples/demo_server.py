"""Intentionally weak HTTP config. Loopback only."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class Demo(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Set-Cookie', 'demo=fake-value; SameSite=None')
        self.send_header('Content-Security-Policy', "script-src * 'unsafe-inline'")
        origin = self.headers.get('Origin')
        if origin:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers()
        try: self.wfile.write(b'<h1>veem local demo</h1>')
        except (BrokenPipeError, ConnectionResetError): pass

if __name__ == '__main__':
    server = ThreadingHTTPServer(('127.0.0.1', 8765), Demo)
    print('demo: http://127.0.0.1:8765 / Ctrl+C to stop')
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
