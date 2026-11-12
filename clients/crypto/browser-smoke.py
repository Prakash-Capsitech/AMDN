"""Run only the synthetic browser experiment, with the Chrome sandbox enabled."""
from functools import partial
from html.parser import HTMLParser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import threading


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


class ResultParser(HTMLParser):
    passed = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'pre' and values.get('id') == 'result':
            self.passed = values.get('data-status') == 'pass'


def main():
    chrome = os.environ.get('CHROME_BIN') or shutil.which('google-chrome')
    if not chrome:
        raise SystemExit('Chrome is required for this separate browser check. Set CHROME_BIN; do not disable its sandbox.')
    root = Path(__file__).resolve().parent
    server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=str(root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix='amdn-f0-browser-') as profile:
            result = subprocess.run([
                chrome, '--headless', '--disable-gpu', '--no-first-run',
                '--disable-background-networking', '--disable-extensions',
                '--user-data-dir=' + profile, '--dump-dom', '--virtual-time-budget=10000',
                f'http://127.0.0.1:{server.server_port}/browser-smoke.html',
            ], capture_output=True, text=True, timeout=45)
            parsed = ResultParser()
            parsed.feed(result.stdout)
            if result.returncode or not parsed.passed:
                raise SystemExit('Browser experiment did not pass. Check Chrome/WebCrypto availability; sandbox bypass is not supported.')
            version = subprocess.run([chrome, '--version'], capture_output=True, text=True, check=True, timeout=5)
            print('PASS: browser offline exchange, restored receiver and reply; ' + version.stdout.strip())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == '__main__':
    main()
