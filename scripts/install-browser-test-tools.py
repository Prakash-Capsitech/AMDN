"""Pinned, local-only Ubuntu browser fixtures; no system installation or sandbox bypass."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / '.tools/browser-matrix'
PACKAGES = [
    ('pool/main/n/nss/libnss3-tools_3.98-1ubuntu0.3_amd64.deb', '0bb7919188cb21d3bfba5d45b5aa45848aa61b92ced34ff3f8ecda7b92d788c0'),
    ('pool/main/libe/libevent/libevent-2.1-7t64_2.1.12-stable-9ubuntu2.2_amd64.deb', '083ced6efb23476cb4de4e441b741af02db5653e67fa7fcd6cf7e5f7b78f6101'),
    ('pool/universe/liba/libavif/libavif16_1.0.4-1ubuntu3_amd64.deb', 'b295a9954a4b756af05ff381d9808f3c0c582a111b7e4c7678cfe13de9ae8818'),
    ('pool/universe/libg/libgav1/libgav1-1_0.18.0-1build3_amd64.deb', '428f353f449e6b15cdcf5823215416e36adcfba75fe9f0fedc1cd132d68e6b3f'),
    ('pool/universe/liby/libyuv/libyuv0_0.0~git202401110.af6ac82-1_amd64.deb', '88bd472e50a7e45469e31f8e0ba232b4d8ed30322f5badb285c58cc1ba0d2176'),
]


def verified_package(url, expected, destination):
    archive = TOOLS / 'downloads' / url.rsplit('/', 1)[-1]
    archive.parent.mkdir(parents=True, exist_ok=True)
    if archive.exists():
        with archive.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != expected:
                raise SystemExit('Cached browser fixture checksum mismatch: ' + archive.name)
    else:
        partial = archive.with_suffix('.part')
        try:
            with urllib.request.urlopen(url, timeout=60) as response, partial.open('wb') as output:
                while chunk := response.read(1048576):
                    output.write(chunk)
            with partial.open('rb') as source:
                if hashlib.file_digest(source, 'sha256').hexdigest() != expected:
                    raise SystemExit('Browser fixture checksum mismatch: ' + archive.name)
            partial.rename(archive)
        finally:
            partial.unlink(missing_ok=True)
    subprocess.run(['dpkg-deb', '--extract', str(archive), str(destination)], check=True)
    print('Verified local fixture: ' + archive.name, flush=True)


def main():
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if platform.system() != 'Linux' or platform.machine() != 'x86_64' or release.get('ID') != 'ubuntu' or release.get('VERSION_ID') != '"24.04"':
        raise SystemExit('Automatic browser fixture setup supports Ubuntu 24.04 x86_64; other platforms require reviewed local setup.')
    node = shutil.which('node')
    if not node or subprocess.check_output([node, '--version'], text=True).strip() != 'v24.22.3':
        raise SystemExit('Use the Node version in .nvmrc before installing browser fixtures.')
    if not shutil.which('dpkg-deb'):
        raise SystemExit('dpkg-deb is required; no system package installation is performed.')
    chrome = shutil.which(os.environ.get('CHROME_BIN', 'google-chrome'))
    if not chrome:
        raise SystemExit('Installed Google Chrome is required; no system browser is replaced.')
    helper = Path(os.environ.get('AMDN_BROWSER_SANDBOX_HELPER', '/opt/google/chrome/chrome-sandbox')).resolve(strict=True)
    properties = helper.stat()
    if properties.st_uid != 0 or not stat.S_ISREG(properties.st_mode) or not properties.st_mode & stat.S_ISUID or properties.st_mode & 0o022:
        raise SystemExit('An existing root-owned, non-writable setuid Chromium sandbox helper is required; sandbox disabling is unsupported.')
    browsers = TOOLS / 'browsers'
    environment = dict(os.environ, PLAYWRIGHT_BROWSERS_PATH=str(browsers))
    subprocess.run([node, str(ROOT / 'clients/web/node_modules/playwright/cli.js'), 'install', 'firefox', 'webkit', 'chromium', '--no-shell'],
                   env=environment, check=True)
    verified_package('https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/microsoft-edge-stable_155.0.4283.62-1_amd64.deb',
                     '3e53834d9d6e505bc57e6bff44d92cfe8cf0bed9064e88efc5b0d8f1c75f70fa', TOOLS / 'edge')
    edge = TOOLS / 'edge/opt/microsoft/msedge'
    edge_helper = edge / 'msedge-sandbox'
    edge_helper.unlink(missing_ok=True)
    edge_helper.symlink_to(helper)
    libraries = TOOLS / 'dependencies'
    for filename, digest in PACKAGES:
        verified_package('https://archive.ubuntu.com/ubuntu/' + filename, digest, libraries)
    library_root = libraries / 'usr/lib/x86_64-linux-gnu'
    revisions = json.loads((ROOT / 'clients/web/node_modules/playwright-core/browsers.json').read_text())['browsers']
    revision = next(item['revision'] for item in revisions if item['name'] == 'webkit')
    for flavor in ['minibrowser-wpe', 'minibrowser-gtk']:
        target = browsers / ('webkit-' + revision) / flavor / 'sys/lib'
        for name in ['libevent-2.1.so.7', 'libavif.so.16', 'libgav1.so.1', 'libyuv.so.0']:
            destination = target / name
            if destination.is_symlink():
                destination.unlink()
            if not destination.exists():
                destination.symlink_to((library_root / name).resolve(strict=True))
    manifest = dict(playwright='1.65.1', browsers=str(browsers), chrome=chrome,
                    edge=str(edge / 'msedge'), sandboxHelper=str(helper), libraries=str(library_root))
    (TOOLS / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Browser fixtures ready; system browsers, profiles, certificates and sandbox configuration were not modified.')


if __name__ == '__main__':
    main()
