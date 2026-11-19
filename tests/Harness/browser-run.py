"""Run native browser WebAuthn against owned Gateway/PostgreSQL fixtures."""
import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('amdn_browser_harness_fixture', ROOT / 'tests/Harness/run.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def main():
    destination = ROOT / '.local/browser-evidence'
    destination.mkdir(parents=True, exist_ok=True)
    report = destination / 'native-matrix.json'
    report.write_text(json.dumps(dict(result='running', cleanup='pending')) + '\n')
    if not shutil.which('geckodriver'):
        raise fixture.Failure('Installed Firefox and geckodriver are required for native Firefox tests')
    manifest = json.loads((ROOT / '.tools/browser-matrix/manifest.json').read_text())
    builds = json.loads((ROOT / 'clients/web/node_modules/playwright-core/browsers.json').read_text())['browsers']
    revision = next(item['revision'] for item in builds if item['name'] == 'chromium')
    binaries = dict(chrome=manifest['chrome'], edge=manifest['edge'],
                    chromium=str(Path(manifest['browsers']) / ('chromium-' + revision) / 'chrome-linux64/chrome'))
    run = fixture.Run()
    results = []
    outcome = 'failed'
    cleanup = 'pending'
    module_hash = hashlib.sha256((ROOT / 'clients/web/enrollment.mjs').read_bytes()).hexdigest()
    versions = {name: subprocess.check_output([binary, '--version'], text=True, stderr=subprocess.DEVNULL, timeout=10).splitlines()[0]
                for name, binary in dict(binaries, firefox='firefox', geckodriver='geckodriver').items()}
    try:
        run.setup()
        run.env.update(CHROME_BIN=binaries['chrome'], CHROME_DEVEL_SANDBOX=manifest['sandboxHelper'])
        count = run.test()  # Full existing service suite plus native Chrome case.
        results.append(dict(browser='chrome', tests=count, result='passed'))
        for name in ['edge', 'chromium', 'firefox']:
            if name == 'firefox':
                run.env.update(AMDN_NATIVE_BROWSER='firefox',
                               AMDN_CERTUTIL=str(ROOT / '.tools/browser-matrix/dependencies/usr/bin/certutil'))
            else:
                run.env['CHROME_BIN'] = binaries[name]
            for repetition in range(1, 4):
                evidence = run.evidence / (name + '-' + str(repetition))
                evidence.mkdir()
                run.command(['dotnet', 'test', str(fixture.PROJECT), '--no-restore', '--no-build', '-c', 'Release',
                             '--filter', 'FullyQualifiedName~BrowserEnrollmentTests', '--logger', 'trx;LogFileName=browser.trx',
                             '--results-directory', str(evidence), '--blame-hang-timeout', '90s', '--blame-hang-dump-type', 'none'],
                            'native-' + name + '-' + str(repetition), timeout=120)
                counts = ET.parse(evidence / 'browser.trx').find('.//{*}Counters').attrib
                if int(counts['total']) != 1 or int(counts['passed']) != 1 or int(counts['executed']) != 1:
                    raise fixture.Failure('Native browser case did not execute and pass')
                results.append(dict(browser=name, repetition=repetition, tests=1, result='passed',
                    replacement='pending' if name == 'firefox' else 'passed'))
        outcome = 'passed'
    finally:
        try:
            run.cleanup()
            cleanup = 'complete'
        except BaseException:
            outcome = 'failed'
            cleanup = 'failed'
            raise
        finally:
            report.write_text(json.dumps(dict(result=outcome, cleanup=cleanup, moduleSha256=module_hash, versions=versions,
                scope='Actual browser WebAuthn with CDP/WebDriver virtual authenticators, actual HTTPS Gateway and PostgreSQL; Firefox replacement and physical devices remain pending',
                evidence=str(run.evidence), runs=results), indent=2) + '\n')
    fixture.emit(result=outcome, native_browser_runs=len(results), cleanup='complete', evidence=str(run.evidence),
                 pending='real Safari, physical Android/iOS, physical authenticators, production and independent review')


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        # Arbitrary subprocess/assertion details can contain proof data. Keep logs
        # within the existing runner's redacted evidence boundary.
        fixture.emit(result='failed', message='Native browser matrix failed; inspect the owned sanitized evidence.')
        sys.exit(1)
