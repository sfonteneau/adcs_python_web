"""Vendor pinned Swagger UI dist files for fully offline serving by the ADCS API.

Run once from the adcs_web/ project directory while Internet access is available:
    python3 scripts/vendor_swagger_ui.py

No Node.js needed at runtime and no changes to the upstream ADCS project.
"""
from pathlib import Path
import os
import tempfile
from urllib.request import Request, urlopen

VERSION = '5.32.0'
BASE = 'https://cdn.jsdelivr.net/npm/swagger-ui-dist@{}/'.format(VERSION)
TARGET = Path(__file__).resolve().parents[1] / 'api' / 'docs' / 'assets'
FILES = {'swagger-ui.css': (50_000, 600_000), 'swagger-ui-bundle.js': (500_000, 3_000_000)}


def main():
    TARGET.mkdir(parents=True, exist_ok=True)
    for name, (minimum, maximum) in FILES.items():
        request = Request(BASE + name, headers={'User-Agent': 'adcs-web-swagger-vendor/1'})
        with urlopen(request, timeout=30) as response:
            data = response.read(maximum + 1)
        if not minimum <= len(data) <= maximum or data.lstrip().startswith(b'<'):
            raise RuntimeError('Unexpected Swagger UI file: {}'.format(name))
        handle, tmp = tempfile.mkstemp(prefix='.' + name + '.', dir=TARGET)
        try:
            with os.fdopen(handle, 'wb') as dest:
                dest.write(data)
            os.replace(tmp, TARGET / name)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        print('Downloaded {} ({} bytes)'.format(name, len(data)))
    print('Swagger UI {} is now served locally. No CDN required at runtime.'.format(VERSION))


if __name__ == '__main__':
    main()
