#!/usr/bin/env python3
"""One-command local launcher for the existing ADCS API + static frontend."""
from __future__ import annotations

import getpass
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
STATE = ROOT / '.local'
CONFIG = STATE / 'settings.json'
VENV = ROOT / '.venv'


def python_in_venv():
    return VENV / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def bootstrap():
    exe = python_in_venv()
    if not exe.exists():
        print('[1/3] Creating Python environment…', flush=True)
        subprocess.check_call([sys.executable, '-m', 'venv', '--system-site-packages', str(VENV)])
    if Path(sys.prefix).resolve() != VENV.resolve():
        marker = VENV / '.adcs_web_dependencies_installed'
        if not marker.exists():
            print('[1/3] Installing API dependencies…', flush=True)
            subprocess.check_call([str(exe), '-m', 'pip', 'install', '-r', str(ROOT / 'requirements.txt')])
            marker.touch()
        os.execv(str(exe), [str(exe), str(ROOT / 'start.py'), *sys.argv[1:]])


def find_adcs():
    candidates = [ROOT.parent / 'adcs_python', ROOT.parent / 'adcs_python-main',
                  ROOT / 'adcs_python', Path('/opt/adcs_python')]
    for p in candidates:
        if (p / 'adcs_tool.py').is_file():
            return str(p.resolve())
    return ''


def configure():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        STATE.chmod(0o700)
    except OSError:
        pass
    if CONFIG.exists():
        return json.loads(CONFIG.read_text(encoding='utf-8'))
    from api.auth import hash_password
    print('\n[2/3] First-run setup (once)')
    detected = find_adcs()
    while True:
        project = input('Existing ADCS project directory' + (f' [{detected}]' if detected else '') + ' : ').strip() or detected
        project = str(Path(project).expanduser().resolve())
        if (Path(project) / 'adcs_tool.py').is_file():
            break
        print('Invalid directory: adcs_tool.py not found.')
    default_config = '/etc/adcs/adcs.yaml'
    config_path = input(f'ADCS configuration path [{default_config}] : ').strip() or default_config
    while True:
        password = getpass.getpass('Web admin password (12 characters minimum): ')
        confirm = getpass.getpass('Confirm password: ')
        if password == confirm and len(password) >= 12:
            break
        print('Password too short or confirmation mismatch.')
    port = input('Local HTTP port [8080] : ').strip() or '8080'
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise SystemExit('Invalid port')
    data = {'project_path': project, 'config_path': config_path,
            'username': 'admin', 'password_hash': hash_password(password), 'port': int(port)}
    temp = STATE / ('settings-' + secrets.token_hex(8) + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(temp, CONFIG)
    print('Settings saved to .local/settings.json (private).')
    return data


def serve():
    from flask import send_from_directory
    from waitress import serve as waitress_serve
    from api.server import create_app
    config = configure()
    os.environ.update({
        'ADCS_PROJECT_PATH': config['project_path'],
        'ADCS_CONFIG_PATH': config['config_path'],
        'ADCS_WEB_USERNAME': config['username'],
        'ADCS_WEB_PASSWORD_HASH': config['password_hash'],
        'ADCS_WEB_SESSION_DB': str(STATE / 'sessions.sqlite3'),
        'ADCS_WEB_LOCK_DIR': str(STATE / 'locks'),
        'ADCS_WEB_ALLOWED_ORIGINS': os.environ.get('ADCS_WEB_ALLOWED_ORIGINS') or ','.join(
            [f"http://127.0.0.1:{config['port']}", f"http://localhost:{config['port']}"]
            + config.get('allowed_origins', [])
        ),
    })
    app = create_app()
    webdir = ROOT / 'web'

    @app.route('/')
    def static_index():
        return send_from_directory(webdir, 'index.html')

    @app.route('/<path:filename>')
    def static_assets(filename):
        # Never expose API or local state as static content.
        if filename not in {'styles.css', 'app.js', 'config.js'}:
            return ('Not found', 404)
        return send_from_directory(webdir, filename)

    print(f"\n[3/3] ADCS Web ready : http://127.0.0.1:{config['port']}")
    print(f"Swagger : http://127.0.0.1:{config['port']}/api/docs")
    print('User: admin | Stop: Ctrl+C\n', flush=True)
    waitress_serve(app, host='127.0.0.1', port=config['port'])


if __name__ == '__main__':
    try:
        bootstrap()
        serve()
    except KeyboardInterrupt:
        print('\nStopped.')
