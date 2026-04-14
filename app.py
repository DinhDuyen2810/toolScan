from __future__ import annotations

import html as html_lib
import json
import logging
import os
import re
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import paramiko
import requests
import urllib3
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request
from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

try:
    from pysnmp.hlapi import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
except Exception:
    CommunityData = ContextData = ObjectIdentity = ObjectType = SnmpEngine = UdpTransportTarget = None
    getCmd = nextCmd = None

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:
    PlaywrightTimeoutError = Exception
    sync_playwright = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

logging.basicConfig(level=os.getenv('LOGIN_LOG_LEVEL', 'INFO').upper(), format='[%(asctime)s] %(levelname)s %(message)s')
logger = logging.getLogger('toolscan-login')

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
SSH_DATABASE_PATH = DATA_DIR / 'servers.json'
WEB_DATABASE_PATH = DATA_DIR / 'websites.json'
SOLUTION_DATABASE_PATH = DATA_DIR / 'solutions.json'

DEFAULT_SERVERS = [
    {'ip': '163.223.58.4', 'username': 'root', 'password': 't0ikonho@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.5', 'username': 'root', 'password': 't0ikonho@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.12', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.13', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
    {'ip': '163.223.58.14', 'username': 'root', 'password': 'v2labadmin@123', 'snmp_community': 'public'},
]

DEFAULT_WEBSITES = [
    {'domain': 'v2secure.vn'},
    {'domain': 'jira-int.v2secure.vn'},
    {'domain': 'confluence-int.v2secure.vn'},
    {'domain': 'authentik-int.v2secure.vn'},
    {'domain': 'mail.v2secure.vn'},
]

DEFAULT_SOLUTIONS = [
    {
        'name': 'SIEM',
        'endpoint': '163.223.58.132',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'v2secure',
        'snmp_port': 161,
    },
    {
        'name': 'WAF01',
        'endpoint': '163.223.58.130',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'WAF02',
        'endpoint': '163.223.58.131',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'EDR',
        'endpoint': '163.223.58.133',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NAC',
        'endpoint': '163.223.58.134',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_MCNB',
        'endpoint': '163.223.58.135',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_CSDL',
        'endpoint': '163.223.58.136',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_Tools',
        'endpoint': '163.223.58.137',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_LAN',
        'endpoint': '163.223.58.138',
        'username': 'admin',
        'password': 'admin',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_DMZ',
        'endpoint': '163.223.58.139',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_V2Cloud',
        'endpoint': '163.223.58.144',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NIPS_MGT',
        'endpoint': '163.223.58.146',
        'username': 'admin',
        'password': 'V2SocAdmin@828682',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'PAM',
        'endpoint': '163.223.58.143',
        'username': 'TTS_SOC_DNDuyen',
        'password': 'DNDuyenSOC@2026$#',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': False,
        'snmp_enabled': False,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
    {
        'name': 'NOC',
        'endpoint': 'http://163.223.58.140/cacti/',
        'username': 'admin',
        'password': 'V2labadmin@123',
        'ssh_username': '',
        'ssh_password': '',
        'checkservice': False,
        'snmp_enabled': False,
        'snmp_community': 'public',
        'snmp_port': 161,
    },
]

CPU_RE = re.compile(r'CPU=([-]?[0-9]+(?:[.,][0-9]+)?)')
RAM_RE = re.compile(r'RAM=([-]?[0-9]+(?:[.,][0-9]+)?)')
STORAGE_RE = re.compile(r'STORAGE=([-]?[0-9]+(?:[.,][0-9]+)?)')
PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']?password', re.IGNORECASE)
JSON_LOGIN_ENDPOINT_RE = re.compile(r"(?:fetch|axios\.(?:post|request)|\$\.ajax)\s*\(?\s*['\"]([^'\"]*(?:login|signin|auth)[^'\"]*)['\"]", re.IGNORECASE)
JSON_LOGIN_URL_FIELD_RE = re.compile(r"url\s*:\s*['\"]([^'\"]*(?:login|signin|auth)[^'\"]*)['\"]", re.IGNORECASE)
JSON_LOGIN_KEYS_RE = re.compile(r"JSON\.stringify\s*\(\s*\{(?P<body>.*?)\}\s*\)", re.IGNORECASE | re.DOTALL)
REDIRECT_PATH_RE = re.compile(r"(?:window\.location(?:\.href)?\s*=|redirect\s*[:=])\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
GENERIC_POST_LOGIN_PATHS = ['/default/system/status', '/system/status', '/dashboard', '/status', '/overview', '/home', '/index', '/main']
JSON_SUCCESS_KEYS = ('success', 'ok', 'authenticated', 'is_authenticated', 'logged_in')
USERNAME_HINTS = ('user', 'username', 'login', 'email', 'mail', 'account', 'uid')
PASSWORD_HINTS = ('pass', 'password', 'passwd', 'pwd')
LOGIN_WORDS = ('login', 'log in', 'sign in', 'đăng nhập', 'authentication')
DEFAULT_HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/128.0 Safari/537.36'
    )
}


MAX_SSH_SCAN_WORKERS = int(os.getenv('MAX_SSH_SCAN_WORKERS', '10'))
MAX_WEB_SCAN_WORKERS = int(os.getenv('MAX_WEB_SCAN_WORKERS', '20'))
MAX_SOLUTION_SCAN_WORKERS = int(os.getenv('MAX_SOLUTION_SCAN_WORKERS', '8'))
WEBSITE_CONNECT_TIMEOUT = float(os.getenv('WEBSITE_CONNECT_TIMEOUT', '3'))
WEBSITE_READ_TIMEOUT = float(os.getenv('WEBSITE_READ_TIMEOUT', '5'))
SOLUTION_HTTP_TIMEOUT = float(os.getenv('SOLUTION_HTTP_TIMEOUT', '15'))
LOGIN_TRACE_LIMIT = int(os.getenv('LOGIN_TRACE_LIMIT', '200'))


def _compact(value: Any, limit: int = 220) -> str:
    try:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    except Exception:
        text = repr(value)
    text = text.replace('\n', ' ').replace('\r', ' ').strip()
    return text[:limit] + ('…' if len(text) > limit else '')


def append_login_debug(debug_steps: list[str] | None, stage: str, message: str, **fields: Any) -> None:
    entry = f'[{stage}] {message}'
    if fields:
        entry += ' | ' + ', '.join(f"{key}={_compact(value)}" for key, value in fields.items() if value not in (None, ''))
    logger.info(entry)
    if debug_steps is not None and len(debug_steps) < LOGIN_TRACE_LIMIT:
        debug_steps.append(entry)


def attach_login_debug(result: dict[str, Any], debug_steps: list[str] | None) -> dict[str, Any]:
    result['login_debug'] = debug_steps or []
    return result

SSH_CONNECT_TIMEOUT = float(os.getenv('SSH_CONNECT_TIMEOUT', '5'))
SSH_COMMAND_TIMEOUT = float(os.getenv('SSH_COMMAND_TIMEOUT', '10'))
SNMP_DEFAULT_TIMEOUT = int(os.getenv('SNMP_DEFAULT_TIMEOUT', '1'))
SNMP_DEFAULT_RETRIES = int(os.getenv('SNMP_DEFAULT_RETRIES', '0'))
PROXY_SNMP_USERNAME = os.getenv('PROXY_SNMP_USERNAME', 'root')
PROXY_SNMP_PASSWORD = os.getenv('PROXY_SNMP_PASSWORD', 'Vipstmt@828912')
PROXY_SNMP_HOPS = [
    {'host': os.getenv('PROXY_SNMP_HOST_1', '163.223.58.150'), 'username': PROXY_SNMP_USERNAME, 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@150'},
    {'host': os.getenv('PROXY_SNMP_HOST_2', '163.223.58.132'), 'username': PROXY_SNMP_USERNAME, 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@132'},
]

_thread_local = threading.local()


def parse_float_loose(value: str) -> float:
    return float(str(value).strip().replace(',', '.'))


def ensure_databases() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_DATABASE_PATH.exists():
        save_servers(DEFAULT_SERVERS)
    if not WEB_DATABASE_PATH.exists():
        save_websites(DEFAULT_WEBSITES)
    if not SOLUTION_DATABASE_PATH.exists():
        save_solutions(DEFAULT_SOLUTIONS)


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def normalize_server(raw: dict[str, Any]) -> dict[str, str]:
    return {
        'ip': str(raw.get('ip', '')).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': str(raw.get('password', '')).strip(),
        'snmp_community': str(raw.get('snmp_community', raw.get('community', 'public'))).strip(),
    }


def validate_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = [normalize_server(item) for item in servers]
    if not cleaned:
        raise ValueError('Database SSH phải có ít nhất 1 dòng máy.')
    for index, server in enumerate(cleaned, start=1):
        if not (server['ip'] and server['username'] and server['password'] and server['snmp_community']):
            raise ValueError(f'Dòng SSH {index} đang thiếu IP, username, password hoặc SNMP CommunityString.')
    return cleaned


def normalize_website(raw: Any) -> dict[str, str]:
    value = raw if isinstance(raw, str) else raw.get('domain', '')
    return {'domain': str(value).strip().replace(' ', '')}


def validate_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = [normalize_website(item) for item in websites]
    if not cleaned:
        raise ValueError('Database website phải có ít nhất 1 dòng domain.')
    for index, website in enumerate(cleaned, start=1):
        if not website['domain']:
            raise ValueError(f'Dòng website {index} đang thiếu domain.')
    return cleaned


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def normalize_solution(raw: dict[str, Any]) -> dict[str, Any]:
    endpoint = raw.get('endpoint', raw.get('target', ''))
    return {
        'name': str(raw.get('name', '')).strip(),
        'endpoint': str(endpoint).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': str(raw.get('password', '')).strip(),
        'ssh_username': str(raw.get('ssh_username', raw.get('ssh_user', ''))).strip(),
        'ssh_password': str(raw.get('ssh_password', raw.get('ssh_pass', ''))).strip(),
        'checkservice': to_bool(raw.get('checkservice', False)),
        'snmp_enabled': to_bool(raw.get('snmp_enabled', raw.get('use_snmp', True))),
        'snmp_port': int(str(raw.get('snmp_port', raw.get('port', 161)) or '161')),
        'snmp_version': str(raw.get('snmp_version', raw.get('version', '2c'))).strip().lower() or '2c',
        'snmp_community': str(raw.get('snmp_community', raw.get('community', 'public'))).strip() or 'public',
        'snmp_timeout': int(str(raw.get('snmp_timeout', SNMP_DEFAULT_TIMEOUT)) or str(SNMP_DEFAULT_TIMEOUT)),
        'snmp_retries': int(str(raw.get('snmp_retries', SNMP_DEFAULT_RETRIES)) or str(SNMP_DEFAULT_RETRIES)),
    }


def validate_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = [normalize_solution(item) for item in solutions]
    if not cleaned:
        raise ValueError('Database giải pháp phải có ít nhất 1 dòng.')
    for index, solution in enumerate(cleaned, start=1):
        if not solution['name'] or not solution['endpoint']:
            raise ValueError(f'Dòng giải pháp {index} đang thiếu tên hoặc endpoint.')
        if solution.get('snmp_enabled') and not solution.get('snmp_community'):
            raise ValueError(f'Dòng giải pháp {index} đã bật SNMP nhưng thiếu SNMP CommunityString.')
    return cleaned


def load_servers() -> list[dict[str, str]]:
    ensure_databases()
    try:
        data = read_json_file(SSH_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database SSH không đúng định dạng.')
        return validate_servers(data)
    except Exception:
        save_servers(DEFAULT_SERVERS)
        return [item.copy() for item in DEFAULT_SERVERS]


def save_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = validate_servers(servers)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SSH_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_websites() -> list[dict[str, str]]:
    ensure_databases()
    try:
        data = read_json_file(WEB_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database website không đúng định dạng.')
        return validate_websites(data)
    except Exception:
        save_websites(DEFAULT_WEBSITES)
        return [item.copy() for item in DEFAULT_WEBSITES]


def save_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = validate_websites(websites)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_solutions() -> list[dict[str, Any]]:
    ensure_databases()
    try:
        data = read_json_file(SOLUTION_DATABASE_PATH)
        if not isinstance(data, list):
            raise ValueError('Database giải pháp không đúng định dạng.')
        return validate_solutions(data)
    except Exception:
        save_solutions(DEFAULT_SOLUTIONS)
        return [dict(item) for item in DEFAULT_SOLUTIONS]


def save_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = validate_solutions(solutions)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SOLUTION_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


@app.get('/')
def index() -> str:
    ensure_databases()
    return render_template('index.html')


@app.get('/health')
def health() -> Any:
    return jsonify({'ok': True})


@app.get('/api/database')
def get_ssh_database() -> Any:
    return jsonify({'servers': load_servers()})


@app.post('/api/database')
def update_ssh_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        servers = save_servers(payload.get('servers', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database SSH thành công.', 'servers': servers})


@app.get('/api/web-database')
def get_web_database() -> Any:
    return jsonify({'websites': load_websites()})


@app.post('/api/web-database')
def update_web_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        websites = save_websites(payload.get('websites', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database website thành công.', 'websites': websites})


@app.get('/api/solution-database')
def get_solution_database() -> Any:
    return jsonify({'solutions': load_solutions()})


@app.post('/api/solution-database')
def update_solution_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        solutions = save_solutions(payload.get('solutions', []))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu database giải pháp thành công.', 'solutions': solutions})




def _parse_scan_index() -> int:
    payload = request.get_json(silent=True) or {}
    raw_index = payload.get('index')
    if raw_index is None:
        raise ValueError('Thiếu index của dòng cần quét.')
    try:
        index = int(raw_index)
    except (TypeError, ValueError):
        raise ValueError('Index cần là số nguyên hợp lệ.')
    if index < 0:
        raise ValueError('Index phải lớn hơn hoặc bằng 0.')
    return index


def _pick_item_by_index(items: list[dict[str, Any]], index: int, label: str) -> dict[str, Any]:
    if index >= len(items):
        raise ValueError(f'Không tìm thấy dòng {index + 1} trong database {label}.')
    return items[index]

@app.post('/api/scan')
def scan_servers() -> Any:
    servers = load_servers()
    results = run_parallel_checks(servers, check_one_server, max_workers=MAX_SSH_SCAN_WORKERS)
    success_count = sum(1 for item in results if item['is_success'])
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'success': success_count,
            'failed': len(results) - success_count,
        },
    })


@app.post('/api/web-scan')
def scan_websites() -> Any:
    websites = load_websites()
    results = run_parallel_checks(websites, check_one_website, max_workers=MAX_WEB_SCAN_WORKERS)
    success_count = sum(1 for item in results if item['is_success'])
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'success': success_count,
            'failed': len(results) - success_count,
        },
    })


@app.post('/api/solution-scan')
def scan_solutions() -> Any:
    solutions = load_solutions()
    results = run_parallel_checks(solutions, check_one_solution, max_workers=MAX_SOLUTION_SCAN_WORKERS)
    running_count = sum(1 for item in results if item['is_running'])
    login_success_count = sum(1 for item in results if item['is_success'])
    issue_count = len(results) - login_success_count
    running_services = sum(int(item.get('service_running_count', 0) or 0) for item in results)
    total_services = sum(int(item.get('service_total_count', 0) or 0) for item in results)
    return jsonify({
        'results': results,
        'summary': {
            'total': len(results),
            'running': running_count,
            'login_success': login_success_count,
            'issues': issue_count,
            'running_services': running_services,
            'total_services': total_services,
        },
    })


@app.post('/api/scan-one')
def scan_one_server_route() -> Any:
    try:
        index = _parse_scan_index()
        servers = load_servers()
        server = _pick_item_by_index(servers, index, 'SSH')
        _, result = check_one_server(index, server)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'Lỗi khi quét riêng server: {exc}'}), 500

    return jsonify({'index': index, 'result': result})


@app.post('/api/web-scan-one')
def scan_one_website_route() -> Any:
    try:
        index = _parse_scan_index()
        websites = load_websites()
        website = _pick_item_by_index(websites, index, 'website')
        _, result = check_one_website(index, website)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'Lỗi khi quét riêng website: {exc}'}), 500

    return jsonify({'index': index, 'result': result})


@app.post('/api/solution-scan-one')
def scan_one_solution_route() -> Any:
    try:
        index = _parse_scan_index()
        solutions = load_solutions()
        solution = _pick_item_by_index(solutions, index, 'giải pháp')
        _, result = check_one_solution(index, solution)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        return jsonify({'error': f'Lỗi khi quét riêng giải pháp: {exc}'}), 500

    return jsonify({'index': index, 'result': result})


def run_parallel_checks(
    items: list[dict[str, Any]],
    checker: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any] | None] = [None] * len(items)
    if max_workers is None:
        max_workers = min(16, max(4, len(items))) or 1
    else:
        max_workers = max(1, min(int(max_workers), max(1, len(items))))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(checker, index, item): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            src_item = items[index]
            try:
                _, result = future.result()
            except Exception as exc:
                result = {
                    'name': src_item.get('name') or src_item.get('ip') or src_item.get('domain') or f'item-{index + 1}',
                    'status': 'Lỗi xử lý',
                    'is_success': False,
                    'error': str(exc),
                    'login_method': None,
                    'login_debug': [f'run_parallel_checks exception: {exc}'],
                }
            results[index] = result

    return [item for item in results if item is not None]


def ssh_exec_command(host: str, username: str, password: str, command: str, timeout: float = SSH_COMMAND_TIMEOUT) -> tuple[str, str, int]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=22,
            username=username,
            password=password,
            timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        _ = stdin
        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()
        return stdout_text, stderr_text, exit_code
    finally:
        client.close()


def remote_snmp_get_values_via_ssh(
    proxy_host: str,
    proxy_username: str,
    proxy_password: str,
    target_host: str,
    community: str,
    port: int,
    oid_list: list[str],
) -> dict[str, str]:
    if not oid_list:
        return {}

    target_arg = shlex.quote(f'{target_host}:{int(port)}')
    community_arg = shlex.quote(str(community))
    oid_args = ' '.join(shlex.quote(str(oid)) for oid in oid_list)
    command = (
        'sh -lc ' + shlex.quote(
            f'snmpget -v2c -c {community_arg} -On -Oqv -t {SNMP_DEFAULT_TIMEOUT} -r {SNMP_DEFAULT_RETRIES} {target_arg} {oid_args}'
        )
    )

    stdout_text, stderr_text, exit_code = ssh_exec_command(proxy_host, proxy_username, proxy_password, command)
    if exit_code != 0:
        raise RuntimeError(stderr_text.strip() or f'snmpget lỗi trên {proxy_host}')

    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if len(lines) != len(oid_list):
        raise RuntimeError(f'snmpget trả về {len(lines)} dòng, cần {len(oid_list)} dòng')
    return {oid: value for oid, value in zip(oid_list, lines)}


def fetch_metrics_via_proxy_snmp(target_host: str, community: str, port: int) -> tuple[dict[str, float], str, str]:
    oid_list = [
        '1.3.6.1.4.1.2021.11.11.0',
        '1.3.6.1.4.1.2021.4.5.0',
        '1.3.6.1.4.1.2021.4.6.0',
        '1.3.6.1.4.1.2021.4.15.0',
        '1.3.6.1.4.1.2021.4.14.0',
        '1.3.6.1.2.1.25.2.3.1.5.41',
        '1.3.6.1.2.1.25.2.3.1.6.41',
    ]
    errors: list[str] = []
    for hop in PROXY_SNMP_HOPS:
        try:
            oid_values = remote_snmp_get_values_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                oid_list=oid_list,
            )
            cpu_idle = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.11.11.0'])
            mem_total_real = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.5.0'])
            mem_avail_real = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.6.0'])
            mem_cached = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.15.0'])
            mem_buffer = parse_snmp_numeric(oid_values['1.3.6.1.4.1.2021.4.14.0'])
            storage_size = parse_snmp_numeric(oid_values['1.3.6.1.2.1.25.2.3.1.5.41'])
            storage_used = parse_snmp_numeric(oid_values['1.3.6.1.2.1.25.2.3.1.6.41'])
            if mem_total_real <= 0:
                raise RuntimeError('memTotalReal <= 0')
            if storage_size <= 0:
                raise RuntimeError('hrStorageSize <= 0')
            cpu_percent = max(0.0, min(100.0, 100.0 - cpu_idle))
            ram_used = mem_total_real - mem_avail_real - mem_cached - mem_buffer
            ram_percent = max(0.0, min(100.0, (ram_used / mem_total_real) * 100.0))
            storage_percent = max(0.0, min(100.0, (storage_used / storage_size) * 100.0))
            return ({'cpu': cpu_percent, 'ram': ram_percent, 'storage': storage_percent}, hop['label'], f"{hop['label']} -> {target_host}:{port}")
        except Exception as exc:
            errors.append(f"{hop['label']}: {exc}")
    raise RuntimeError('; '.join(errors) or 'proxy snmp failed')


def log_server_metric_source(ip: str, source: str, message: str, metrics: dict[str, float] | None = None) -> None:
    metric_text = ''
    if metrics:
        metric_text = ' | ' + ', '.join(
            f'{key.upper()}={value:.1f}%'
            for key, value in metrics.items()
        )
    print(f'[SERVER_SCAN] {ip} | {source} | {message}{metric_text}', flush=True)


def log_solution_metric_source(name: str, source: str, message: str, metrics: dict[str, str] | None = None) -> None:
    metric_text = ''
    if metrics:
        metric_text = ' | ' + ', '.join(f'{k}={v}' for k, v in metrics.items())
    print(f'[SOLUTION_SCAN] {name} | {source} | {message}{metric_text}', flush=True)


def parse_snmp_numeric(value: Any) -> float:
    if value is None:
        raise ValueError('SNMP value is None')
    raw = str(value).strip().replace(',', '.')
    match = re.search(r'-?\d+(?:\.\d+)?', raw)
    if not match:
        raise ValueError(f'Không parse được giá trị SNMP: {raw}')
    return float(match.group(0))


def snmp_supported() -> bool:
    return all(item is not None for item in (
        SnmpEngine, CommunityData, ContextData, ObjectIdentity, ObjectType, UdpTransportTarget, getCmd, nextCmd
    ))


def snmp_get_values(host: str, community: str, port: int, timeout: int, retries: int, oid_list: list[str]) -> dict[str, Any]:
    if not snmp_supported():
        return {}
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port)), timeout=float(timeout), retries=int(retries)),
        ContextData(),
        *[ObjectType(ObjectIdentity(oid)) for oid in oid_list],
    )
    error_indication, error_status, error_index, var_binds = next(iterator)
    if error_indication or error_status:
        return {}
    values: dict[str, Any] = {}
    for var_bind in var_binds:
        values[str(var_bind[0])] = var_bind[1]
    return values


def snmp_walk_values(host: str, community: str, port: int, timeout: int, retries: int, base_oid: str) -> list[tuple[str, Any]]:
    if not snmp_supported():
        return []
    results: list[tuple[str, Any]] = []
    for error_indication, error_status, error_index, var_binds in nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, int(port)), timeout=float(timeout), retries=int(retries)),
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    ):
        if error_indication or error_status:
            return []
        for var_bind in var_binds:
            results.append((str(var_bind[0]), var_bind[1]))
    return results


def fetch_server_metrics_snmp(server: dict[str, Any]) -> tuple[dict[str, float], str, str]:
    ip = server['ip']
    community = server.get('snmp_community') or 'public'
    return fetch_metrics_via_proxy_snmp(ip, community, 161)


def fetch_server_metrics_ssh(server: dict[str, Any]) -> dict[str, float]:
    ip = server['ip']
    username = server['username']
    password = server['password']

    command = r"""sh -lc '
LC_ALL=C top -bn1 | grep -m1 "%Cpu\|Cpu(s)" ;
LC_ALL=C top -bn1 | grep -m1 "MiB Mem\|KiB Mem\|GiB Mem" ;
df -P / | awk "NR==2 {print \$5}"
'"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            port=22,
            username=username,
            password=password,
            timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(command, timeout=SSH_COMMAND_TIMEOUT)
        _ = stdin

        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0 and not stdout_text.strip():
            raise RuntimeError(stderr_text.strip() or 'Lệnh SSH lấy metrics trả về lỗi.')

        lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
        if len(lines) < 3:
            raise RuntimeError(f'Output SSH không đủ dữ liệu: {stdout_text.strip()}')

        cpu_line = lines[0]
        mem_line = lines[1]
        storage_line = lines[2]

        cpu_idle_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*id', cpu_line, re.IGNORECASE)
        if not cpu_idle_match:
            raise RuntimeError(f'Không tìm được CPU idle từ top: {cpu_line}')
        cpu_idle = parse_float_loose(cpu_idle_match.group(1))
        cpu_value = max(0.0, min(100.0, 100.0 - cpu_idle))

        mem_numbers = re.findall(r'([0-9]+(?:[.,][0-9]+)?)', mem_line)
        if len(mem_numbers) < 3:
            raise RuntimeError(f'Không parse được dòng RAM từ top: {mem_line}')

        mem_total = parse_float_loose(mem_numbers[0])

        used_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s+used', mem_line, re.IGNORECASE)
        if used_match:
            mem_used = parse_float_loose(used_match.group(1))
        else:
            mem_used = parse_float_loose(mem_numbers[2])

        if mem_total <= 0:
            raise RuntimeError(f'Tổng RAM không hợp lệ: {mem_total}')
        ram_value = max(0.0, min(100.0, (mem_used / mem_total) * 100.0))

        storage_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', storage_line)
        if storage_match:
            storage_value = parse_float_loose(storage_match.group(1))
        else:
            storage_value = parse_float_loose(storage_line.replace('%', '').strip())
        storage_value = max(0.0, min(100.0, storage_value))

        metrics = {
            'cpu': cpu_value,
            'ram': ram_value,
            'storage': storage_value,
        }

        log_server_metric_source(ip, 'SSH_RAW', f'CPU_LINE={cpu_line} | MEM_LINE={mem_line} | STORAGE_LINE={storage_line}')
        return metrics
    finally:
        client.close()


def fetch_solution_metrics_ssh_priority(solution: dict[str, Any]) -> tuple[dict[str, str], str]:
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint'

    ssh_username = solution.get('ssh_username', '')
    ssh_password = solution.get('ssh_password', '')
    if not ssh_username or not ssh_password:
        return {}, 'missing ssh credentials'

    command = r"""sh -lc '
LC_ALL=C top -bn1 | grep -m1 "%Cpu\|Cpu(s)" ;
LC_ALL=C top -bn1 | grep -m1 "MiB Mem\|KiB Mem\|GiB Mem" ;
df -P / | awk "NR==2 {print \$5}"
'"""

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=22,
            username=ssh_username,
            password=ssh_password,
            timeout=SSH_CONNECT_TIMEOUT,
            auth_timeout=SSH_CONNECT_TIMEOUT,
            banner_timeout=SSH_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )

        stdin, stdout, stderr = client.exec_command(command, timeout=SSH_COMMAND_TIMEOUT)
        _ = stdin

        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0 and not stdout_text.strip():
            return {}, stderr_text.strip() or 'ssh metrics command failed'

        lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
        if len(lines) < 3:
            return {}, f'not enough ssh output: {stdout_text.strip()}'

        cpu_line, mem_line, storage_line = lines[0], lines[1], lines[2]

        cpu_idle_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*id', cpu_line, re.IGNORECASE)
        if not cpu_idle_match:
            return {}, f'cannot parse cpu line: {cpu_line}'
        cpu_idle = parse_float_loose(cpu_idle_match.group(1))
        cpu_percent = max(0.0, min(100.0, 100.0 - cpu_idle))

        mem_numbers = re.findall(r'([0-9]+(?:[.,][0-9]+)?)', mem_line)
        if len(mem_numbers) < 3:
            return {}, f'cannot parse mem line: {mem_line}'

        mem_total = parse_float_loose(mem_numbers[0])

        used_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s+used', mem_line, re.IGNORECASE)
        if used_match:
            mem_used = parse_float_loose(used_match.group(1))
        else:
            mem_used = parse_float_loose(mem_numbers[2])

        if mem_total <= 0:
            return {}, 'mem total <= 0'
        ram_percent = max(0.0, min(100.0, (mem_used / mem_total) * 100.0))

        storage_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', storage_line)
        storage_percent = parse_float_loose((storage_match.group(1) if storage_match else storage_line).replace('%', '').strip())
        storage_percent = max(0.0, min(100.0, storage_percent))

        metrics = {
            'cpu_percent': f'{cpu_percent:.1f}%',
            'ram_percent': f'{ram_percent:.1f}%',
            'storage_percent': f'{storage_percent:.1f}%',
        }
        return metrics, f'SSH metrics from {host}'
    except Exception as exc:
        return {}, str(exc)
    finally:
        client.close()


def check_one_server(index: int, server: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    ip = server['ip']
    username = server['username']

    snmp_error = ''
    ssh_error = ''

    try:
        snmp_metrics = fetch_server_metrics_snmp(server)
        log_server_metric_source(ip, 'SNMP', 'Lấy dữ liệu thành công', snmp_metrics)
        return index, {
            'ip': ip,
            'username': username,
            'metric_source': 'SNMP',
            'cpu_percent': f"{snmp_metrics['cpu']:.1f}%",
            'ram_percent': f"{snmp_metrics['ram']:.1f}%",
            'storage_percent': f"{snmp_metrics['storage']:.1f}%",
            'status': f'{snmp_source} thành công',
            'is_success': True,
            'error': '',
        }
    except Exception as exc:
        snmp_error = str(exc)
        log_server_metric_source(ip, 'PROXY_SNMP', f'Lỗi: {snmp_error}')

    try:
        ssh_metrics = fetch_server_metrics_ssh(server)
        log_server_metric_source(ip, 'SSH', 'Fallback thành công', ssh_metrics)
        return index, {
            'ip': ip,
            'username': username,
            'metric_source': 'SSH',
            'cpu_percent': f"{ssh_metrics['cpu']:.1f}%",
            'ram_percent': f"{ssh_metrics['ram']:.1f}%",
            'storage_percent': f"{ssh_metrics['storage']:.1f}%",
            'status': 'Proxy SNMP lỗi, fallback SSH thành công',
            'is_success': True,
            'error': f'SNMP lỗi: {snmp_error}',
        }
    except Exception as exc:
        ssh_error = str(exc)
        log_server_metric_source(ip, 'SSH', f'Fallback lỗi: {ssh_error}')

    return index, {
        'ip': ip,
        'username': username,
        'metric_source': 'NONE',
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'status': 'Proxy SNMP và SSH đều lỗi',
        'is_success': False,
        'error': f'Proxy SNMP lỗi: {snmp_error}; SSH lỗi: {ssh_error}',
    }


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    domain = normalize_website(website)['domain']
    candidate_urls = build_candidate_urls(domain)
    errors: list[str] = []

    for url in candidate_urls:
        try:
            response = get_thread_session().get(
                url,
                timeout=(WEBSITE_CONNECT_TIMEOUT, WEBSITE_READ_TIMEOUT),
                allow_redirects=True,
                stream=True,
            )
            status_code = response.status_code
            reason = (response.reason or '').strip()
            checked_url = response.url or url
            response.close()

            status_text = f'{status_code} {reason}'.strip()
            return index, {
                'domain': domain,
                'checked_url': checked_url,
                'http_status': status_text,
                'status': '200 OK' if status_code == 200 else status_text,
                'is_success': status_code == 200,
                'error': '' if status_code == 200 else status_text,
            }
        except RequestException as exc:
            errors.append(describe_request_error(exc))

    return index, {
        'domain': domain,
        'checked_url': candidate_urls[-1],
        'http_status': 'N/A',
        'status': errors[-1] if errors else 'Không truy cập được',
        'is_success': False,
        'error': '; '.join(errors),
    }


def parse_solution_host(endpoint: str) -> str:
    cleaned = (endpoint or '').strip()
    if not cleaned:
        return ''
    if cleaned.startswith(('http://', 'https://')):
        return urlparse(cleaned).hostname or ''
    if '/' in cleaned:
        cleaned = cleaned.split('/', 1)[0]
    if ':' in cleaned:
        cleaned = cleaned.split(':', 1)[0]
    return cleaned


def format_percent(value: float | int | None) -> str:
    if value is None:
        return 'N/A'
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return 'N/A'


def fetch_solution_metrics_snmp(solution: dict[str, Any]) -> tuple[dict[str, str], str, str]:
    if not solution.get('snmp_enabled', True):
        return {}, 'SNMP disabled', 'NONE'

    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint', 'NONE'

    community = solution.get('snmp_community') or 'public'
    port = int(solution.get('snmp_port', 161) or 161)

    try:
        raw_metrics, source_label, note = fetch_metrics_via_proxy_snmp(host, community, port)
        return {
            'cpu_percent': format_percent(raw_metrics['cpu']),
            'ram_percent': format_percent(raw_metrics['ram']),
            'storage_percent': format_percent(raw_metrics['storage']),
        }, note, source_label
    except Exception as exc:
        return {}, str(exc), 'NONE'


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = normalize_solution(solution)
    name = cleaned['name']
    endpoint = cleaned['endpoint']
    username = cleaned['username']
    password = cleaned['password']
    checkservice = cleaned['checkservice']

    snmp_metrics, snmp_note, snmp_source = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        log_solution_metric_source(name, snmp_source, snmp_note, snmp_metrics)

        candidate_urls = build_solution_urls(endpoint)
        web_result = None
        for url in candidate_urls:
            web_result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
            if web_result.get('is_success') or web_result.get('is_running'):
                break

        if web_result is None:
            web_result = {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': endpoint,
                'http_status': 'N/A',
                'login_status': 'Chưa kiểm tra',
                'running_status': 'Đang chạy',
                'status': 'Đang chạy',
                'note': snmp_note,
                'is_success': False,
                'is_running': True,
                'checkservice': checkservice,
                'service_summary': 'Không kiểm tra',
                'services': [],
                'service_running_count': 0,
                'service_total_count': 0,
            }

        web_result.update(snmp_metrics)
        web_result['metric_source'] = snmp_source
        web_result['note'] = f"{web_result.get('note', '')} | {snmp_note}".strip(' |')
        return index, web_result

    log_solution_metric_source(name, 'PROXY_SNMP', snmp_note or 'Proxy SNMP failed')

    ssh_metrics, ssh_note = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        log_solution_metric_source(name, 'SSH', ssh_note, ssh_metrics)

        candidate_urls = build_solution_urls(endpoint)
        web_result = None
        for url in candidate_urls:
            web_result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
            if web_result.get('is_success') or web_result.get('is_running'):
                break

        if web_result is None:
            web_result = {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': endpoint,
                'http_status': 'N/A',
                'login_status': 'Chưa kiểm tra',
                'running_status': 'Đang chạy',
                'status': 'Đang chạy',
                'note': ssh_note,
                'is_success': False,
                'is_running': True,
                'checkservice': checkservice,
                'service_summary': 'Không kiểm tra',
                'services': [],
                'service_running_count': 0,
                'service_total_count': 0,
            }

        web_result.update(ssh_metrics)
        web_result['metric_source'] = 'SSH'
        web_result['note'] = f"{web_result.get('note', '')} | {ssh_note}".strip(' |')
        return index, web_result

    log_solution_metric_source(name, 'SSH', ssh_note or 'SSH failed')

    candidate_urls = build_solution_urls(endpoint)
    best_result = None

    for url in candidate_urls:
        result = attempt_solution_login(name, endpoint, username, password, url, checkservice, cleaned)
        if best_result is None or solution_result_score(result) > solution_result_score(best_result):
            best_result = result
        if result['is_success']:
            break

    if best_result is None:
        best_result = {
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': candidate_urls[-1] if candidate_urls else endpoint,
            'http_status': 'N/A',
            'login_status': 'Không truy cập được',
            'running_status': 'Không chạy',
            'status': 'Không truy cập được',
            'note': f'Proxy SNMP failed: {snmp_note}; SSH failed: {ssh_note}; web failed',
            'is_success': False,
            'is_running': False,
            'checkservice': checkservice,
            'service_summary': 'Không kiểm tra',
            'services': [],
            'service_running_count': 0,
            'service_total_count': 0,
            'cpu_percent': 'N/A',
            'ram_percent': 'N/A',
            'storage_percent': 'N/A',
        }

    best_result['metric_source'] = 'WEB'
    best_result['note'] = f"SNMP failed: {snmp_note}; SSH failed: {ssh_note}; {best_result.get('note', '')}".strip('; ')
    log_solution_metric_source(
        name,
        'WEB',
        best_result.get('note', 'web metrics/login result'),
        {
            'cpu_percent': best_result.get('cpu_percent', 'N/A'),
            'ram_percent': best_result.get('ram_percent', 'N/A'),
            'storage_percent': best_result.get('storage_percent', 'N/A'),
        },
    )
    return index, best_result


def build_candidate_urls(domain: str) -> list[str]:
    cleaned = domain.strip()
    if cleaned.startswith(('http://', 'https://')):
        return [cleaned]
    return [f'https://{cleaned}', f'http://{cleaned}']


def build_solution_urls(endpoint: str) -> list[str]:
    cleaned = endpoint.strip().replace(' ', '')
    if cleaned.startswith(('http://', 'https://')):
        return [cleaned]
    return [
        f'https://{cleaned}',
        f'https://{cleaned}:8443',
        f'https://{cleaned}:9443',
        f'http://{cleaned}',
        f'http://{cleaned}:8080',
    ]


def describe_request_error(exc: RequestException) -> str:
    text = str(exc).strip()
    return text or exc.__class__.__name__


def build_session() -> Session:
    session = requests.Session()
    session.verify = False
    session.headers.update(DEFAULT_HEADERS)
    return session



def get_thread_session() -> Session:
    session = getattr(_thread_local, 'session', None)
    if session is None:
        session = requests.Session()
        session.verify = False
        session.headers.update(DEFAULT_HEADERS)
        adapter = requests.adapters.HTTPAdapter(pool_connections=MAX_WEB_SCAN_WORKERS, pool_maxsize=MAX_WEB_SCAN_WORKERS)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        _thread_local.session = session
    return session


def score_metric_html(html: str) -> int:
    if not html:
        return 0
    score = 0
    for marker in ('cpuUsageText', 'memoryUsageText', 'ramUsageText', 'diskUsageText', 'storageUsageText'):
        if marker in html:
            score += 1
    return score


def fetch_best_solution_html(session: Session, final_url: str, fallback_url: str) -> str:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            candidates.append(url)

    add(final_url)
    add(fallback_url)

    parsed = urlparse(final_url or fallback_url)
    if parsed.scheme and parsed.netloc:
        base = f'{parsed.scheme}://{parsed.netloc}'
        add(base)
        add(base + '/')
        add(base + '/dashboard')
        add(base + '/index')
        add(base + '/home')
        add(base + '/main')
        add(base + '/status')

    best_html = ''
    best_score = -1

    for url in candidates:
        try:
            resp = session.get(url, timeout=SOLUTION_HTTP_TIMEOUT, allow_redirects=True)
        except RequestException:
            continue

        content_type = (resp.headers.get('Content-Type') or '').lower()
        if 'html' not in content_type:
            continue

        html = resp.text or ''
        current_score = score_metric_html(html)

        if current_score > best_score:
            best_score = current_score
            best_html = html

        if current_score >= 3:
            return html

    return best_html


def should_try_browser_metric_fallback(metrics: dict[str, str]) -> bool:
    return metrics.get('cpu_percent') == 'N/A' or metrics.get('ram_percent') == 'N/A'


def score_metric_values(metrics: dict[str, str]) -> int:
    score = 0
    for key in ('cpu_percent', 'ram_percent', 'storage_percent'):
        if metrics.get(key) not in (None, '', 'N/A'):
            score += 1
    return score


def merge_metric_maps(primary: dict[str, str], secondary: dict[str, str]) -> dict[str, str]:
    merged = dict(primary)
    for key, value in (secondary or {}).items():
        if merged.get(key) in (None, '', 'N/A') and value not in (None, '', 'N/A'):
            merged[key] = value
    return merged


def collect_solution_candidate_urls(html: str, final_url: str, fallback_url: str) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(url: str) -> None:
        if url and url not in seen:
            seen.add(url)
            candidates.append(url)

    add(final_url)
    add(fallback_url)

    parsed = urlparse(final_url or fallback_url)
    if parsed.scheme and parsed.netloc:
        base = f'{parsed.scheme}://{parsed.netloc}'
        for suffix in ('', '/', '/dashboard', '/index', '/home', '/main', '/status', '/system', '/monitor', '/overview'):
            add(base + suffix)

    soup = BeautifulSoup(html or '', 'html.parser')
    for tag_name, attr_name in (('a', 'href'), ('iframe', 'src'), ('frame', 'src')):
        for tag in soup.find_all(tag_name):
            target = (tag.get(attr_name) or '').strip()
            if not target or target.startswith(('javascript:', '#', 'mailto:')):
                continue
            lowered = target.lower()
            if any(word in lowered for word in ('dashboard', 'status', 'monitor', 'overview', 'system', 'home', 'main')):
                add(urljoin(final_url or fallback_url, target))

    return candidates


def fetch_best_solution_response(
    session: Session,
    html: str,
    final_url: str,
    fallback_url: str,
) -> Response | None:
    candidates = collect_solution_candidate_urls(html, final_url, fallback_url)
    best_response: Response | None = None
    best_score = -1

    for url in candidates:
        try:
            resp = session.get(url, timeout=SOLUTION_HTTP_TIMEOUT, allow_redirects=True)
        except RequestException:
            continue

        content_type = (resp.headers.get('Content-Type') or '').lower()
        if 'html' not in content_type:
            continue

        body = resp.text or ''
        score = score_metric_html(body)
        if looks_like_authenticated_html(body, resp.url or url):
            score += 3
        if 'engine-card' in body or 'status-badge' in body:
            score += 1

        if score > best_score:
            best_score = score
            best_response = resp

        if score >= 4:
            return resp

    return best_response


def looks_like_authenticated_html(text: str, url: str = '') -> bool:
    body = text or ''
    lowered = body.lower()
    url_lower = (url or '').lower()

    if any(marker in body for marker in ('cpuUsageText', 'memoryUsageText', 'ramUsageText', 'diskUsageText', 'storageUsageText')):
        return True
    if 'system information :: status' in lowered:
        return True
    if '/default/system/status' in url_lower:
        return True
    if 'engine-card' in body or 'status-badge' in body:
        return True
    if any(word in lowered for word in ('logout', 'sign out', 'dashboard', 'overview', 'welcome')) and not PASSWORD_INPUT_RE.search(body):
        return True
    if extract_services(body):
        return True
    if score_metric_values(extract_solution_metrics(body)) > 0:
        return True
    return False


def fetch_rendered_solution_metrics(
    session: Session,
    html: str,
    final_url: str,
    fallback_url: str,
) -> tuple[dict[str, str], str]:
    if sync_playwright is None:
        return {}, ''

    candidates = collect_solution_candidate_urls(html, final_url, fallback_url)
    if not candidates:
        return {}, ''

    best_metrics: dict[str, str] = {}
    best_html = ''
    best_score = -1

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            cookie_urls: list[str] = []
            cookie_seen: set[str] = set()
            for url in candidates:
                parsed = urlparse(url)
                if not (parsed.scheme and parsed.netloc):
                    continue
                base = f'{parsed.scheme}://{parsed.netloc}'
                if base not in cookie_seen:
                    cookie_seen.add(base)
                    cookie_urls.append(base)

            cookie_payloads = []
            for cookie in session.cookies:
                for base_url in cookie_urls:
                    cookie_payloads.append({
                        'name': cookie.name,
                        'value': cookie.value,
                        'url': base_url,
                        'path': cookie.path or '/',
                    })
            if cookie_payloads:
                context.add_cookies(cookie_payloads)

            for url in candidates:
                page = context.new_page()
                try:
                    page.goto(url, wait_until='domcontentloaded', timeout=15000)
                    page.wait_for_timeout(3000)

                    page_metrics_raw = page.evaluate(
                        """() => {
                            const read = (id) => {
                                const el = document.getElementById(id);
                                if (!el) return '';
                                return (el.innerText || el.textContent || '').trim();
                            };
                            return {
                                cpu_percent: read('cpuUsageText'),
                                ram_percent: read('memoryUsageText') || read('ramUsageText'),
                                storage_percent: read('diskUsageText') || read('storageUsageText') || read('diskUsageTextWrapper')
                            };
                        }"""
                    )
                    page_html = page.content() or ''
                    page_metrics = {
                        'cpu_percent': normalize_percent_text((page_metrics_raw or {}).get('cpu_percent', '')),
                        'ram_percent': normalize_percent_text((page_metrics_raw or {}).get('ram_percent', '')),
                        'storage_percent': normalize_percent_text((page_metrics_raw or {}).get('storage_percent', '')),
                    }
                    page_metrics = merge_metric_maps(page_metrics, extract_solution_metrics(page_html))

                    current_score = score_metric_values(page_metrics)
                    if current_score > best_score:
                        best_score = current_score
                        best_metrics = page_metrics
                        best_html = page_html

                    for frame in page.frames:
                        if frame == page.main_frame:
                            continue
                        try:
                            frame_html = frame.content() or ''
                        except Exception:
                            continue
                        frame_metrics = extract_solution_metrics(frame_html)
                        try:
                            frame_metrics_raw = frame.evaluate(
                                """() => {
                                    const read = (id) => {
                                        const el = document.getElementById(id);
                                        if (!el) return '';
                                        return (el.innerText || el.textContent || '').trim();
                                    };
                                    return {
                                        cpu_percent: read('cpuUsageText'),
                                        ram_percent: read('memoryUsageText') || read('ramUsageText'),
                                        storage_percent: read('diskUsageText') || read('storageUsageText') || read('diskUsageTextWrapper')
                                    };
                                }"""
                            )
                            frame_metrics = merge_metric_maps(frame_metrics, {
                                'cpu_percent': normalize_percent_text((frame_metrics_raw or {}).get('cpu_percent', '')),
                                'ram_percent': normalize_percent_text((frame_metrics_raw or {}).get('ram_percent', '')),
                                'storage_percent': normalize_percent_text((frame_metrics_raw or {}).get('storage_percent', '')),
                            })
                        except Exception:
                            pass

                        frame_score = score_metric_values(frame_metrics)
                        if frame_score > best_score:
                            best_score = frame_score
                            best_metrics = frame_metrics
                            best_html = frame_html
                except PlaywrightTimeoutError:
                    pass
                except Exception:
                    pass
                finally:
                    page.close()

            browser.close()
    except Exception:
        return {}, ''

    return best_metrics, best_html


def attempt_browser_solution_login(
    name: str,
    endpoint: str,
    username: str,
    password: str,
    url: str,
    checkservice: bool,
    debug_steps: list[str] | None = None,
) -> dict[str, Any] | None:
    if sync_playwright is None:
        append_login_debug(debug_steps, 'BROWSER', 'Bỏ qua browser fallback vì Playwright chưa có.')
        return None

    user_selectors = [
        'input[name*=user i]', 'input[id*=user i]', 'input[name*=login i]', 'input[id*=login i]',
        'input[name*=email i]', 'input[id*=email i]', 'input[type=email]', 'input[type=text]'
    ]
    pass_selectors = [
        'input[type=password]', 'input[name*=pass i]', 'input[id*=pass i]', 'input[name*=pwd i]', 'input[id*=pwd i]'
    ]
    submit_selectors = [
        'button[type=submit]', 'input[type=submit]', 'button[name*=login i]', 'button[id*=login i]',
        'button:has-text("Login")', 'button:has-text("Đăng nhập")', 'text=/login|đăng nhập/i'
    ]

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            append_login_debug(debug_steps, 'BROWSER', 'Mở trang bằng Playwright.', url=url)
            page.goto(url, wait_until='domcontentloaded', timeout=15000)
            page.wait_for_timeout(1500)

            user_locator = None
            for selector in user_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    user_locator = locator.first
                    break

            pass_locator = None
            for selector in pass_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    pass_locator = locator.first
                    break

            append_login_debug(debug_steps, 'BROWSER', 'Kết quả dò selector.', found_user=user_locator is not None, found_password=pass_locator is not None)
            if user_locator is None or pass_locator is None:
                html = page.content() or ''
                if looks_like_authenticated_html(html, page.url or url):
                    metrics = extract_solution_metrics(html)
                    services = extract_services(html) if checkservice else []
                    browser.close()
                    return {
                        'name': name, 'endpoint': endpoint, 'username': username, 'checked_url': page.url or url,
                        'http_status': '200 OK', 'login_status': 'Đăng nhập thành công', 'running_status': 'Đang chạy',
                        'status': 'Đang chạy', 'note': 'Trang đã ở trạng thái authenticated.', 'is_success': True, 'is_running': True,
                        'checkservice': checkservice, 'service_summary': summarize_services(services) if checkservice else 'Không kiểm tra',
                        'services': services, 'service_running_count': sum(1 for item in services if item.get('status','').strip().lower() == 'running'),
                        'service_total_count': len(services), **metrics
                    }
                browser.close()
                return None

            append_login_debug(debug_steps, 'BROWSER', 'Điền username/password và submit form.')
            user_locator.fill(username, timeout=5000)
            pass_locator.fill(password, timeout=5000)

            submitted = False
            for selector in submit_selectors:
                locator = page.locator(selector)
                if locator.count() > 0:
                    locator.first.click(timeout=3000)
                    submitted = True
                    break
            if not submitted:
                pass_locator.press('Enter')

            try:
                page.wait_for_load_state('networkidle', timeout=7000)
            except Exception:
                page.wait_for_timeout(3000)

            html = page.content() or ''
            final_url = page.url or url
            services = extract_services(html) if checkservice else []
            metrics = extract_solution_metrics(html)
            success = looks_like_authenticated_html(html, final_url) or (not PASSWORD_INPUT_RE.search(html) and ('login' not in html.lower() and 'đăng nhập' not in html.lower()))
            if checkservice and services:
                success = True
            if score_metric_values(metrics) > 0:
                success = True

            result = {
                'name': name, 'endpoint': endpoint, 'username': username, 'checked_url': final_url,
                'http_status': '200 OK', 'login_status': 'Đăng nhập thành công' if success else 'Không đăng nhập được',
                'running_status': 'Đang chạy', 'status': 'Đang chạy',
                'note': 'Đăng nhập qua trình duyệt headless.' if success else 'Headless browser chưa đăng nhập được.',
                'is_success': success, 'is_running': True, 'checkservice': checkservice,
                'service_summary': summarize_services(services) if checkservice else 'Không kiểm tra',
                'services': services, 'service_running_count': sum(1 for item in services if item.get('status','').strip().lower() == 'running'),
                'service_total_count': len(services), **metrics
            }
            browser.close()
            return result
    except Exception as exc:
        append_login_debug(debug_steps, 'BROWSER', 'Browser fallback lỗi.', error=str(exc))
        return None


def attempt_solution_login(
    name: str,
    endpoint: str,
    username: str,
    password: str,
    url: str,
    checkservice: bool,
    solution: dict[str, Any],
) -> dict[str, Any]:
    session = build_session()
    debug_steps: list[str] = []
    append_login_debug(debug_steps, 'START', 'Bắt đầu login solution.', name=name, endpoint=endpoint, url=url)

    try:
        response = session.get(url, timeout=SOLUTION_HTTP_TIMEOUT, allow_redirects=True)
        append_login_debug(debug_steps, 'HTTP', 'GET trang login thành công.', status=response.status_code, final_url=response.url or url, content_type=response.headers.get('Content-Type'))
    except RequestException as exc:
        append_login_debug(debug_steps, 'HTTP', 'GET trang login lỗi.', error=describe_request_error(exc))
        return attach_login_debug({
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': url,
            'http_status': 'N/A',
            'login_status': 'Không truy cập được',
            'running_status': 'Không chạy',
            'status': 'Không truy cập được',
            'note': describe_request_error(exc),
            'is_success': False,
            'is_running': False,
            'checkservice': checkservice,
            'service_summary': 'N/A',
            'services': [],
            'cpu_percent': 'N/A',
            'ram_percent': 'N/A',
            'storage_percent': 'N/A',
            'service_running_count': 0,
            'service_total_count': 0,
        }, debug_steps)

    initial_status = response.status_code
    initial_status_text = format_status(response)
    checked_url = response.url or url
    is_running = initial_status < 500
    running_status = 'Đang chạy' if is_running else f'Lỗi dịch vụ {initial_status}'
    content_type = (response.headers.get('Content-Type') or '').lower()

    if initial_status in (401, 403) or 'www-authenticate' in response.headers:
        append_login_debug(debug_steps, 'BASIC_AUTH', 'Trang yêu cầu HTTP auth, thử Basic Auth.', status=initial_status)
        auth_result = try_basic_auth(session, url, username, password)
        if auth_result is not None:
            append_login_debug(debug_steps, 'BASIC_AUTH', 'Basic Auth có phản hồi.', status=auth_result.status_code, final_url=auth_result.url or url)
            return attach_login_debug(finalize_solution_result(
                name=name,
                endpoint=endpoint,
                username=username,
                fallback_url=checked_url,
                fallback_status=initial_status_text,
                fallback_running=is_running,
                response=auth_result,
                success_note='Đăng nhập thành công bằng HTTP Basic Auth.',
                failure_note='Trang yêu cầu xác thực HTTP nhưng tài khoản chưa đăng nhập được.',
                checkservice=checkservice,
                session=session,
            ), debug_steps)

    if 'html' in content_type:
        append_login_debug(debug_steps, 'JSON', 'Kiểm tra chiến lược AJAX/JSON login.')
        json_response = attempt_json_login(session, checked_url, response.text or '', username, password, debug_steps=debug_steps)
        if json_response is not None:
            append_login_debug(debug_steps, 'JSON', 'JSON login trả về response hợp lệ.', status=json_response.status_code, final_url=json_response.url or checked_url)
            return attach_login_debug(finalize_solution_result(
                name=name,
                endpoint=endpoint,
                username=username,
                fallback_url=checked_url,
                fallback_status=initial_status_text,
                fallback_running=is_running,
                response=json_response,
                success_note='Đăng nhập AJAX/JSON thành công.',
                failure_note='Endpoint AJAX/JSON có phản hồi nhưng chưa đăng nhập được.',
                checkservice=checkservice,
                session=session,
            ), debug_steps)

        form_info = extract_login_form(response.text, checked_url)
        if form_info is not None:
            append_login_debug(debug_steps, 'FORM', 'Đã nhận diện form login.', action=form_info.get('action'), method=form_info.get('method'), username_field=form_info.get('username_field'), password_field=form_info.get('password_field'))
            try:
                submit_response = submit_login_form(session, form_info, checked_url, username, password, debug_steps=debug_steps)
            except RequestException as exc:
                append_login_debug(debug_steps, 'FORM', 'Submit form lỗi.', error=describe_request_error(exc))
                return attach_login_debug({
                    'name': name,
                    'endpoint': endpoint,
                    'username': username,
                    'checked_url': checked_url,
                    'http_status': initial_status_text,
                    'login_status': 'Không đăng nhập được',
                    'running_status': running_status,
                    'status': 'Đang chạy nhưng login lỗi',
                    'note': describe_request_error(exc),
                    'is_success': False,
                    'is_running': is_running,
                    'checkservice': checkservice,
                    'service_summary': 'N/A',
                    'services': [],
                    'cpu_percent': 'N/A',
                    'ram_percent': 'N/A',
                    'storage_percent': 'N/A',
                    'service_running_count': 0,
                    'service_total_count': 0,
                }, debug_steps)

            append_login_debug(debug_steps, 'FORM', 'Form submit có phản hồi.', status=submit_response.status_code, final_url=submit_response.url or form_info.get('action'))
            return attach_login_debug(finalize_solution_result(
                name=name,
                endpoint=endpoint,
                username=username,
                fallback_url=checked_url,
                fallback_status=initial_status_text,
                fallback_running=is_running,
                response=submit_response,
                success_note='Đăng nhập form thành công.',
                failure_note='Đăng nhập form chưa thành công hoặc hệ thống dùng xác thực đặc biệt.',
                checkservice=checkservice,
                session=session,
            ), debug_steps)

        if initial_status < 400:
            append_login_debug(debug_steps, 'BROWSER', 'Không thấy JSON/form chắc chắn, thử browser fallback.')
            browser_result = attempt_browser_solution_login(name, endpoint, username, password, checked_url, checkservice, debug_steps=debug_steps)
            if browser_result is not None:
                return attach_login_debug(browser_result, debug_steps)
            metrics = extract_solution_metrics(response.text or '')
            services = extract_services(response.text or '') if checkservice else []
            guessed_success = looks_like_authenticated_html(response.text or '', checked_url) or bool(services) or score_metric_values(metrics) > 0
            return attach_login_debug({
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': checked_url,
                'http_status': initial_status_text,
                'login_status': 'Đăng nhập thành công' if guessed_success else 'Không tìm thấy form đăng nhập',
                'running_status': running_status,
                'status': 'Đang chạy',
                'note': 'Suy luận từ nội dung trang phản hồi.' if guessed_success else 'Trang có phản hồi nhưng tool chưa nhận diện được form login.',
                'is_success': guessed_success,
                'is_running': is_running,
                'checkservice': checkservice,
                'service_summary': summarize_services(services) if checkservice else 'Không kiểm tra',
                'services': services,
                'cpu_percent': metrics.get('cpu_percent', 'N/A'),
                'ram_percent': metrics.get('ram_percent', 'N/A'),
                'storage_percent': metrics.get('storage_percent', 'N/A'),
                'service_running_count': sum(1 for item in services if item.get('status','').strip().lower() == 'running'),
                'service_total_count': len(services),
            }, debug_steps)

    append_login_debug(debug_steps, 'BROWSER', 'Thử browser fallback cuối cùng.')
    browser_result = attempt_browser_solution_login(name, endpoint, username, password, checked_url, checkservice, debug_steps=debug_steps)
    if browser_result is not None:
        return attach_login_debug(browser_result, debug_steps)

    append_login_debug(debug_steps, 'END', 'Kết thúc: chưa tìm được phương pháp login phù hợp.', checked_url=checked_url, status=initial_status_text)
    return attach_login_debug({
        'name': name,
        'endpoint': endpoint,
        'username': username,
        'checked_url': checked_url,
        'http_status': initial_status_text,
        'login_status': 'Không đăng nhập được',
        'running_status': running_status,
        'status': 'Đang chạy' if is_running else 'Không chạy',
        'note': 'Có phản hồi HTTP nhưng chưa tự động login được.',
        'login_method': 'unknown',
        'is_success': False,
        'is_running': is_running,
        'checkservice': checkservice,
        'service_summary': 'Không kiểm tra',
        'services': [],
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'service_running_count': 0,
        'service_total_count': 0,
    }, debug_steps)


def try_basic_auth(session: Session, url: str, username: str, password: str) -> Response | None:
    try:
        return session.get(
            url,
            timeout=SOLUTION_HTTP_TIMEOUT,
            allow_redirects=True,
            auth=HTTPBasicAuth(username, password),
        )
    except RequestException:
        return None


def finalize_solution_result(
    *,
    name: str,
    endpoint: str,
    username: str,
    fallback_url: str,
    fallback_status: str,
    fallback_running: bool,
    response: Response,
    success_note: str,
    failure_note: str,
    checkservice: bool,
    session: Session | None = None,
) -> dict[str, Any]:
    status_text = format_status(response)
    final_url = response.url or fallback_url
    final_running = response.status_code < 500
    is_running = fallback_running or final_running
    running_status = 'Đang chạy' if is_running else 'Không chạy'
    login_success = looks_like_logged_in(response)

    best_html = response.text or ''
    best_response = response

    if session is not None:
        probed_response = fetch_best_solution_response(session, best_html, final_url, fallback_url)
        if probed_response is not None:
            probed_html = probed_response.text or ''
            if score_metric_html(probed_html) >= score_metric_html(best_html):
                best_html = probed_html
                best_response = probed_response
                final_url = probed_response.url or final_url
                status_text = format_status(probed_response)
                is_running = is_running or (probed_response.status_code < 500)
                running_status = 'Đang chạy' if is_running else 'Không chạy'
            if not login_success and looks_like_authenticated_html(probed_html, probed_response.url or final_url):
                login_success = True

    services: list[dict[str, str]] = []
    service_summary = 'Không kiểm tra'
    metrics = {
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'service_running_count': 0,
        'service_total_count': 0,
    }

    if login_success:
        if session is not None:
            discovered_html = fetch_best_solution_html(session, final_url, fallback_url)
            if score_metric_html(discovered_html) > score_metric_html(best_html):
                best_html = discovered_html

        static_metrics = extract_solution_metrics(best_html)
        metrics.update(static_metrics)

        if session is not None and should_try_browser_metric_fallback(metrics):
            rendered_metrics, rendered_html = fetch_rendered_solution_metrics(
                session=session,
                html=best_html or (response.text or ''),
                final_url=final_url,
                fallback_url=fallback_url,
            )
            metrics.update(merge_metric_maps(metrics, rendered_metrics))
            if score_metric_values(rendered_metrics) > score_metric_values(static_metrics) and rendered_html:
                best_html = rendered_html

        if checkservice:
            services = extract_services(best_html)
            if not services:
                services = extract_services(best_response.text or '')
            service_summary = summarize_services(services)
    elif checkservice:
        service_summary = 'Chưa login'

    service_running_count = sum(
        1 for item in services
        if item.get('status', '').strip().lower() == 'running'
    )
    service_total_count = len(services)
    display_running_status = service_summary if service_total_count else 'Đang chạy'
    metrics['service_running_count'] = service_running_count
    metrics['service_total_count'] = service_total_count

    if login_success:
        return {
            'name': name,
            'endpoint': endpoint,
            'username': username,
            'checked_url': final_url,
            'http_status': status_text,
            'login_status': 'Đăng nhập thành công',
            'running_status': display_running_status,
            'status': 'Đang chạy',
            'note': success_note,
            'login_method': infer_login_method_from_note(success_note),
            'is_success': True,
            'is_running': True,
            'checkservice': checkservice,
            'service_summary': service_summary,
            'services': services,
            **metrics,
        }

    return {
        'name': name,
        'endpoint': endpoint,
        'username': username,
        'checked_url': final_url,
        'http_status': status_text or fallback_status,
        'login_status': 'Không đăng nhập được',
        'running_status': running_status,
        'status': 'Đang chạy' if is_running else 'Không chạy',
        'note': failure_note,
        'login_method': infer_login_method_from_note(failure_note),
        'is_success': False,
        'is_running': is_running,
        'checkservice': checkservice,
        'service_summary': service_summary,
        'services': [],
        **metrics,
    }


def extract_solution_metrics(html: str) -> dict[str, str]:
    html = html or ''
    soup = BeautifulSoup(html, 'html.parser')
    return {
        'cpu_percent': extract_metric_from_ids(html, soup, ['cpuUsageText']),
        'ram_percent': extract_metric_from_ids(html, soup, ['memoryUsageText', 'ramUsageText']),
        'storage_percent': extract_metric_from_ids(html, soup, ['diskUsageText', 'storageUsageText', 'diskUsageTextWrapper']),
    }


def extract_metric_from_ids(html: str, soup: BeautifulSoup, ids: list[str]) -> str:
    for element_id in ids:
        value = extract_percent_from_dom_id(soup, element_id)
        if value != 'N/A':
            return value

        value = extract_percent_from_exact_id_block(html, element_id)
        if value != 'N/A':
            return value

        value = extract_percent_from_js_assignment(html, element_id)
        if value != 'N/A':
            return value

    return 'N/A'


def extract_percent_from_dom_id(soup: BeautifulSoup, element_id: str) -> str:
    node = soup.find(id=element_id)
    if node is None:
        return 'N/A'

    own_text_parts: list[str] = []
    for child in node.children:
        if isinstance(child, str):
            own_text_parts.append(child)
    own_text = ' '.join(part.strip() for part in own_text_parts if part and part.strip())
    value = normalize_percent_text(own_text)
    if value != 'N/A':
        return value

    value = normalize_percent_text(node.get_text(' ', strip=True))
    if value != 'N/A':
        return value

    for descendant in node.find_all(True):
        value = normalize_percent_text(descendant.get_text(' ', strip=True))
        if value != 'N/A':
            return value

    return 'N/A'


def extract_percent_from_exact_id_block(html: str, element_id: str) -> str:
    if not html:
        return 'N/A'

    escaped_id = re.escape(element_id)
    patterns = [
        re.compile(
            rf"<(?P<tag>[a-zA-Z0-9:_-]+)[^>]*\bid=[\"']{escaped_id}[\"'][^>]*>(?P<content>.*?)</(?P=tag)>",
            re.IGNORECASE | re.DOTALL,
        ),
        re.compile(
            rf"<(?P<tag>[a-zA-Z0-9:_-]+)[^>]*\bid=[\"']{escaped_id}[\"'][^>]*>(?P<content>[^<]*?)<",
            re.IGNORECASE | re.DOTALL,
        ),
    ]

    for pattern in patterns:
        for match in pattern.finditer(html):
            content = match.group('content') or ''
            value = normalize_percent_text(strip_style_and_script_blocks(content))
            if value != 'N/A':
                return value

    return 'N/A'


def extract_percent_from_js_assignment(html: str, element_id: str) -> str:
    if not html:
        return 'N/A'

    escaped_id = re.escape(element_id)
    patterns = [
        re.compile(
            rf"getElementById\([\"']{escaped_id}[\"']\)\.(?:innerText|textContent|innerHTML)\s*=\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
        re.compile(
            rf"\$\([\"']#{escaped_id}[\"']\)\.(?:text|html|val)\(\s*[\"']([^\"']+)[\"']\s*\)",
            re.IGNORECASE,
        ),
        re.compile(
            rf"[\"']{escaped_id}[\"']\s*:\s*[\"']([^\"']+)[\"']",
            re.IGNORECASE,
        ),
    ]

    for pattern in patterns:
        match = pattern.search(html)
        if match:
            value = normalize_percent_text(match.group(1))
            if value != 'N/A':
                return value

    return 'N/A'


def strip_style_and_script_blocks(text: str) -> str:
    cleaned = re.sub(r'<script\b[^>]*>.*?</script>', ' ', text or '', flags=re.IGNORECASE | re.DOTALL)
    cleaned = re.sub(r'<style\b[^>]*>.*?</style>', ' ', cleaned, flags=re.IGNORECASE | re.DOTALL)
    return cleaned


def normalize_percent_text(raw_text: str) -> str:
    text = html_lib.unescape(raw_text or '')
    if not text:
        return 'N/A'

    text = BeautifulSoup(text, 'html.parser').get_text(' ', strip=True)
    text = html_lib.unescape(' '.join(text.split()))
    if not text:
        return 'N/A'

    match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', text)
    if not match:
        return 'N/A'
    return f"{parse_float_loose(match.group(1)):.1f}%"


def extract_services(html: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html or '', 'html.parser')
    services: list[dict[str, str]] = []

    for card in soup.select('div.engine-card'):
        title_tag = card.select_one('div.engine-title')
        badge_tag = card.select_one('div.status-badge')

        name = title_tag.get_text(' ', strip=True) if title_tag else ''
        status = ''
        if badge_tag:
            status = (badge_tag.get('title') or badge_tag.get_text(' ', strip=True)).strip()

        if name:
            services.append({
                'name': name,
                'status': status or 'Unknown',
            })

    return services


def summarize_services(services: list[dict[str, str]]) -> str:
    if not services:
        return '0/0 service đang chạy'
    running = sum(
        1 for item in services
        if item.get('status', '').strip().lower() == 'running'
    )
    return f'{running}/{len(services)} service đang chạy'


def format_status(response: Response) -> str:
    reason = (response.reason or '').strip()
    return f'{response.status_code} {reason}'.strip()


def detect_json_login_strategy(html: str, base_url: str) -> dict[str, Any] | None:
    body = html or ''
    lowered = body.lower()
    endpoint_candidates: list[str] = []

    for pattern in (JSON_LOGIN_ENDPOINT_RE, JSON_LOGIN_URL_FIELD_RE):
        for match in pattern.finditer(body):
            endpoint_candidates.append(urljoin(base_url, match.group(1).strip()))

    if '/default/public/login' in lowered:
        endpoint_candidates.append(urljoin(base_url, '/default/public/login'))

    if ('json.stringify' in lowered or 'application/json' in lowered or 'xmlhttprequest' in lowered) and ('login' in lowered or 'signin' in lowered or 'auth' in lowered):
        for path in ('/default/public/login', '/login', '/signin', '/api/login', '/api/auth/login', '/authenticate'):
            endpoint_candidates.append(urljoin(base_url, path))

    seen = set()
    endpoints: list[str] = []
    for item in endpoint_candidates:
        if item and item not in seen:
            seen.add(item)
            endpoints.append(item)

    if not endpoints:
        return None

    username_field = 'username'
    if 'name="user_name"' in lowered or "name='user_name'" in lowered:
        username_field = 'user_name'
    elif 'name="username"' in lowered or "name='username'" in lowered:
        username_field = 'username'
    elif 'name="email"' in lowered or "name='email'" in lowered:
        username_field = 'email'
    elif 'name="login"' in lowered or "name='login'" in lowered:
        username_field = 'login'

    payload_variants: list[dict[str, str]] = []
    for user_key in (username_field, 'user_name', 'username', 'user', 'login', 'email'):
        payload_variants.append({user_key: '__USERNAME__', 'password': '__PASSWORD__'})

    match = JSON_LOGIN_KEYS_RE.search(body)
    if match:
        snippet = match.group('body') or ''
        for user_key in ('user_name', 'username', 'user', 'login', 'email'):
            if user_key in snippet:
                payload_variants.insert(0, {user_key: '__USERNAME__', 'password': '__PASSWORD__'})
                break

    redirect_candidates: list[str] = []
    for match in REDIRECT_PATH_RE.finditer(body):
        redirect_candidates.append(urljoin(base_url, match.group(1).strip()))
    for path in GENERIC_POST_LOGIN_PATHS:
        redirect_candidates.append(urljoin(base_url, path))

    redirect_seen = set()
    redirects: list[str] = []
    for item in redirect_candidates:
        if item and item not in redirect_seen:
            redirect_seen.add(item)
            redirects.append(item)

    return {'endpoints': endpoints, 'payload_variants': payload_variants, 'redirect_candidates': redirects}


def json_login_response_indicates_success(data: Any) -> tuple[bool, str | None]:
    if isinstance(data, dict):
        for key in JSON_SUCCESS_KEYS:
            if data.get(key) is True:
                return True, data.get('redirect') or data.get('url') or data.get('next')
        status_value = str(data.get('status', '')).strip().lower()
        if status_value in ('ok', 'success', 'authenticated', 'logged_in'):
            return True, data.get('redirect') or data.get('url') or data.get('next')
        if any(key in data for key in ('token', 'access_token', 'sessionid', 'session_id')):
            return True, data.get('redirect') or data.get('url') or data.get('next')
    return False, None


def attempt_json_login(session: Session, base_url: str, html: str, username: str, password: str, debug_steps: list[str] | None = None) -> Response | None:
    strategy = detect_json_login_strategy(html, base_url)
    if strategy is None:
        append_login_debug(debug_steps, 'JSON', 'Không phát hiện chiến lược JSON login trong HTML.')
        return None
    append_login_debug(debug_steps, 'JSON', 'Phát hiện chiến lược JSON login.', endpoints=strategy.get('endpoints'), redirects=strategy.get('redirect_candidates'))

    headers = {
        'Referer': base_url,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*',
        'X-Requested-With': 'XMLHttpRequest',
    }

    for endpoint in strategy['endpoints']:
        for template in strategy['payload_variants']:
            payload = {k: (username if v == '__USERNAME__' else password if v == '__PASSWORD__' else v) for k, v in template.items()}
            try:
                append_login_debug(debug_steps, 'JSON', 'Thử JSON login.', endpoint=endpoint, payload_keys=list(payload.keys()))
                resp = session.post(endpoint, json=payload, headers=headers, timeout=SOLUTION_HTTP_TIMEOUT, allow_redirects=True)
            except RequestException as exc:
                append_login_debug(debug_steps, 'JSON', 'POST JSON lỗi.', endpoint=endpoint, error=describe_request_error(exc))
                continue

            append_login_debug(debug_steps, 'JSON', 'POST JSON có phản hồi.', endpoint=endpoint, status=resp.status_code, content_type=resp.headers.get('Content-Type'), final_url=resp.url or endpoint, body_preview=(resp.text or '')[:180])
            if looks_like_logged_in(resp) or looks_like_authenticated_html(resp.text or '', resp.url or endpoint):
                append_login_debug(debug_steps, 'JSON', 'Response sau JSON login đã giống trạng thái authenticated.')
                return resp

            content_type = (resp.headers.get('Content-Type') or '').lower()
            if 'json' not in content_type:
                continue
            try:
                data = resp.json()
            except ValueError:
                append_login_debug(debug_steps, 'JSON', 'Response không parse được JSON.')
                continue
            success, redirect = json_login_response_indicates_success(data)
            append_login_debug(debug_steps, 'JSON', 'Kết quả parse JSON.', success=success, redirect=redirect, json_preview=data)
            if not success:
                continue
            targets = []
            if redirect:
                targets.append(urljoin(endpoint, str(redirect)))
            targets.extend(strategy['redirect_candidates'])
            for target in targets:
                try:
                    append_login_debug(debug_steps, 'JSON', 'Probe trang sau login.', target=target)
                    probe = session.get(target, timeout=SOLUTION_HTTP_TIMEOUT, allow_redirects=True)
                except RequestException as exc:
                    append_login_debug(debug_steps, 'JSON', 'Probe sau login lỗi.', target=target, error=describe_request_error(exc))
                    continue
                if looks_like_logged_in(probe) or looks_like_authenticated_html(probe.text or '', probe.url or target):
                    return probe
            return resp
    return None


def extract_login_form(html: str, base_url: str) -> dict[str, Any] | None:
    soup = BeautifulSoup(html, 'html.parser')
    candidate_forms: list[tuple[int, Any]] = []

    for form in soup.find_all('form'):
        score = 0
        inputs = form.find_all('input')

        for input_tag in inputs:
            input_type = (input_tag.get('type') or 'text').lower()
            field_name = (input_tag.get('name') or '').strip().lower()
            if input_type == 'password' or any(hint in field_name for hint in PASSWORD_HINTS):
                score += 4
            if any(hint in field_name for hint in USERNAME_HINTS):
                score += 2
            if input_type == 'hidden':
                score += 1

        form_text = ' '.join(filter(None, [form.get('id', ''), form.get('name', ''), form.get('action', '')]))
        if any(word in str(form_text).lower() for word in LOGIN_WORDS):
            score += 2

        if score > 0:
            candidate_forms.append((score, form))

    if not candidate_forms:
        return None

    candidate_forms.sort(key=lambda item: item[0], reverse=True)
    form = candidate_forms[0][1]
    method = (form.get('method') or 'post').strip().lower()
    action = urljoin(base_url, form.get('action') or base_url)

    fields: dict[str, str] = {}
    username_field = None
    password_field = None

    for element in form.find_all(['input', 'button', 'textarea', 'select']):
        name = (element.get('name') or '').strip()
        if not name:
            continue

        input_type = (element.get('type') or '').lower()
        value = element.get('value') or ''
        lowered = name.lower()

        if input_type == 'password' or any(hint in lowered for hint in PASSWORD_HINTS):
            password_field = password_field or name
            continue

        if any(hint in lowered for hint in USERNAME_HINTS) and input_type not in ('hidden', 'checkbox', 'radio'):
            username_field = username_field or name
            continue

        if input_type in ('hidden', 'checkbox', 'radio'):
            fields[name] = value
            continue

        if input_type in ('submit', 'button'):
            if value:
                fields[name] = value
            continue

        if input_type not in ('file', 'image') and value:
            fields[name] = value

    if password_field is None:
        return None

    if username_field is None:
        for item in form.find_all('input', attrs={'type': ['text', 'email', 'search', 'tel']}):
            field_name = (item.get('name') or '').strip()
            if field_name:
                username_field = field_name
                break

    if username_field is None:
        return None

    return {
        'method': method,
        'action': action,
        'fields': fields,
        'username_field': username_field,
        'password_field': password_field,
    }


def submit_login_form(
    session: Session,
    form_info: dict[str, Any],
    referer_url: str,
    username: str,
    password: str,
    debug_steps: list[str] | None = None,
) -> Response:
    payload = dict(form_info['fields'])
    payload[form_info['username_field']] = username
    payload[form_info['password_field']] = password
    headers = {'Referer': referer_url}

    if form_info['method'] == 'get':
        append_login_debug(debug_steps, 'FORM', 'Submit form GET.', action=form_info['action'], payload_keys=list(payload.keys()))
        return session.get(
            form_info['action'],
            params=payload,
            headers=headers,
            timeout=SOLUTION_HTTP_TIMEOUT,
            allow_redirects=True,
        )

    append_login_debug(debug_steps, 'FORM', 'Submit form POST.', action=form_info['action'], payload_keys=list(payload.keys()))
    return session.post(
        form_info['action'],
        data=payload,
        headers=headers,
        timeout=SOLUTION_HTTP_TIMEOUT,
        allow_redirects=True,
    )


def infer_login_method_from_note(note: str) -> str:
    lowered = (note or '').lower()
    if 'basic auth' in lowered:
        return 'basic_auth'
    if 'ajax/json' in lowered or 'json' in lowered:
        return 'json'
    if 'form' in lowered:
        return 'form'
    if 'trình duyệt' in lowered or 'browser' in lowered or 'headless' in lowered:
        return 'browser'
    return 'unknown'


def looks_like_logged_in(response: Response) -> bool:
    if response.status_code >= 400:
        return False

    text = response.text or ''
    lowered = text.lower()
    url_lower = (response.url or '').lower()

    if looks_like_authenticated_html(text, response.url or ''):
        return True

    if PASSWORD_INPUT_RE.search(text):
        return False

    if any(word in url_lower for word in ('/login', '/signin', '/auth', '/authenticate')) and any(word in lowered for word in LOGIN_WORDS):
        return False

    return True


def solution_result_score(result: dict[str, Any]) -> int:
    if result.get('is_success'):
        return 3
    if result.get('is_running'):
        return 2
    if result.get('http_status') not in (None, '', 'N/A'):
        return 1
    return 0


if __name__ == '__main__':
    ensure_databases()
    host = os.environ.get('HOST', '127.0.0.1')
    port = int(os.environ.get('PORT', '5000'))
    app.run(host=host, port=port, debug=False)