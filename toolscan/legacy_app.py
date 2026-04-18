from __future__ import annotations

import html as html_lib
import json
import logging
import os
import re
import shlex
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import paramiko
import requests
import urllib3
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from requests import Response, Session
from requests.auth import HTTPBasicAuth
from requests.exceptions import RequestException

from toolscan.modules.websites import resolve_public_ip

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

BASE_DIR = Path(__file__).resolve().parent.parent
app = Flask(__name__, template_folder=str(BASE_DIR / 'templates'))

load_dotenv(BASE_DIR / '.env')

logging.basicConfig(level=os.getenv('LOGIN_LOG_LEVEL', 'INFO').upper(), format='[%(asctime)s] %(levelname)s %(message)s')
logging.getLogger('paramiko').setLevel(logging.CRITICAL)
logging.getLogger('paramiko.transport').setLevel(logging.CRITICAL)
logging.getLogger('paramiko.transport').propagate = False
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('werkzeug').setLevel(logging.WARNING)
logger = logging.getLogger('toolscan-login')
DATA_DIR = BASE_DIR / 'data'
DEFAULT_GROUP_NAME = 'A'
SSH_DATABASE_PATH = DATA_DIR / 'servers.json'
WEB_DATABASE_PATH = DATA_DIR / 'websites.json'
SOLUTION_DATABASE_PATH = DATA_DIR / 'solutions.json'
MANAGED_SECRETS_PATH = DATA_DIR / 'managed_secrets.json'
SETTINGS_PATH = DATA_DIR / 'settings.json'
ENV_PATH = BASE_DIR / '.env'
SECRET_ADMIN_PASSWORD = os.getenv('SECRET_ADMIN_PASSWORD', 'DuyenV2')

DEFAULT_TIMEOUT_SETTINGS: dict[str, dict[str, float]] = {
    'ssh': {
        'ssh_connect_timeout': float(os.getenv('SSH_CONNECT_TIMEOUT', '5')),
        'ssh_command_timeout': float(os.getenv('SSH_COMMAND_TIMEOUT', '10')),
        'snmp_timeout': float(os.getenv('SNMP_DEFAULT_TIMEOUT', '1')),
    },
    'web': {
        'web_connect_timeout': float(os.getenv('WEBSITE_CONNECT_TIMEOUT', '3')),
        'web_read_timeout': float(os.getenv('WEBSITE_READ_TIMEOUT', '5')),
    },
    'solution': {
        'web_connect_timeout': float(os.getenv('SOLUTION_WEB_CONNECT_TIMEOUT', os.getenv('WEBSITE_CONNECT_TIMEOUT', '3'))),
        'web_read_timeout': float(os.getenv('SOLUTION_HTTP_TIMEOUT', '15')),
        'ssh_connect_timeout': float(os.getenv('SOLUTION_SSH_CONNECT_TIMEOUT', os.getenv('SSH_CONNECT_TIMEOUT', '5'))),
        'ssh_command_timeout': float(os.getenv('SOLUTION_SSH_COMMAND_TIMEOUT', os.getenv('SSH_COMMAND_TIMEOUT', '10'))),
        'snmp_timeout': float(os.getenv('SOLUTION_SNMP_TIMEOUT', os.getenv('SNMP_DEFAULT_TIMEOUT', '1'))),
        'large_file_threshold_gb': float(os.getenv('SOLUTION_LARGE_FILE_THRESHOLD_GB', '5')),
    },
}

SCAN_JOB_LOCK = threading.Lock()
SCAN_JOBS: dict[str, dict[str, Any]] = {}
SCAN_JOB_TTL_SECONDS = int(os.getenv('SCAN_JOB_TTL_SECONDS', '3600'))


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
MAX_SOLUTION_SCAN_WORKERS = int(os.getenv('MAX_SOLUTION_SCAN_WORKERS', '20'))
WEBSITE_CONNECT_TIMEOUT = float(os.getenv('WEBSITE_CONNECT_TIMEOUT', '3'))
WEBSITE_READ_TIMEOUT = float(os.getenv('WEBSITE_READ_TIMEOUT', '5'))
SOLUTION_HTTP_TIMEOUT = float(os.getenv('SOLUTION_HTTP_TIMEOUT', '15'))
SOLUTION_FORM_TIMEOUT = float(os.getenv('SOLUTION_FORM_TIMEOUT', '25'))
JSON_LOGIN_MAX_ENDPOINTS = int(os.getenv('JSON_LOGIN_MAX_ENDPOINTS', '3'))
JSON_LOGIN_MAX_PAYLOADS = int(os.getenv('JSON_LOGIN_MAX_PAYLOADS', '3'))
LOGIN_TRACE_LIMIT = int(os.getenv('LOGIN_TRACE_LIMIT', '200'))

SECRET_ALIAS_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')
SECRET_ALIAS_EXAMPLE_TEXT = 'ví dụ pass_mac_dinh, pass_giai_phap, pass_ssh_root, snmpstring_mac_dinh'


def normalize_secret_alias(value: Any) -> str:
    return str(value or '').strip()


def load_managed_secrets() -> dict[str, str]:
    ensure_databases()
    env_data = read_env_file(ENV_PATH)
    try:
        data = read_json_file(MANAGED_SECRETS_PATH) if MANAGED_SECRETS_PATH.exists() else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    cleaned: dict[str, str] = {}
    for key, value in data.items():
        alias = normalize_secret_alias(key)
        if alias:
            cleaned[alias] = str(value or '')
    for key, value in env_data.items():
        alias = normalize_secret_alias(key).lower()
        if alias:
            cleaned[alias] = value
    return cleaned


def save_managed_secrets(secrets: dict[str, Any]) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    env_values: dict[str, str] = {}
    for key, value in (secrets or {}).items():
        alias = normalize_secret_alias(key)
        if not alias:
            continue
        if not SECRET_ALIAS_RE.fullmatch(alias):
            raise ValueError(f'Alias bí mật "{alias}" không hợp lệ. Chỉ dùng chữ, số và dấu gạch dưới, không bắt đầu bằng số.')
        secret_value = str(value or '')
        if not secret_value.strip():
            raise ValueError(f'Giá trị của alias {alias} không được để trống.')
        cleaned[alias] = secret_value
        env_values[alias.upper()] = secret_value
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    MANAGED_SECRETS_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    write_env_file(env_values, ENV_PATH)
    for key, value in env_values.items():
        os.environ[key] = value
    return load_managed_secrets()


def validate_secret_alias(alias: str, field_label: str, allow_blank: bool = False) -> None:
    normalized = normalize_secret_alias(alias)
    if not normalized:
        if allow_blank:
            return
        raise ValueError(f'{field_label} không được để trống.')


def resolve_secret_alias(alias: str, field_label: str, allow_blank: bool = False) -> str:
    normalized = normalize_secret_alias(alias)
    if not normalized:
        if allow_blank:
            return ''
        raise ValueError(f'{field_label} không được để trống.')
    env_name = normalized.upper()
    resolved = os.getenv(env_name, '').strip()
    if resolved:
        return resolved
    managed = load_managed_secrets().get(normalized, '').strip()
    if managed:
        return managed
    return normalized


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
    last_entry = getattr(_thread_local, 'last_login_debug_entry', None)
    if last_entry != entry:
        logger.info(entry)
        _thread_local.last_login_debug_entry = entry
    if debug_steps is not None and len(debug_steps) < LOGIN_TRACE_LIMIT:
        if not debug_steps or debug_steps[-1] != entry:
            debug_steps.append(entry)


def attach_login_debug(result: dict[str, Any], debug_steps: list[str] | None) -> dict[str, Any]:
    result['login_debug'] = debug_steps or []
    return result

SSH_CONNECT_TIMEOUT = float(os.getenv('SSH_CONNECT_TIMEOUT', '5'))
SSH_COMMAND_TIMEOUT = float(os.getenv('SSH_COMMAND_TIMEOUT', '10'))
SNMP_DEFAULT_TIMEOUT = int(os.getenv('SNMP_DEFAULT_TIMEOUT', '1'))
SNMP_DEFAULT_RETRIES = int(os.getenv('SNMP_DEFAULT_RETRIES', '0'))
PROXY_SNMP_USERNAME = os.getenv('PROXY_SNMP_USERNAME', 'root')
PROXY_SNMP_PASSWORD = os.getenv('PROXY_SNMP_PASSWORD', '').strip()
PROXY_SNMP_HOPS = [
    {'host': os.getenv('PROXY_SNMP_HOST_1', '163.223.58.150'), 'username': PROXY_SNMP_USERNAME, 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@150'},
    {'host': os.getenv('PROXY_SNMP_HOST_2', '163.223.58.132'), 'username': PROXY_SNMP_USERNAME, 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@132'},
]

_thread_local = threading.local()


def parse_float_loose(value: str) -> float:
    return float(str(value).strip().replace(',', '.'))


def read_env_file(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = raw_line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        if key:
            result[key] = value
    return result


def write_env_file(values: dict[str, Any], path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    existing_lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
    normalized = {str(k).strip().upper(): str(v) for k, v in (values or {}).items() if str(k).strip()}
    output_lines: list[str] = []
    seen: set[str] = set()
    for raw_line in existing_lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#') or '=' not in raw_line:
            output_lines.append(raw_line)
            continue
        key = raw_line.split('=', 1)[0].strip()
        if key in normalized:
            output_lines.append(f'{key}={normalized[key]}')
            seen.add(key)
        else:
            output_lines.append(raw_line)
    for key in sorted(normalized.keys()):
        if key not in seen:
            output_lines.append(f'{key}={normalized[key]}')
    path.write_text('\n'.join(output_lines).rstrip() + ('\n' if output_lines else ''), encoding='utf-8')
    return read_env_file(path)


def ensure_databases() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_DATABASE_PATH.exists():
        SSH_DATABASE_PATH.write_text('[]', encoding='utf-8')
    if not WEB_DATABASE_PATH.exists():
        WEB_DATABASE_PATH.write_text('[]', encoding='utf-8')
    if not SOLUTION_DATABASE_PATH.exists():
        SOLUTION_DATABASE_PATH.write_text('[]', encoding='utf-8')
    if not MANAGED_SECRETS_PATH.exists():
        MANAGED_SECRETS_PATH.write_text('{}', encoding='utf-8')
    if not SETTINGS_PATH.exists():
        SETTINGS_PATH.write_text(json.dumps(DEFAULT_TIMEOUT_SETTINGS, ensure_ascii=False, indent=2), encoding='utf-8')


def read_json_file(path: Path) -> Any:
    return json.loads(path.read_text(encoding='utf-8'))


def normalize_group_name(value: Any) -> str:
    text = str(value or '').strip()
    return text or DEFAULT_GROUP_NAME


def resolve_server_secrets(server: dict[str, Any]) -> dict[str, str]:
    resolved = dict(server)
    resolved['password'] = resolve_secret_alias(server.get('password', ''), 'password')
    resolved['snmp_community'] = resolve_secret_alias(server.get('snmp_community', ''), 'SNMP CommunityString')
    return resolved


def resolve_solution_secrets(solution: dict[str, Any]) -> dict[str, Any]:
    resolved = dict(solution)
    resolved['password'] = resolve_secret_alias(solution.get('password', ''), 'pass giao diện', allow_blank=True)
    resolved['ssh_password'] = resolve_secret_alias(solution.get('ssh_password', ''), 'pass SSH', allow_blank=True)
    if solution.get('snmp_enabled'):
        resolved['snmp_community'] = resolve_secret_alias(solution.get('snmp_community', ''), 'SNMP CommunityString')
    else:
        resolved['snmp_community'] = resolve_secret_alias(solution.get('snmp_community', ''), 'SNMP CommunityString', allow_blank=True)
    return resolved


def normalize_server(raw: dict[str, Any]) -> dict[str, str]:
    return {
        'group': normalize_group_name(raw.get('group', DEFAULT_GROUP_NAME)),
        'name': str(raw.get('name', 'server')).strip() or 'server',
        'ip': str(raw.get('ip', '')).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': normalize_secret_alias(raw.get('password', '')),
        'snmp_community': normalize_secret_alias(raw.get('snmp_community', raw.get('community', ''))),
    }



def _settings_shape() -> dict[str, dict[str, float]]:
    return json.loads(json.dumps(DEFAULT_TIMEOUT_SETTINGS))


def load_timeout_settings() -> dict[str, dict[str, float]]:
    ensure_databases()
    base = _settings_shape()
    try:
        raw = read_json_file(SETTINGS_PATH)
    except Exception:
        raw = {}
    if not isinstance(raw, dict):
        raw = {}
    for section, defaults in base.items():
        section_raw = raw.get(section, {}) if isinstance(raw.get(section, {}), dict) else {}
        for key, default_value in defaults.items():
            try:
                value = float(section_raw.get(key, default_value))
            except (TypeError, ValueError):
                value = float(default_value)
            if value <= 0:
                value = float(default_value)
            base[section][key] = value
    return base


def get_timeout_settings(section: str) -> dict[str, float]:
    settings = load_timeout_settings()
    if section not in settings:
        raise ValueError('Loại cài đặt không hợp lệ.')
    return settings[section].copy()


def save_timeout_settings(section: str, payload: dict[str, Any]) -> dict[str, float]:
    if section not in DEFAULT_TIMEOUT_SETTINGS:
        raise ValueError('Loại cài đặt không hợp lệ.')
    current = load_timeout_settings()
    cleaned: dict[str, float] = {}
    defaults = DEFAULT_TIMEOUT_SETTINGS[section]
    incoming = payload if isinstance(payload, dict) else {}
    for key, default_value in defaults.items():
        raw_value = incoming.get(key, current.get(section, {}).get(key, default_value))
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            raise ValueError(f'Giá trị {key} phải là số hợp lệ.')
        if value <= 0:
            raise ValueError(f'Giá trị {key} phải lớn hơn 0.')
        cleaned[key] = value
    current[section] = cleaned
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned

def validate_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = [normalize_server(item) for item in servers]
    for index, server in enumerate(cleaned, start=1):
        if not (server['group'] and server['name'] and server['ip'] and server['username'] and server['password'] and server['snmp_community']):
            raise ValueError(f'Dòng SSH {index} đang thiếu name, IP, username, password alias hoặc SNMP CommunityString alias.')
        validate_secret_alias(server['password'], f'Dòng SSH {index} - password')
        validate_secret_alias(server['snmp_community'], f'Dòng SSH {index} - SNMP CommunityString')
    return cleaned


def normalize_website(raw: Any) -> dict[str, str]:
    if isinstance(raw, str):
        return {'group': DEFAULT_GROUP_NAME, 'domain': str(raw).strip().replace(' ', '')}
    value = raw.get('domain', '')
    return {'group': normalize_group_name(raw.get('group', DEFAULT_GROUP_NAME)), 'domain': str(value).strip().replace(' ', '')}


def validate_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = [normalize_website(item) for item in websites]
    for index, website in enumerate(cleaned, start=1):
        if not website['group'] or not website['domain']:
            raise ValueError(f'Dòng website {index} đang thiếu domain.')
    return cleaned


def to_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on'}


def normalize_solution(raw: dict[str, Any]) -> dict[str, Any]:
    endpoint = raw.get('endpoint', raw.get('target', ''))
    return {
        'group': normalize_group_name(raw.get('group', DEFAULT_GROUP_NAME)),
        'name': str(raw.get('name', '')).strip(),
        'endpoint': str(endpoint).strip(),
        'username': str(raw.get('username', '')).strip(),
        'password': normalize_secret_alias(raw.get('password', '')),
        'ssh_username': str(raw.get('ssh_username', raw.get('ssh_user', ''))).strip(),
        'ssh_password': normalize_secret_alias(raw.get('ssh_password', raw.get('ssh_pass', ''))),
        'checkservice': True,
        'snmp_enabled': True,
        'snmp_port': 161,
        'snmp_version': str(raw.get('snmp_version', raw.get('version', '2c'))).strip().lower() or '2c',
        'snmp_community': normalize_secret_alias(raw.get('snmp_community', raw.get('community', ''))),
        'snmp_timeout': int(str(raw.get('snmp_timeout', get_timeout_settings('solution').get('snmp_timeout', SNMP_DEFAULT_TIMEOUT))) or str(int(get_timeout_settings('solution').get('snmp_timeout', SNMP_DEFAULT_TIMEOUT)))),
        'snmp_retries': int(str(raw.get('snmp_retries', SNMP_DEFAULT_RETRIES)) or str(SNMP_DEFAULT_RETRIES)),
    }


def validate_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = [normalize_solution(item) for item in solutions]
    for index, solution in enumerate(cleaned, start=1):
        if not solution['group'] or not solution['name'] or not solution['endpoint']:
            raise ValueError(f'Dòng giải pháp {index} đang thiếu tên hoặc endpoint.')
        if solution.get('password'):
            validate_secret_alias(solution['password'], f'Dòng giải pháp {index} - pass giao diện', allow_blank=True)
        if solution.get('ssh_password'):
            validate_secret_alias(solution['ssh_password'], f'Dòng giải pháp {index} - pass SSH', allow_blank=True)
        if solution.get('snmp_enabled'):
            if not solution.get('snmp_community'):
                raise ValueError(f'Dòng giải pháp {index} đã bật SNMP nhưng thiếu SNMP CommunityString alias.')
            validate_secret_alias(solution['snmp_community'], f'Dòng giải pháp {index} - SNMP CommunityString')
        elif solution.get('snmp_community'):
            validate_secret_alias(solution['snmp_community'], f'Dòng giải pháp {index} - SNMP CommunityString', allow_blank=True)
    return cleaned


def load_servers() -> list[dict[str, str]]:
    ensure_databases()
    data = read_json_file(SSH_DATABASE_PATH)
    if not isinstance(data, list):
        raise ValueError('Database SSH không đúng định dạng.')
    return validate_servers(data)


def save_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = validate_servers(servers)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SSH_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_websites() -> list[dict[str, str]]:
    ensure_databases()
    data = read_json_file(WEB_DATABASE_PATH)
    if not isinstance(data, list):
        raise ValueError('Database website không đúng định dạng.')
    return validate_websites(data)


def save_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = validate_websites(websites)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    WEB_DATABASE_PATH.write_text(json.dumps(cleaned, ensure_ascii=False, indent=2), encoding='utf-8')
    return cleaned


def load_solutions() -> list[dict[str, Any]]:
    ensure_databases()
    data = read_json_file(SOLUTION_DATABASE_PATH)
    if not isinstance(data, list):
        raise ValueError('Database giải pháp không đúng định dạng.')
    return validate_solutions(data)


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




def require_secret_admin(payload: dict[str, Any]) -> None:
    provided = str(payload.get('auth', '') or '').strip()
    if provided != SECRET_ADMIN_PASSWORD:
        raise ValueError('Sai mật khẩu quản lý bí mật.')


@app.get('/api/secrets')
def get_managed_secret_database() -> Any:
    auth = request.args.get('auth', '').strip()
    try:
        require_secret_admin({'auth': auth})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 403
    secrets = load_managed_secrets()
    return jsonify({'secrets': [{'alias': key, 'value': value} for key, value in sorted(secrets.items())]})


@app.post('/api/secrets')
def update_managed_secret_database() -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        require_secret_admin(payload)
        raw_items = payload.get('secrets', [])
        if isinstance(raw_items, dict):
            secrets = save_managed_secrets(raw_items)
        else:
            secrets = save_managed_secrets({str(item.get('alias', '')).strip(): item.get('value', '') for item in (raw_items or [])})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400 if 'Sai mật khẩu' not in str(exc) else 403
    return jsonify({'message': 'Đã lưu bí mật thành công.', 'secrets': [{'alias': key, 'value': value} for key, value in sorted(secrets.items())]})

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


@app.get('/api/settings/<section>')
def get_section_settings_route(section: str) -> Any:
    try:
        settings = get_timeout_settings(section)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'section': section, 'settings': settings})


@app.post('/api/settings/<section>')
def update_section_settings_route(section: str) -> Any:
    payload = request.get_json(silent=True) or {}
    try:
        settings = save_timeout_settings(section, payload.get('settings', {}))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400
    return jsonify({'message': 'Đã lưu cài đặt timeout thành công.', 'section': section, 'settings': settings})



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

def get_requested_group() -> str | None:
    payload = request.get_json(silent=True) or {}
    group = str(payload.get('group', '') or '').strip()
    return normalize_group_name(group) if group else None


def filter_items_by_group(items: list[dict[str, Any]], group: str | None) -> list[dict[str, Any]]:
    if not group:
        return items
    return [item for item in items if normalize_group_name(item.get('group', DEFAULT_GROUP_NAME)) == group]


@app.post('/api/scan')
def scan_servers() -> Any:
    servers = filter_items_by_group(load_servers(), get_requested_group())
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
    websites = filter_items_by_group(load_websites(), get_requested_group())
    results = run_parallel_checks(websites, check_one_website, max_workers=MAX_WEB_SCAN_WORKERS)
    results = [{**item, 'has_scanned': True} for item in results]
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
    solutions = filter_items_by_group(load_solutions(), get_requested_group())
    results = run_parallel_checks(solutions, check_one_solution, max_workers=MAX_SOLUTION_SCAN_WORKERS)
    running_count = sum(1 for item in results if item.get('is_running'))
    login_success_count = sum(1 for item in results if item.get('is_success'))
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
    progress_callback: Callable[[dict[str, Any], int, int], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any] | None] = [None] * len(items)
    if max_workers is None:
        max_workers = min(16, max(4, len(items))) or 1
    else:
        max_workers = max(1, min(int(max_workers), max(1, len(items))))

    total = len(items)
    completed = 0
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
                    'group': src_item.get('group', DEFAULT_GROUP_NAME),
                    'name': src_item.get('name') or src_item.get('ip') or src_item.get('domain') or f'item-{index + 1}',
                    'ip': src_item.get('ip', ''),
                    'domain': src_item.get('domain', ''),
                    'endpoint': src_item.get('endpoint', ''),
                    'status': 'Lỗi xử lý',
                    'is_success': False,
                    'is_running': False,
                    'error': str(exc),
                    'login_method': None,
                    'login_debug': [f'run_parallel_checks exception: {exc}'],
                }
            results[index] = result
            completed += 1
            if progress_callback is not None:
                progress_callback(result, completed, total)

    return [item for item in results if item is not None]



def _cleanup_scan_jobs() -> None:
    now = time.time()
    with SCAN_JOB_LOCK:
        stale = [job_id for job_id, job in SCAN_JOBS.items() if now - float(job.get('created_at', now)) > SCAN_JOB_TTL_SECONDS]
        for job_id in stale:
            SCAN_JOBS.pop(job_id, None)


def _create_scan_job(kind: str, payload: dict[str, Any]) -> str:
    _cleanup_scan_jobs()
    job_id = uuid.uuid4().hex
    with SCAN_JOB_LOCK:
        SCAN_JOBS[job_id] = {
            'job_id': job_id,
            'kind': kind,
            'payload': payload,
            'status': 'running',
            'created_at': time.time(),
            'started_at': time.time(),
            'finished_at': None,
            'result': None,
            'error': None,
            'partial_results': [],
            'progress': {'completed': 0, 'total': 0},
        }
    return job_id


def _finish_scan_job(job_id: str, *, result: dict[str, Any] | None = None, error: str | None = None) -> None:
    with SCAN_JOB_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return
        job['status'] = 'failed' if error else 'completed'
        job['result'] = result
        job['error'] = error
        job['finished_at'] = time.time()


def _scan_job_status_payload(job_id: str) -> dict[str, Any]:
    with SCAN_JOB_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            raise KeyError(job_id)
        return {
            'job_id': job['job_id'],
            'kind': job['kind'],
            'status': job['status'],
            'result': job.get('result'),
            'error': job.get('error'),
            'created_at': job.get('created_at'),
            'started_at': job.get('started_at'),
            'finished_at': job.get('finished_at'),
            'partial_results': list(job.get('partial_results') or []),
            'progress': dict(job.get('progress') or {}),
        }


def _update_scan_job_progress(job_id: str, result: dict[str, Any], completed: int, total: int) -> None:
    with SCAN_JOB_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return
        partials = list(job.get('partial_results') or [])
        partials.append(result)
        job['partial_results'] = partials
        job['progress'] = {'completed': completed, 'total': total}


def _run_scan_job(job_id: str, kind: str, payload: dict[str, Any]) -> None:
    try:
        group = payload.get('group')

        def progress(result_item: dict[str, Any], completed: int, total: int) -> None:
            _update_scan_job_progress(job_id, {**result_item, 'has_scanned': True}, completed, total)

        if kind == 'ssh-all':
            items = filter_items_by_group(load_servers(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['progress'] = {'completed': 0, 'total': len(items)}
            results = run_parallel_checks(items, check_one_server, max_workers=MAX_SSH_SCAN_WORKERS, progress_callback=progress)
            success_count = sum(1 for item in results if item.get('is_success'))
            result = {'results': results, 'summary': {'total': len(results), 'success': success_count, 'failed': len(results) - success_count}}
        elif kind == 'web-all':
            items = filter_items_by_group(load_websites(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['progress'] = {'completed': 0, 'total': len(items)}
            results = run_parallel_checks(items, check_one_website, max_workers=MAX_WEB_SCAN_WORKERS, progress_callback=progress)
            results = [{**item, 'has_scanned': True} for item in results]
            success_count = sum(1 for item in results if item.get('is_success'))
            result = {'results': results, 'summary': {'total': len(results), 'success': success_count, 'failed': len(results) - success_count}}
        elif kind == 'solution-all':
            items = filter_items_by_group(load_solutions(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['progress'] = {'completed': 0, 'total': len(items)}
            results = run_parallel_checks(items, check_one_solution, max_workers=MAX_SOLUTION_SCAN_WORKERS, progress_callback=progress)
            running_count = sum(1 for item in results if item.get('is_running'))
            login_success_count = sum(1 for item in results if item.get('is_success'))
            issue_count = len(results) - login_success_count
            running_services = sum(int(item.get('service_running_count', 0) or 0) for item in results)
            total_services = sum(int(item.get('service_total_count', 0) or 0) for item in results)
            result = {'results': results, 'summary': {'total': len(results), 'running': running_count, 'login_success': login_success_count, 'issues': issue_count, 'running_services': running_services, 'total_services': total_services}}
        elif kind == 'ssh-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_servers(), index, 'SSH')
            _, one_result = check_one_server(index, item)
            _update_scan_job_progress(job_id, {**one_result, 'has_scanned': True}, 1, 1)
            result = {'index': index, 'result': one_result}
        elif kind == 'web-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_websites(), index, 'website')
            _, one_result = check_one_website(index, item)
            _update_scan_job_progress(job_id, {**one_result, 'has_scanned': True}, 1, 1)
            result = {'index': index, 'result': one_result}
        elif kind == 'solution-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_solutions(), index, 'giải pháp')
            _, one_result = check_one_solution(index, item)
            _update_scan_job_progress(job_id, {**one_result, 'has_scanned': True}, 1, 1)
            result = {'index': index, 'result': one_result}
        else:
            raise ValueError(f'Unknown scan job kind: {kind}')
        _finish_scan_job(job_id, result=result)
    except Exception as exc:
        _finish_scan_job(job_id, error=str(exc))


def _start_scan_job(kind: str, payload: dict[str, Any]) -> str:
    job_id = _create_scan_job(kind, payload)
    thread = threading.Thread(target=_run_scan_job, args=(job_id, kind, payload), daemon=True)
    thread.start()
    return job_id


@app.post('/api/scan-jobs/start')
def start_scan_job_route() -> Any:
    payload = request.get_json(silent=True) or {}
    kind = str(payload.get('kind') or '').strip()
    if not kind:
        return jsonify({'error': 'Thiếu kind cho scan job.'}), 400
    try:
        job_id = _start_scan_job(kind, payload)
    except Exception as exc:
        return jsonify({'error': f'Không tạo được scan job: {exc}'}), 500
    return jsonify({'job_id': job_id, 'status': 'running'})


@app.get('/api/scan-jobs/<job_id>')
def get_scan_job_route(job_id: str) -> Any:
    try:
        return jsonify(_scan_job_status_payload(job_id))
    except KeyError:
        return jsonify({'error': 'Không tìm thấy scan job.'}), 404


def ssh_exec_command(host: str, username: str, password: str, command: str, timeout: float | None = None, connect_timeout: float | None = None, get_pty: bool = False) -> tuple[str, str, int]:
    ssh_settings = get_timeout_settings('ssh')
    command_timeout = float(timeout if timeout is not None else ssh_settings.get('ssh_command_timeout', SSH_COMMAND_TIMEOUT))
    ssh_connect_timeout = float(connect_timeout if connect_timeout is not None else ssh_settings.get('ssh_connect_timeout', SSH_CONNECT_TIMEOUT))
    last_exc: Exception | None = None
    for attempt in range(2):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=22,
                username=username,
                password=password,
                timeout=ssh_connect_timeout,
                auth_timeout=ssh_connect_timeout,
                banner_timeout=ssh_connect_timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            transport = client.get_transport()
            if transport is not None:
                transport.set_keepalive(max(1, int(min(command_timeout, 15.0))))
            stdin, stdout, stderr = client.exec_command(command, timeout=command_timeout, get_pty=get_pty)
            _ = stdin
            stdout_text = stdout.read().decode('utf-8', errors='ignore')
            stderr_text = stderr.read().decode('utf-8', errors='ignore')
            exit_code = stdout.channel.recv_exit_status()
            return stdout_text, stderr_text, exit_code
        except (paramiko.SSHException, EOFError, OSError) as exc:
            last_exc = exc
            if attempt == 0:
                continue
            raise
        finally:
            client.close()
    if last_exc is not None:
        raise last_exc
    raise RuntimeError('SSH command failed without a specific error')

def remote_snmp_get_values_via_ssh(
    proxy_host: str,
    proxy_username: str,
    proxy_password: str,
    target_host: str,
    community: str,
    port: int,
    oid_list: list[str],
    timeout: float | None = None,
    retries: int | None = None,
) -> dict[str, str]:
    if not oid_list:
        return {}

    target_arg = shlex.quote(f'{target_host}:{int(port)}')
    community_arg = shlex.quote(str(community))
    oid_args = ' '.join(shlex.quote(str(oid)) for oid in oid_list)
    snmp_timeout = float(timeout if timeout is not None else get_timeout_settings('ssh').get('snmp_timeout', SNMP_DEFAULT_TIMEOUT))
    snmp_retries = int(retries if retries is not None else SNMP_DEFAULT_RETRIES)
    command = (
        'sh -lc ' + shlex.quote(
            f'snmpget -v2c -c {community_arg} -On -Oqv -t {snmp_timeout:g} -r {snmp_retries} {target_arg} {oid_args}'
        )
    )

    stdout_text, stderr_text, exit_code = ssh_exec_command(proxy_host, proxy_username, proxy_password, command)
    if exit_code != 0:
        raise RuntimeError(stderr_text.strip() or f'snmpget lỗi trên {proxy_host}')

    lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    if len(lines) != len(oid_list):
        raise RuntimeError(f'snmpget trả về {len(lines)} dòng, cần {len(oid_list)} dòng')
    return {oid: value for oid, value in zip(oid_list, lines)}

def remote_snmp_walk_via_ssh(
    proxy_host: str,
    proxy_username: str,
    proxy_password: str,
    target_host: str,
    community: str,
    port: int,
    base_oid: str,
    timeout: float | None = None,
    retries: int | None = None,
) -> list[tuple[str, str]]:
    target_arg = shlex.quote(f'{target_host}:{int(port)}')
    community_arg = shlex.quote(str(community))
    base_oid_arg = shlex.quote(str(base_oid))
    snmp_timeout = float(timeout if timeout is not None else get_timeout_settings('ssh').get('snmp_timeout', SNMP_DEFAULT_TIMEOUT))
    snmp_retries = int(retries if retries is not None else SNMP_DEFAULT_RETRIES)
    command = (
        'sh -lc ' + shlex.quote(
            f'snmpwalk -v2c -c {community_arg} -On -t {snmp_timeout:g} -r {snmp_retries} {target_arg} {base_oid_arg}'
        )
    )

    stdout_text, stderr_text, exit_code = ssh_exec_command(proxy_host, proxy_username, proxy_password, command)
    if exit_code != 0:
        raise RuntimeError(stderr_text.strip() or f'snmpwalk lỗi trên {proxy_host}')

    results: list[tuple[str, str]] = []
    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if not line or ' = ' not in line:
            continue
        oid_text, value_text = line.split(' = ', 1)
        oid_text = oid_text.strip()
        value_text = value_text.strip()
        if ': ' in value_text:
            value_text = value_text.split(': ', 1)[1].strip()
        results.append((oid_text, value_text))
    if not results:
        raise RuntimeError(f'snmpwalk không trả về dữ liệu cho {base_oid} từ {proxy_host}')
    return results


def fetch_metrics_via_proxy_snmp_host_resources(target_host: str, community: str, port: int) -> tuple[dict[str, float], str, str]:
    errors: list[str] = []
    for hop in PROXY_SNMP_HOPS:
        try:
            cpu_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.3.3.1.2',
                timeout=timeout,
                retries=retries,
            )
            type_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.2',
                timeout=timeout,
                retries=retries,
            )
            descr_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.3',
                timeout=timeout,
                retries=retries,
            )
            size_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.5',
                timeout=timeout,
                retries=retries,
            )
            used_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.6',
                timeout=timeout,
                retries=retries,
            )

            cpu_values = [parse_snmp_numeric(value) for _oid, value in cpu_rows]
            if not cpu_values:
                raise RuntimeError('Không có hrProcessorLoad')
            cpu_percent = max(0.0, min(100.0, sum(cpu_values) / len(cpu_values)))

            def by_index(rows: list[tuple[str, str]]) -> dict[str, str]:
                mapped: dict[str, str] = {}
                for oid_text, value_text in rows:
                    idx = oid_text.rsplit('.', 1)[-1]
                    mapped[idx] = value_text
                return mapped

            type_map = by_index(type_rows)
            descr_map = by_index(descr_rows)
            size_map = by_index(size_rows)
            used_map = by_index(used_rows)

            ram_index = None
            for idx, descr in descr_map.items():
                if str(descr).strip().lower() == 'real memory':
                    ram_index = idx
                    break
            if ram_index is None:
                for idx, type_name in type_map.items():
                    type_lc = str(type_name).lower()
                    if 'hrstorageram' in type_lc or type_lc.endswith('hrstorageram'):
                        ram_index = idx
                        break
            if ram_index is None or ram_index not in size_map or ram_index not in used_map:
                raise RuntimeError('Không tìm thấy Real Memory trong hrStorage')

            ram_size = parse_snmp_numeric(size_map[ram_index])
            ram_used = parse_snmp_numeric(used_map[ram_index])
            if ram_size <= 0:
                raise RuntimeError('hrStorageSize của RAM <= 0')
            ram_percent = max(0.0, min(100.0, (ram_used / ram_size) * 100.0))

            storage_total = 0.0
            storage_used_total = 0.0
            for idx, type_name in type_map.items():
                type_lc = str(type_name).lower()
                if 'hrstoragefixeddisk' not in type_lc:
                    continue
                if idx not in size_map or idx not in used_map:
                    continue
                storage_total += parse_snmp_numeric(size_map[idx])
                storage_used_total += parse_snmp_numeric(used_map[idx])
            if storage_total <= 0:
                raise RuntimeError('Không tìm thấy hrStorageFixedDisk hợp lệ')
            storage_percent = max(0.0, min(100.0, (storage_used_total / storage_total) * 100.0))
            return ({'cpu': cpu_percent, 'ram': ram_percent, 'storage': storage_percent}, hop['label'], f"{hop['label']} -> {target_host}:{port} (host-resources)")
        except Exception as exc:
            errors.append(f"{hop['label']}: {exc}")
    raise RuntimeError('; '.join(errors) or 'proxy host-resources snmp failed')


def fetch_metrics_via_proxy_snmp(target_host: str, community: str, port: int, timeout: float | None = None, retries: int | None = None) -> tuple[dict[str, float], str, str]:
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
        hop_label = hop['label']
        try:
            oid_values = remote_snmp_get_values_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                oid_list=oid_list,
                timeout=timeout,
                retries=retries,
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
            return ({'cpu': cpu_percent, 'ram': ram_percent, 'storage': storage_percent}, hop_label, f"{hop_label} -> {target_host}:{port} (ucd-snmp)")
        except Exception as exc:
            errors.append(f"{hop_label}: ucd-snmp {exc}")

        try:
            cpu_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.3.3.1.2',
                timeout=timeout,
                retries=retries,
            )
        except Exception:
            cpu_rows = []

        try:
            type_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.2',
                timeout=timeout,
                retries=retries,
            )
            descr_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.3',
                timeout=timeout,
                retries=retries,
            )
            size_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.5',
                timeout=timeout,
                retries=retries,
            )
            used_rows = remote_snmp_walk_via_ssh(
                proxy_host=hop['host'],
                proxy_username=hop['username'],
                proxy_password=hop['password'],
                target_host=target_host,
                community=community,
                port=port,
                base_oid='1.3.6.1.2.1.25.2.3.1.6',
                timeout=timeout,
                retries=retries,
            )

            def by_index(rows: list[tuple[str, str]]) -> dict[str, str]:
                mapped: dict[str, str] = {}
                for oid_text, value_text in rows:
                    idx = oid_text.rsplit('.', 1)[-1]
                    mapped[idx] = value_text
                return mapped

            type_map = by_index(type_rows)
            descr_map = by_index(descr_rows)
            size_map = by_index(size_rows)
            used_map = by_index(used_rows)

            cpu_percent = 0.0
            if cpu_rows:
                cpu_values = [parse_snmp_numeric(value) for _oid, value in cpu_rows]
                if cpu_values:
                    cpu_percent = max(0.0, min(100.0, sum(cpu_values) / len(cpu_values)))

            ram_index = None
            preferred_ram_labels = {'real memory', 'physical memory'}
            for idx, descr in descr_map.items():
                if str(descr).strip().lower() in preferred_ram_labels:
                    ram_index = idx
                    break
            if ram_index is None:
                for idx, type_name in type_map.items():
                    type_lc = str(type_name).lower()
                    if 'hrstorageram' in type_lc or type_lc.endswith('hrstorageram'):
                        ram_index = idx
                        break
            if ram_index is None or ram_index not in size_map or ram_index not in used_map:
                raise RuntimeError('Không tìm thấy RAM trong hrStorage')

            ram_size = parse_snmp_numeric(size_map[ram_index])
            ram_used = parse_snmp_numeric(used_map[ram_index])
            if ram_size <= 0:
                raise RuntimeError('hrStorageSize của RAM <= 0')
            ram_percent = max(0.0, min(100.0, (ram_used / ram_size) * 100.0))

            storage_total = 0.0
            storage_used_total = 0.0
            for idx, type_name in type_map.items():
                type_lc = str(type_name).lower()
                if 'hrstoragefixeddisk' not in type_lc:
                    continue
                if idx not in size_map or idx not in used_map:
                    continue
                storage_total += parse_snmp_numeric(size_map[idx])
                storage_used_total += parse_snmp_numeric(used_map[idx])
            if storage_total <= 0:
                raise RuntimeError('Không tìm thấy hrStorageFixedDisk hợp lệ')
            storage_percent = max(0.0, min(100.0, (storage_used_total / storage_total) * 100.0))
            return ({'cpu': cpu_percent, 'ram': ram_percent, 'storage': storage_percent}, hop_label, f"{hop_label} -> {target_host}:{port} (host-resources)")
        except Exception as exc:
            errors.append(f"{hop_label}: host-resources {exc}")

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


def log_web_scan(domain: str, message: str, extra: dict[str, Any] | None = None) -> None:
    metric_text = ''
    if extra:
        metric_text = ' | ' + ', '.join(f'{k}={v}' for k, v in extra.items())
    print(f'[WEB_SCAN] {domain} | {message}{metric_text}', flush=True)


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
    ssh_settings = get_timeout_settings('ssh')
    return fetch_metrics_via_proxy_snmp(ip, community, 161, timeout=ssh_settings.get('snmp_timeout'), retries=SNMP_DEFAULT_RETRIES)


def fetch_solution_metrics_snmp(solution: dict[str, Any]) -> tuple[dict[str, str], str, str]:
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint', 'PROXY_SNMP'
    community = solution.get('snmp_community') or 'public'
    port = int(solution.get('snmp_port', 161) or 161)
    try:
        solution_settings = get_timeout_settings('solution')
        metrics, source, note = fetch_metrics_via_proxy_snmp(host, community, port, timeout=solution_settings.get('snmp_timeout'), retries=SNMP_DEFAULT_RETRIES)
        return {
            'cpu_percent': f"{metrics['cpu']:.1f}%",
            'ram_percent': f"{metrics['ram']:.1f}%",
            'storage_percent': f"{metrics['storage']:.1f}%",
        }, note, source
    except Exception as exc:
        return {}, str(exc), 'PROXY_SNMP'



def ssh_exec_multiline(host: str, username: str, password: str, commands: str, connect_timeout: float | None = None, command_timeout: float | None = None, get_pty: bool = False) -> tuple[str, str, int]:
    cmd = 'sh -lc ' + shlex.quote(commands)
    return ssh_exec_command(host, username, password, cmd, timeout=command_timeout, connect_timeout=connect_timeout, get_pty=get_pty)




def ssh_exec_interactive_sequence(
    host: str,
    username: str,
    password: str,
    steps: list[str],
    connect_timeout: float | None = None,
    command_timeout: float | None = None,
    settle_delay: float = 0.45,
    idle_timeout: float = 1.1,
) -> tuple[str, str]:
    ssh_settings = get_timeout_settings('ssh')
    ssh_connect_timeout = float(connect_timeout if connect_timeout is not None else ssh_settings.get('ssh_connect_timeout', SSH_CONNECT_TIMEOUT))
    ssh_command_timeout = float(command_timeout if command_timeout is not None else ssh_settings.get('ssh_command_timeout', SSH_COMMAND_TIMEOUT))
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell: Any | None = None
    transcript_parts: list[str] = []
    try:
        client.connect(
            hostname=host,
            port=22,
            username=username,
            password=password,
            timeout=ssh_connect_timeout,
            auth_timeout=ssh_connect_timeout,
            banner_timeout=ssh_connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(max(1, int(min(ssh_command_timeout, 15.0))))
        shell = client.invoke_shell(width=160, height=400)
        shell.settimeout(0.2)
        deadline = time.monotonic() + max(ssh_command_timeout, 3.0)

        def drain(idle_window: float) -> str:
            chunks: list[str] = []
            last_data_at = time.monotonic()
            while time.monotonic() < deadline:
                try:
                    if shell is not None and shell.recv_ready():
                        data = shell.recv(65535)
                        if not data:
                            break
                        chunks.append(data.decode('utf-8', errors='ignore'))
                        last_data_at = time.monotonic()
                        continue
                except socket.timeout:
                    pass
                if time.monotonic() - last_data_at >= idle_window:
                    break
                time.sleep(0.05)
            return ''.join(chunks)

        initial = drain(settle_delay)
        if initial:
            transcript_parts.append(initial)

        for step in steps:
            if time.monotonic() >= deadline:
                break
            shell.send(step.rstrip('\r\n') + '\n')
            time.sleep(settle_delay)
            chunk = drain(idle_timeout)
            if chunk:
                transcript_parts.append(chunk)

        tail = drain(0.35)
        if tail:
            transcript_parts.append(tail)
        return ''.join(transcript_parts), ''
    finally:
        try:
            if shell is not None:
                shell.close()
        except Exception:
            pass
        client.close()


def parse_solution_service_lines(stdout_text: str) -> list[dict[str, str]]:
    services: list[dict[str, str]] = []
    seen: set[str] = set()
    status_words = r'running|stopped|stop|active|inactive|failed|error|unknown|restarting|disabled|disable|degraded|warning'
    table_row_pattern = re.compile(r'^\|\s*(?P<name>[^|]+?)\s*:?\s*\|\s*(?P<status>[^|]+?)\s*\|$')
    loose_pattern = re.compile(rf'^(?P<name>[A-Za-z0-9._/\- ][A-Za-z0-9._/\- ]{{1,120}}?)\s*[:\-	 ]+\s*(?P<status>{status_words})', re.IGNORECASE)
    trailing_pattern = re.compile(rf'(?P<name>.+?)\s+(?P<status>{status_words})\s*$', re.IGNORECASE)

    def add_service(name: str, status_text: str) -> None:
        normalized_name = re.sub(r'\s+', ' ', str(name or '')).strip(' :-|	')
        if not normalized_name or set(normalized_name) <= {'-'}:
            return
        normalized_status = extract_service_status_text(status_text)
        if normalized_status == 'Unknown' and not re.search(rf'({status_words})', str(status_text or ''), re.IGNORECASE):
            return
        key = normalized_name.lower()
        if key in seen:
            return
        seen.add(key)
        services.append({'name': normalized_name, 'status': normalized_status})

    for raw_line in str(stdout_text or '').splitlines():
        line = str(raw_line or '').strip()
        if not line:
            continue
        if re.fullmatch(r'[+\-|= ]{3,}', line):
            continue
        line = re.sub(r'\[[0-9;]*[A-Za-z]', '', line)

        match = table_row_pattern.match(line)
        if match:
            add_service(match.group('name'), match.group('status'))
            continue

        if '|' in line:
            cells = [re.sub(r'\s+', ' ', cell).strip(' :-|	') for cell in line.split('|') if cell.strip(' :-|	')]
            if len(cells) >= 2:
                add_service(cells[0], cells[1])
                continue

        match = loose_pattern.search(line)
        if match:
            add_service(match.group('name'), match.group('status'))
            continue

        match = trailing_pattern.search(line)
        if match:
            add_service(match.group('name'), match.group('status'))

    return services

def fetch_solution_services_via_ssh(solution: dict[str, Any]) -> tuple[list[dict[str, str]], bool, str, str]:
    host = parse_solution_host(solution.get('endpoint', ''))
    ssh_username = str(solution.get('ssh_username', '')).strip()
    ssh_password = str(solution.get('ssh_password', '')).strip()
    name = str(solution.get('name', '')).strip() or host
    if not host or not ssh_username or not ssh_password:
        return [], False, 'Kết nối SSH thất bại', 'Thiếu endpoint hoặc SSH credentials'

    solution_settings = get_timeout_settings('solution')
    connect_timeout = float(solution_settings.get('ssh_connect_timeout', 5))
    command_timeout = max(12.0, float(solution_settings.get('ssh_command_timeout', 10)) + 10.0)
    menu_wait = min(6.0, max(1.5, command_timeout / 4.0))
    result_wait = min(8.0, max(2.5, command_timeout / 3.0))

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    shell: Any | None = None
    transcript_parts: list[str] = []

    def parse_services_from(text: str) -> list[dict[str, str]]:
        cleaned_text = re.sub(r'+', '', str(text or ''))
        return parse_solution_service_lines(cleaned_text)

    try:
        client.connect(
            hostname=host,
            port=22,
            username=ssh_username,
            password=ssh_password,
            timeout=connect_timeout,
            auth_timeout=connect_timeout,
            banner_timeout=connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(max(1, int(min(command_timeout, 15.0))))
        shell = client.invoke_shell(width=200, height=500)
        shell.settimeout(0.25)
        deadline = time.monotonic() + command_timeout

        def drain(idle_window: float) -> str:
            chunks: list[str] = []
            last_data_at = time.monotonic()
            while time.monotonic() < deadline:
                try:
                    if shell is not None and shell.recv_ready():
                        data = shell.recv(65535)
                        if not data:
                            break
                        chunks.append(data.decode('utf-8', errors='ignore'))
                        last_data_at = time.monotonic()
                        continue
                except socket.timeout:
                    pass
                if time.monotonic() - last_data_at >= idle_window:
                    break
                time.sleep(0.05)
            return ''.join(chunks)

        initial = drain(0.8)
        if initial:
            transcript_parts.append(initial)

        shell.send('su admin\n')
        time.sleep(0.35)
        after_su = drain(menu_wait)
        if after_su:
            transcript_parts.append(after_su)

        shell.send('5\n')
        time.sleep(0.35)
        after_first_5 = drain(result_wait)
        if after_first_5:
            transcript_parts.append(after_first_5)

        stdout_text = ''.join(transcript_parts)
        services = parse_services_from(stdout_text)
        if not services:
            lowered = stdout_text.lower()
            if 'system configuration' in lowered or 'interfaces information' in lowered or 'stop system' in lowered:
                shell.send('5\n')
                time.sleep(0.35)
                after_second_5 = drain(result_wait)
                if after_second_5:
                    transcript_parts.append(after_second_5)
                stdout_text = ''.join(transcript_parts)
                services = parse_services_from(stdout_text)

        if services:
            log_solution_metric_source(name, 'SERVICE_SSH', 'Lấy danh sách service qua SSH thành công (su admin -> 5)', {'services': str(len(services))})
            return services, True, 'Kết nối SSH thành công', f'Lấy service qua SSH từ {host} (su admin -> 5)'

        compact_output = re.sub(r'\s+', ' ', str(stdout_text or '')).strip()
        if stdout_text:
            log_solution_metric_source(name, 'SERVICE_SSH', 'Không parse được service từ output su admin -> 5', {'stdout_len': str(len(stdout_text))})
        note = compact_output[:400] if compact_output else 'Không parse được service từ output su admin -> 5'
        log_solution_metric_source(name, 'SERVICE_SSH', f'Lỗi khi lấy service: {note}')
        return [], False, 'Kết nối SSH thất bại', note
    except Exception as exc:
        note = f'su admin -> 5 thất bại: {exc}'
        log_solution_metric_source(name, 'SERVICE_SSH', f'Lỗi exception: {note}')
        return [], False, 'Kết nối SSH thất bại', note
    finally:
        try:
            if shell is not None:
                shell.close()
        except Exception:
            pass
        client.close()

def fetch_solution_login_via_web(solution: dict[str, Any]) -> tuple[bool, str, str]:
    username = str(solution.get('username', '')).strip()
    password = str(solution.get('password', '')).strip()
    endpoint = str(solution.get('endpoint', '')).strip()
    name = str(solution.get('name', '')).strip()
    if not endpoint or not username or not password:
        return False, 'Đăng nhập thất bại', 'Thiếu thông tin đăng nhập web'
    notes: list[str] = []
    for url in build_solution_urls(endpoint):
        try:
            result = attempt_solution_login(name, endpoint, username, password, url, False, solution)
        except Exception as exc:
            notes.append(f'{url}: {exc}')
            continue
        checked_url = str(result.get('checked_url') or url)
        login_status = str(result.get('login_status') or '').strip()
        note = str(result.get('note') or result.get('status') or login_status or checked_url).strip()
        if login_status == 'Đăng nhập thành công' or bool(result.get('is_success')):
            return True, 'Đăng nhập thành công', f"{note} @ {checked_url}" if checked_url not in note else note
        notes.append(note or checked_url)
    joined = '; '.join([n for n in notes if n])
    lowered = joined.lower()
    if 'timeout' in lowered or 'timed out' in lowered:
        status = 'Đăng nhập thất bại (timeout)'
    elif joined:
        status = f'Đăng nhập thất bại ({joined[:120]})'
    else:
        status = 'Đăng nhập thất bại'
    return False, status, joined


def parse_large_file_lines(stdout_text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in str(stdout_text or '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        size, path = parts[0].strip(), parts[1].strip()
        if size and path:
            rows.append({'size': size, 'path': path})
    return rows


def parse_index_lines(stdout_text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in str(stdout_text or '').splitlines():
        parts = line.split('\t', 1)
        if len(parts) != 2:
            continue
        index_name, log_time = parts[0].strip(), parts[1].strip()
        if index_name:
            rows.append({'index': index_name, 'log_time': log_time or 'NO_DATA'})
    return rows


def fetch_solution_storage_details(solution: dict[str, Any]) -> dict[str, Any]:
    host = parse_solution_host(solution.get('endpoint', ''))
    ssh_username = str(solution.get('ssh_username', '')).strip()
    ssh_password = str(solution.get('ssh_password', '')).strip()
    if not host or not ssh_username or not ssh_password:
        raise ValueError('Thiếu endpoint hoặc SSH credentials')
    settings = get_timeout_settings('solution')
    threshold_gb = float(settings.get('large_file_threshold_gb', 5))
    threshold_bytes = int(threshold_gb * 1024 * 1024 * 1024)
    command = f"find / -xdev -type f -exec du -B1 {{}} + 2>/dev/null | awk '$1 > {threshold_bytes} {{printf \"%.2f GB\\t%s\\n\", $1/1073741824, $2}}' | sort -n"
    stdout_text, stderr_text, exit_code = ssh_exec_multiline(host, ssh_username, ssh_password, command, connect_timeout=settings.get('ssh_connect_timeout'), command_timeout=max(12.0, float(settings.get('ssh_command_timeout', 10))))
    if exit_code != 0 and not stdout_text.strip():
        raise RuntimeError(stderr_text.strip() or 'Không lấy được file lớn')
    return {'threshold_gb': threshold_gb, 'items': parse_large_file_lines(stdout_text), 'raw_error': stderr_text.strip()}


def fetch_solution_index_details(solution: dict[str, Any]) -> dict[str, Any]:
    host = parse_solution_host(solution.get('endpoint', ''))
    ssh_username = str(solution.get('ssh_username', '')).strip()
    ssh_password = str(solution.get('ssh_password', '')).strip()
    if not host or not ssh_username or not ssh_password:
        raise ValueError('Thiếu endpoint hoặc SSH credentials')
    settings = get_timeout_settings('solution')
    command = (
        "for i in $(curl -s \"http://localhost:8686/_cat/indices?h=index\"); do "
        "printf \"%s\\t\" \"$i\"; "
        "curl -s -X GET \"http://localhost:8686/$i/_search\" "
        "-H 'Content-Type: application/json' "
        "-d '{\"size\":1,\"sort\":[{\"LogTime\":{\"order\":\"desc\",\"unmapped_type\":\"date\"}}],\"_source\":[\"LogTime\"]}' "
        "| jq -r '.hits.hits[0]._source.LogTime // \"NO_DATA\"'; "
        "done"
    )
    last_exc: Exception | None = None
    for use_pty in (False, True):
        try:
            stdout_text, stderr_text, exit_code = ssh_exec_multiline(host, ssh_username, ssh_password, command, connect_timeout=settings.get('ssh_connect_timeout'), command_timeout=max(12.0, float(settings.get('ssh_command_timeout', 10))), get_pty=use_pty)
            if exit_code != 0 and not stdout_text.strip():
                raise RuntimeError(stderr_text.strip() or 'Không lấy được index')
            return {'items': parse_index_lines(stdout_text), 'raw_error': stderr_text.strip()}
        except Exception as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise RuntimeError('Không lấy được index')

@app.post('/api/solution-extra')
def solution_extra_route() -> Any:
    try:
        payload = request.get_json(silent=True) or {}
        index = int(payload.get('index'))
        kind = str(payload.get('kind') or '').strip().lower()
        solution = _pick_item_by_index(load_solutions(), index, 'giải pháp')
        cleaned = resolve_solution_secrets(normalize_solution(solution))
        if kind == 'storage':
            data = fetch_solution_storage_details(cleaned)
        elif kind == 'index':
            data = fetch_solution_index_details(cleaned)
        else:
            raise ValueError('Loại chi tiết không hợp lệ.')
        return jsonify({'index': index, 'kind': kind, 'data': data})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 400


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    website = normalize_website(website)
    group = website.get('group', DEFAULT_GROUP_NAME)
    domain = website.get('domain', '')
    public_ip = ''
    try:
        public_ip = resolve_public_ip(domain) or ''
    except Exception:
        public_ip = ''

    last_error = ''
    session = requests.Session()
    session.headers.update({'User-Agent': 'ToolScan/1.0'})
    for candidate in build_candidate_urls(domain):
        try:
            response = session.get(candidate, timeout=get_web_request_timeout(), allow_redirects=True, verify=False)
            checked_url = response.url or candidate
            http_status = str(response.status_code)
            ok = 200 <= response.status_code < 400
            return index, {
                'group': group,
                'domain': domain,
                'public_ip': public_ip,
                'checked_url': checked_url,
                'http_status': http_status,
                'status': '200 OK' if response.status_code == 200 else ('Truy cập được' if ok else f'HTTP {response.status_code}'),
                'is_success': ok,
                'error': '',
            }
        except Exception as exc:
            last_error = str(exc)
    return index, {
        'group': group,
        'domain': domain,
        'public_ip': public_ip,
        'checked_url': build_candidate_urls(domain)[0] if domain else '',
        'http_status': 'N/A',
        'status': 'Không truy cập được',
        'is_success': False,
        'error': last_error,
    }


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
    server = resolve_server_secrets(normalize_server(server))
    ip = server['ip']
    username = server['username']
    group = server.get('group', DEFAULT_GROUP_NAME)
    name = server.get('name', 'server')
    snmp_error = ''
    direct_ssh_error = ''
    proxy_ssh_error = ''

    try:
        snmp_metrics, snmp_source, snmp_note = fetch_server_metrics_snmp(server)
        log_server_metric_source(ip, snmp_source, snmp_note, snmp_metrics)
        return index, {
            'group': group,
            'name': name,
            'ip': ip,
            'username': username,
            'metric_source': snmp_source,
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

    ssh_settings = get_timeout_settings('ssh')
    try:
        metrics, _services, _stderr = execute_metrics_over_ssh(ip, username, server['password'], include_services=False, connect_timeout=ssh_settings.get('ssh_connect_timeout'), command_timeout=ssh_settings.get('ssh_command_timeout'))
        storage_text = metrics.get('storage_percent', 'N/A')
        log_server_metric_source(ip, 'SSH', 'Fallback SSH trực tiếp thành công', metrics)
        return index, {
            'group': group,
            'name': name,
            'ip': ip,
            'username': username,
            'metric_source': 'SSH',
            'cpu_percent': metrics.get('cpu_percent', 'N/A'),
            'ram_percent': metrics.get('ram_percent', 'N/A'),
            'storage_percent': storage_text,
            'status': 'SNMP lỗi, SSH trực tiếp thành công',
            'is_success': True,
            'error': f'SNMP lỗi: {snmp_error}' if snmp_error else '',
        }
    except Exception as exc:
        direct_ssh_error = str(exc)
        log_server_metric_source(ip, 'SSH', f'Lỗi SSH trực tiếp: {direct_ssh_error}')

    try:
        metrics, _services, _stderr = execute_metrics_over_ssh(
            ip,
            username,
            server['password'],
            include_services=False,
            proxy_host=PROXY_SSH_HOP['host'],
            proxy_username=PROXY_SSH_HOP['username'],
            proxy_password=PROXY_SSH_HOP['password'],
            connect_timeout=ssh_settings.get('ssh_connect_timeout'),
            command_timeout=ssh_settings.get('ssh_command_timeout'),
        )
        log_server_metric_source(ip, PROXY_SSH_HOP['label'], 'Fallback SSH qua 132 thành công', metrics)
        return index, {
            'group': group,
            'name': name,
            'ip': ip,
            'username': username,
            'metric_source': PROXY_SSH_HOP['label'],
            'cpu_percent': metrics.get('cpu_percent', 'N/A'),
            'ram_percent': metrics.get('ram_percent', 'N/A'),
            'storage_percent': metrics.get('storage_percent', 'N/A'),
            'status': f'SNMP lỗi, SSH trực tiếp lỗi, {PROXY_SSH_HOP["label"]} thành công',
            'is_success': True,
            'error': '; '.join([part for part in [f'SNMP lỗi: {snmp_error}' if snmp_error else '', f'SSH trực tiếp lỗi: {direct_ssh_error}' if direct_ssh_error else ''] if part]),
        }
    except Exception as exc:
        proxy_ssh_error = str(exc)
        log_server_metric_source(ip, PROXY_SSH_HOP['label'], f'Lỗi: {proxy_ssh_error}')

    return index, {
        'group': group,
        'name': name,
        'ip': ip,
        'username': username,
        'metric_source': 'NONE',
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'status': 'Thất bại theo toàn bộ luồng 150 -> 132 -> SSH trực tiếp -> SSH qua 132',
        'is_success': False,
        'error': f'Proxy SNMP lỗi: {snmp_error}; SSH trực tiếp lỗi: {direct_ssh_error}; SSH qua 132 lỗi: {proxy_ssh_error}',
    }


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = resolve_solution_secrets(normalize_solution(solution))
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



def run_parallel_checks(
    items: list[dict[str, Any]],
    checker: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
    max_workers: int | None = None,
    progress_callback: Callable[[int, dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any] | None] = [None] * len(items)
    if max_workers is None:
        max_workers = min(16, max(4, len(items))) or 1
    else:
        max_workers = max(1, min(int(max_workers), max(1, len(items)))) if items else 1
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(checker, index, item): index for index, item in enumerate(items)}
        for future in as_completed(future_map):
            index = future_map[future]
            src_item = items[index]
            try:
                _, result = future.result()
            except Exception as exc:
                result = {
                    'group': src_item.get('group', DEFAULT_GROUP_NAME),
                    'name': src_item.get('name') or src_item.get('ip') or src_item.get('domain') or f'item-{index + 1}',
                    'ip': src_item.get('ip', ''),
                    'domain': src_item.get('domain', ''),
                    'endpoint': src_item.get('endpoint', ''),
                    'status': 'Lỗi xử lý',
                    'is_success': False,
                    'error': str(exc),
                    'login_method': None,
                    'login_debug': [f'run_parallel_checks exception: {exc}'],
                }
            results[index] = result
            if progress_callback is not None:
                progress_callback(index, result)
    return [item for item in results if item is not None]


def _job_summary(kind: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    if kind == 'solution-all':
        running_count = sum(1 for item in results if item.get('is_running'))
        login_success_count = sum(1 for item in results if item.get('is_success'))
        issue_count = len(results) - login_success_count
        running_services = sum(int(item.get('service_running_count', 0) or 0) for item in results)
        total_services = sum(int(item.get('service_total_count', 0) or 0) for item in results)
        return {'total': len(results), 'running': running_count, 'login_success': login_success_count, 'issues': issue_count, 'running_services': running_services, 'total_services': total_services}
    success_count = sum(1 for item in results if item.get('is_success'))
    return {'total': len(results), 'success': success_count, 'failed': len(results) - success_count}


def _update_scan_job_progress(job_id: str, index: int, result: dict[str, Any]) -> None:
    with SCAN_JOB_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            return
        partial_results = job.setdefault('partial_results', {})
        partial_results[str(index)] = result
        ordered = [partial_results[key] for key in sorted(partial_results.keys(), key=lambda x: int(x))]
        job['progress'] = {
            'completed': len(ordered),
            'total': int(job.get('total_items', 0) or 0),
            'summary': _job_summary(job['kind'], ordered),
        }


def _create_scan_job(kind: str, payload: dict[str, Any]) -> str:
    _cleanup_scan_jobs()
    job_id = uuid.uuid4().hex
    with SCAN_JOB_LOCK:
        SCAN_JOBS[job_id] = {
            'job_id': job_id,
            'kind': kind,
            'payload': payload,
            'status': 'running',
            'created_at': time.time(),
            'started_at': time.time(),
            'finished_at': None,
            'result': None,
            'error': None,
            'partial_results': {},
            'progress': {'completed': 0, 'total': 0, 'summary': {}},
            'total_items': 0,
        }
    return job_id


def _scan_job_status_payload(job_id: str) -> dict[str, Any]:
    with SCAN_JOB_LOCK:
        job = SCAN_JOBS.get(job_id)
        if not job:
            raise KeyError(job_id)
        partial_map = job.get('partial_results', {}) or {}
        partial_results = [partial_map[key] for key in sorted(partial_map.keys(), key=lambda x: int(x))]
        return {
            'job_id': job['job_id'],
            'kind': job['kind'],
            'status': job['status'],
            'result': job.get('result'),
            'partial_results': partial_results,
            'progress': job.get('progress') or {'completed': len(partial_results), 'total': job.get('total_items', 0), 'summary': {}},
            'error': job.get('error'),
            'created_at': job.get('created_at'),
            'started_at': job.get('started_at'),
            'finished_at': job.get('finished_at'),
        }


def _run_scan_job(job_id: str, kind: str, payload: dict[str, Any]) -> None:
    try:
        group = payload.get('group')
        if kind == 'ssh-all':
            items = filter_items_by_group(load_servers(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['total_items'] = len(items)
            results = run_parallel_checks(items, check_one_server, max_workers=MAX_SSH_SCAN_WORKERS, progress_callback=lambda i, r: _update_scan_job_progress(job_id, i, r))
            result = {'results': results, 'summary': _job_summary(kind, results)}
        elif kind == 'web-all':
            items = filter_items_by_group(load_websites(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['total_items'] = len(items)
            results = run_parallel_checks(items, check_one_website, max_workers=MAX_WEB_SCAN_WORKERS, progress_callback=lambda i, r: _update_scan_job_progress(job_id, i, {**r, 'has_scanned': True}))
            results = [{**item, 'has_scanned': True} for item in results]
            result = {'results': results, 'summary': _job_summary(kind, results)}
        elif kind == 'solution-all':
            items = filter_items_by_group(load_solutions(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['total_items'] = len(items)
            results = run_parallel_checks(items, check_one_solution, max_workers=MAX_SOLUTION_SCAN_WORKERS, progress_callback=lambda i, r: _update_scan_job_progress(job_id, i, r))
            result = {'results': results, 'summary': _job_summary(kind, results)}
        elif kind == 'ssh-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_servers(), index, 'SSH')
            _, one_result = check_one_server(index, item)
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        elif kind == 'web-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_websites(), index, 'website')
            _, one_result = check_one_website(index, item)
            one_result = {**one_result, 'has_scanned': True}
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        elif kind == 'solution-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_solutions(), index, 'giải pháp')
            _, one_result = check_one_solution(index, item)
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        else:
            raise ValueError(f'Unknown scan job kind: {kind}')
        _finish_scan_job(job_id, result=result)
    except Exception as exc:
        _finish_scan_job(job_id, error=str(exc))


# ===== Final overrides for v4 stability =====
ALLOWED_SECRET_ENV_KEYS = [
    'PASS_MAC_DINH',
    'PASS_GIAI_PHAP',
    'PASS_SSH_ROOT',
    'PASS_SSH_SERVER_01',
    'PASS_SSH_SERVER_02',
    'SNMPSTRING_MAC_DINH',
    'PROXY_SNMP_USERNAME',
    'PROXY_SNMP_PASSWORD',
    'PROXY_SNMP_HOST_1',
    'PROXY_SNMP_HOST_2',
]
ENV_OPTIONAL_TUNING_MARKER = '# Optional tuning'


def read_env_file(path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    lines = path.read_text(encoding='utf-8').splitlines()
    for raw_line in lines:
        if raw_line.strip().startswith(ENV_OPTIONAL_TUNING_MARKER):
            break
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in raw_line:
            continue
        key, value = raw_line.split('=', 1)
        key = key.strip()
        value = value.strip()
        if key not in ALLOWED_SECRET_ENV_KEYS:
            continue
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        result[key] = value
    return result


def write_env_file(values: dict[str, Any], path: Path | None = None) -> dict[str, str]:
    path = path or ENV_PATH
    existing_lines = path.read_text(encoding='utf-8').splitlines() if path.exists() else []
    normalized = {str(k).strip().upper(): str(v) for k, v in (values or {}).items() if str(k).strip().upper() in ALLOWED_SECRET_ENV_KEYS}
    output_lines: list[str] = []
    seen: set[str] = set()
    inserted_missing = False
    for raw_line in existing_lines:
        stripped = raw_line.strip()
        if stripped.startswith(ENV_OPTIONAL_TUNING_MARKER):
            for key in ALLOWED_SECRET_ENV_KEYS:
                if key in normalized and key not in seen:
                    output_lines.append(f'{key}={normalized[key]}')
                    seen.add(key)
            inserted_missing = True
            output_lines.append(raw_line)
            continue
        if inserted_missing:
            output_lines.append(raw_line)
            continue
        if not stripped or stripped.startswith('#') or '=' not in raw_line:
            output_lines.append(raw_line)
            continue
        key = raw_line.split('=', 1)[0].strip()
        if key in ALLOWED_SECRET_ENV_KEYS:
            if key in normalized:
                output_lines.append(f'{key}={normalized[key]}')
                seen.add(key)
            else:
                output_lines.append(raw_line)
                seen.add(key)
        else:
            output_lines.append(raw_line)
    if not inserted_missing:
        for key in ALLOWED_SECRET_ENV_KEYS:
            if key in normalized and key not in seen:
                output_lines.append(f'{key}={normalized[key]}')
                seen.add(key)
    path.write_text('\n'.join(output_lines).rstrip() + ('\n' if output_lines else ''), encoding='utf-8')
    return read_env_file(path)


def parse_solution_host(endpoint: str) -> str:
    value = str(endpoint or '').strip()
    if not value:
        return ''
    if value.startswith(('http://', 'https://')):
        return urlparse(value).hostname or ''
    if '://' in value:
        try:
            return urlparse(value).hostname or ''
        except Exception:
            pass
    return value.split('/', 1)[0].split(':', 1)[0].strip()


def fetch_solution_metrics_snmp(solution: dict[str, Any]) -> tuple[dict[str, str], str, str]:
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint', 'PROXY_SNMP'
    community = solution.get('snmp_community') or 'public'
    try:
        solution_settings = get_timeout_settings('solution')
        metrics, source, note = fetch_metrics_via_proxy_snmp(host, community, 161, timeout=solution_settings.get('snmp_timeout'), retries=SNMP_DEFAULT_RETRIES)
        return {
            'cpu_percent': f"{metrics['cpu']:.1f}%",
            'ram_percent': f"{metrics['ram']:.1f}%",
            'storage_percent': f"{metrics['storage']:.1f}%",
        }, note, source
    except Exception as exc:
        return {}, str(exc), 'PROXY_SNMP'


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    website = normalize_website(website)
    group = website.get('group', DEFAULT_GROUP_NAME)
    domain = website.get('domain', '')
    public_ip = ''
    try:
        public_ip = resolve_public_ip(domain) or ''
    except Exception:
        public_ip = ''

    last_error = ''
    last_candidate = ''
    session = requests.Session()
    session.headers.update({'User-Agent': 'ToolScan/1.0'})
    timeout = (WEBSITE_CONNECT_TIMEOUT, WEBSITE_READ_TIMEOUT)
    for candidate in build_candidate_urls(domain):
        last_candidate = candidate
        try:
            response = session.get(candidate, timeout=timeout, allow_redirects=True, verify=False)
            checked_url = response.url or candidate
            http_status = str(response.status_code)
            ok = 200 <= response.status_code < 400
            return index, {
                'group': group,
                'domain': domain,
                'public_ip': public_ip,
                'checked_url': checked_url,
                'http_status': http_status,
                'status': '200 OK' if response.status_code == 200 else f'HTTP {response.status_code}',
                'is_success': ok,
                'error': '',
            }
        except requests.exceptions.RequestException as exc:
            response = getattr(exc, 'response', None)
            if response is not None:
                checked_url = response.url or candidate
                http_status = str(response.status_code)
                ok = 200 <= response.status_code < 400
                return index, {
                    'group': group,
                    'domain': domain,
                    'public_ip': public_ip,
                    'checked_url': checked_url,
                    'http_status': http_status,
                    'status': '200 OK' if response.status_code == 200 else f'HTTP {response.status_code}',
                    'is_success': ok,
                    'error': str(exc),
                }
            last_error = str(exc)
        except Exception as exc:
            last_error = str(exc)
    return index, {
        'group': group,
        'domain': domain,
        'public_ip': public_ip,
        'checked_url': last_candidate or (build_candidate_urls(domain)[0] if domain else ''),
        'http_status': 'N/A',
        'status': 'Không truy cập được',
        'is_success': False,
        'error': last_error,
    }


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = resolve_solution_secrets(normalize_solution(solution))
    result = build_solution_result_base(cleaned)
    name = cleaned['name']
    checkservice = True

    snmp_metrics, snmp_note, snmp_source = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        log_solution_metric_source(name, snmp_source, snmp_note, snmp_metrics)
        result.update(snmp_metrics)
        result['metric_source'] = snmp_source
        result['status'] = 'Lấy thông số thành công qua SNMP'
        result['running_status'] = 'Đang chạy'
        result['is_success'] = True
        result['is_running'] = True
        result['note'] = snmp_note
        if cleaned.get('ssh_username') and cleaned.get('ssh_password'):
            _ssh_metrics, ssh_note, services = fetch_solution_metrics_ssh_priority(cleaned)
            if services:
                apply_services_to_solution_result(result, services, checkservice)
                result['note'] = f"{snmp_note}; {ssh_note}".strip('; ')
        return index, result

    log_solution_metric_source(name, 'PROXY_SNMP', snmp_note or 'Proxy SNMP failed')

    ssh_metrics, ssh_note, services = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        log_solution_metric_source(name, 'SSH_FLOW', ssh_note, ssh_metrics)
        result.update(ssh_metrics)
        result['metric_source'] = 'SSH@132' if 'SSH@132' in ssh_note else 'SSH'
        result['status'] = 'Lấy thông số thành công qua SSH'
        result['running_status'] = 'Đang chạy'
        result['is_success'] = True
        result['is_running'] = True
        result['note'] = f'SNMP lỗi: {snmp_note}; SSH: {ssh_note}'.strip('; ')
        apply_services_to_solution_result(result, services, checkservice)
        return index, result

    result['status'] = 'Không lấy được thông số'
    result['running_status'] = 'Không chạy'
    result['login_status'] = 'Không dùng web'
    result['metric_source'] = 'NONE'
    result['is_success'] = False
    result['is_running'] = False
    result['note'] = f'SNMP lỗi: {snmp_note}; SSH lỗi: {ssh_note}'.strip('; ')
    apply_services_to_solution_result(result, [], checkservice)
    return index, result


# ===== Final overrides for v5 =====
PROXY_SNMP_USERNAME = 'root'
PROXY_SNMP_PASSWORD = os.getenv('PASS_SSH_ROOT', os.getenv('PROXY_SNMP_PASSWORD', '')).strip()
PROXY_SNMP_HOPS = [
    {'host': os.getenv('PROXY_SNMP_HOST_1', '163.223.58.150'), 'username': 'root', 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@150'},
    {'host': os.getenv('PROXY_SNMP_HOST_2', '163.223.58.132'), 'username': 'root', 'password': PROXY_SNMP_PASSWORD, 'label': 'SNMP@132'},
]
PROXY_SSH_HOP = {'host': os.getenv('PROXY_SSH_HOST', os.getenv('PROXY_SNMP_HOST_2', '163.223.58.132')), 'username': 'root', 'password': PROXY_SNMP_PASSWORD, 'label': 'SSH@132'}
ALLOWED_SECRET_ENV_KEYS = [
    'PASS_MAC_DINH',
    'PASS_GIAI_PHAP',
    'PASS_SSH_ROOT',
    'PASS_SSH_SERVER_01',
    'PASS_SSH_SERVER_02',
    'SNMPSTRING_MAC_DINH',
    'PROXY_SNMP_HOST_1',
    'PROXY_SNMP_HOST_2',
]

def fetch_solution_services_via_web(solution: dict[str, Any]) -> tuple[list[dict[str, str]], bool, str, str]:
    username = str(solution.get('username', '')).strip()
    password = str(solution.get('password', '')).strip()
    endpoint = str(solution.get('endpoint', '')).strip()
    name = str(solution.get('name', '')).strip()
    if not endpoint or not username or not password:
        return [], False, 'Đăng nhập thất bại', 'Thiếu thông tin đăng nhập web'
    notes: list[str] = []
    for url in build_solution_urls(endpoint):
        try:
            result = attempt_solution_login(name, endpoint, username, password, url, True, solution)
        except Exception as exc:
            notes.append(f'{url}: {exc}')
            continue
        services = result.get('services') or []
        login_status = str(result.get('login_status') or '').strip()
        checked_url = result.get('checked_url') or url
        note = result.get('note') or result.get('status') or login_status or checked_url
        if login_status == 'Đăng nhập thành công' or services:
            return services, True, 'Đăng nhập thành công', f"{note} @ {checked_url}" if checked_url not in str(note) else str(note)
        notes.append(note)
    joined = '; '.join([n for n in notes if n])
    lowered = joined.lower()
    if 'timeout' in lowered or 'timed out' in lowered:
        status = 'Đăng nhập thất bại (timeout)'
    elif joined:
        status = f'Dăng nhập thất bại ({joined[:120]})'.replace('Dăng','Đăng')
    else:
        status = 'Đăng nhập thất bại'
    return [], False, status, joined


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = resolve_solution_secrets(normalize_solution(solution))
    result = build_solution_result_base(cleaned)
    name = cleaned['name']
    checkservice = True

    services, login_ok, login_status, web_note = fetch_solution_services_via_web(cleaned)
    result['status'] = login_status
    result['login_status'] = login_status
    if services:
        apply_services_to_solution_result(result, services, checkservice)
    else:
        apply_services_to_solution_result(result, [], checkservice)

    snmp_metrics, snmp_note, snmp_source = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        log_solution_metric_source(name, snmp_source, snmp_note, snmp_metrics)
        result.update(snmp_metrics)
        result['metric_source'] = snmp_source
        result['is_success'] = login_ok
        result['is_running'] = login_ok and (result.get('service_running_count', 0) > 0 if services else True)
        result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
        result['note'] = '; '.join([x for x in [snmp_note, web_note] if x])
        return index, result

    log_solution_metric_source(name, 'PROXY_SNMP', snmp_note or 'Proxy SNMP failed')
    ssh_metrics, ssh_note, _ssh_services = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        log_solution_metric_source(name, 'SSH_FLOW', ssh_note, ssh_metrics)
        result.update(ssh_metrics)
        result['metric_source'] = 'SSH@132' if 'SSH@132' in ssh_note else 'SSH'
        result['is_success'] = login_ok
        result['is_running'] = login_ok and (result.get('service_running_count', 0) > 0 if services else True)
        result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
        result['note'] = '; '.join([x for x in [f'SNMP lỗi: {snmp_note}' if snmp_note else '', ssh_note, web_note] if x])
        return index, result

    result['metric_source'] = 'NONE'
    result['is_success'] = login_ok
    result['is_running'] = login_ok and result.get('service_running_count', 0) > 0
    result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
    result['note'] = '; '.join([x for x in [f'SNMP lỗi: {snmp_note}' if snmp_note else '', f'SSH lỗi: {ssh_note}' if ssh_note else '', web_note] if x])
    return index, result

    log_solution_metric_source(name, 'PROXY_SNMP', snmp_note or 'Proxy SNMP failed')
    ssh_metrics, ssh_note, _ssh_services = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        log_solution_metric_source(name, 'SSH_FLOW', ssh_note, ssh_metrics)
        result.update(ssh_metrics)
        result['metric_source'] = 'SSH@132' if 'SSH@132' in ssh_note else 'SSH'
        result['status'] = 'Lấy thông số thành công qua SSH'
        result['running_status'] = 'Đang chạy'
        result['is_success'] = True
        result['is_running'] = True
        services, web_note = fetch_solution_services_via_web(cleaned)
        if services:
            apply_services_to_solution_result(result, services, checkservice)
        result['note'] = '; '.join([x for x in [f'SNMP lỗi: {snmp_note}' if snmp_note else '', ssh_note, web_note] if x])
        return index, result

    services, web_note = fetch_solution_services_via_web(cleaned)
    if services:
        apply_services_to_solution_result(result, services, checkservice)
        result['status'] = 'Đăng nhập web thành công, đã lấy service'
        result['running_status'] = 'Đang chạy' if result.get('service_running_count', 0) > 0 else 'Có service dừng'
        result['is_success'] = True
        result['is_running'] = result.get('service_running_count', 0) > 0
        result['note'] = '; '.join([x for x in [f'SNMP lỗi: {snmp_note}' if snmp_note else '', f'SSH lỗi: {ssh_note}' if ssh_note else '', web_note] if x])
        return index, result

    result['status'] = 'Không lấy được thông số'
    result['running_status'] = 'Không chạy'
    result['login_status'] = 'Không đăng nhập được web giải pháp'
    result['metric_source'] = 'NONE'
    result['is_success'] = False
    result['is_running'] = False
    result['note'] = '; '.join([x for x in [f'SNMP lỗi: {snmp_note}' if snmp_note else '', f'SSH lỗi: {ssh_note}' if ssh_note else '', web_note] if x])
    apply_services_to_solution_result(result, [], checkservice)
    return index, result

# ===== Final stable overrides for scan logic =====
WEB_REQUEST_TIMEOUT = (WEBSITE_CONNECT_TIMEOUT, WEBSITE_READ_TIMEOUT)


def get_web_request_timeout() -> tuple[float, float]:
    settings = get_timeout_settings('web')
    return (float(settings.get('web_connect_timeout', WEBSITE_CONNECT_TIMEOUT)), float(settings.get('web_read_timeout', WEBSITE_READ_TIMEOUT)))


def build_candidate_urls(domain: str) -> list[str]:
    value = str(domain or '').strip()
    if not value:
        return []
    if value.startswith(('http://', 'https://')):
        return [value]
    return [f'https://{value}', f'http://{value}']


def build_solution_urls(endpoint: str) -> list[str]:
    value = str(endpoint or '').strip()
    if not value:
        return []
    if value.startswith(('http://', 'https://')):
        parsed = urlparse(value)
        return [f'{parsed.scheme}://{parsed.netloc}']
    return [f'https://{value}', f'http://{value}']


def build_solution_result_base(solution: dict[str, Any]) -> dict[str, Any]:
    return {
        'group': normalize_group_name(solution.get('group', DEFAULT_GROUP_NAME)),
        'name': str(solution.get('name', '')).strip(),
        'endpoint': str(solution.get('endpoint', '')).strip(),
        'status': 'Chưa quét',
        'login_status': 'Chưa quét',
        'running_status': 'Chưa quét',
        'metric_source': '',
        'cpu_percent': 'N/A',
        'ram_percent': 'N/A',
        'storage_percent': 'N/A',
        'is_success': False,
        'is_running': False,
        'services': [],
        'service_summary': '0/0 đang chạy',
        'service_running_count': 0,
        'service_total_count': 0,
        'large_files': [],
        'large_file_threshold_gb': get_timeout_settings('solution').get('large_file_threshold_gb', 5),
        'large_file_error': '',
        'index_items': [],
        'index_error': '',
        'note': '',
        'error': '',
    }


def apply_services_to_solution_result(result: dict[str, Any], services: list[dict[str, Any]], checkservice: bool = True) -> dict[str, Any]:
    normalized: list[dict[str, str]] = []
    for item in services or []:
        name = str(item.get('name') or item.get('title') or '').strip()
        status = str(item.get('status') or '').strip() or 'Unknown'
        if name:
            normalized.append({'name': name, 'status': status})
    running = sum(1 for svc in normalized if str(svc.get('status', '')).strip().lower() == 'running')
    result['services'] = normalized
    result['service_running_count'] = running
    result['service_total_count'] = len(normalized)
    result['service_summary'] = f'{running}/{len(normalized)} đang chạy' if normalized else 'Chưa lấy được service'
    return result


def _extract_ssh_metrics(stdout_text: str, context: str = 'SSH') -> dict[str, str]:
    lines = [line.strip() for line in str(stdout_text or '').splitlines() if line.strip()]
    cpu_line = next((line for line in lines if '%Cpu' in line or 'Cpu(s)' in line), '')
    mem_line = next((line for line in lines if ' Mem' in line or 'Mem :' in line), '')
    storage_line = ''
    for line in reversed(lines):
        if '%' in line:
            storage_line = line
            break
    metrics: dict[str, str] = {}
    if cpu_line:
        cpu_idle_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*id', cpu_line, re.IGNORECASE)
        if cpu_idle_match:
            cpu_idle = parse_float_loose(cpu_idle_match.group(1))
            metrics['cpu_percent'] = f'{max(0.0, min(100.0, 100.0 - cpu_idle)):.1f}%'
    if mem_line:
        mem_numbers = re.findall(r'([0-9]+(?:[.,][0-9]+)?)', mem_line)
        if len(mem_numbers) >= 3:
            mem_total = parse_float_loose(mem_numbers[0])
            used_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s+used', mem_line, re.IGNORECASE)
            mem_used = parse_float_loose(used_match.group(1)) if used_match else parse_float_loose(mem_numbers[2])
            if mem_total > 0:
                metrics['ram_percent'] = f'{max(0.0, min(100.0, (mem_used / mem_total) * 100.0)):.1f}%'
    if storage_line:
        storage_match = re.search(r'([0-9]+(?:[.,][0-9]+)?)\s*%', storage_line)
        if storage_match:
            storage_value = parse_float_loose(storage_match.group(1))
            metrics['storage_percent'] = f'{max(0.0, min(100.0, storage_value)):.1f}%'
    if not metrics:
        raise RuntimeError(f'Output {context} không đủ dữ liệu: {stdout_text.strip()}')
    metrics.setdefault('cpu_percent', 'N/A')
    metrics.setdefault('ram_percent', 'N/A')
    metrics.setdefault('storage_percent', 'N/A')
    return metrics


def execute_metrics_over_ssh(
    host: str,
    username: str,
    password: str,
    include_services: bool = False,
    proxy_host: str | None = None,
    proxy_username: str | None = None,
    proxy_password: str | None = None,
    connect_timeout: float | None = None,
    command_timeout: float | None = None,
) -> tuple[dict[str, str], list[dict[str, str]], str]:
    metrics_command = """sh -lc '
LC_ALL=C top -bn1 | grep -m1 "%Cpu\\|Cpu(s)" ;
LC_ALL=C top -bn1 | grep -m1 "MiB Mem\\|KiB Mem\\|GiB Mem" ;
df -P / | awk "NR==2 {print \\$5}"
'"""
    services: list[dict[str, str]] = []
    ssh_settings = get_timeout_settings('ssh')
    current_connect_timeout = float(connect_timeout if connect_timeout is not None else ssh_settings.get('ssh_connect_timeout', SSH_CONNECT_TIMEOUT))
    current_command_timeout = float(command_timeout if command_timeout is not None else ssh_settings.get('ssh_command_timeout', SSH_COMMAND_TIMEOUT))
    if proxy_host:
        target = shlex.quote(host)
        user = shlex.quote(username)
        pw = shlex.quote(password)
        remote_cmd = (
            'sshpass -p ' + pw + ' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
            '-o ConnectTimeout=' + str(int(current_connect_timeout)) + f' {user}@{target} ' + shlex.quote(metrics_command)
        )
        cmd = 'sh -lc ' + shlex.quote(remote_cmd)
        stdout_text, stderr_text, exit_code = ssh_exec_command(proxy_host, proxy_username or 'root', proxy_password or '', cmd, timeout=current_command_timeout, connect_timeout=current_connect_timeout)
        if exit_code != 0 and not stdout_text.strip():
            raise RuntimeError(stderr_text.strip() or f'Jump SSH lỗi trên {proxy_host}->{host}')
        return _extract_ssh_metrics(stdout_text, 'Jump SSH'), services, stderr_text

    stdout_text, stderr_text, exit_code = ssh_exec_command(host, username, password, metrics_command, timeout=current_command_timeout, connect_timeout=current_connect_timeout)
    if exit_code != 0 and not stdout_text.strip():
        raise RuntimeError(stderr_text.strip() or f'SSH lỗi trên {host}')
    return _extract_ssh_metrics(stdout_text, 'SSH'), services, stderr_text


def fetch_solution_metrics_ssh_priority(solution: dict[str, Any]) -> tuple[dict[str, str], str, list[dict[str, str]]]:
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint', []
    ssh_username = str(solution.get('ssh_username', '')).strip()
    ssh_password = str(solution.get('ssh_password', '')).strip()
    if not ssh_username or not ssh_password:
        return {}, 'missing ssh credentials', []
    try:
        solution_settings = get_timeout_settings('solution')
        metrics, services, _stderr = execute_metrics_over_ssh(host, ssh_username, ssh_password, include_services=False, connect_timeout=solution_settings.get('ssh_connect_timeout'), command_timeout=solution_settings.get('ssh_command_timeout'))
        return metrics, f'SSH trực tiếp thành công tới {host}', services
    except Exception as direct_exc:
        try:
            metrics, services, _stderr = execute_metrics_over_ssh(
                host,
                ssh_username,
                ssh_password,
                include_services=False,
                proxy_host=PROXY_SSH_HOP['host'],
                proxy_username=PROXY_SSH_HOP['username'],
                proxy_password=PROXY_SSH_HOP['password'],
                connect_timeout=solution_settings.get('ssh_connect_timeout'),
                command_timeout=solution_settings.get('ssh_command_timeout'),
            )
            return metrics, f'{PROXY_SSH_HOP["label"]} thành công tới {host} sau lỗi SSH trực tiếp: {direct_exc}', services
        except Exception as proxy_exc:
            return {}, f'SSH trực tiếp lỗi: {direct_exc}; SSH qua 132 lỗi: {proxy_exc}', []


def extract_service_status_text(raw_text: Any) -> str:
    text = re.sub(r'\s+', ' ', str(raw_text or '')).strip()
    if not text:
        return 'Unknown'
    match = re.search(r'\b(running|stopped|stop|active|inactive|failed|error|unknown|restarting|disabled|disable|degraded|warning)\b', text, re.IGNORECASE)
    if not match:
        return text
    value = match.group(1).lower()
    mapping = {
        'running': 'Running',
        'active': 'Running',
        'stopped': 'Stopped',
        'stop': 'Stopped',
        'inactive': 'Stopped',
        'failed': 'Failed',
        'error': 'Error',
        'unknown': 'Unknown',
        'restarting': 'Restarting',
        'disabled': 'Disabled',
        'disable': 'Disabled',
        'degraded': 'Degraded',
        'warning': 'Warning',
    }
    return mapping.get(value, value.title())


def _direct_text_from_element(el: Any) -> str:
    if el is None:
        return ''
    chunks: list[str] = []
    for child in getattr(el, 'contents', []):
        if isinstance(child, str):
            part = re.sub(r'\s+', ' ', child).strip()
            if part:
                chunks.append(part)
    if chunks:
        return ' '.join(chunks).strip()
    return re.sub(r'\s+', ' ', el.get_text(' ', strip=True)).strip()


def extract_service_name_and_status(container: Any) -> tuple[str, str]:
    name = ''
    title_el = container.select_one('div.engine-title, .engine-title')
    if title_el is not None:
        name = _direct_text_from_element(title_el)
    if not name:
        for selector in ['.service-name', '.name', 'strong', 'b', 'td:first-child']:
            el = container.select_one(selector)
            if el is not None:
                name = re.sub(r'\s+', ' ', el.get_text(' ', strip=True)).strip()
                if name:
                    break

    status = ''
    badge_el = container.select_one('div.status-badge, .status-badge')
    if badge_el is not None:
        status = extract_service_status_text(badge_el.get('title') or _direct_text_from_element(badge_el) or badge_el.get_text(' ', strip=True))
    if not status or status == 'Unknown':
        status = extract_service_status_text(container.get('class', [])) if isinstance(container.get('class', []), list) else 'Unknown'
    if not status or status == 'Unknown':
        classes = ' '.join(container.get('class', []))
        status = extract_service_status_text(classes)
    return name, status or 'Unknown'


def parse_solution_services_from_html(html_text: str) -> list[dict[str, str]]:
    soup = BeautifulSoup(html_text or '', 'html.parser')
    services: list[dict[str, str]] = []
    seen: set[str] = set()
    for container in soup.select('div.engine-card'):
        name, status = extract_service_name_and_status(container)
        name = re.sub(r'\s+', ' ', str(name or '')).strip()
        if not name:
            continue
        normalized_key = name.lower()
        if normalized_key in seen:
            continue
        seen.add(normalized_key)
        services.append({'name': name, 'status': status or 'Unknown'})
    return services


def looks_like_logged_in(response_text: str) -> bool:
    text = (response_text or '').lower()
    return ('engine-card' in text and 'engine-title' in text) or ('logout' in text) or ('status-badge' in text)


def attempt_solution_login(name: str, endpoint: str, username: str, password: str, base_url: str, checkservice: bool, solution: dict[str, Any]) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)
    solution_settings = get_timeout_settings('solution')
    timeout = (float(solution_settings.get('web_connect_timeout', WEBSITE_CONNECT_TIMEOUT)), float(solution_settings.get('web_read_timeout', SOLUTION_HTTP_TIMEOUT)))
    try:
        resp = session.get(base_url, timeout=timeout, verify=False, allow_redirects=True)
        checked_url = resp.url or base_url
        html_text = resp.text or ''
        if looks_like_logged_in(html_text):
            services = parse_solution_services_from_html(html_text)
            return {'login_status': 'Đăng nhập thành công', 'checked_url': checked_url, 'services': services, 'note': checked_url}
        soup = BeautifulSoup(html_text, 'html.parser')
        form = soup.find('form')
        if not form:
            return {'login_status': 'Đăng nhập thất bại', 'checked_url': checked_url, 'services': [], 'note': 'Không tìm thấy form đăng nhập'}
        action = form.get('action') or checked_url
        submit_url = urljoin(checked_url, action)
        payload: dict[str, str] = {}
        user_field = None
        pass_field = None
        for inp in form.find_all('input'):
            input_type = str(inp.get('type', 'text')).lower()
            input_name = str(inp.get('name') or inp.get('id') or '').strip()
            if not input_name:
                continue
            input_value = str(inp.get('value') or '')
            lowered = input_name.lower()
            if input_type == 'password' or any(h in lowered for h in PASSWORD_HINTS):
                pass_field = input_name
            elif any(h in lowered for h in USERNAME_HINTS):
                user_field = input_name
            payload[input_name] = input_value
        user_field = user_field or 'username'
        pass_field = pass_field or 'password'
        payload[user_field] = username
        payload[pass_field] = password
        post_resp = session.post(submit_url, data=payload, timeout=timeout, verify=False, allow_redirects=True)
        checked_url = post_resp.url or submit_url
        html_text = post_resp.text or ''
        services = parse_solution_services_from_html(html_text)
        if looks_like_logged_in(html_text) or services:
            return {'login_status': 'Đăng nhập thành công', 'checked_url': checked_url, 'services': services, 'note': checked_url}
        return {'login_status': 'Đăng nhập thất bại', 'checked_url': checked_url, 'services': services, 'note': f'HTTP {post_resp.status_code} @ {checked_url}'}
    except requests.exceptions.Timeout:
        return {'login_status': 'Đăng nhập thất bại (timeout)', 'checked_url': base_url, 'services': [], 'note': 'timeout'}
    except Exception as exc:
        return {'login_status': 'Đăng nhập thất bại', 'checked_url': base_url, 'services': [], 'note': str(exc)}


def fetch_solution_services_via_web(solution: dict[str, Any]) -> tuple[list[dict[str, str]], bool, str, str]:
    return fetch_solution_services_via_ssh(solution)


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    website = normalize_website(website)
    group = website.get('group', DEFAULT_GROUP_NAME)
    domain = website.get('domain', '')
    public_ip = ''
    try:
        public_ip = resolve_public_ip(domain) or ''
    except Exception:
        public_ip = ''
    last_error = ''
    last_candidate = ''
    session = requests.Session()
    session.headers.update({'User-Agent': 'ToolScan/1.0'})
    for candidate in build_candidate_urls(domain):
        last_candidate = candidate
        try:
            response = session.get(candidate, timeout=get_web_request_timeout(), allow_redirects=True, verify=False)
            checked_url = response.url or candidate
            http_status = str(response.status_code)
            ok = 200 <= response.status_code < 400
            result = {'group': group, 'domain': domain, 'public_ip': public_ip, 'checked_url': checked_url, 'http_status': http_status, 'status': f'HTTP {response.status_code}', 'is_success': ok, 'error': ''}
            log_web_scan(domain, 'HTTP request completed', {'url': checked_url, 'status': http_status, 'ok': str(ok)})
            return index, result
        except requests.exceptions.RequestException as exc:
            response = getattr(exc, 'response', None)
            if response is not None:
                checked_url = response.url or candidate
                http_status = str(response.status_code)
                ok = 200 <= response.status_code < 400
                result = {'group': group, 'domain': domain, 'public_ip': public_ip, 'checked_url': checked_url, 'http_status': http_status, 'status': f'HTTP {response.status_code}', 'is_success': ok, 'error': str(exc)}
                log_web_scan(domain, 'HTTP request returned response with exception', {'url': checked_url, 'status': http_status, 'ok': str(ok)})
                return index, result
            last_error = str(exc)
        except Exception as exc:
            last_error = str(exc)
    log_web_scan(domain, 'HTTP request failed', {'candidate': last_candidate or '', 'error': last_error})
    return index, {'group': group, 'domain': domain, 'public_ip': public_ip, 'checked_url': last_candidate or (build_candidate_urls(domain)[0] if domain else ''), 'http_status': 'N/A', 'status': 'Không truy cập được', 'is_success': False, 'error': last_error}


def check_one_server(index: int, server: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    server = resolve_server_secrets(normalize_server(server))
    ip = server['ip']
    username = server['username']
    group = server.get('group', DEFAULT_GROUP_NAME)
    name = server.get('name', 'server')
    snmp_error = ''
    direct_ssh_error = ''
    proxy_ssh_error = ''
    try:
        snmp_metrics, snmp_source, snmp_note = fetch_server_metrics_snmp(server)
        log_server_metric_source(ip, snmp_source, snmp_note, snmp_metrics)
        return index, {'group': group, 'name': name, 'ip': ip, 'username': username, 'metric_source': snmp_source, 'cpu_percent': f"{snmp_metrics['cpu']:.1f}%", 'ram_percent': f"{snmp_metrics['ram']:.1f}%", 'storage_percent': f"{snmp_metrics['storage']:.1f}%", 'status': f'{snmp_source} thành công', 'is_success': True, 'error': ''}
    except Exception as exc:
        snmp_error = str(exc)
        log_server_metric_source(ip, 'PROXY_SNMP', f'Lỗi: {snmp_error}')
    ssh_settings = get_timeout_settings('ssh')
    try:
        metrics, _services, _stderr = execute_metrics_over_ssh(ip, username, server['password'], include_services=False, connect_timeout=ssh_settings.get('ssh_connect_timeout'), command_timeout=ssh_settings.get('ssh_command_timeout'))
        return index, {'group': group, 'name': name, 'ip': ip, 'username': username, 'metric_source': 'SSH', 'cpu_percent': metrics.get('cpu_percent', 'N/A'), 'ram_percent': metrics.get('ram_percent', 'N/A'), 'storage_percent': metrics.get('storage_percent', 'N/A'), 'status': 'SSH trực tiếp thành công', 'is_success': True, 'error': f'SNMP lỗi: {snmp_error}' if snmp_error else ''}
    except Exception as exc:
        direct_ssh_error = str(exc)
        log_server_metric_source(ip, 'SSH', f'Lỗi: {direct_ssh_error}')
    try:
        metrics, _services, _stderr = execute_metrics_over_ssh(ip, username, server['password'], include_services=False, proxy_host=PROXY_SSH_HOP['host'], proxy_username=PROXY_SSH_HOP['username'], proxy_password=PROXY_SSH_HOP['password'], connect_timeout=ssh_settings.get('ssh_connect_timeout'), command_timeout=ssh_settings.get('ssh_command_timeout'))
        return index, {'group': group, 'name': name, 'ip': ip, 'username': username, 'metric_source': PROXY_SSH_HOP['label'], 'cpu_percent': metrics.get('cpu_percent', 'N/A'), 'ram_percent': metrics.get('ram_percent', 'N/A'), 'storage_percent': metrics.get('storage_percent', 'N/A'), 'status': f'{PROXY_SSH_HOP["label"]} thành công', 'is_success': True, 'error': '; '.join([part for part in [f'SNMP lỗi: {snmp_error}' if snmp_error else '', f'SSH trực tiếp lỗi: {direct_ssh_error}' if direct_ssh_error else ''] if part])}
    except Exception as exc:
        proxy_ssh_error = str(exc)
        log_server_metric_source(ip, PROXY_SSH_HOP['label'], f'Lỗi: {proxy_ssh_error}')
    return index, {'group': group, 'name': name, 'ip': ip, 'username': username, 'metric_source': 'NONE', 'cpu_percent': 'N/A', 'ram_percent': 'N/A', 'storage_percent': 'N/A', 'status': 'Thất bại', 'is_success': False, 'error': '; '.join([part for part in [f'Proxy SNMP lỗi: {snmp_error}' if snmp_error else '', f'SSH trực tiếp lỗi: {direct_ssh_error}' if direct_ssh_error else '', f'SSH qua 132 lỗi: {proxy_ssh_error}' if proxy_ssh_error else ''] if part])}


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = resolve_solution_secrets(normalize_solution(solution))
    result = build_solution_result_base(cleaned)
    services, login_ok, login_status, service_note = fetch_solution_services_via_ssh(cleaned)
    result['status'] = login_status
    result['login_status'] = login_status
    apply_services_to_solution_result(result, services, True)

    snmp_metrics, snmp_note, snmp_source = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        result.update(snmp_metrics)
        result['metric_source'] = snmp_source
        result['is_success'] = login_ok
        result['is_running'] = login_ok and (result.get('service_running_count', 0) > 0 if services else False)
        result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
        result['note'] = '; '.join([x for x in [service_note, snmp_note] if x])
        log_solution_metric_source(result.get('name', ''), snmp_source, 'Hoàn tất quét solution', {'status': result['status'], 'service_summary': result.get('service_summary', ''), 'storage': result.get('storage_percent', 'N/A')})
        return index, result

    ssh_metrics, ssh_note, _ssh_services = fetch_solution_metrics_ssh_priority(cleaned)
    if ssh_metrics:
        result.update(ssh_metrics)
        result['metric_source'] = 'SSH@132' if 'SSH@132' in ssh_note else 'SSH'
        result['is_success'] = login_ok
        result['is_running'] = login_ok and (result.get('service_running_count', 0) > 0 if services else False)
        result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
        result['note'] = '; '.join([x for x in [service_note, f'SNMP lỗi: {snmp_note}' if snmp_note else '', ssh_note] if x])
        log_solution_metric_source(result.get('name', ''), result['metric_source'], 'Hoàn tất quét solution', {'status': result['status'], 'service_summary': result.get('service_summary', ''), 'storage': result.get('storage_percent', 'N/A')})
        return index, result

    result['metric_source'] = 'NONE'
    result['is_success'] = login_ok
    result['is_running'] = login_ok and (result.get('service_running_count', 0) > 0)
    result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
    result['note'] = '; '.join([x for x in [service_note, f'SNMP lỗi: {snmp_note}' if snmp_note else '', f'SSH lỗi: {ssh_note}' if ssh_note else ''] if x])
    result['error'] = result['note'] if not login_ok else ''
    log_solution_metric_source(result.get('name', ''), 'NONE', 'Quét solution thất bại', {'status': result['status'], 'note': result['note']})
    return index, result


# ===== Final overrides for v5 phased solution scan =====
def _solution_worker_count(total_items: int) -> int:
    base = max(MAX_SOLUTION_SCAN_WORKERS * 3, 6)
    return max(1, min(base, max(1, total_items)))


def _storage_percent_over_threshold(value: Any, threshold: float = 80.0) -> bool:
    try:
        parsed = float(str(value or '').replace('%', '').replace(',', '.').strip())
        return parsed > threshold
    except Exception:
        return False




def _solution_metric_phase(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, Any]]:
    cleaned = resolve_solution_secrets(normalize_solution(solution))
    result = build_solution_result_base(cleaned)
    result['name'] = cleaned.get('name', '')
    result['endpoint'] = cleaned.get('endpoint', '')
    result['status'] = '30%'
    result['login_status'] = 'Đang chờ bước service / file lớn / đăng nhập'
    snmp_metrics, snmp_note, snmp_source = fetch_solution_metrics_snmp(cleaned)
    if snmp_metrics:
        result.update(snmp_metrics)
        result['metric_source'] = snmp_source
        result['note'] = '; '.join([x for x in [result.get('note', ''), snmp_note] if x])
    else:
        ssh_metrics, ssh_note, _ssh_services = fetch_solution_metrics_ssh_priority(cleaned)
        if ssh_metrics:
            result.update(ssh_metrics)
            result['metric_source'] = 'SSH@132' if 'SSH@132' in ssh_note else 'SSH'
            result['note'] = '; '.join([x for x in [result.get('note', ''), f'SNMP lỗi: {snmp_note}' if snmp_note else '', ssh_note] if x])
        else:
            result['metric_source'] = 'NONE'
            result['note'] = '; '.join([x for x in [result.get('note', ''), f'SNMP lỗi: {snmp_note}' if snmp_note else '', f'SSH lỗi: {ssh_note}' if 'ssh_note' in locals() and ssh_note else ''] if x])
    log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', 'Phase 1 metrics xong', {'storage': result.get('storage_percent', 'N/A')})
    return index, result, cleaned

def _solution_service_phase(result: dict[str, Any], cleaned: dict[str, Any]) -> dict[str, Any]:
    result = dict(result)
    services, service_ok, service_status, service_note = fetch_solution_services_via_ssh(cleaned)
    apply_services_to_solution_result(result, services, True)
    result['service_status'] = service_status or ('Đã lấy service' if services else 'Không lấy được service')
    result['note'] = '; '.join([x for x in [result.get('note', ''), service_note] if x])
    if not services:
        result['service_summary'] = 'Chưa lấy được service'
    log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', 'Phase 2 service xong', {'service_summary': result.get('service_summary', '')})
    return result

def _solution_storage_phase(result: dict[str, Any], cleaned: dict[str, Any]) -> dict[str, Any]:
    result = dict(result)
    if _storage_percent_over_threshold(result.get('storage_percent')):
        try:
            storage_data = fetch_solution_storage_details(cleaned)
            result['large_files'] = storage_data.get('items', [])
            result['large_file_threshold_gb'] = storage_data.get('threshold_gb', result.get('large_file_threshold_gb'))
            result['large_file_error'] = storage_data.get('raw_error', '')
            log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', 'Phase 3 file lớn xong', {'files': str(len(result.get('large_files', [])))})
        except Exception as exc:
            result['large_files'] = []
            result['large_file_error'] = str(exc)
            result['note'] = '; '.join([x for x in [result.get('note', ''), f'File lớn lỗi: {exc}'] if x])
            log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', f'Phase 3 file lớn lỗi: {exc}')
    return result

def _solution_login_phase(result: dict[str, Any], cleaned: dict[str, Any]) -> dict[str, Any]:
    result = dict(result)
    login_ok, login_status, login_note = fetch_solution_login_via_web(cleaned)
    result['status'] = '60%'
    result['login_status'] = login_status or 'Đã kiểm tra đăng nhập'
    result['is_success'] = login_ok
    result['is_running'] = result.get('service_running_count', 0) > 0
    result['running_status'] = 'Đang chạy' if result['is_running'] else 'Không chạy'
    result['note'] = '; '.join([x for x in [result.get('note', ''), login_note] if x])
    if not login_ok:
        result['error'] = login_note or login_status
    log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', 'Phase 4 login xong', {'login_status': result.get('login_status', ''), 'service_summary': result.get('service_summary', '')})
    return result

def _solution_index_phase(result: dict[str, Any], cleaned: dict[str, Any]) -> dict[str, Any]:
    result = dict(result)
    try:
        data = fetch_solution_index_details(cleaned)
        result['index_items'] = data.get('items', [])
        result['index_error'] = data.get('raw_error', '')
        result['status'] = '100%'
        log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', 'Phase 5 index xong', {'indices': str(len(result.get('index_items', [])))})
    except Exception as exc:
        result['index_items'] = []
        result['index_error'] = str(exc)
        result['status'] = '100%'
        log_solution_metric_source(result.get('name', ''), result.get('metric_source', 'NONE') or 'NONE', f'Phase 5 index lỗi: {exc}')
    return result

def _solution_finalize_after_metrics(result: dict[str, Any], cleaned: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    phase2_result = _solution_login_phase(_solution_storage_phase(_solution_service_phase(result, cleaned), cleaned), cleaned)
    final_result = _solution_index_phase(phase2_result, cleaned)
    return phase2_result, final_result

def _check_one_solution_full(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    index, result, cleaned = _solution_metric_phase(index, solution)
    result = _solution_service_phase(result, cleaned)
    result = _solution_storage_phase(result, cleaned)
    result = _solution_login_phase(result, cleaned)
    result = _solution_index_phase(result, cleaned)
    return index, result
def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    return _check_one_solution_full(index, solution)



def _run_solution_all_job(job_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    total_steps = len(items) * 3
    worker_count = _solution_worker_count(len(items))
    with SCAN_JOB_LOCK:
        if job_id in SCAN_JOBS:
            SCAN_JOBS[job_id]['total_items'] = total_steps

    partial_by_idx: dict[int, dict[str, Any]] = {}
    finalized_results: list[dict[str, Any] | None] = [None] * len(items)
    progress_done = 0

    def push_progress(idx: int, result_obj: dict[str, Any], increment: int) -> None:
        nonlocal progress_done
        progress_done += increment
        partial_by_idx[idx] = {**result_obj, 'has_scanned': True}
        ordered = [partial_by_idx[i] for i in sorted(partial_by_idx.keys())]
        with SCAN_JOB_LOCK:
            job = SCAN_JOBS.get(job_id)
            if job:
                job['partial_results'] = {str(i): partial_by_idx[i] for i in sorted(partial_by_idx.keys())}
                job['progress'] = {'completed': progress_done, 'total': total_steps, 'summary': _job_summary('solution-all', ordered)}

    def run_one(idx: int, item: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        _idx, result, cleaned = _solution_metric_phase(idx, item)
        push_progress(idx, result, 1)
        result = _solution_service_phase(result, cleaned)
        result = _solution_storage_phase(result, cleaned)
        result = _solution_login_phase(result, cleaned)
        push_progress(idx, result, 1)
        result = _solution_index_phase(result, cleaned)
        push_progress(idx, result, 1)
        return idx, result

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(run_one, idx, item): idx for idx, item in enumerate(items)}
        for future in as_completed(future_map):
            idx, final_result = future.result()
            finalized_results[idx] = final_result

    done = [item for item in finalized_results if item is not None]
    return {'results': done, 'summary': _job_summary('solution-all', done)}

def _run_scan_job(job_id: str, kind: str, payload: dict[str, Any]) -> None:

    try:
        group = payload.get('group')
        if kind == 'ssh-all':
            items = filter_items_by_group(load_servers(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['total_items'] = len(items)
            results = run_parallel_checks(items, check_one_server, max_workers=MAX_SSH_SCAN_WORKERS, progress_callback=lambda i, r: _update_scan_job_progress(job_id, i, r))
            result = {'results': results, 'summary': _job_summary(kind, results)}
        elif kind == 'web-all':
            items = filter_items_by_group(load_websites(), group)
            with SCAN_JOB_LOCK:
                if job_id in SCAN_JOBS:
                    SCAN_JOBS[job_id]['total_items'] = len(items)
            results = run_parallel_checks(items, check_one_website, max_workers=MAX_WEB_SCAN_WORKERS, progress_callback=lambda i, r: _update_scan_job_progress(job_id, i, {**r, 'has_scanned': True}))
            results = [{**item, 'has_scanned': True} for item in results]
            result = {'results': results, 'summary': _job_summary(kind, results)}
        elif kind == 'solution-all':
            items = filter_items_by_group(load_solutions(), group)
            result = _run_solution_all_job(job_id, items)
        elif kind == 'ssh-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_servers(), index, 'SSH')
            _, one_result = check_one_server(index, item)
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        elif kind == 'web-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_websites(), index, 'website')
            _, one_result = check_one_website(index, item)
            one_result = {**one_result, 'has_scanned': True}
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        elif kind == 'solution-one':
            index = int(payload['index'])
            item = _pick_item_by_index(load_solutions(), index, 'giải pháp')
            _, one_result = check_one_solution(index, item)
            _update_scan_job_progress(job_id, 0, one_result)
            result = {'index': index, 'result': one_result}
        else:
            raise ValueError(f'Unknown scan job kind: {kind}')
        _finish_scan_job(job_id, result=result)
    except Exception as exc:
        _finish_scan_job(job_id, error=str(exc))
