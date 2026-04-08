from __future__ import annotations

import html as html_lib
import json
import os
import re
import shlex
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
        Integer,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        getCmd,
        nextCmd,
    )
except Exception:
    CommunityData = ContextData = Integer = ObjectIdentity = ObjectType = SnmpEngine = UdpTransportTarget = None
    getCmd = nextCmd = None

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright
except Exception:
    PlaywrightTimeoutError = Exception
    sync_playwright = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / 'data'
SSH_DATABASE_PATH = DATA_DIR / 'servers.json'
WEB_DATABASE_PATH = DATA_DIR / 'websites.json'
SOLUTION_DATABASE_PATH = DATA_DIR / 'solutions.json'

DEFAULT_SERVERS = [
    {'ip': '163.223.58.4', 'username': 'root', 'password': 't0ikonho@123'},
    {'ip': '163.223.58.5', 'username': 'root', 'password': 't0ikonho@123'},
    {'ip': '163.223.58.12', 'username': 'root', 'password': 'v2labadmin@123'},
    {'ip': '163.223.58.13', 'username': 'root', 'password': 'v2labadmin@123'},
    {'ip': '163.223.58.14', 'username': 'root', 'password': 'v2labadmin@123'},
]

DEFAULT_WEBSITES = [
    {'domain': 'v2secure.vn'},
    {'domain': 'jira-int.v2secure.vn'},
    {'domain': 'confluence-int.v2secure.vn'},
    {'domain': 'authentik-int.v2secure.vn'},
    {'domain': 'mail.v2secure.vn'},
]

DEFAULT_SOLUTIONS = [
    {'name': 'SIEM', 'endpoint': '163.223.58.132', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True, 'snmp_enabled': True, 'snmp_community': 'v2secure', 'snmp_port': 161},
    {'name': 'WAF01', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.130', 'username': 'admin', 'password': 'admin', 'checkservice': True},
    {'name': 'WAF02', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.131', 'username': 'admin', 'password': 'admin', 'checkservice': True},
    {'name': 'EDR', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.133', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NAC', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.134', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_MCNB', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.135', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_CSDL', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.136', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_Tools', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.137', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_LAN', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.138', 'username': 'admin', 'password': 'admin', 'checkservice': True},
    {'name': 'NIPS_DMZ', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.139', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_V2Cloud', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.144', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'NIPS_MGT', 'snmp_enabled': True, 'snmp_community': 'public', 'snmp_port': 161, 'endpoint': '163.223.58.146', 'username': 'admin', 'password': 'V2SocAdmin@828682', 'checkservice': True},
    {'name': 'PAM', 'endpoint': '163.223.58.143', 'username': 'TTS_SOC_DNDuyen', 'password': 'DNDuyenSOC@2026$#', 'checkservice': False, 'snmp_enabled': False, 'snmp_community': 'public', 'snmp_port': 161},
    {'name': 'NOC', 'endpoint': 'http://163.223.58.140/cacti/', 'username': 'admin', 'password': 'V2labadmin@123', 'checkservice': False, 'snmp_enabled': False, 'snmp_community': 'public', 'snmp_port': 161},
]

REMOTE_SCRIPT = r"""read cpu user nice system idle iowait irq softirq steal guest < /proc/stat
user1=$user
total1=$((user + nice + system + idle + iowait + irq + softirq + steal))

sleep 1

read cpu user nice system idle iowait irq softirq steal guest < /proc/stat
user2=$user
total2=$((user + nice + system + idle + iowait + irq + softirq + steal))

cpu_usage=$(awk -v user1="$user1" -v user2="$user2" -v total1="$total1" -v total2="$total2" 'BEGIN {
    diff_total = total2 - total1;
    diff_user = user2 - user1;
    if (diff_total <= 0) {
        printf "0.0";
    } else {
        printf "%.1f", (diff_user / diff_total) * 100;
    }
}')

ram_usage=$(free | awk '/^Mem:/ {
    total = $2;
    available = $7;
    used = total - available;
    if (total <= 0) {
        printf "0.0";
    } else {
        printf "%.1f", (used / total) * 100;
    }
}')

storage_usage=$(df -P / | awk 'NR==2 {
    gsub(/%/, "", $5);
    print $5;
}')

printf "CPU=%s
RAM=%s
STORAGE=%s
" "$cpu_usage" "$ram_usage" "$storage_usage"
"""

CPU_RE = re.compile(r'CPU=([0-9]+(?:\.[0-9]+)?)')
RAM_RE = re.compile(r'RAM=([0-9]+(?:\.[0-9]+)?)')
STORAGE_RE = re.compile(r'STORAGE=([0-9]+(?:\.[0-9]+)?)')
PERCENT_VALUE_RE = re.compile(r'([0-9]+(?:\.[0-9]+)?)\s*%')
ID_BLOCK_RE_TEMPLATE = r'<(?P<tag>[a-zA-Z0-9:_-]+)[^>]*\bid=["\']{element_id}["\'][^>]*>(?P<content>.*?)</(?P=tag)>'
PASSWORD_INPUT_RE = re.compile(r'<input[^>]+type=["\']?password', re.IGNORECASE)
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
    }


def validate_servers(servers: list[dict[str, Any]]) -> list[dict[str, str]]:
    cleaned = [normalize_server(item) for item in servers]
    if len(cleaned) != 5:
        raise ValueError('Database SSH phải có đúng 5 dòng máy.')
    for index, server in enumerate(cleaned, start=1):
        if not (server['ip'] and server['username'] and server['password']):
            raise ValueError(f'Dòng SSH {index} đang thiếu IP, username hoặc password.')
    return cleaned


def normalize_website(raw: Any) -> dict[str, str]:
    value = raw if isinstance(raw, str) else raw.get('domain', '')
    return {'domain': str(value).strip().replace(' ', '')}


def validate_websites(websites: list[Any]) -> list[dict[str, str]]:
    cleaned = [normalize_website(item) for item in websites]
    if len(cleaned) != 5:
        raise ValueError('Database website phải có đúng 5 dòng domain.')
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
        'checkservice': to_bool(raw.get('checkservice', False)),
        'snmp_enabled': to_bool(raw.get('snmp_enabled', raw.get('use_snmp', True))),
        'snmp_port': int(str(raw.get('snmp_port', raw.get('port', 161)) or '161')),
        'snmp_version': str(raw.get('snmp_version', raw.get('version', '2c'))).strip().lower() or '2c',
        'snmp_community': str(raw.get('snmp_community', raw.get('community', 'public'))).strip() or 'public',
        'snmp_timeout': int(str(raw.get('snmp_timeout', 2)) or '2'),
        'snmp_retries': int(str(raw.get('snmp_retries', 0)) or '0'),
    }


def validate_solutions(solutions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cleaned = [normalize_solution(item) for item in solutions]
    if not cleaned:
        raise ValueError('Database giải pháp phải có ít nhất 1 dòng.')
    for index, solution in enumerate(cleaned, start=1):
        if not (solution['name'] and solution['endpoint'] and solution['username'] and solution['password']):
            raise ValueError(f'Dòng giải pháp {index} đang thiếu tên, endpoint, username hoặc password.')
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


@app.post('/api/scan')
def scan_servers() -> Any:
    servers = load_servers()
    results = run_parallel_checks(servers, check_one_server)
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
    results = run_parallel_checks(websites, check_one_website)
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
    results = run_parallel_checks(solutions, check_one_solution)
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


def run_parallel_checks(
    items: list[dict[str, Any]],
    checker: Callable[[int, dict[str, Any]], tuple[int, dict[str, Any]]],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any] | None] = [None] * len(items)
    max_workers = min(6, len(items)) or 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(checker, index, item): index
            for index, item in enumerate(items)
        }
        for future in as_completed(future_map):
            index = future_map[future]
            try:
                _, result = future.result()
            except Exception as exc:  # noqa: BLE001
                item = items[index]
                result = {
                    'name': item.get('name') or item.get('ip') or item.get('domain') or f'item-{index + 1}',
                    'status': 'Lỗi xử lý',
                    'is_success': False,
                    'error': str(exc),
                }
            results[index] = result

    return [item for item in results if item is not None]


def check_one_server(index: int, server: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    ip = server['ip']
    username = server['username']
    password = server['password']

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=ip,
            port=22,
            username=username,
            password=password,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        command = f"sh -lc {shlex.quote(REMOTE_SCRIPT)}"
        stdin, stdout, stderr = client.exec_command(command, timeout=20)
        _ = stdin

        stdout_text = stdout.read().decode('utf-8', errors='ignore')
        stderr_text = stderr.read().decode('utf-8', errors='ignore')
        exit_code = stdout.channel.recv_exit_status()

        metrics = parse_metrics(stdout_text)
        if exit_code != 0 and not metrics:
            raise RuntimeError(stderr_text.strip() or 'Lệnh kiểm tra tài nguyên trả về lỗi.')
        if not metrics:
            raise RuntimeError('Không đọc được CPU, RAM hoặc Storage từ máy đích.')

        return index, {
            'ip': ip,
            'username': username,
            'cpu_percent': f"{metrics['cpu']:.1f}%",
            'ram_percent': f"{metrics['ram']:.1f}%",
            'storage_percent': f"{metrics['storage']:.1f}%",
            'status': 'SSH thành công',
            'is_success': True,
            'error': '',
        }
    except Exception as exc:  # noqa: BLE001
        return index, {
            'ip': ip,
            'username': username,
            'cpu_percent': 'N/A',
            'ram_percent': 'N/A',
            'storage_percent': 'N/A',
            'status': 'Không SSH được',
            'is_success': False,
            'error': str(exc),
        }
    finally:
        client.close()


def parse_metrics(output: str) -> dict[str, float]:
    cpu_match = CPU_RE.search(output)
    ram_match = RAM_RE.search(output)
    storage_match = STORAGE_RE.search(output)
    if not (cpu_match and ram_match and storage_match):
        return {}
    return {
        'cpu': float(cpu_match.group(1)),
        'ram': float(ram_match.group(1)),
        'storage': float(storage_match.group(1)),
    }


def check_one_website(index: int, website: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    domain = normalize_website(website)['domain']
    candidate_urls = build_candidate_urls(domain)
    errors: list[str] = []

    for url in candidate_urls:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,
                stream=True,
                headers=DEFAULT_HEADERS,
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


def snmp_supported() -> bool:
    return all(item is not None for item in (SnmpEngine, CommunityData, ContextData, ObjectIdentity, ObjectType, UdpTransportTarget, getCmd, nextCmd))


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


def format_percent(value: float | int | None) -> str:
    if value is None:
        return 'N/A'
    try:
        return f"{float(value):.1f}%"
    except Exception:
        return 'N/A'


def fetch_solution_metrics_snmp(solution: dict[str, Any]) -> tuple[dict[str, str], str]:
    if not solution.get('snmp_enabled'):
        return {}, 'SNMP disabled'
    if not snmp_supported():
        return {}, 'pysnmp not installed'
    host = parse_solution_host(solution.get('endpoint', ''))
    if not host:
        return {}, 'invalid endpoint'

    community = solution.get('snmp_community') or 'public'
    port = int(solution.get('snmp_port', 161) or 161)
    timeout = int(solution.get('snmp_timeout', 2) or 2)
    retries = int(solution.get('snmp_retries', 0) or 0)

    metrics = {'cpu_percent': 'N/A', 'ram_percent': 'N/A', 'storage_percent': 'N/A'}

    cpu_rows = snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.2.1.25.3.3.1.2')
    cpu_vals: list[float] = []
    for _, val in cpu_rows:
        try:
            cpu_vals.append(float(int(val)))
        except Exception:
            try:
                cpu_vals.append(float(str(val)))
            except Exception:
                pass
    if cpu_vals:
        metrics['cpu_percent'] = format_percent(sum(cpu_vals) / len(cpu_vals))

    mem_values = snmp_get_values(
        host,
        community,
        port,
        timeout,
        retries,
        ['1.3.6.1.4.1.2021.4.5.0', '1.3.6.1.4.1.2021.4.6.0'],
    )
    try:
        total_real = float(int(mem_values['1.3.6.1.4.1.2021.4.5.0']))
        avail_real = float(int(mem_values['1.3.6.1.4.1.2021.4.6.0']))
        used_real = max(total_real - avail_real, 0.0)
        if total_real > 0:
            metrics['ram_percent'] = format_percent((used_real / total_real) * 100.0)
    except Exception:
        pass

    descr_rows = snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.2.1.25.2.3.1.3')
    alloc_rows = dict(snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.2.1.25.2.3.1.4'))
    size_rows = dict(snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.2.1.25.2.3.1.5'))
    used_rows = dict(snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.2.1.25.2.3.1.6'))

    selected_index = None
    for oid, val in descr_rows:
        descr = str(val).strip().lower()
        idx = oid.rsplit('.', 1)[-1]
        if descr in ('/', '/root', 'rootfs') or descr.endswith(' /'):
            selected_index = idx
            break
    if selected_index is None and descr_rows:
        for oid, val in descr_rows:
            descr = str(val).strip().lower()
            idx = oid.rsplit('.', 1)[-1]
            if 'root' in descr or '/' in descr:
                selected_index = idx
                break
    if selected_index is not None:
        try:
            alloc = float(int(alloc_rows[f'1.3.6.1.2.1.25.2.3.1.4.{selected_index}']))
            size = float(int(size_rows[f'1.3.6.1.2.1.25.2.3.1.5.{selected_index}']))
            used = float(int(used_rows[f'1.3.6.1.2.1.25.2.3.1.6.{selected_index}']))
            total_units = size * alloc
            used_units = used * alloc
            if total_units > 0:
                metrics['storage_percent'] = format_percent((used_units / total_units) * 100.0)
        except Exception:
            pass

    if metrics['storage_percent'] == 'N/A':
        dsk_rows = snmp_walk_values(host, community, port, timeout, retries, '1.3.6.1.4.1.2021.9.1.9')
        dsk_vals: list[float] = []
        for _, val in dsk_rows:
            try:
                dsk_vals.append(float(int(val)))
            except Exception:
                pass
        if dsk_vals:
            metrics['storage_percent'] = format_percent(max(dsk_vals))

    if all(metrics[k] == 'N/A' for k in metrics):
        return {}, f'SNMP no metrics from {host}:{port}'
    return metrics, f'SNMP metrics from {host}:{port}'


def check_one_solution(index: int, solution: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    cleaned = normalize_solution(solution)
    name = cleaned['name']
    endpoint = cleaned['endpoint']
    username = cleaned['username']
    password = cleaned['password']
    checkservice = cleaned['checkservice']

    candidate_urls = build_solution_urls(endpoint)
    best_result: dict[str, Any] | None = None

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
            'note': 'Không tạo được URL kiểm tra.',
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


def score_metric_html(html: str) -> int:
    if not html:
        return 0

    score = 0
    for marker in (
        'cpuUsageText',
        'memoryUsageText',
        'ramUsageText',
        'diskUsageText',
        'storageUsageText',
    ):
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
            resp = session.get(url, timeout=12, allow_redirects=True)
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
            resp = session.get(url, timeout=12, allow_redirects=True)
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
                    payload = {
                        'name': cookie.name,
                        'value': cookie.value,
                        'url': base_url,
                        'path': cookie.path or '/',
                    }
                    cookie_payloads.append(payload)
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

    try:
        response = session.get(url, timeout=12, allow_redirects=True)
    except RequestException as exc:
        return {
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
        }

    initial_status = response.status_code
    initial_status_text = format_status(response)
    checked_url = response.url or url
    is_running = initial_status < 500
    running_status = 'Đang chạy' if is_running else f'Lỗi dịch vụ {initial_status}'
    content_type = (response.headers.get('Content-Type') or '').lower()

    if initial_status in (401, 403) or 'www-authenticate' in response.headers:
        auth_result = try_basic_auth(session, url, username, password)
        if auth_result is not None:
            return finalize_solution_result(
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
                solution=solution,
            )

    if 'html' in content_type:
        form_info = extract_login_form(response.text, checked_url)
        if form_info is not None:
            try:
                submit_response = submit_login_form(session, form_info, checked_url, username, password)
            except RequestException as exc:
                return {
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
                }

            return finalize_solution_result(
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
                solution=solution,
            )

        if initial_status < 400:
            return {
                'name': name,
                'endpoint': endpoint,
                'username': username,
                'checked_url': checked_url,
                'http_status': initial_status_text,
                'login_status': 'Không tìm thấy form đăng nhập',
                'running_status': running_status,
                'status': 'Đang chạy',
                'note': 'Trang có phản hồi nhưng tool chưa nhận diện được form login.',
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
            }

    return {
        'name': name,
        'endpoint': endpoint,
        'username': username,
        'checked_url': checked_url,
        'http_status': initial_status_text,
        'login_status': 'Không đăng nhập được',
        'running_status': running_status,
        'status': 'Đang chạy' if is_running else 'Không chạy',
        'note': 'Có phản hồi HTTP nhưng chưa tự động login được.',
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
    }


def try_basic_auth(session: Session, url: str, username: str, password: str) -> Response | None:
    try:
        return session.get(
            url,
            timeout=12,
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
    solution: dict[str, Any] | None = None,
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

        snmp_metrics, snmp_note = fetch_solution_metrics_snmp(solution or {'endpoint': endpoint})
        if snmp_metrics:
            metrics.update(merge_metric_maps(metrics, snmp_metrics))
            success_note = f"{success_note} {snmp_note}".strip()
        elif solution and solution.get('snmp_enabled'):
            success_note = f"{success_note} SNMP unavailable.".strip()

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

    if not login_success and solution and solution.get('snmp_enabled'):
        snmp_metrics, snmp_note = fetch_solution_metrics_snmp(solution)
        if snmp_metrics:
            metrics.update(merge_metric_maps(metrics, snmp_metrics))
            failure_note = f"{failure_note} {snmp_note}".strip()

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

    match = re.search(r'([0-9]+(?:\.[0-9]+)?)\s*%', text)
    if not match:
        return 'N/A'
    return f"{float(match.group(1)):.1f}%"

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
) -> Response:
    payload = dict(form_info['fields'])
    payload[form_info['username_field']] = username
    payload[form_info['password_field']] = password
    headers = {'Referer': referer_url}

    if form_info['method'] == 'get':
        return session.get(
            form_info['action'],
            params=payload,
            headers=headers,
            timeout=12,
            allow_redirects=True,
        )

    return session.post(
        form_info['action'],
        data=payload,
        headers=headers,
        timeout=12,
        allow_redirects=True,
    )


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