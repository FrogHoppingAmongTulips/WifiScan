#!/usr/bin/env python3
"""Движок монитора исходящих соединений:
читает активные TCP-соединения, фильтрует интернет, обогащает geo-IP."""
import subprocess
import re
import socket
import ipaddress
import json
from pathlib import Path

import urllib.request

GEO_CACHE_PATH = Path.home() / '.net-monitor' / 'geo_cache.json'
GEO_CACHE_PATH.parent.mkdir(exist_ok=True, parents=True)


def is_public_ip(ip):
    """True если IP внешний (интернет), а не локальный/служебный."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_multicast or
                    addr.is_reserved or addr.is_unspecified)
    except:
        return False


def parse_remote(name_field):
    """Из 'local->remote' достаёт (remote_ip, remote_port)."""
    if '->' not in name_field:
        return None, None
    remote = name_field.split('->')[1].strip().split(' ')[0]
    # IPv6 в скобках: [fe80::1]:443
    m6 = re.match(r'\[(.+)\]:(\d+)', remote)
    if m6:
        return m6.group(1), m6.group(2)
    # IPv4: 1.2.3.4:443
    m4 = re.match(r'([\d.]+):(\d+)', remote)
    if m4:
        return m4.group(1), m4.group(2)
    return None, None


def full_process_name(pid):
    """Полное имя процесса по PID (lsof обрезает до 9 символов)."""
    try:
        r = subprocess.run(['ps', '-p', str(pid), '-o', 'comm='],
                           capture_output=True, text=True, timeout=2)
        path = r.stdout.strip()
        # берём последний компонент пути приложения
        if '.app/' in path:
            m = re.search(r'/([^/]+)\.app/', path)
            if m:
                return m.group(1)
        return path.split('/')[-1] or path
    except:
        return ''


def list_connections():
    """Возвращает список интернет-соединений: app, pid, ip, port."""
    conns = {}
    try:
        r = subprocess.run(
            ['lsof', '-nP', '-i', 'TCP', '-sTCP:ESTABLISHED'],
            capture_output=True, text=True, timeout=10
        )
        for line in r.stdout.split('\n')[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            command = parts[0]
            pid = parts[1]
            name_field = ' '.join(parts[8:])
            ip, port = parse_remote(name_field)
            if not ip or not is_public_ip(ip):
                continue
            key = (pid, ip, port)
            if key not in conns:
                conns[key] = {
                    'command': command,
                    'pid': pid,
                    'ip': ip,
                    'port': port,
                }
    except Exception as e:
        print(f"lsof error: {e}")

    # дополняем полным именем процесса
    result = list(conns.values())
    name_cache = {}
    for c in result:
        if c['pid'] not in name_cache:
            name_cache[c['pid']] = full_process_name(c['pid']) or c['command']
        c['app'] = name_cache[c['pid']]
    return result


_RDNS_CACHE = {}

def reverse_dns(ip):
    """Имя хоста по IP (с кэшем)."""
    if ip in _RDNS_CACHE:
        return _RDNS_CACHE[ip]
    try:
        host = socket.gethostbyaddr(ip)[0]
    except:
        host = ''
    _RDNS_CACHE[ip] = host
    return host

def reverse_dns_batch(ips):
    """Параллельный reverse DNS для списка IP."""
    import threading
    out = {}
    lock = threading.Lock()
    def task(ip):
        h = reverse_dns(ip)
        with lock:
            out[ip] = h
    threads = [threading.Thread(target=task, args=(ip,)) for ip in ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)
    return out

def load_geo_cache():
    if GEO_CACHE_PATH.exists():
        try:
            return json.loads(GEO_CACHE_PATH.read_text())
        except:
            pass
    return {}


def save_geo_cache(cache):
    try:
        GEO_CACHE_PATH.write_text(json.dumps(cache))
    except:
        pass


# Смотреть на чужой сервис, чтобы узнать, куда уходят твои данные, — само по
# себе отправка этих данных третьей стороне. Поэтому по умолчанию имя сервера
# берётся из обратного DNS, а запрос наружу делается только когда его попросили
# явно: wfs out --geo.
GEO_ENDPOINT = 'http://ip-api.com/batch'


def geo_lookup(ips, allow_network=False):
    """{ip: {country, cc, isp, org}}. Без allow_network — только из кэша."""
    cache = load_geo_cache()
    unknown = [ip for ip in ips if ip not in cache]

    if unknown and allow_network:
        for i in range(0, len(unknown), 100):
            chunk = unknown[i:i + 100]
            payload = [{'query': ip, 'fields': 'query,country,countryCode,isp,org,as'}
                       for ip in chunk]
            try:
                req = urllib.request.Request(
                    GEO_ENDPOINT,
                    data=json.dumps(payload).encode(),
                    headers={'Content-Type': 'application/json'},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    items = json.loads(resp.read().decode())
                for item in items:
                    ip = item.get('query')
                    if ip:
                        cache[ip] = {
                            'country': item.get('country', '?'),
                            'cc': item.get('countryCode', ''),
                            'isp': item.get('isp', ''),
                            'org': item.get('org', '') or item.get('isp', ''),
                        }
            except Exception:
                for ip in chunk:
                    cache.setdefault(ip, {'country': '?', 'cc': '', 'isp': '', 'org': ''})
        save_geo_cache(cache)

    return {ip: cache.get(ip, {'country': '?', 'cc': '', 'isp': '', 'org': ''})
            for ip in ips}


if __name__ == '__main__':
    print("Active internet connections:\n")
    conns = list_connections()
    if not conns:
        print("No external connections right now.")
    else:
        ips = list({c['ip'] for c in conns})
        geo = geo_lookup(ips)
        print(f"{'App':<20} {'Remote IP':<18} {'Port':<6} {'Country':<14} {'Org'}")
        print('-' * 90)
        for c in sorted(conns, key=lambda x: x['app'].lower()):
            g = geo.get(c['ip'], {})
            print(f"{c['app'][:20]:<20} {c['ip']:<18} {c['port']:<6} "
                  f"{g.get('country','?')[:14]:<14} {g.get('org','')[:30]}")
        print(f"\nTotal: {len(conns)} connections, {len(ips)} unique servers")
