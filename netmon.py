#!/usr/bin/env python3
"""Network Monitor — что твой Mac отправляет в интернет.
Показывает исходящие соединения: приложение -> сервер -> страна/компания.
Watch-режим ловит новые/подозрительные соединения и шлёт уведомления."""
import subprocess
import socket
import re
import sys
import time
import json
from datetime import datetime
from pathlib import Path

from connections import (list_connections, geo_lookup, is_public_ip,
                         full_process_name, reverse_dns_batch)

import urllib.request

BASE = Path.home() / '.net-monitor'
BASE.mkdir(exist_ok=True, parents=True)
LOG_PATH = BASE / 'connections.log'
THREAT_CACHE = BASE / 'threatlist.json'
PROFILE_PATH = BASE / 'profile.json'

# Порты, которые считаются обычными/безопасными
SAFE_PORTS = {
    443: 'HTTPS', 80: 'HTTP', 5223: 'Apple Push', 5228: 'Google Push',
    993: 'IMAPS', 995: 'POP3S', 587: 'SMTP', 465: 'SMTP', 853: 'DNS-over-TLS',
    8443: 'HTTPS-alt',
}

# ─── Уведомления macOS ────────────────────────────────────────────────────────

def notify(title, message, sound='Ping'):
    try:
        msg = message.replace('"', "'").replace('\\', '')
        ttl = title.replace('"', "'").replace('\\', '')
        subprocess.run(
            ['osascript', '-e',
             f'display notification "{msg}" with title "{ttl}" sound name "{sound}"'],
            capture_output=True, timeout=5)
    except:
        pass

# ─── Threat intelligence (известные вредоносные IP) ───────────────────────────

_THREATS = None

def load_threats():
    global _THREATS
    if _THREATS is not None:
        return _THREATS
    if THREAT_CACHE.exists():
        try:
            _THREATS = set(json.loads(THREAT_CACHE.read_text()))
            return _THREATS
        except:
            pass
    _THREATS = set()
    return _THREATS

def update_threats():
    """Скачивает свежие списки вредоносных IP (ipsum + abuse.ch)."""
    ips = set()
    sources = [
        'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt',
        'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    ]
    print("Downloading threat lists...")
    for url in sources:
        try:
            with urllib.request.urlopen(url, timeout=20) as resp:
                text = resp.read().decode('utf-8', 'replace')
            for line in text.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                ip = line.split('\t')[0].split()[0]
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                    ips.add(ip)
        except Exception as e:
            print(f"  {url.split('/')[2]} failed: {e}")
    if ips:
        THREAT_CACHE.write_text(json.dumps(list(ips)))
        global _THREATS
        _THREATS = ips
        print(f"Loaded {len(ips)} malicious IPs.")
        return True
    return False

def is_malicious(ip):
    return ip in load_threats()

# ─── Профиль поведения (детект аномалий) ──────────────────────────────────────

def load_profile():
    if PROFILE_PATH.exists():
        try:
            return json.loads(PROFILE_PATH.read_text())
        except:
            pass
    return {}

def save_profile(prof):
    try:
        PROFILE_PATH.write_text(json.dumps(prof, indent=2))
    except:
        pass

def learn(conns, geo):
    """Запоминает нормальное поведение: app -> страны/компании."""
    prof = load_profile()
    for c in conns:
        g = geo.get(c['ip'], {})
        app = c['app']
        entry = prof.setdefault(app, {'countries': [], 'orgs': []})
        cc = g.get('country', '')
        org = g.get('org', '')
        if cc and cc not in entry['countries']:
            entry['countries'].append(cc)
        if org and org not in entry['orgs']:
            entry['orgs'].append(org)
    save_profile(prof)
    return prof

def anomalies(conn, geo, prof):
    """Возвращает причины, почему соединение аномально для этого приложения."""
    reasons = []
    g = geo.get(conn['ip'], {})
    known = prof.get(conn['app'])
    if known:
        if g.get('country') and g['country'] not in known['countries']:
            reasons.append(f"first time to {g['country']}")
        if g.get('org') and g['org'] not in known['orgs']:
            reasons.append("new server/company")
    return reasons

# ─── Bandwidth по процессам (nettop) ──────────────────────────────────────────

def get_bandwidth(secs=3):
    """Скорость по процессам через один nettop с двумя замерами.
    Возвращает {name: (down_Bps, up_Bps)}."""
    try:
        r = subprocess.run(
            ['nettop', '-P', '-x', '-s', str(secs), '-L', '2',
             '-J', 'bytes_in,bytes_out'],
            capture_output=True, text=True, timeout=secs + 10)
    except:
        return {}

    # разбиваем вывод на два блока по строке-заголовку
    samples = []
    cur = {}
    for line in r.stdout.split('\n'):
        if line.startswith(',bytes_in'):
            if cur:
                samples.append(cur)
                cur = {}
            continue
        parts = line.split(',')
        if len(parts) >= 3 and parts[0]:
            try:
                cur[parts[0]] = (int(parts[1]), int(parts[2]))
            except:
                pass
    if cur:
        samples.append(cur)
    if len(samples) < 2:
        return {}

    s1, s2 = samples[0], samples[-1]
    rates = {}
    for name, (i2, o2) in s2.items():
        i1, o1 = s1.get(name, (i2, o2))
        din = max(0, i2 - i1) / secs
        dout = max(0, o2 - o1) / secs
        if din > 0 or dout > 0:
            clean = name.rsplit('.', 1)[0]
            d, u = rates.get(clean, (0, 0))
            rates[clean] = (d + din, u + dout)
    return rates

def fmt_speed(b):
    if b > 1024 * 1024:
        return f"{b/1024/1024:.1f} MB/s"
    if b > 1024:
        return f"{b/1024:.1f} KB/s"
    return f"{b:.0f} B/s"

def show_traffic():
    sep('=')
    print(" BANDWIDTH BY APP — who's using your internet (3s sample)")
    sep('=')
    print("Measuring...")
    rates = get_bandwidth(3)
    active = {k: v for k, v in rates.items() if v[0] + v[1] > 0}
    if not active:
        print("No active traffic right now.")
        sep()
        return
    print(f"{'App':<28} {'Download':<14} {'Upload'}")
    sep()
    for app, (d, u) in sorted(active.items(), key=lambda x: -(x[1][0] + x[1][1])):
        print(f"{app[:28]:<28} {fmt_speed(d):<14} {fmt_speed(u)}")
    sep()

# ─── Анализ подозрительности ──────────────────────────────────────────────────

def flag_connection(conn, geo, geo_known=True):
    """Метки-предупреждения. geo_known=False — сведений о владельце и стране
    не запрашивали, и их отсутствие не повод считать соединение подозрительным:
    иначе помеченным окажется вообще всё, и метки перестанут что-то значить."""
    flags = []
    port = int(conn['port'])
    g = geo.get(conn['ip'], {})

    if is_malicious(conn['ip']):
        flags.append("MALICIOUS IP (threat list)")
    if port not in SAFE_PORTS:
        flags.append(f"unusual port {port}")
    if geo_known:
        if not g.get('org') or g.get('org') == '?':
            flags.append("unidentified server")
        # Отсутствие поля — тоже «неизвестно»: раньше проверялись только '?'
        # и пустая строка, и адрес, которого нет в справочнике вовсе,
        # проходил без метки.
        if not g.get('country') or g.get('country') == '?':
            flags.append("unknown location")
    return flags

# ─── Сбор + отображение ───────────────────────────────────────────────────────

# USE_GEO: спрашивать ли у стороннего сервиса, кому принадлежат адреса.
# Выключено по умолчанию: чтобы узнать, куда уходят твои данные, инструмент
# отправил бы список этих адресов третьей стороне. Включается флагом --geo.
USE_GEO = False


def gather():
    """Снимок: соединения + geo + reverse DNS."""
    conns = list_connections()
    ips = list({c['ip'] for c in conns})
    geo = geo_lookup(ips, allow_network=USE_GEO) if ips else {}
    hosts = reverse_dns_batch(ips) if ips else {}
    for c in conns:
        c['host'] = hosts.get(c['ip'], '')
    return conns, geo

def sep(char='-', n=92):
    print(char * n)

def display_connections(conns, geo):
    sep('=')
    print(f" NETWORK MONITOR  |  {datetime.now().strftime('%H:%M:%S %d.%m.%Y')}  |  {len(conns)} connections")
    sep('=')
    if not conns:
        print("No external (internet) connections right now.")
        sep()
        return

    print(f"{'#':<3} {'App':<18} {'Server (host or org)':<30} {'Port':<6} {'Country':<13} Flags")
    sep()
    for i, c in enumerate(sorted(conns, key=lambda x: x['app'].lower()), 1):
        g = geo.get(c['ip'], {})
        flags = flag_connection(c, geo, geo_known=USE_GEO)
        flag_str = ('[!] ' + ', '.join(flags)) if flags else ''
        server = c.get('host') or g.get('org', '') or c['ip']
        print(f"{i:<3} {c['app'][:18]:<18} {server[:30]:<30} {c['port']:<6} "
              f"{g.get('country','?')[:13]:<13} {flag_str}")
    sep()

    # сводка
    countries = {}
    for c in conns:
        cc = geo.get(c['ip'], {}).get('country', '?')
        countries[cc] = countries.get(cc, 0) + 1
    print("Countries: " + "  ".join(f"{k}:{v}" for k, v in
                                     sorted(countries.items(), key=lambda x: -x[1])))
    sep()

def group_by_app(conns, geo):
    sep('=')
    print(" BY APPLICATION — who talks where")
    sep('=')
    apps = {}
    for c in conns:
        apps.setdefault(c['app'], []).append(c)
    for app in sorted(apps, key=lambda a: -len(apps[a])):
        servers = apps[app]
        countries = sorted({geo.get(s['ip'], {}).get('country', '?') for s in servers})
        orgs = sorted({(geo.get(s['ip'], {}).get('org', '') or '?') for s in servers})
        print(f"\n{app}  ({len(servers)} connection(s))")
        print(f"  countries: {', '.join(countries)}")
        print(f"  servers:   {', '.join(o[:25] for o in orgs)}")
    sep()

def show_listening():
    """Что на твоём Mac СЛУШАЕТ входящие (локальные серверы/возможные бэкдоры)."""
    sep('=')
    print(" LISTENING PORTS — what accepts incoming connections")
    sep('=')
    try:
        r = subprocess.run(['lsof', '-nP', '-iTCP', '-sTCP:LISTEN'],
                          capture_output=True, text=True, timeout=10)
        rows = {}
        for line in r.stdout.split('\n')[1:]:
            parts = line.split()
            if len(parts) < 9:
                continue
            app = parts[0]
            pid = parts[1]
            name = ' '.join(parts[8:])
            m = name.split('(')[0].strip()
            port = m.rsplit(':', 1)[-1] if ':' in m else '?'
            scope = m.rsplit(':', 1)[0] if ':' in m else ''
            # public-facing если слушает на * или 0.0.0.0, локально если 127.0.0.1
            facing = 'ALL (exposed)' if scope in ('*', '0.0.0.0', '[::]') else 'localhost only'
            key = (app, port, facing)
            rows[key] = full_process_name(pid) or app
        if not rows:
            print("Nothing is listening.")
        else:
            print(f"{'App':<22} {'Port':<8} {'Exposure'}")
            sep()
            for (app, port, facing), full in sorted(rows.items()):
                warn = '  [!] reachable from network' if 'exposed' in facing else ''
                print(f"{full[:22]:<22} {port:<8} {facing}{warn}")
    except Exception as e:
        print(f"error: {e}")
    sep()

# ─── Watch ────────────────────────────────────────────────────────────────────

def log_line(text):
    try:
        with open(LOG_PATH, 'a') as f:
            f.write(text + '\n')
    except:
        pass

def watch_mode(interval=5):
    sep('=')
    print(f" WATCH MODE — new connections alert.  Every {interval}s.  Ctrl+C to stop.")
    print(f" Log: {LOG_PATH}")
    sep('=')

    conns, geo = gather()
    seen = {(c['app'], c['ip'], c['port']) for c in conns}
    prof = learn(conns, geo)   # запоминаем нормальное поведение
    print(f"Baseline: {len(seen)} connections, profile has {len(prof)} apps.")
    print("Watching for new / anomalous / malicious connections...\n")

    try:
        while True:
            for r in range(interval, 0, -1):
                print(f"\r  watching... next check {r}s ", end='', flush=True)
                time.sleep(1)
            print('\r' + ' ' * 50 + '\r', end='')

            conns, geo = gather()
            current = {(c['app'], c['ip'], c['port']): c for c in conns}
            ts = datetime.now().strftime('%H:%M:%S')

            for key, c in current.items():
                if key not in seen:
                    g = geo.get(c['ip'], {})
                    flags = flag_connection(c, geo, geo_known=USE_GEO)
                    anom = anomalies(c, geo, prof)
                    country = g.get('country', '?')
                    org = g.get('org', '') or '?'
                    server = c.get('host') or org
                    notes = flags + anom
                    note_str = ('  [!] ' + ', '.join(notes)) if notes else ''
                    line = f"[{ts}] NEW: {c['app']} -> {server}:{c['port']} ({country}){note_str}"
                    print(line)
                    log_line(line)
                    # уведомление по уровню угрозы
                    if is_malicious(c['ip']):
                        notify(f"!! MALICIOUS: {c['app']}",
                               f"{c['ip']} ({country}) is on threat list!", 'Sosumi')
                    elif anom:
                        notify(f"Anomaly: {c['app']}",
                               f"{', '.join(anom)} -> {server} ({country})", 'Basso')
                    elif flags:
                        notify(f"Suspicious: {c['app']}",
                               f"{', '.join(flags)} ({country})", 'Basso')
                    else:
                        notify(f"{c['app']} connected out",
                               f"{server} ({country})", 'Ping')
            seen = set(current.keys())
            prof = learn(conns, geo)   # дообучаем
    except KeyboardInterrupt:
        print("\nWatch stopped.")

# ─── Экспорт ──────────────────────────────────────────────────────────────────


# ─── Детали соединения ────────────────────────────────────────────────────────

def show_detail(conn, geo):
    g = geo.get(conn['ip'], {})
    sep()
    print(f"App:      {conn['app']}  (PID {conn['pid']})")
    print(f"Remote:   {conn['ip']}:{conn['port']}")
    print(f"Country:  {g.get('country','?')}")
    print(f"ISP:      {g.get('isp','?')}")
    print(f"Org:      {g.get('org','?')}")
    # reverse DNS
    try:
        host = socket.gethostbyaddr(conn['ip'])[0]
        print(f"Hostname: {host}")
    except:
        print("Hostname: (no reverse DNS)")
    flags = flag_connection(conn, geo, geo_known=USE_GEO)
    if flags:
        print(f"Flags:    [!] {', '.join(flags)}")
    sep()

# ─── Меню ─────────────────────────────────────────────────────────────────────

def main():
    global USE_GEO
    if '--geo' in sys.argv:
        USE_GEO = True
        sys.argv.remove('--geo')

    print("Network Monitor — outbound connections")
    if not USE_GEO:
        print("страна и владелец не запрашиваются — это отправка адресов "
              "стороннему сервису. Нужны: wfs out --geo")
    conns, geo = [], {}

    while True:
        if not conns:
            print("\nScanning connections...")
            conns, geo = gather()

        display_connections(conns, geo)
        print("\nCommands:")
        print("  r          - rescan")
        print(f"  1-{len(conns):<8} - connection details")
        print("  apps       - group by application")
        print("  traffic    - bandwidth per app (who eats your internet)")
        print("  watch      - monitor: new / anomalous / malicious (alerts)")
        print("  listen     - what's listening on your Mac")
        print("  threats    - update malicious-IP database")
        print("  q          - quit")

        try:
            cmd = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            sys.exit(0)

        if cmd == 'q':
            print("Bye.")
            sys.exit(0)
        elif cmd == 'r':
            conns = []
            continue
        elif cmd == 'apps':
            group_by_app(conns, geo)
        elif cmd == 'traffic':
            show_traffic()
        elif cmd == 'watch':
            watch_mode()
        elif cmd == 'listen':
            show_listening()
        elif cmd == 'threats':
            update_threats()
        elif cmd.isdigit():
            idx = int(cmd) - 1
            ordered = sorted(conns, key=lambda x: x['app'].lower())
            if 0 <= idx < len(ordered):
                show_detail(ordered[idx], geo)
            else:
                print("Invalid number.")
        else:
            print("Unknown command.")

        if cmd not in ('r', 'q'):
            input("\nPress Enter to continue...")

if __name__ == '__main__':
    main()
