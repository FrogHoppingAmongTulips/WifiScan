#!/usr/bin/env python3
import subprocess
import re
import socket
import json
import sys
import time
import csv
import errno
import logging
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait
from datetime import datetime
from pathlib import Path

log = logging.getLogger('wfs')
logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')

HAS_NMAP = shutil.which('nmap') is not None

try:
    from identify import (mdns_discover, ssdp_discover, port_fingerprint,
                          grab_banners, guess_from_banners, banner_risk,
                          ttl_os_hint, netbios_name)
except ImportError:
    def mdns_discover(timeout=4): return {}
    def ssdp_discover(timeout=3): return {}
    def port_fingerprint(ip, timeout=0.5): return ''
    def grab_banners(ip): return {}
    def guess_from_banners(banners): return ''
    def banner_risk(banners): return []
    def ttl_os_hint(ip, timeout=2): return ''
    def netbios_name(ip, timeout=1.0): return ''

try:
    from store import Store
except ImportError:
    Store = None

try:
    import security
except ImportError:
    security = None

try:
    import exporter
except ImportError:
    exporter = None

try:
    import config
    CFG = config.load()
except Exception:
    CFG = {'interface': 'en0', 'auto_oui': True}


OUI_DB = {
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
    '00:1C:B3': 'Apple',        'AC:DE:48': 'Apple',
    'F0:18:98': 'Apple',        'A4:C3:F0': 'Apple',
    '00:1B:8F': 'Samsung',      '00:23:99': 'Samsung',
    'B0:72:BF': 'TP-Link',      '14:CC:20': 'TP-Link',
    '50:C7:BF': 'TP-Link',      '90:F6:52': 'TP-Link',
    '00:1A:70': 'D-Link',       '1C:7E:E5': 'D-Link',
    '00:1A:2B': 'Cisco',        '00:16:D4': 'Cisco',
    '38:6B:1C': 'Arcadyan',     '00:50:56': 'VMware',
    '08:00:27': 'VirtualBox',   'FC:FB:FB': 'Apple',
    '00:11:22': 'Cimsys',
}

DEVICE_TYPES = {
    'apple': 'Apple Device',     'samsung': 'Samsung',
    'huawei': 'Huawei',          'xiaomi': 'Xiaomi',
    'raspberry': 'Raspberry Pi', 'tp-link': 'TP-Link Router',
    'asus': 'ASUS',              'netgear': 'Netgear Router',
    'cisco': 'Cisco',            'd-link': 'D-Link Router',
    'arcadyan': 'ISP Router',    'sony': 'Sony',
    'amazon': 'Amazon Device',   'google': 'Google Device',
    'intel': 'PC/Laptop',        'microsoft': 'Windows PC',
}

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 53: 'DNS',
    80: 'HTTP', 443: 'HTTPS', 445: 'SMB (Windows)',
    554: 'RTSP/Camera', 1883: 'MQTT/IoT', 3306: 'MySQL',
    3389: 'RDP/Windows', 5900: 'VNC', 8080: 'HTTP-Alt',
    9100: 'Printer', 548: 'AFP/Apple', 32400: 'Plex',
}



OUI_CACHE = Path.home() / '.wifi-scanner' / 'oui.json'
_OUI_FULL = None

def load_oui_full():
    """Загружает полную базу OUI из кэша (скачивается один раз)"""
    global _OUI_FULL
    if _OUI_FULL is not None:
        return _OUI_FULL
    if OUI_CACHE.exists():
        try:
            _OUI_FULL = json.loads(OUI_CACHE.read_text())
            return _OUI_FULL
        except Exception:
            pass
    _OUI_FULL = {}
    return _OUI_FULL

def download_oui(quiet=False):
    """Download the full vendor (OUI) database and cache it. Runs once.
    quiet=True suppresses output (used for the background auto-download)."""
    import urllib.request
    def say(msg):
        if not quiet:
            print(msg)
    urls = [
        'https://www.wireshark.org/download/automated/data/manuf',
        'https://raw.githubusercontent.com/boundary/wireshark/master/manuf',
        'https://standards-oui.ieee.org/oui/oui.csv',
    ]
    say("Downloading vendor database (one time)...")
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            data = urllib.request.urlopen(req, timeout=30).read().decode('utf-8', 'ignore')
            db = {}
            if url.endswith('.csv'):
                # IEEE CSV: Registry,Assignment,Org Name,Org Address
                for row in csv.reader(data.splitlines()):
                    if len(row) >= 3 and re.match(r'^[0-9A-F]{6}$', row[1]):
                        p = ':'.join(row[1][i:i+2] for i in range(0, 6, 2))
                        db[p] = row[2].strip()[:30]
            else:
                # wireshark manuf: prefix<TAB>short<TAB>long
                for line in data.split('\n'):
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        prefix = parts[0].strip().upper()
                        if re.match(r'^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$', prefix):
                            name = parts[2].strip() if len(parts) > 2 and parts[2].strip() else parts[1].strip()
                            db[prefix] = name[:30]
            if db:
                OUI_CACHE.write_text(json.dumps(db))
                global _OUI_FULL
                _OUI_FULL = db
                say(f"Saved {len(db)} vendor entries.")
                return True
        except Exception as e:
            say(f"  {url.split('/')[2]} failed: {e}")
    say("All sources failed — using built-in mini database.")
    return False

def is_random_mac(mac):
    """Приватный (рандомизированный) MAC — 2-й бит первого байта = 1"""
    try:
        return bool(int(mac[1], 16) & 0x2)
    except Exception:
        return False

def lookup_vendor(mac):
    if not mac:
        return ''
    prefix = mac[:8].upper()
    # сначала встроенная мини-база
    if prefix in OUI_DB:
        return OUI_DB[prefix]
    # потом полная скачанная
    full = load_oui_full()
    if prefix in full:
        return full[prefix]
    if is_random_mac(mac):
        return 'Private/Randomized'
    return ''

def get_device_type(vendor, hostname=''):
    text = (vendor + ' ' + hostname).lower()
    for key, dtype in DEVICE_TYPES.items():
        if key in text:
            return dtype
    if any(x in text for x in ['iphone', 'ipad', 'macbook', 'imac']):
        return 'Apple Device'
    if any(x in text for x in ['android', 'pixel', 'oneplus']):
        return 'Android Phone'
    if any(x in text for x in ['smart-tv', 'smarttv', '-tv']):
        return 'Smart TV'
    if any(x in text for x in ['router', 'gateway', 'modem']):
        return 'Router/Gateway'
    return 'Unknown'

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ''

def get_local_ip():
    """Local IP of the configured Wi-Fi interface (default en0), ignoring VPNs."""
    iface = CFG.get('interface', 'en0')
    try:
        r = subprocess.run(['ipconfig', 'getifaddr', iface],
                           capture_output=True, text=True)
        ip = r.stdout.strip()
        if ip and ip.startswith(('10.', '192.168.', '172.')):
            return ip
    except Exception:
        pass
    try:
        r = subprocess.run(['ifconfig', iface], capture_output=True, text=True)
        m = re.search(r'inet ((?:10|192\.168|172\.\d+)\.\d+\.\d+)', r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    log.warning("could not detect an IP on interface '%s' — guessing 192.168.1.x. "
                "Set the right interface in ~/.wifi-scanner/config.json", iface)
    return '192.168.1.100'

def get_network_base():
    ip = get_local_ip()
    parts = ip.split('.')
    return '.'.join(parts[:3])

# Порты для TCP-ping: если устройство отвечает (открыт ИЛИ refused) — оно живо
# 62078 = iPhone (lockdownd), 7000 = AirPlay, 5353 = mDNS
TCP_PING_PORTS = [80, 443, 22, 445, 62078, 7000, 548, 53]

def ping_host(ip):
    """ICMP ping (на macOS -W в миллисекундах)"""
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '600', '-t', '1', ip],
            capture_output=True, timeout=2
        )
        return r.returncode == 0
    except Exception:
        return False

def tcp_ping(ip, ports=TCP_PING_PORTS, timeout=0.5):
    """Трюк Angry IP: устройство живо, если порт открыт ИЛИ соединение
    отвергнуто (RST). Оба случая доказывают что хост существует —
    даже если он блокирует ICMP."""
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, port))
            s.close()
            if rc == 0:
                return True, port            # порт открыт
            if rc == errno.ECONNREFUSED:
                return True, None            # RST — хост жив, порт закрыт
        except Exception:
            pass
    return False, None

def is_alive(ip):
    """Комбинированная проверка: сначала быстрый TCP, потом ICMP"""
    alive, open_port = tcp_ping(ip)
    if alive:
        return True
    return ping_host(ip)

def get_ping_ms(ip):
    try:
        r = subprocess.run(
            ['ping', '-c', '1', '-W', '1000', ip],
            capture_output=True, text=True, timeout=3
        )
        m = re.search(r'time=([\d.]+)', r.stdout)
        if m:
            return float(m.group(1))
    except Exception:
        pass
    return -1

def ping_sweep(base, workers=128):
    """Многопоточная разведка: ICMP + TCP-ping через пул потоков"""
    alive = []
    ips = [f"{base}.{i}" for i in range(1, 255)]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(is_alive, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                if fut.result():
                    alive.append(ip)
            except Exception:
                pass

    alive.sort(key=lambda x: int(x.split('.')[-1]))
    return alive

def parse_arp_output(text):
    """Pure parser for `arp -an` output → {ip: {mac, hostname}}. Testable."""
    devices = {}
    for line in text.split('\n'):
        m = re.search(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})', line)
        if m:
            hostname, ip, mac = m.group(1), m.group(2), m.group(3).upper()
            if 'ff:ff:ff:ff:ff:ff' not in mac.lower():
                devices[ip] = {'mac': mac, 'hostname': hostname if hostname != '?' else ''}
    return devices


def parse_nmap_output(text):
    """Pure parser for `nmap -sn` output → {ip: {hostname, mac, vendor}}. Testable."""
    devices, current_ip = {}, None
    for line in text.split('\n'):
        m = re.search(r'Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)', line)
        if m:
            current_ip = m.group(2)
            devices[current_ip] = {'hostname': m.group(1) or '', 'mac': '', 'vendor': ''}
        m2 = re.search(r'MAC Address: ([0-9A-F:]{17})(?: \((.+)\))?', line)
        if m2 and current_ip:
            devices[current_ip]['mac'] = m2.group(1)
            devices[current_ip]['vendor'] = m2.group(2) or ''
    return devices


def read_arp():
    # -n = numeric: skip reverse-DNS, which can stall for a minute+ on a large
    # ARP cache. Hostnames still come from mDNS / nmap / getent.
    try:
        r = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=5)
        return parse_arp_output(r.stdout)
    except Exception as e:
        log.debug("arp failed: %s", e)
        return {}

def nmap_scan(base):
    """nmap без sudo — только ping scan. Молча деградирует, если nmap не установлен."""
    if not HAS_NMAP:
        return {}
    try:
        r = subprocess.run(
            ['nmap', '-sn', '--host-timeout', '2s', f'{base}.0/24'],
            capture_output=True, text=True, timeout=60)
        return parse_nmap_output(r.stdout)
    except Exception as e:
        log.debug("nmap failed: %s", e)
        return {}

def fast_sweep(base, workers=128):
    """Быстрая ICMP-разведка присутствия (~1-2с): без TCP-ping/nmap/mDNS."""
    def alive(ip):
        try:
            return subprocess.run(['ping', '-c', '1', '-W', '300', '-t', '1', ip],
                                  capture_output=True, timeout=1).returncode == 0
        except Exception:
            return False
    ips = [f"{base}.{i}" for i in range(1, 255)]
    out = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(alive, ip): ip for ip in ips}
        for fut in as_completed(futs):
            try:
                if fut.result():
                    out.add(futs[fut])
            except Exception:
                pass
    return out


def quick_refresh(old_devices):
    """Быстрый рескан присутствия. Возвращает (new_devices, joined, left).
    Сохраняет обогащённые данные для уже известных, для новых — минимум."""
    base = get_network_base()
    my_ip = get_local_ip()
    present = fast_sweep(base) | set(read_arp().keys())
    present = {ip for ip in present if ip.startswith(base + '.')}
    present -= {f"{base}.255", f"{base}.0"}
    arp = read_arp()

    old_by_ip = {d['ip']: d for d in old_devices}
    left = [d for d in old_devices if d['ip'] not in present]
    new_devices = [d for d in old_devices if d['ip'] in present]
    joined = []
    for ip in present - set(old_by_ip):
        mac = arp.get(ip, {}).get('mac', '')
        d = {
            'ip': ip, 'mac': mac, 'vendor': lookup_vendor(mac) or '',
            'hostname': arp.get(ip, {}).get('hostname', ''),
            'name': arp.get(ip, {}).get('hostname', ''),
            'type': 'Unknown', 'os_hint': '',
            'is_me': ip == my_ip, 'is_gateway': ip.endswith('.1'),
            'random_mac': is_random_mac(mac) if mac else False,
        }
        new_devices.append(d)
        joined.append(d)
    new_devices.sort(key=lambda x: list(map(int, x['ip'].split('.'))))
    return new_devices, joined, left


def _enrich_device(d):
    """Per-device network enrichment (runs in a thread pool): OS hint from TTL,
    NetBIOS name for nameless hosts, port fingerprint for unknown types."""
    ip = d['ip']
    hint = ttl_os_hint(ip)
    if hint:
        d['os_hint'] = hint
    if not d['name']:
        nb = netbios_name(ip)
        if nb:
            d['name'] = nb
            if d['type'] in ('Unknown', ''):
                d['type'] = 'Windows PC'
    if d['type'] in ('Unknown', ''):
        fp = port_fingerprint(ip)
        if fp:
            d['type'] = fp
    if d['type'] in ('Unknown', ''):
        if hint == 'Windows':
            d['type'] = 'Windows PC'
        elif hint == 'Network':
            d['type'] = 'Router/Network'
    return d


def full_scan(quiet=False):
    base = get_network_base()
    my_ip = get_local_ip()

    if not quiet:
        print(f"Network: {base}.0/24   Your IP: {my_ip}")
        if not HAS_NMAP:
            print("note: nmap not found — results are still good; "
                  "`brew install nmap` improves them.")
        print("Discovering (ping · arp · nmap · mDNS · SSDP, in parallel)...")

    # Independent phases run concurrently: the passive mDNS/SSDP listeners
    # overlap with the active ping/nmap sweeps instead of running after them.
    with ThreadPoolExecutor(max_workers=4) as ex:
        f_ping = ex.submit(ping_sweep, base)
        f_nmap = ex.submit(nmap_scan, base)
        f_mdns = ex.submit(mdns_discover, 4)
        f_ssdp = ex.submit(ssdp_discover, 3)
        arp = read_arp()
        alive = f_ping.result()
        nmap = f_nmap.result()
        mdns = f_mdns.result()
        ssdp = f_ssdp.result()

    if not quiet:
        print(f"         {len(alive)} responding hosts")

    # Оставляем только хосты своей /24 (ARP-кэш полон мусора)
    all_ips = set(alive) | set(arp.keys()) | set(nmap.keys()) | set(mdns.keys()) | set(ssdp.keys())
    all_ips = {ip for ip in all_ips if ip.startswith(base + '.')}
    all_ips.discard(f"{base}.255")
    all_ips.discard(f"{base}.0")

    # Reverse-DNS параллельно и с дедлайном (иначе последовательный
    # gethostbyaddr по большой сети может висеть минутами).
    need_rdns = [ip for ip in all_ips
                 if not (arp.get(ip, {}).get('hostname')
                         or nmap.get(ip, {}).get('hostname')
                         or mdns.get(ip))]
    rdns = {}
    if need_rdns:
        with ThreadPoolExecutor(max_workers=min(64, len(need_rdns))) as pool:
            futs = {pool.submit(get_hostname, ip): ip for ip in need_rdns}
            done, _ = wait(futs, timeout=3.0)
            for fut in done:
                try:
                    h = fut.result()
                    if h:
                        rdns[futs[fut]] = h
                except Exception:
                    pass

    result = []
    for ip in all_ips:
        mac = arp.get(ip, {}).get('mac') or nmap.get(ip, {}).get('mac', '')
        vendor = (nmap.get(ip, {}).get('vendor') or lookup_vendor(mac) or '')
        hostname = (arp.get(ip, {}).get('hostname') or
                   nmap.get(ip, {}).get('hostname') or
                   rdns.get(ip) or '')

        ssdp_info = ssdp.get(ip, {})
        # Лучшее имя: mDNS > SSDP friendlyName > hostname
        name = (mdns.get(ip) or ssdp_info.get('name') or hostname or '')

        # Тип: SSDP модель > по вендору  (fingerprint делаем в enrichment)
        ssdp_model = ssdp_info.get('model') or ssdp_info.get('manufacturer') or ''
        dtype = ssdp_model or get_device_type(vendor, name)

        result.append({
            'ip': ip,
            'mac': mac,
            'vendor': vendor,
            'hostname': hostname,
            'name': name,
            'type': dtype or 'Unknown',
            'os_hint': '',
            'is_me': ip == my_ip,
            'is_gateway': ip.endswith('.1'),
            'random_mac': is_random_mac(mac) if mac else False,
        })

    # Параллельное обогащение: TTL / NetBIOS / fingerprint по каждому устройству.
    # Кап 16: каждый _enrich_device внутри ещё поднимает потоки (fingerprint),
    # без капа на большой сети получается взрыв потоков.
    if result:
        with ThreadPoolExecutor(max_workers=min(16, len(result))) as pool:
            list(pool.map(_enrich_device, result))

    result.sort(key=lambda x: list(map(int, x['ip'].split('.'))))
    return result


def scan_ports(ip):
    open_ports = []
    lock = threading.Lock()

    def check(port, service):
        try:
            s = socket.socket()
            s.settimeout(0.8)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    open_ports.append((port, service))
            s.close()
        except Exception:
            pass

    threads = [threading.Thread(target=check, args=(p, s))
               for p, s in COMMON_PORTS.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return sorted(open_ports)



def sep(char='-', n=70):
    print(char * n)

def display_devices(devices):
    sep('=')
    print(f" WiFi Scanner  |  {datetime.now().strftime('%H:%M:%S %d.%m.%Y')}  |  {len(devices)} devices")
    sep('=')

    print(f"{'#':<4} {'IP':<16} {'Name':<22} {'Type':<18} {'Vendor':<18} {'MAC'}")
    sep()

    for i, d in enumerate(devices, 1):
        name = d.get('name') or d.get('hostname') or '—'
        print(f"{i:<4} {d['ip']:<16} {name[:22]:<22} {d['type'][:18]:<18} {(d['vendor'] or '—')[:18]:<18} {d['mac'] or '—'}")

    sep()

def detect_os(ip):
    """OS detection через sudo nmap -O."""
    sep()
    print(f"Detecting OS on {ip} (sudo nmap)...")
    try:
        result = subprocess.run(
            ['sudo', 'nmap', '-O', '--osscan-guess',
             '--host-timeout', '15s', '--max-retries', '2', ip],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        os_details  = re.search(r'OS details:\s*(.+)', output)
        os_running  = re.search(r'Running:\s*(.+)', output)
        os_guess    = re.findall(r'Aggressive OS guesses:\s*(.+)', output)
        cpe         = re.search(r'OS CPE:\s*(.+)', output)
        mac_line    = re.search(r'MAC Address:\s*([0-9A-F:]{17})(?:\s+\((.+)\))?', output)

        sep()
        print("OS Detection Results:")
        sep()

        if os_details:
            print(f"  OS:          {os_details.group(1).strip()}")
        elif os_running:
            print(f"  Running:     {os_running.group(1).strip()}")
        elif os_guess:
            print(f"  Best guess:  {os_guess[0].strip()[:80]}")
        else:
            print("  OS:          Could not determine")
            # показываем что nmap вообще нашёл
            for line in output.split('\n'):
                if any(x in line for x in ['open', 'filtered', 'uptime']):
                    print(f"  {line.strip()}")

        if cpe:
            print(f"  CPE:         {cpe.group(1).strip()}")
        if mac_line:
            vendor = mac_line.group(2) or ''
            print(f"  MAC/Vendor:  {mac_line.group(1)} {f'({vendor})' if vendor else ''}")

        # uptime если есть
        uptime = re.search(r'Uptime guess:\s*(.+)', output)
        if uptime:
            print(f"  Uptime:      {uptime.group(1).strip()}")

        sep()

    except subprocess.TimeoutExpired:
        print("Timeout — device did not respond to OS probes.")
        sep()
    except Exception as e:
        print(f"Error: {e}")
        sep()

def show_device(device, port_cache=None):
    sep()

    print(f"IP:          {device['ip']}")
    print(f"Name:        {device.get('name') or '—'}")
    print(f"Type:        {device['type']}")
    if device.get('os_hint'):
        print(f"OS hint:     {device['os_hint']}")
    print(f"Hostname:    {device['hostname'] or '—'}")
    print(f"MAC:         {device['mac'] or '—'}")
    print(f"Vendor:      {device['vendor'] or 'Unknown'}")
    if device.get('first_seen'):
        print(f"First seen:  {device['first_seen']}   раз в сети: {device.get('times_seen', '?')}")

    ms = get_ping_ms(device['ip'])
    print(f"Ping:        {ms:.1f}ms" if ms > 0 else "Ping:        no response")
    sep()

    ans = input("Scan ports? [y/n]: ").strip().lower()
    if ans != 'y':
        return

    # OS detection через sudo nmap
    ans_os = input("Detect OS? (requires sudo) [y/n]: ").strip().lower()
    if ans_os == 'y':
        detect_os(device['ip'])

    ip = device['ip']
    if port_cache is not None and ip in port_cache:
        ports = port_cache[ip]
        print(f"Ports on {ip} (cached this session):")
    else:
        print(f"Scanning {len(COMMON_PORTS)} ports on {ip}...")
        ports = scan_ports(ip)
        if port_cache is not None:
            port_cache[ip] = ports
    sep()
    if ports:
        risk_map = {
            23: 'DANGER - no encryption',
            21: 'DANGER - no encryption',
            3389: 'Remote Desktop access',
            5900: 'VNC remote access',
            1883: 'IoT device',
            554: 'IP Camera stream',
            445: 'Windows file share',
        }
        print(f"{'Port':<8} {'Service':<20} {'Note'}")
        sep()
        for port, service in ports:
            note = risk_map.get(port, '')
            print(f"{port:<8} {service:<20} {note}")
    else:
        print("No open ports found.")
    sep()

    # Banner grabbing — опознаём конкретную модель/софт
    print("Grabbing service banners...")
    banners = grab_banners(device['ip'])
    if banners:
        sep()
        print("Service banners:")
        for svc, info in banners.items():
            if isinstance(info, dict):
                for k, v in info.items():
                    print(f"  {svc}/{k:<8} {v}")
            else:
                print(f"  {svc:<12} {info}")
        guess = guess_from_banners(banners)
        if guess:
            print(f"\n  >> Identified as: {guess}")
        risks = banner_risk(banners)
        for r in risks:
            print(f"  [!] {r}")
        sep()
    else:
        print("No banners (device exposes no readable services).")
        sep()

def show_traffic():
    def get_bytes():
        try:
            r = subprocess.run(['netstat', '-I', 'en0', '-b'],
                               capture_output=True, text=True)
            lines = r.stdout.strip().split('\n')
            if len(lines) > 1:
                parts = lines[1].split()
                if len(parts) >= 10:
                    return int(parts[6]), int(parts[9])
        except Exception:
            pass
        return 0, 0

    print("Measuring for 5 seconds...")
    b1_in, b1_out = get_bytes()
    for i in range(5, 0, -1):
        print(f"\r{i}...", end='', flush=True)
        time.sleep(1)
    print()
    b2_in, b2_out = get_bytes()

    dl = (b2_in - b1_in) / 5
    ul = (b2_out - b1_out) / 5

    def fmt(b):
        if b > 1024*1024: return f"{b/1024/1024:.1f} MB/s"
        if b > 1024:      return f"{b/1024:.1f} KB/s"
        return f"{b:.0f} B/s"

    sep()
    print(f"Download: {fmt(dl)}")
    print(f"Upload:   {fmt(ul)}")
    sep()

def show_router(ip):
    import urllib.request
    print(f"Analyzing {ip}...")
    sep()
    print(f"IP:       {ip}")

    ms = get_ping_ms(ip)
    print(f"Ping:     {ms:.1f}ms" if ms > 0 else "Ping:     no response")

    for url in [f'http://{ip}', f'https://{ip}']:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            resp = urllib.request.urlopen(req, timeout=3)
            html = resp.read().decode('utf-8', errors='ignore')[:1000]
            print(f"Web UI:   {url}")
            m = re.search(r'<title>(.+?)</title>', html, re.I)
            if m:
                print(f"Title:    {m.group(1)[:60]}")
            break
        except Exception:
            pass

    open_ports = []
    for port, service in [(80,'HTTP'),(443,'HTTPS'),(22,'SSH'),(23,'Telnet'),(8080,'HTTP-Alt')]:
        try:
            s = socket.socket()
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(f"{port}/{service}")
            s.close()
        except Exception:
            pass

    if open_ports:
        print(f"Ports:    {', '.join(open_ports)}")

    if '23/Telnet' in open_ports:
        print("[!] WARNING: Telnet open — router may be vulnerable!")
    sep()

def _run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ''

def _grab(text, pattern):
    m = re.search(pattern, text)
    return m.group(1).strip() if m else ''

def recommend_channel(neighbor_5ghz_channels):
    """Из занятых соседями 5GHz-каналов выбирает наименее загруженный якорный
    канал (учитывая перекрытие 80MHz). Возвращает (channel, load)."""
    candidates = [36, 40, 44, 48, 149, 153, 157, 161]
    load = {c: 0 for c in candidates}
    for ch in neighbor_5ghz_channels:
        for c in candidates:
            if abs(c - ch) <= 8:          # 80MHz-блок перекрывает ±несколько каналов
                load[c] += 1
    # при равной загрузке предпочитаем UNII-3 (149+) — там обычно чище
    best = min(candidates, key=lambda c: (load[c], 0 if c >= 149 else 1))
    return best, load[best]


def wifi_audit():
    sep('=')
    print(" FULL WIFI AUDIT")
    sep('=')

    # ---- Wi-Fi линк ----
    sp = _run(['system_profiler', 'SPAirPortDataType'], 20)

    card = _grab(sp, r'Card Type: (.+)')
    fw = _grab(sp, r'Firmware Version: (.+)')
    country = _grab(sp, r'Country Code: (\w+)')

    # блок текущей сети
    cur = ''
    if 'Current Network Information:' in sp:
        cur = sp.split('Current Network Information:')[1]
        if 'Other Local Wi-Fi Networks:' in cur:
            cur = cur.split('Other Local Wi-Fi Networks:')[0]

    phy = _grab(cur, r'PHY Mode: (.+)')
    chan = _grab(cur, r'Channel: (.+)')
    sec = _grab(cur, r'Security: (.+)')
    sig_noise = _grab(cur, r'Signal / Noise: (.+)')
    txrate = _grab(cur, r'Transmit Rate: (.+)')
    mcs = _grab(cur, r'MCS Index: (.+)')

    snr = ''
    sn = re.search(r'(-?\d+) dBm / (-?\d+) dBm', sig_noise)
    if sn:
        snr = f"{int(sn.group(1)) - int(sn.group(2))} dB"

    print("\n[ Wi-Fi Link ]")
    print(f"  Card:        {card}")
    print(f"  Firmware:    {fw[:50]}")
    print(f"  PHY Mode:    {phy}")
    print(f"  Channel:     {chan}")
    print(f"  Security:    {sec}")
    print(f"  Signal/Noise:{sig_noise}")
    print(f"  SNR:         {snr}")
    print(f"  TX Rate:     {txrate} Mbps")
    print(f"  MCS Index:   {mcs}")
    print(f"  Country:     {country}")

    # ---- Соседние сети ----
    print("\n[ Nearby Networks (co-channel check) ]")
    if 'Other Local Wi-Fi Networks:' in sp:
        others = sp.split('Other Local Wi-Fi Networks:')[1].split('awdl0')[0]
        blocks = re.findall(r'PHY Mode: (.+?)\n.*?Channel: (.+?)\n.*?Security: (.+?)\n(?:.*?Signal / Noise: (.+?)\n)?', others, re.DOTALL)
        my_chan = re.search(r'Channel: (\d+)', cur)
        my_ch_num = my_chan.group(1) if my_chan else ''
        five_ghz = []
        if blocks:
            for phy_n, ch_n, sec_n, sn_n in blocks:
                warn = '  <-- SAME CHANNEL!' if my_ch_num and ch_n.startswith(my_ch_num + ' ') else ''
                print(f"  Ch {ch_n:<18} {sec_n:<22} {sn_n or '':<12}{warn}")
                m = re.match(r'(\d+)', ch_n.strip())
                if m and '5GHz' in ch_n:
                    five_ghz.append(int(m.group(1)))
            best, load = recommend_channel(five_ghz)
            if str(best) == my_ch_num:
                if load == 0:
                    print(f"  → Твой канал {best} оптимален — рядом нет других 5GHz сетей")
                else:
                    print(f"  → Твой канал {best} — уже лучший из доступных")
            else:
                note = 'свободен' if load == 0 else f'рядом {load} соседей'
                print(f"  → Рекомендация: перейти на 5GHz канал {best} — {note}")
        else:
            print("  нет")
    else:
        print("  нет")

    # ---- Сеть ----
    print("\n[ Network ]")
    ifc = _run(['ifconfig', 'en0'])
    ip = _grab(ifc, r'inet (\d+\.\d+\.\d+\.\d+)')
    mask_hex = _grab(ifc, r'netmask (0x[0-9a-f]+)')
    mac = _grab(ifc, r'ether ([0-9a-f:]+)')
    mask = '.'.join(str((int(mask_hex, 16) >> (24 - 8*i)) & 0xff) for i in range(4)) if mask_hex else ''
    rt = _run(['netstat', '-rn'])
    gw = _grab(rt, r'default\s+(\d+\.\d+\.\d+\.\d+)')
    dns = _run(['scutil', '--dns'])
    dns_list = list(dict.fromkeys(re.findall(r'nameserver\[\d+\] : (\S+)', dns)))

    print(f"  Local IP:    {ip}")
    print(f"  Subnet mask: {mask}")
    print(f"  Gateway:     {gw}")
    print(f"  Adapter MAC: {mac}")
    print(f"  DNS:         {', '.join(dns_list[:4])}")

    # ---- Внешний IP ----
    print("\n[ External / ISP ]")
    ext = _run(['curl', '-s', '--max-time', '8', 'https://ipinfo.io/json'], 10)
    print(f"  External IP: {_grab(ext, chr(34)+'ip'+chr(34)+': '+chr(34)+'([^'+chr(34)+']+)')}")
    print(f"  Location:    {_grab(ext, chr(34)+'city'+chr(34)+': '+chr(34)+'([^'+chr(34)+']+)')}, {_grab(ext, chr(34)+'country'+chr(34)+': '+chr(34)+'([^'+chr(34)+']+)')}")
    print(f"  Org/ISP:     {_grab(ext, chr(34)+'org'+chr(34)+': '+chr(34)+'([^'+chr(34)+']+)')}")

    # ---- Роутер ----
    print("\n[ Router ]")
    if gw:
        rports = []
        for port, svc in [(22,'SSH'),(23,'Telnet'),(53,'DNS'),(80,'HTTP'),(443,'HTTPS'),(8080,'HTTP-Alt')]:
            try:
                s = socket.socket(); s.settimeout(0.6)
                if s.connect_ex((gw, port)) == 0:
                    rports.append(f"{port}/{svc}")
                s.close()
            except Exception: pass
        ms = get_ping_ms(gw)
        print(f"  Gateway:     {gw}")
        print(f"  Ping:        {ms:.1f} ms" if ms > 0 else "  Ping:        no response")
        print(f"  Open ports:  {', '.join(rports) if rports else 'none'}")
        if any(p.startswith('23/') for p in rports):
            print("  [!] Telnet open — router may be vulnerable")
        if any(p.startswith('80/') for p in rports) and not any(p.startswith('443/') for p in rports):
            print("  [!] Admin over HTTP only (no HTTPS) — password sent in clear on LAN")

    # ---- Производительность ----
    print("\n[ Performance ]  measuring ~20s...")
    nq = _run(['networkQuality'], 40)
    if nq:
        for label, pat in [('Download', r'Downlink capacity: (.+)'),
                            ('Upload',   r'Uplink capacity: (.+)'),
                            ('Idle latency', r'Idle Latency: (.+)'),
                            ('DL respons.', r'Downlink Responsiveness: (.+)'),
                            ('UL respons.', r'Uplink Responsiveness: (.+)')]:
            val = _grab(nq, pat)
            if val:
                print(f"  {label:<13} {val}")
    else:
        print("  networkQuality недоступен")

    sep('=')
    print("Tip: for neighbor BSSID + full channel survey run:  sudo wdutil info")
    sep('=')

def notify(title, message, sound='Ping'):
    """Нативное уведомление macOS (баннер в углу экрана)."""
    try:
        safe_msg = message.replace('"', "'").replace('\\', '')
        safe_title = title.replace('"', "'").replace('\\', '')
        subprocess.run(
            ['osascript', '-e',
             f'display notification "{safe_msg}" with title "{safe_title}" sound name "{sound}"'],
            capture_output=True, timeout=5
        )
    except Exception:
        pass

def internet_monitor(interval=10, host='1.1.1.1'):
    """Мониторит интернет: ловит падения, логирует длительность, шлёт уведомления."""
    log_path = Path.home() / '.wifi-scanner' / 'outages.log'
    print("\n" + "=" * 70)
    print(f" INTERNET MONITOR — pinging {host} every {interval}s.  Ctrl+C to stop.")
    print(f" Outages logged to: {log_path}")
    print("=" * 70)

    def is_up():
        return get_ping_ms(host) > 0

    state = is_up()
    print(f"Start: internet is {'UP' if state else 'DOWN'}")
    down_since = None if state else datetime.now()
    total_outages = 0
    total_down = 0.0

    def log_line(text):
        try:
            with open(log_path, 'a') as f:
                f.write(text + '\n')
        except Exception:
            pass

    try:
        while True:
            for r in range(interval, 0, -1):
                print(f"\r  {'UP ' if state else 'DOWN'}  next check {r}s ...   ", end='', flush=True)
                time.sleep(1)
            print('\r' + ' ' * 50 + '\r', end='')

            now_up = is_up()
            ts = datetime.now()
            tss = ts.strftime('%H:%M:%S %d.%m')

            if state and not now_up:
                # переход UP -> DOWN
                down_since = ts
                total_outages += 1
                msg = f"[{tss}] Internet DOWN"
                print(msg)
                log_line(msg)
                notify("Internet DOWN", f"Connection lost at {ts.strftime('%H:%M:%S')}", 'Basso')

            elif not state and now_up:
                # переход DOWN -> UP
                dur = (ts - down_since).total_seconds() if down_since else 0
                total_down += dur
                msg = f"[{tss}] Internet RESTORED after {dur:.0f}s down"
                print(msg)
                log_line(msg)
                notify("Internet restored", f"Was down {dur:.0f}s", 'Glass')
                down_since = None
            else:
                ms = get_ping_ms(host)
                stat = f"{ms:.0f}ms" if ms > 0 else "no reply"
                print(f"\r  UP  {stat}   outages: {total_outages}   ", end='', flush=True)

            state = now_up
    except KeyboardInterrupt:
        print("\n" + "-" * 70)
        print(f"Summary: {total_outages} outage(s), total downtime {total_down:.0f}s")
        print(f"Full log: {log_path}")
        print("-" * 70)

def watch_mode(interval=30, store=None):
    """Следит за сетью: пищит когда устройство подключается/отключается.
    С хранилищем отличает впервые виденные устройства от просто вернувшихся."""
    print("\n" + "=" * 70)
    print(f" WATCH MODE — checking every {interval}s.  Ctrl+C to stop.")
    print("=" * 70)

    def label(d):
        return d.get('label') or d.get('name') or d.get('hostname') or d.get('vendor') or d['type']

    print("Initial scan...")
    devices = full_scan(quiet=True)
    if store:
        store.record_scan(devices)
        store.annotate(devices)
    known = {d['mac'] or d['ip']: d for d in devices}
    print(f"Baseline: {len(known)} devices online.\n")
    for d in devices:
        print(f"  online: {d['ip']:<16} {label(d)}")
    print()

    try:
        while True:
            for remaining in range(interval, 0, -1):
                print(f"\r  next check in {remaining}s ...", end='', flush=True)
                time.sleep(1)
            print("\r" + " " * 40 + "\r", end='')

            devices = full_scan(quiet=True)
            new_keys = store.record_scan(devices) if store else set()
            if store:
                store.annotate(devices)
            current = {d['mac'] or d['ip']: d for d in devices}
            ts = datetime.now().strftime('%H:%M:%S')

            for key, d in current.items():
                if key not in known:
                    dkey = (d.get('mac') or d.get('ip') or '').upper()
                    first_time = dkey in new_keys
                    tag = 'NEW DEVICE' if first_time else 'JOINED'
                    print(f"\a[{ts}] + {tag}:  {d['ip']:<16} {label(d)}")
                    notify("NEW device on network" if first_time else "Device JOINED network",
                           f"{label(d)} ({d['ip']})", 'Ping')
            for key, d in known.items():
                if key not in current:
                    print(f"[{ts}] - LEFT:    {d['ip']:<16} {label(d)}")
                    notify("Device LEFT network",
                           f"{label(d)} ({d['ip']})", 'Pop')

            known = current
    except KeyboardInterrupt:
        print("\nWatch stopped.")

_SPARK = '▁▂▃▄▅▆▇█'

def sparkline(values):
    """ASCII-спарклайн из списка чисел."""
    if not values:
        return ''
    lo, hi = min(values), max(values)
    if hi == lo:
        return _SPARK[3] * len(values)
    step = len(_SPARK) - 1
    return ''.join(_SPARK[int((v - lo) / (hi - lo) * step)] for v in values)


def show_trends(store):
    if store is None:
        print("Trends unavailable (store module missing).")
        return
    st = store.stats()
    sep('=')
    print(f" TRENDS  |  {st['scans']} сканов  |  {st['devices']} известных устройств")
    sep('=')
    counts = store.scan_counts(40)
    if counts:
        print(f"Устройств онлайн (последние {len(counts)} сканов):")
        print("  " + sparkline(counts) + f"   мин {min(counts)} / макс {max(counts)}")
        print()
    total = st['scans'] or 1
    rows = store.known_devices()
    if not rows:
        print("Нет данных — сделай несколько сканов.")
        sep()
        return
    print(f"{'Устройство':<22} {'Присутствие':<16} {'Последний раз'}")
    sep()
    for r in sorted(rows, key=lambda x: x.get('times_seen', 0), reverse=True):
        name = (r.get('label') or r.get('name') or r.get('vendor') or r.get('last_ip') or '?')[:22]
        pct = min(100, round(r.get('times_seen', 0) / total * 100))
        bar = '#' * (pct // 10)
        last = (r.get('last_seen') or '').replace('T', ' ')[5:16]
        print(f"{name:<22} {str(pct) + '%':<4} {bar:<10} {last}")
    sep()
    print("Присутствие = в каком % сканов устройство было онлайн.")
    sep()


def show_history(store):
    sep('=')
    st = store.stats()
    print(f" DEVICE HISTORY  |  {st['devices']} known devices  |  {st['scans']} scans")
    sep('=')
    rows = store.known_devices()
    if not rows:
        print("No history yet — run a scan first.")
        sep()
        return
    print(f"{'Name':<24} {'Type':<16} {'Last IP':<15} {'Seen':<5} {'Last seen'}")
    sep()
    for r in rows:
        name = (r.get('label') or r.get('name') or r.get('vendor') or r.get('last_ip') or '?')[:24]
        last = (r.get('last_seen') or '').replace('T', ' ')
        print(f"{name:<24} {(r.get('type') or '')[:16]:<16} {(r.get('last_ip') or ''):<15} {str(r.get('times_seen', 0)):<5} {last}")
    sep()


def print_audit(audited):
    for a in audited:
        d = a['device']
        name = d.get('label') or d.get('name') or d.get('vendor') or d.get('type') or d['ip']
        ports = f"  ports: {','.join(map(str, a['open_ports']))}" if a['open_ports'] else ''
        print(f"[{a['level']:<8}] {a['score']:>3}  {d['ip']:<15} {name}{ports}")
        for r in a['reasons']:
            print(f"            - {r}")


def do_security(devices, new_keys, store, network_id=None):
    if security is None:
        print("Security module unavailable.")
        return
    sep('=')
    print(" SECURITY AUDIT — probing risk ports on all devices...")
    sep('=')
    audited = security.audit(devices, new_keys, store=store, network_id=network_id)
    print_audit(audited)
    sep()
    try:
        ans = input("Save report? [t]ext / [j]son / [n]o: ").strip().lower()
        if ans in ('t', 'y'):
            print(f"Saved: {security.write_report(audited)}")
            sep()
        elif ans == 'j':
            print(f"Saved: {security.write_report_json(audited)}")
            sep()
    except (EOFError, KeyboardInterrupt):
        pass


def ping_quality(host, count=20, interval=0.15):
    """Качество линка до host: loss%, min/avg/max, jitter (среднее отклонение)."""
    times, lost = [], 0
    for _ in range(count):
        try:
            r = subprocess.run(['ping', '-c', '1', '-W', '1000', host],
                               capture_output=True, text=True, timeout=2)
            m = re.search(r'time=([\d.]+)', r.stdout)
            if r.returncode == 0 and m:
                times.append(float(m.group(1)))
            else:
                lost += 1
        except Exception:
            lost += 1
        time.sleep(interval)
    n = len(times)
    if not n:
        return {'host': host, 'count': count, 'received': 0, 'loss': 100.0}
    avg = sum(times) / n
    jitter = sum(abs(t - avg) for t in times) / n
    return {'host': host, 'count': count, 'received': n,
            'loss': round(lost / count * 100, 1),
            'min': round(min(times), 1), 'avg': round(avg, 1),
            'max': round(max(times), 1), 'jitter': round(jitter, 2)}


def _quality_verdict(q):
    # Судим по потерям и jitter — это и есть «качество». Сама задержка (avg)
    # зависит от расстояния до сервера и не является проблемой сама по себе.
    if q['received'] == 0:
        return 'НЕТ ОТВЕТА'
    if q['loss'] > 2 or q['jitter'] > 15:
        return 'проблемы'
    if q['loss'] > 0 or q['jitter'] > 8:
        return 'средне'
    return 'отлично'


def do_quality():
    base = get_network_base()
    targets = [(f'{base}.1', 'Роутер-шлюз'), ('1.1.1.1', 'Интернет')]
    sep('=')
    print(" LINK QUALITY — по 20 пингов на цель (loss / задержка / jitter)...")
    sep('=')
    for host, label in targets:
        q = ping_quality(host)
        verdict = _quality_verdict(q)
        if q['received'] == 0:
            print(f"  {label:<20} {host:<14}  loss 100%  → {verdict}")
        else:
            print(f"  {label:<20} {host:<14}  loss {q['loss']}%  "
                  f"avg {q['avg']}ms  min {q['min']}  max {q['max']}  "
                  f"jitter {q['jitter']}ms  → {verdict}")
    sep()
    print("  Ориентир: loss 0%, jitter <8ms, avg <30ms локально = звонки/игры без лагов.")
    sep()


def do_export(devices, path):
    if exporter is None:
        print("Export module unavailable.")
        return
    try:
        out = exporter.write(devices, path)
        print(f"Exported {len(devices)} devices -> {out}")
    except Exception as e:
        print(f"Export failed: {e}")


def show_wdutil():
    """Полная Wi-Fi диагностика через встроенный macOS `wdutil` (нужен sudo).
    Обёртка, чтобы не набирать длинное `sudo wdutil info`."""
    if not shutil.which('wdutil'):
        print("wdutil не найден.")
        return
    print("Запуск: sudo wdutil info")
    sep()
    try:
        subprocess.run(['sudo', 'wdutil', 'info'])   # наследует терминал: и пароль, и вывод
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"wdutil error: {e}")


def net_health():
    """Быстрая проверка здоровья сети: шлюз, интернет, DNS."""
    base = get_network_base()
    out = {'gateway_up': get_ping_ms(f'{base}.1') > 0,
           'internet_up': get_ping_ms('1.1.1.1') > 0}
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3)
    try:
        socket.gethostbyname('apple.com')
        out['dns_ok'] = True
    except Exception:
        out['dns_ok'] = False
    finally:
        socket.setdefaulttimeout(old)
    return out


def do_report(devices, new_keys, store):
    """Единый полный отчёт: health + устройства + безопасность + качество линка.
    Печатает и сохраняет в ~/.wifi-scanner (0600). Отвечает «всё ли ок»."""
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    lines = ['WFS FULL REPORT', ts, '=' * 70]
    problems = []

    h = net_health()
    lines += ['[ Health ]',
              f"  Gateway:   {'up' if h['gateway_up'] else 'DOWN'}",
              f"  Internet:  {'up' if h['internet_up'] else 'DOWN'}",
              f"  DNS:       {'ok' if h['dns_ok'] else 'FAIL'}", '']
    if not h['internet_up']:
        problems.append('нет интернета')
    if not h['dns_ok']:
        problems.append('DNS не резолвит')

    lines.append(f"[ Devices ]  {len(devices)} online")
    for d in devices:
        lines.append(f"  {d['ip']:<15} {d.get('name') or d.get('vendor') or d['type']}")
    lines.append('')

    if security is not None:
        audited = security.audit(devices, new_keys, store=store, network_id=get_network_base())
        risky = [a for a in audited if a['score'] > 0]
        lines.append(f"[ Security ]  {len(risky)} устройств(а) с замечаниями")
        for a in risky:
            d = a['device']
            lines.append(f"  [{a['level']}] {d['ip']} {d.get('name') or d['type']}")
            for r in a['reasons']:
                lines.append(f"     - {r}")
            if a['level'] in ('HIGH', 'CRITICAL'):
                problems.append(f"{d['ip']}: {a['reasons'][0] if a['reasons'] else 'риск'}")
        lines.append('')

    base = get_network_base()
    lines.append('[ Link quality ]')
    for host, label in [(f'{base}.1', 'gateway '), ('1.1.1.1', 'internet')]:
        q = ping_quality(host, count=15)
        v = _quality_verdict(q)
        if q['received'] == 0:
            lines.append(f"  {label}  loss 100%  → {v}")
            problems.append(f'{label.strip()}: нет ответа')
        else:
            lines.append(f"  {label}  loss {q['loss']}%  avg {q['avg']}ms  "
                         f"jitter {q['jitter']}ms  → {v}")
            if v == 'проблемы':
                problems.append(f'{label.strip()}: качество связи')
    lines += ['', '=' * 70]

    if problems:
        lines.append(f"НАЙДЕНЫ ПРОБЛЕМЫ ({len(problems)}):")
        lines += [f"  ! {p}" for p in problems]
    else:
        lines.append("Явных проблем не найдено.")

    text = '\n'.join(lines) + '\n'
    print(text)
    try:
        p = Path.home() / '.wifi-scanner' / f"full-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        import os
        os.chmod(p, 0o600)
        print(f"Сохранено: {p}")
    except Exception as e:
        print(f"(не удалось сохранить отчёт: {e})")


def maybe_auto_oui():
    """Download the full vendor DB once, in the background, on first run."""
    if CFG.get('auto_oui', True) and not OUI_CACHE.exists():
        threading.Thread(target=download_oui, kwargs={'quiet': True},
                         daemon=True).start()


def _label(d):
    return d.get('name') or d.get('hostname') or d.get('vendor') or d.get('type') or d['ip']


def print_menu():
    left = [
        ('ls', 'показать устройства'),
        ('r', 'полный рескан'),
        ('rr', 'быстрый рескан'),
        ('N', 'детали устройства N'),
        ('sec', 'аудит безопасности'),
        ('report', 'полный отчёт'),
        ('trends', 'тренды присутствия'),
        ('history', 'устройства за всё время'),
        ('export F', 'экспорт в файл'),
    ]
    right = [
        ('wifi', 'Wi-Fi аудит'),
        ('diag', 'диагностика Wi-Fi'),
        ('quality', 'качество связи'),
        ('watch', 'мониторинг сети'),
        ('uptime', 'мониторинг интернета'),
        ('router', 'инфо о роутере'),
        ('traffic', 'скорость интернета'),
        ('oui', 'база вендоров'),
        ('q', 'выход'),
    ]
    for (lc, ld), (rc, rd) in zip(left, right):
        print(f"   {lc:<9} - {ld:<26}     {rc:<9} - {rd}")


def _print_new(devices, new_keys):
    # «впервые в сети» — но НЕ для рандомных MAC (телефоны их крутят).
    fresh = [d for d in devices
             if (d.get('mac') or d.get('ip') or '').upper() in new_keys
             and not d.get('is_me') and not d.get('random_mac')]
    if fresh:
        print("NEW (впервые в сети): " +
              ", ".join(f"{d['ip']} {_label(d)}" for d in fresh))


def main():
    store = Store() if Store else None
    state = {'devices': [], 'new_keys': set()}
    port_cache = {}
    maybe_auto_oui()

    def scan_now():
        state['devices'] = full_scan()
        port_cache.clear()
        if store:
            state['new_keys'] = store.record_scan(state['devices'])
            store.annotate(state['devices'])
        _print_new(state['devices'], state['new_keys'])
        return state['devices']

    def devices():
        """Return current devices, scanning once if we don't have any yet."""
        return state['devices'] or scan_now()

    print("wfs · WiFi scanner.   «?» — команды · «ls» — устройства · «q» — выход")

    while True:
        try:
            raw = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            sys.exit(0)
        if not raw:
            continue
        cmd = raw.lower()

        if cmd in ('q', 'quit', 'exit'):
            print("Bye.")
            sys.exit(0)
        elif cmd in ('?', 'help', 'h'):
            print_menu()
        elif cmd in ('ls', 'l'):
            display_devices(devices())
        elif cmd == 'r':
            state['devices'] = []
            display_devices(scan_now())
        elif cmd == 'rr':
            if not state['devices']:
                display_devices(devices())
            else:
                state['devices'], joined, left = quick_refresh(state['devices'])
                port_cache.clear()
                if store:
                    state['new_keys'] = store.record_scan(state['devices'])
                    store.annotate(state['devices'])
                parts = []
                if joined:
                    parts.append("+ " + ", ".join(f"{d['ip']} {_label(d)}" for d in joined))
                if left:
                    parts.append("- " + ", ".join(f"{d['ip']} {_label(d)}" for d in left))
                print("Δ  " + "    ".join(parts) if parts else "Δ  без изменений")
                display_devices(state['devices'])
        elif cmd == 'wifi':
            wifi_audit()
        elif cmd == 'diag':
            show_wdutil()
        elif cmd == 'watch':
            watch_mode(store=store)
        elif cmd == 'uptime':
            internet_monitor()
        elif cmd == 'quality':
            do_quality()
        elif cmd == 'sec':
            do_security(devices(), state['new_keys'], store, network_id=get_network_base())
        elif cmd == 'report':
            do_report(devices(), state['new_keys'], store)
        elif cmd == 'trends':
            show_trends(store)
        elif cmd == 'history':
            show_history(store) if store else print("История недоступна.")
        elif cmd.startswith('export'):
            parts = raw.split(maxsplit=1)
            if len(parts) == 2 and parts[1].strip():
                do_export(devices(), parts[1].strip())
            else:
                print("Использование: export <файл.json | файл.csv>")
        elif cmd == 'oui':
            download_oui()
            state['devices'] = []
        elif cmd == 'router':
            router = next((d for d in devices() if d['ip'].endswith('.1')), None)
            show_router(router['ip'] if router else input("Router IP: ").strip())
        elif cmd == 'traffic':
            show_traffic()
        elif cmd.isdigit():
            devs = devices()
            idx = int(cmd) - 1
            if 0 <= idx < len(devs):
                show_device(devs[idx], port_cache)
            else:
                print("Нет такого номера.")
        else:
            print(f"Неизвестная команда: {raw}   («?» — список)")


def run_cli(argv=None):
    """Entry point. No flags → interactive UI. Flags → one-shot, script-friendly."""
    import argparse
    p = argparse.ArgumentParser(
        prog='wfs', description='WiFi network scanner (terminal).')
    p.add_argument('--scan', action='store_true', help='scan once and print the table')
    p.add_argument('--sec', action='store_true', help='scan + security audit')
    p.add_argument('--watch', action='store_true', help='monitor network (Ctrl-C to stop)')
    p.add_argument('--diag', action='store_true', help='full Wi-Fi diagnostics (sudo wdutil info)')
    p.add_argument('--report', action='store_true', help='full report: problems/security/quality')
    p.add_argument('--quality', action='store_true', help='link quality (loss/latency/jitter)')
    p.add_argument('--trends', action='store_true', help='presence trends over time')
    p.add_argument('--history', action='store_true', help='show device history')
    p.add_argument('--export', metavar='FILE', help='scan and write to FILE (.json/.csv)')
    p.add_argument('--json', action='store_true', help='machine-readable JSON output')
    p.add_argument('--debug', action='store_true', help='verbose diagnostics to stderr')
    p.add_argument('--version', action='store_true')
    args = p.parse_args(argv)

    if args.debug:
        log.setLevel(logging.DEBUG)

    if args.version:
        print('wfs 2.0')
        return

    if args.diag:
        show_wdutil()
        return

    if args.quality:
        do_quality()
        return

    if not any([args.scan, args.sec, args.watch, args.history, args.export,
                args.report, args.trends]):
        main()
        return

    store = Store() if Store else None

    if args.trends:
        show_trends(store)
        return

    if args.history:
        if args.json and exporter and store:
            print(exporter.to_json(store.known_devices()))
        elif store:
            show_history(store)
        return

    if args.watch:
        watch_mode(store=store)
        return

    devices = full_scan(quiet=args.json)
    new_keys = store.record_scan(devices) if store else set()
    if store:
        store.annotate(devices)

    if args.export:
        do_export(devices, args.export)
        return

    if args.report:
        do_report(devices, new_keys, store)
        return

    if args.sec:
        if security is None:
            print('security module unavailable')
            return
        audited = security.audit(devices, new_keys, store=store,
                                  network_id=get_network_base())
        if args.json:
            print(security.write_report_json(audited).read_text())
        else:
            print_audit(audited)
        return

    # default --scan
    if args.json and exporter:
        print(exporter.to_json(devices))
    else:
        display_devices(devices)


if __name__ == '__main__':
    run_cli()
