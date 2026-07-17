#!/usr/bin/env python3
"""Идентификация устройств без опоры на MAC:
mDNS/Bonjour (имена), SSDP/UPnP (модели), fingerprint по портам."""
import socket
import struct
import re
import time
import threading
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ─── DNS / mDNS парсинг ───────────────────────────────────────────────────────

def decode_name(data, offset):
    """Декодирует DNS-имя с учётом сжатия (указатели 0xC0)."""
    labels = []
    jumped = False
    original_offset = offset
    safety = 0
    while True:
        safety += 1
        if safety > 100 or offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode('utf-8', 'ignore'))
        offset += length
    name = '.'.join(labels)
    return name, (original_offset if jumped else offset)

def build_query(qname, qtype=12):
    """Строит DNS-запрос (PTR по умолчанию)."""
    header = struct.pack('>HHHHHH', 0, 0, 1, 0, 0, 0)
    q = b''
    for part in qname.split('.'):
        q += bytes([len(part)]) + part.encode()
    q += b'\x00'
    q += struct.pack('>HH', qtype, 1)
    return header + q

def parse_response(data):
    """Парсит mDNS-ответ, возвращает список (name, rtype, rdata_name/ip)."""
    results = []
    try:
        qdcount = struct.unpack('>H', data[4:6])[0]
        ancount = struct.unpack('>H', data[6:8])[0]
        offset = 12
        # пропускаем вопросы
        for _ in range(qdcount):
            _, offset = decode_name(data, offset)
            offset += 4
        # читаем ответы
        for _ in range(ancount):
            name, offset = decode_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlen = struct.unpack('>HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            if rtype == 12:   # PTR
                target, _ = decode_name(data, offset)
                results.append((name, 'PTR', target))
            elif rtype == 1 and rdlen == 4:  # A
                ip = '.'.join(str(b) for b in rdata)
                results.append((name, 'A', ip))
            elif rtype == 33:  # SRV
                target, _ = decode_name(data, offset + 6)
                results.append((name, 'SRV', target))
            elif rtype == 16:  # TXT — length-prefixed key=value strings
                txt, i = {}, 0
                while i < rdlen:
                    ln = rdata[i]; i += 1
                    if ln == 0 or i + ln > rdlen:
                        break
                    item = rdata[i:i + ln].decode('utf-8', 'ignore'); i += ln
                    if '=' in item:
                        k, v = item.split('=', 1)
                        txt[k.lower()] = v
                results.append((name, 'TXT', txt))
            offset += rdlen
    except Exception:
        pass
    return results

def mdns_discover(timeout=4):
    """Слушает mDNS, возвращает {ip: hostname}."""
    names = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except Exception:
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)

        # запрашиваем список сервисов и популярные типы
        queries = [
            '_services._dns-sd._udp.local',
            '_airplay._tcp.local', '_raop._tcp.local',
            '_companion-link._tcp.local', '_googlecast._tcp.local',
            '_spotify-connect._tcp.local', '_printer._tcp.local',
            '_ipp._tcp.local', '_homekit._tcp.local',
            '_device-info._tcp.local',
        ]
        for q in queries:
            try:
                sock.sendto(build_query(q, 12), ('224.0.0.251', 5353))
            except Exception:
                pass

        # собираем ответы
        end = time.time() + timeout
        host_by_ip = {}   # ip -> hostname (.local)
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(9000)
                src_ip = addr[0]
                for name, rtype, rdata in parse_response(data):
                    if rtype == 'A':
                        # rdata = ip, name = hostname.local — самый надёжный источник
                        clean = name.replace('.local', '')
                        if clean and not clean.startswith('_'):
                            if rdata not in host_by_ip or len(clean) > len(host_by_ip.get(rdata, '')):
                                host_by_ip[rdata] = clean
                    elif rtype == 'PTR':
                        # имя инстанса сервиса (напр. "Kirill iPhone._airplay._tcp")
                        inst = rdata.split('._')[0]
                        # отбрасываем служебные типы вида _services/_airplay
                        if inst and not inst.startswith('_') and src_ip not in host_by_ip:
                            host_by_ip[src_ip] = inst
                    elif rtype == 'TXT' and isinstance(rdata, dict):
                        # модель из TXT (model=/md=/am=) как имя-фолбэк
                        model = rdata.get('model') or rdata.get('md') or rdata.get('am')
                        if model and src_ip not in host_by_ip:
                            host_by_ip[src_ip] = model
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()
        names = host_by_ip
    except Exception:
        pass
    return names

# ─── SSDP / UPnP ──────────────────────────────────────────────────────────────

def ssdp_discover(timeout=3):
    """M-SEARCH по UPnP, возвращает {ip: {'server':..., 'model':...}}."""
    devices = {}
    msg = '\r\n'.join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 2',
        'ST: ssdp:all',
        '', ''
    ]).encode()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        sock.sendto(msg, ('239.255.255.250', 1900))

        end = time.time() + timeout
        locations = {}
        while time.time() < end:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                text = data.decode('utf-8', 'ignore')
                server = re.search(r'SERVER:\s*(.+)', text, re.I)
                location = re.search(r'LOCATION:\s*(.+)', text, re.I)
                entry = devices.setdefault(ip, {})
                if server:
                    entry['server'] = server.group(1).strip()
                if location:
                    locations[ip] = location.group(1).strip()
            except socket.timeout:
                continue
            except Exception:
                continue
        sock.close()

        # тянем friendlyName/modelName из XML (быстро, по 1 на устройство)
        for ip, url in locations.items():
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                xml = urllib.request.urlopen(req, timeout=2).read().decode('utf-8', 'ignore')
                fn = re.search(r'<friendlyName>(.+?)</friendlyName>', xml)
                mn = re.search(r'<modelName>(.+?)</modelName>', xml)
                man = re.search(r'<manufacturer>(.+?)</manufacturer>', xml)
                if fn:
                    devices[ip]['name'] = fn.group(1).strip()
                if mn:
                    devices[ip]['model'] = mn.group(1).strip()
                if man:
                    devices[ip]['manufacturer'] = man.group(1).strip()
            except Exception:
                pass
    except Exception:
        pass
    return devices

# ─── Fingerprint по портам ────────────────────────────────────────────────────

PORT_FINGERPRINTS = {
    62078: 'iPhone/iPad',
    7000:  'Apple (AirPlay)',
    3689:  'Apple TV / iTunes',
    548:   'Apple (file sharing)',
    8009:  'Chromecast',
    9100:  'Printer',
    515:   'Printer',
    631:   'Printer (IPP)',
    32400: 'Plex Server',
    1883:  'IoT (MQTT)',
    554:   'IP Camera',
    445:   'Windows PC',
    139:   'Windows PC',
    22:    'Linux/SSH host',
    32469: 'Plex DLNA',
    8123:  'Home Assistant',
}

def port_fingerprint(ip, timeout=0.5, workers=8):
    """Тип устройства по характерным открытым портам. Bounded concurrency —
    не поднимает по потоку на каждый порт (иначе на большой сети взрыв потоков)."""
    found = []
    lock = threading.Lock()

    def check(item):
        port, label = item
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                with lock:
                    found.append((port, label))
            s.close()
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(check, list(PORT_FINGERPRINTS.items())))

    if found:
        found.sort()
        return found[0][1]
    return ''


# ─── Banner grabbing ──────────────────────────────────────────────────────────

# Ключевые слова в баннерах -> понятный бренд/тип устройства
BANNER_BRANDS = {
    'synology': 'Synology NAS', 'qnap': 'QNAP NAS', 'truenas': 'TrueNAS',
    'hikvision': 'Hikvision Camera', 'dahua': 'Dahua Camera',
    'axis': 'Axis Camera', 'reolink': 'Reolink Camera',
    'routeros': 'MikroTik Router', 'mikrotik': 'MikroTik Router',
    'openwrt': 'OpenWRT Router', 'dd-wrt': 'DD-WRT Router',
    'tp-link': 'TP-Link', 'tplink': 'TP-Link', 'asus': 'ASUS Router',
    'netgear': 'Netgear', 'dlink': 'D-Link', 'd-link': 'D-Link',
    'ubnt': 'Ubiquiti', 'unifi': 'Ubiquiti UniFi',
    'raspbian': 'Raspberry Pi', 'ubuntu': 'Linux (Ubuntu)',
    'debian': 'Linux (Debian)', 'openssh': 'SSH host',
    'lighttpd': 'embedded device', 'boa': 'IoT device',
    'goahead': 'IoT/Camera', 'mini_httpd': 'embedded device',
    'philips hue': 'Philips Hue', 'sonos': 'Sonos Speaker',
    'roku': 'Roku', 'plex': 'Plex Server', 'jellyfin': 'Jellyfin Server',
    'home assistant': 'Home Assistant', 'printer': 'Printer',
    'hp ': 'HP device', 'canon': 'Canon device', 'epson': 'Epson printer',
    'windows': 'Windows', 'apache': 'Web server (Apache)',
    'nginx': 'Web server (nginx)', 'microsoft-iis': 'Windows (IIS)',
}

def _recv_some(sock, maxlen=2048, timeout=2):
    sock.settimeout(timeout)
    data = b''
    try:
        while len(data) < maxlen:
            chunk = sock.recv(512)
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data

def grab_http(ip, port=80, timeout=2, https=False):
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        if raw.connect_ex((ip, port)) != 0:
            raw.close()
            return {}
        if https:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw, server_hostname=ip)
        else:
            sock = raw
        req = (f"GET / HTTP/1.0\r\nHost: {ip}\r\n"
               f"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode())
        data = _recv_some(sock, 4096, timeout)
        sock.close()
        text = data.decode('utf-8', 'ignore')
        out = {}
        srv = re.search(r'Server:\s*(.+)', text, re.I)
        if srv:
            out['server'] = srv.group(1).strip()[:60]
        wa = re.search(r'WWW-Authenticate:\s*(.+)', text, re.I)
        if wa:
            out['auth'] = wa.group(1).strip()[:60]
        ti = re.search(r'<title>(.+?)</title>', text, re.I | re.S)
        if ti:
            out['title'] = re.sub(r'\s+', ' ', ti.group(1)).strip()[:60]
        return out
    except Exception:
        return {}

def grab_line_banner(ip, port, timeout=2):
    """Сервисы которые шлют баннер сразу (SSH/FTP/Telnet/SMTP)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return ''
        data = _recv_some(s, 256, timeout)
        s.close()
        return data.decode('utf-8', 'ignore').strip().split('\n')[0][:80]
    except Exception:
        return ''

def grab_rtsp(ip, port=554, timeout=2):
    """Камеры: RTSP OPTIONS -> Server header."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            return ''
        s.sendall(f"OPTIONS rtsp://{ip} RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode())
        data = _recv_some(s, 1024, timeout)
        s.close()
        m = re.search(r'Server:\s*(.+)', data.decode('utf-8', 'ignore'), re.I)
        return m.group(1).strip()[:60] if m else 'RTSP/Camera'
    except Exception:
        return ''

def grab_banners(ip):
    """Собирает все баннеры с устройства параллельно."""
    results = {}
    lock = threading.Lock()

    def task(name, fn):
        val = fn()
        if val:
            with lock:
                results[name] = val

    jobs = [
        ('http',   lambda: grab_http(ip, 80)),
        ('http8080', lambda: grab_http(ip, 8080)),
        ('https',  lambda: grab_http(ip, 443, https=True)),
        ('ssh',    lambda: grab_line_banner(ip, 22)),
        ('ftp',    lambda: grab_line_banner(ip, 21)),
        ('telnet', lambda: grab_line_banner(ip, 23)),
        ('rtsp',   lambda: grab_rtsp(ip)),
    ]
    threads = [threading.Thread(target=task, args=(n, f)) for n, f in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results

def guess_from_banners(banners):
    """Из баннеров выводит понятный ярлык устройства."""
    blob = ' '.join(
        v if isinstance(v, str) else ' '.join(v.values())
        for v in banners.values()
    ).lower()
    for kw, label in BANNER_BRANDS.items():
        if kw in blob:
            return label
    return ''


# Известные проблемы/дефолтные креды по ключевым словам в баннерах.
BANNER_RISKS = {
    'hikvision':  'IP-камера Hikvision — частые дефолт admin/12345, RCE CVE-2021-36260',
    'dahua':      'IP-камера Dahua — дефолт-креды и известные бэкдоры',
    'goahead':    'IoT web (GoAhead) — частые дефолт-креды admin/admin',
    'boa':        'Устаревший IoT web-сервер (Boa) — известные уязвимости',
    'rompager':   'Роутер (RomPager) — Misfortune Cookie, CVE-2014-9222',
    'mikrotik':   'MikroTik/RouterOS — обнови (CVE-2018-14847, слив паролей)',
    'routeros':   'RouterOS — проверь версию (CVE-2018-14847)',
    'gpon':       'GPON-роутер — обход авторизации, CVE-2018-10561',
    'dnsmasq':    'dnsmasq — если старый, CVE-2017-14491 (DNS RCE)',
    'miniupnpd':  'UPnP наружу — риск несанкционированного проброса портов',
    'telnetd':    'Telnet-демон — почти всегда дефолт-креды, отключи',
    'busybox':    'BusyBox (IoT) — часто дефолтные логины root/admin',
}


def banner_risk(banners):
    """Список известных рисков/дефолт-кредов по баннерам устройства."""
    blob = ' '.join(
        v if isinstance(v, str) else ' '.join(v.values())
        for v in banners.values()
    ).lower()
    return [msg for kw, msg in BANNER_RISKS.items() if kw in blob]


# ─── OS hint via TTL (no sudo) ────────────────────────────────────────────────

def ttl_os_hint(ip, timeout=2):
    """Rough OS family from the ICMP reply TTL. Initial TTLs: 64 (Apple/Linux/
    Unix), 128 (Windows), 255 (routers / network gear). No root needed."""
    try:
        r = subprocess.run(['ping', '-c', '1', '-W', '600', ip],
                           capture_output=True, text=True, timeout=timeout)
        m = re.search(r'ttl[=\s](\d+)', r.stdout, re.I)
        if not m:
            return ''
        ttl = int(m.group(1))
        if ttl > 128:
            return 'Network'
        if ttl > 64:
            return 'Windows'
        if ttl > 0:
            return 'Apple/Linux'
    except Exception:
        pass
    return ''


# ─── NetBIOS name (Windows machines, no root) ─────────────────────────────────

# NBSTAT (node status) request for the wildcard name "*".
_NBSTAT_QUERY = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01')

def netbios_name(ip, timeout=1.0):
    """Query UDP/137 for a Windows machine's NetBIOS name. Returns '' if the
    host doesn't answer (non-Windows or firewalled)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(_NBSTAT_QUERY, (ip, 137))
        data, _ = s.recvfrom(1024)
        s.close()
    except Exception:
        return ''
    try:
        if len(data) < 57:
            return ''
        num = data[56]           # number of names in the node-status answer
        off, fallback = 57, ''
        for _ in range(num):
            if off + 18 > len(data):
                break
            name = data[off:off + 15].decode('ascii', 'ignore').rstrip(' \x00')
            suffix = data[off + 15]
            flags = (data[off + 16] << 8) | data[off + 17]
            group = bool(flags & 0x8000)
            off += 18
            if name and not group and suffix == 0x00:
                return name      # unique workstation/computer name
            if name and not group and not fallback:
                fallback = name
        return fallback
    except Exception:
        return ''


if __name__ == '__main__':
    print("mDNS discovery (4s)...")
    names = mdns_discover()
    for ip, name in names.items():
        print(f"  {ip:<16} {name}")

    print("\nSSDP discovery (3s)...")
    ssdp = ssdp_discover()
    for ip, info in ssdp.items():
        label = info.get('name') or info.get('model') or info.get('server', '')
        print(f"  {ip:<16} {label}")
