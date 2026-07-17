#!/usr/bin/env python3
"""Security auditing for WFS.

Scans risk-relevant TCP ports across all devices (parallel), scores each device,
detects gateway-MAC changes (ARP spoofing / MITM) and newly-opened ports vs the
last audit, flags brand-new unknown devices as possible intruders, and writes
text or JSON reports. Stdlib only.
"""
import json
import os
import socket
import threading
from datetime import datetime
from pathlib import Path


def _write_private(path: Path, text: str) -> Path:
    """Write a report and restrict it to the owner (0600) — it maps the LAN."""
    path.write_text(text)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return path

# port -> (weight, label)
RISK_PORTS = {
    23:   (40, 'Telnet open — unencrypted remote login'),
    2323: (40, 'Telnet (alt) open — unencrypted remote login'),
    21:   (15, 'FTP open — often unencrypted'),
    3389: (25, 'RDP open — remote desktop exposed'),
    5900: (25, 'VNC open — remote screen exposed'),
    5555: (30, 'ADB open — Android debug bridge exposed'),
    445:  (15, 'SMB open — Windows file sharing exposed'),
    139:  (10, 'NetBIOS open — legacy Windows sharing'),
    22:   (5,  'SSH open — remote shell (fine if patched)'),
    1883: (10, 'MQTT open — unauthenticated IoT broker?'),
    554:  (5,  'RTSP open — camera stream exposed'),
}
CONTEXT_PORTS = {80, 443}
ALL_PORTS = sorted(set(RISK_PORTS) | CONTEXT_PORTS)
LEVELS = [(60, 'CRITICAL'), (35, 'HIGH'), (18, 'MEDIUM'), (1, 'LOW')]


def _level(score: int) -> str:
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return 'OK'


def _scan(ip, ports, timeout, results, lock):
    open_ = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_.append(port)
            s.close()
        except Exception:
            pass
    with lock:
        results[ip] = open_


def audit(devices: list, new_keys=None, store=None, network_id=None,
          timeout: float = 0.6, workers: int = 40) -> list:
    """Score every device by exposure. Returns a risk-sorted list of dicts:
    {device, score, level, open_ports, reasons}. ``network_id`` scopes the
    gateway-MAC (ARP-spoof) check so a network switch isn't a false alarm."""
    new_keys = new_keys or set()
    results, lock, threads = {}, threading.Lock(), []
    for d in devices:
        t = threading.Thread(target=_scan, args=(d['ip'], ALL_PORTS, timeout, results, lock))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    # Gateway-MAC change => ARP spoofing / MITM.
    spoof = None
    if store is not None:
        gw = next((d for d in devices if d.get('is_gateway') and d.get('mac')), None)
        if gw:
            status, prev = store.check_gateway_mac(gw['mac'], network_id)
            if status == 'changed':
                spoof = (gw['ip'], prev)

    audited = []
    for d in devices:
        open_ports = results.get(d['ip'], [])
        score, reasons = 0, []

        for port in open_ports:
            if port in RISK_PORTS:
                w, label = RISK_PORTS[port]
                score += w
                reasons.append(label)

        if d.get('is_gateway') and 80 in open_ports and 443 not in open_ports:
            score += 20
            reasons.append('Router admin over HTTP only (no HTTPS) — LAN password sniffable')

        # Newly-opened risky ports since the last audit.
        if store is not None:
            prev_ports = store.update_ports(d, open_ports)
            for p in open_ports:
                if p not in prev_ports and p in RISK_PORTS:
                    score += 10
                    reasons.append(f'Port {p} newly opened since last audit')

        # Gateway MAC change.
        if spoof and d['ip'] == spoof[0]:
            score += 50
            reasons.append(f'GATEWAY MAC CHANGED (was {spoof[1]}) — possible ARP spoofing / MITM')

        # Brand-new unrecognized device. Skip randomized-MAC devices: modern
        # phones rotate their MAC, so a "new" random MAC is expected churn, not
        # an intrusion — flagging it would fire false alarms every rotation.
        key = (d.get('mac') or d.get('ip') or '').upper()
        unknown = (d.get('type') in (None, '', 'Unknown')) and not d.get('name')
        if key in new_keys and unknown and not d.get('is_me') and not d.get('random_mac'):
            score += 30
            reasons.append('NEW unrecognized device — possible intruder')

        audited.append({'device': d, 'score': score, 'level': _level(score),
                        'open_ports': open_ports, 'reasons': reasons})

    audited.sort(key=lambda a: a['score'], reverse=True)
    return audited


def _label(d: dict) -> str:
    return (d.get('label') or d.get('name') or d.get('hostname')
            or d.get('vendor') or d.get('type') or d.get('ip') or '?')


def _report_dir(directory: Path = None) -> Path:
    directory = directory or (Path.home() / '.wifi-scanner')
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def write_report(audited: list, directory: Path = None) -> Path:
    """Plain-text security report."""
    d = _report_dir(directory)
    path = d / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
    lines = ['WFS SECURITY REPORT', datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '=' * 70]
    for a in audited:
        dev = a['device']
        lines.append(f"[{a['level']:<8}] score {a['score']:<3}  {dev['ip']:<15} {_label(dev)}")
        if a['open_ports']:
            lines.append(f"           open ports: {', '.join(map(str, a['open_ports']))}")
        for r in a['reasons']:
            lines.append(f"           - {r}")
        if not a['reasons']:
            lines.append('           - no exposure detected')
    return _write_private(path, '\n'.join(lines) + '\n')


def write_report_json(audited: list, directory: Path = None) -> Path:
    """Machine-readable JSON security report."""
    d = _report_dir(directory)
    path = d / f"report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    payload = {
        'generated': datetime.now().isoformat(timespec='seconds'),
        'findings': [{
            'ip': a['device']['ip'],
            'name': _label(a['device']),
            'mac': a['device'].get('mac'),
            'level': a['level'],
            'score': a['score'],
            'open_ports': a['open_ports'],
            'reasons': a['reasons'],
        } for a in audited],
    }
    return _write_private(path, json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
