#!/usr/bin/env python3
"""Local device history for WFS.

A tiny SQLite store (stdlib only) at ~/.wifi-scanner/history.db that remembers
devices across runs: first/last seen, times seen, user labels/notes, a snapshot
of each device's open ports (for change detection), and the gateway MAC (for
ARP-spoof detection). Keyed by MAC (falling back to IP).

Every method degrades gracefully — a broken/locked DB never crashes a scan.
"""
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path.home() / '.wifi-scanner' / 'history.db'


def _key(device: dict) -> str:
    return (device.get('mac') or device.get('ip') or '').upper()


def _now() -> str:
    return datetime.now().isoformat(timespec='seconds')


class Store:
    def __init__(self, path: Path = DB_PATH):
        self.ok = False
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.conn = sqlite3.connect(str(path))
            self.conn.row_factory = sqlite3.Row
            self._init()
            self.ok = True
        except Exception:
            self.conn = None

    def _init(self):
        self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS devices (
                key TEXT PRIMARY KEY, mac TEXT, label TEXT, note TEXT,
                last_ip TEXT, name TEXT, vendor TEXT, type TEXT,
                last_ports TEXT,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, device_count INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
        ''')
        # Migrate older DBs that predate note/last_ports columns.
        cols = {r['name'] for r in self.conn.execute('PRAGMA table_info(devices)')}
        for col in ('note', 'last_ports'):
            if col not in cols:
                self.conn.execute(f'ALTER TABLE devices ADD COLUMN {col} TEXT')
        self.conn.commit()

    # ── settings (key/value) ──────────────────────────────────────────────────

    def get_setting(self, k: str):
        if not self.ok:
            return None
        try:
            r = self.conn.execute('SELECT v FROM settings WHERE k=?', (k,)).fetchone()
            return r['v'] if r else None
        except Exception:
            return None

    def set_setting(self, k: str, v: str):
        if not self.ok:
            return
        try:
            self.conn.execute('INSERT INTO settings(k, v) VALUES(?, ?) '
                              'ON CONFLICT(k) DO UPDATE SET v=excluded.v', (k, v))
            self.conn.commit()
        except Exception:
            pass

    def check_gateway_mac(self, mac: str, network_id: str = None):
        """Track the gateway MAC *per network* (keyed by subnet), so a legit
        network switch (home → office) is not mistaken for spoofing. Returns
        ('first'|'ok'|'changed', previous_mac); 'changed' on the same network is
        a strong ARP-spoof / MITM signal."""
        if not mac:
            return ('unknown', None)
        key = f'gw_mac:{network_id or "default"}'
        prev = self.get_setting(key)
        if prev is None:
            self.set_setting(key, mac)
            return ('first', None)
        if prev.upper() != mac.upper():
            self.set_setting(key, mac)
            return ('changed', prev)
        return ('ok', prev)

    # ── writes ────────────────────────────────────────────────────────────────

    def record_scan(self, devices: list) -> set:
        """Upsert every device and log the scan. Returns keys never seen before."""
        if not self.ok:
            return set()
        new_keys, now = set(), _now()
        try:
            cur = self.conn.cursor()
            for d in devices:
                k = _key(d)
                if not k:
                    continue
                row = cur.execute('SELECT key FROM devices WHERE key=?', (k,)).fetchone()
                if row:
                    cur.execute(
                        'UPDATE devices SET mac=?, last_ip=?, name=?, vendor=?, '
                        'type=?, last_seen=?, times_seen=times_seen+1 WHERE key=?',
                        (d.get('mac'), d.get('ip'), d.get('name'), d.get('vendor'),
                         d.get('type'), now, k))
                else:
                    cur.execute(
                        'INSERT INTO devices (key, mac, last_ip, name, vendor, type, '
                        'first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)',
                        (k, d.get('mac'), d.get('ip'), d.get('name'), d.get('vendor'),
                         d.get('type'), now, now))
                    new_keys.add(k)
            cur.execute('INSERT INTO scans (ts, device_count) VALUES (?, ?)',
                        (now, len(devices)))
            self.conn.commit()
        except Exception:
            pass
        return new_keys

    def update_ports(self, device: dict, ports: list) -> list:
        """Store a device's open-port snapshot; return the *previous* snapshot
        (list of ints) so callers can diff for newly-opened ports."""
        if not self.ok:
            return []
        k = _key(device)
        if not k:
            return []
        try:
            row = self.conn.execute('SELECT last_ports FROM devices WHERE key=?',
                                    (k,)).fetchone()
            prev = [int(p) for p in (row['last_ports'].split(',') if row and row['last_ports'] else []) if p]
            csv_ports = ','.join(str(p) for p in ports)
            if row is None:
                now = _now()
                self.conn.execute(
                    'INSERT INTO devices (key, mac, last_ip, last_ports, first_seen, last_seen) '
                    'VALUES (?,?,?,?,?,?)',
                    (k, device.get('mac'), device.get('ip'), csv_ports, now, now))
            else:
                self.conn.execute('UPDATE devices SET last_ports=? WHERE key=?', (csv_ports, k))
            self.conn.commit()
            return prev
        except Exception:
            return []

    # ── reads ─────────────────────────────────────────────────────────────────

    def annotate(self, devices: list):
        """Attach first_seen/times_seen from the store onto each live device
        dict (in place)."""
        if not self.ok:
            return
        try:
            rows = {r['key']: r for r in self.conn.execute(
                'SELECT key, first_seen, times_seen FROM devices')}
        except Exception:
            return
        for d in devices:
            r = rows.get(_key(d))
            if r:
                d['first_seen'] = r['first_seen']
                d['times_seen'] = r['times_seen']

    def known_devices(self) -> list:
        if not self.ok:
            return []
        try:
            return [dict(r) for r in self.conn.execute(
                'SELECT label, note, mac, last_ip, name, vendor, type, first_seen, '
                'last_seen, times_seen FROM devices ORDER BY last_seen DESC')]
        except Exception:
            return []

    def stats(self) -> dict:
        if not self.ok:
            return {'scans': 0, 'devices': 0}
        try:
            s = self.conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            d = self.conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
            return {'scans': s, 'devices': d}
        except Exception:
            return {'scans': 0, 'devices': 0}

    def scan_counts(self, limit: int = 40) -> list:
        """Online-device counts of the last N scans, oldest→newest (for a trend)."""
        if not self.ok:
            return []
        try:
            rows = self.conn.execute(
                'SELECT device_count FROM scans ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
            return [r[0] for r in rows][::-1]
        except Exception:
            return []
