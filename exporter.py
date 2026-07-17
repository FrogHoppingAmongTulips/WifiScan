#!/usr/bin/env python3
"""Export scans / history to JSON or CSV. Stdlib only."""
import csv
import io
import json
from datetime import datetime

FIELDS = ['ip', 'mac', 'name', 'type', 'vendor', 'hostname',
          'os_hint', 'is_me', 'is_gateway', 'random_mac']


def to_json(devices: list, meta: dict = None) -> str:
    payload = {
        'generated': datetime.now().isoformat(timespec='seconds'),
        'device_count': len(devices),
        'devices': devices,
    }
    if meta:
        payload.update(meta)
    return json.dumps(payload, ensure_ascii=False, indent=2)


def to_csv(devices: list) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction='ignore')
    w.writeheader()
    for d in devices:
        w.writerow({k: d.get(k, '') for k in FIELDS})
    return buf.getvalue()


def write(devices: list, path: str, meta: dict = None) -> str:
    """Write devices to ``path``; format chosen by extension (.csv else JSON)."""
    text = to_csv(devices) if str(path).lower().endswith('.csv') else to_json(devices, meta)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    return path
