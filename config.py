#!/usr/bin/env python3
"""User configuration for WFS.

A small JSON file at ~/.wifi-scanner/config.json, created with defaults on first
run. Stdlib only. Unknown/missing keys always fall back to DEFAULTS, so an older
or hand-edited file never breaks the scanner.
"""
import json
from pathlib import Path

CONFIG_DIR = Path.home() / '.wifi-scanner'
CONFIG_PATH = CONFIG_DIR / 'config.json'

DEFAULTS = {
    'interface': 'en0',        # Wi-Fi interface (macOS)
    'auto_oui': True,          # auto-download the full vendor DB on first run
    'scan_workers': 128,       # ping-sweep concurrency
    'port_timeout': 0.8,       # per-port connect timeout (seconds)
    'ping_timeout_ms': 600,    # ICMP ping timeout
    'mdns_timeout': 4,         # mDNS listen window (seconds)
    'ssdp_timeout': 3,         # SSDP listen window (seconds)
}


def load() -> dict:
    """Return the effective config (DEFAULTS overlaid with the user's file)."""
    cfg = dict(DEFAULTS)
    try:
        if CONFIG_PATH.exists():
            user = json.loads(CONFIG_PATH.read_text())
            if isinstance(user, dict):
                cfg.update({k: v for k, v in user.items() if k in DEFAULTS})
        else:
            save(cfg)  # materialise defaults on first run
    except Exception:
        pass
    return cfg


def save(cfg: dict) -> bool:
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + '\n')
        return True
    except Exception:
        return False
