# WFS

Две стороны одной картины: кто сидит в твоей сети и куда твоя машина сама
шлёт данные. Из терминала или в браузере. **Ноль зависимостей.**

```
wfs           разбор сети: кто подключён, что за устройства, что открыто
wfs out       исходящие соединения: программа → сервер → страна
wfs web       то же самое в браузере, печатает ссылку
```

## Установка

```
curl -fsSL https://raw.githubusercontent.com/FrogHoppingAmongTulips/WifiScan/main/scripts/install.sh | bash
```

Без root: файлы в `~/.local/share/wfs`, запуск ссылкой из каталога, который уже
есть в PATH. Нужен только `python3` — сторонних библиотек нет.

```
wfs update      обновить до свежей версии
wfs uninstall   удалить (история устройств и кэши остаются)
```

## Веб-вид

`wfs web` поднимает сервер на петле, открывает браузер и печатает ссылку —
если запускаете не за тем компьютером, за которым сидите, `wfs web --no-open`
даст только ссылку. Страница чёрная, текст
белый, список строк: нажал — развернулось, посмотрел — свернул. Наружу не
смотрит: ни шрифтов, ни скриптов со стороны.

Слушает только `127.0.0.1`. Сеть, за которой смотрит wfs, — не та сеть, в
которую его стоит выставлять.

## Куда уходят данные

`wfs out` показывает исходящие соединения. Страна и владелец адреса **не
запрашиваются по умолчанию**: чтобы их узнать, список твоих адресов пришлось бы
отправить стороннему сервису — ровно то, от чего эта команда и защищает.
Нужно — `wfs out --geo`.

## What it does

- **Multi-method discovery** — TCP + ICMP ping sweep, ARP, `nmap`, mDNS/Bonjour,
  SSDP/UPnP — all run **in parallel**. Works without root.
- **Device identification** — OUI vendor lookup (auto-downloaded on first run),
  port fingerprinting, service banners, **OS hint from TTL** (no sudo),
  **NetBIOS names** for Windows hosts, mDNS/TXT models, randomized-MAC detection.
- **History** — local SQLite (`~/.wifi-scanner/history.db`) remembers
  first/last seen and how many times each device appeared, across runs.
- **Security audit** — per-device risk score (Telnet/FTP/VNC/RDP/SMB, router
  admin over plain HTTP…), **ARP-spoof detection** (gateway-MAC change),
  **newly-opened-port** alerts vs last audit, brand-new-device = possible
  intruder. Save reports as text or JSON.
- **Wi-Fi & network audit** — signal/SNR, channel, security, PHY, co-channel
  interference, gateway/ISP, router posture, macOS speed test.
- **Scriptable** — non-interactive flags with JSON/CSV output for cron/pipes.
- **Live tools** — `watch` (NEW vs returning devices), `uptime`, `traffic`.

## Files

```
wifi_cli.py   ← interactive UI + discovery engine + CLI entry
identify.py   ← mDNS / SSDP / fingerprint / banners / TTL / NetBIOS
store.py      ← SQLite history, labels, notes, gateway-MAC & port snapshots
security.py   ← risk scoring, ARP-spoof, port-delta, text/JSON reports
config.py     ← ~/.wifi-scanner/config.json (interface, timeouts, auto-oui)
exporter.py   ← scan/history → JSON & CSV
tests/        ← pure unit tests (no network)
```

## Run

Interactive:

```bash
wfs                   # or: python3 wifi_cli.py
```

Non-interactive (for scripts / cron):

```bash
wfs --scan            # scan, print table      (--json for JSON)
wfs --sec             # security audit          (--json)
wfs --history         # device history          (--json)
wfs --export out.csv  # scan → file (.json/.csv)
wfs --watch           # monitor (Ctrl-C to stop)
```

The interactive UI is a small REPL — a `wfs>` prompt, no wall-of-text reprints.
Type `?` for the command list, `ls` to show the device table (scans on first
use), a device number for details, then commands: `r`/`rr` rescan · `sec` ·
`report` · `quality` · `trends` · `history` · `export F` · `wifi` · `diag` ·
`watch` · `uptime` · `router` · `traffic` · `oui` · `q`. Commands that don't
need the device list (`wifi`, `quality`, `diag`, …) run instantly without a scan.

Non-interactive flags: `--scan --sec --report --quality --trends --watch
--history --diag --export FILE --json --debug`.

## Config

`~/.wifi-scanner/config.json` (created on first run): `interface`, `auto_oui`,
`scan_workers`, `port_timeout`, `ping_timeout_ms`, `mdns_timeout`,
`ssdp_timeout`.

## Install (optional)

```bash
pipx install .        # provides the `wfs` command via pyproject.toml
```

Or just symlink `./wfs` into your PATH (already set up at `/opt/homebrew/bin/wfs`).

## Test

```bash
python3 tests/test_parsers.py     # no pytest needed
pytest                            # if installed
```

## Notes

- **No external dependencies** — Python 3 stdlib only (`sqlite3` included).
- Tuned for **macOS**; discovery works cross-platform, the Wi-Fi audit is macOS-specific.
- `nmap` optional but improves results: `brew install nmap`.
- All data stays local in `~/.wifi-scanner/`.
