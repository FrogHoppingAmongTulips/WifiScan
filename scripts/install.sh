#!/usr/bin/env bash
# Установка wfs одной командой.
#
#   curl -fsSL https://raw.githubusercontent.com/FrogHoppingAmongTulips/WifiScan/main/scripts/install.sh | bash
#   curl -fsSL ... | bash -s uninstall
#
# Ставит без root: файлы в ~/.local/share/wfs, запуск — ссылкой в каталоге,
# который уже есть в PATH. Права администратора нужны только если своего
# каталога в PATH не нашлось.
set -euo pipefail

REPO="${WFS_REPO:-FrogHoppingAmongTulips/WifiScan}"
BRANCH="${WFS_BRANCH:-main}"
SRC_URL="${WFS_URL:-https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH}"

LIB="${WFS_LIB:-$HOME/.local/share/wfs}"
DATA_DIRS=("$HOME/.wifi-scanner" "$HOME/.net-monitor")

# Файлы, из которых состоит инструмент. Список явный: в архиве лежат ещё
# тесты и заготовки, тащить их в установку незачем.
FILES=(wfs wifi_cli.py identify.py store.py security.py config.py
       exporter.py connections.py netmon.py web.py)

say()  { printf '  %s\n' "$*"; }
die()  { printf '\033[31m  %s\033[0m\n' "$*" >&2; exit 1; }

# bin_dir выбирает, куда положить ссылку: сначала то, что уже в PATH и куда
# можно писать без sudo.
bin_dir() {
  local d
  for d in "$HOME/.local/bin" "$HOME/bin"; do
    case ":$PATH:" in *":$d:"*) mkdir -p "$d" && [ -w "$d" ] && { echo "$d"; return; };; esac
  done
  for d in /opt/homebrew/bin /usr/local/bin; do
    [ -d "$d" ] && [ -w "$d" ] && { echo "$d"; return; }
  done
  # Ничего своего в PATH нет: создаётся ~/.local/bin, о нём говорится в конце.
  mkdir -p "$HOME/.local/bin"
  echo "$HOME/.local/bin"
}

check_python() {
  command -v python3 >/dev/null 2>&1 || die "нужен python3 (xcode-select --install)"
  python3 - <<'PY' || die "нужен python3 версии 3.8 или новее"
import sys
sys.exit(0 if sys.version_info >= (3, 8) else 1)
PY
}

install_wfs() {
  check_python
  command -v curl >/dev/null 2>&1 || die "нужен curl"
  command -v tar  >/dev/null 2>&1 || die "нужен tar"

  local tmp; tmp="$(mktemp -d)"
  # Путь подставляется в ловушку сразу: к моменту выхода локальная переменная
  # уже не существует, и уборка падала бы вместо уборки.
  trap "rm -rf '$tmp'" EXIT

  say "скачиваю…"
  curl -fsSL "$SRC_URL" -o "$tmp/src.tar.gz" \
    || die "не скачалось. Если репозиторий закрыт, установка по открытой ссылке невозможна"
  tar xzf "$tmp/src.tar.gz" -C "$tmp"

  local root; root="$(find "$tmp" -maxdepth 1 -type d -name '*-*' | head -1)"
  [ -n "$root" ] || die "архив выглядит не так, как ожидалось"

  local f
  for f in "${FILES[@]}"; do
    [ -f "$root/$f" ] || die "в архиве нет $f — установка отменена"
  done

  # Каталог пересоздаётся целиком: файл, удалённый в новой версии, не должен
  # остаться от старой и молча использоваться.
  rm -rf "$LIB"
  mkdir -p "$LIB"
  for f in "${FILES[@]}"; do
    cp "$root/$f" "$LIB/$f"
  done
  chmod +x "$LIB/wfs"

  local bin; bin="$(bin_dir)"
  ln -sf "$LIB/wfs" "$bin/wfs"

  say "готово"
  say ""
  say "  wfs        сеть: кто подключён"
  say "  wfs out    исходящие соединения"
  say "  wfs web    то же в браузере"
  say ""
  case ":$PATH:" in
    *":$bin:"*) ;;
    *) say "добавь в PATH: export PATH=\"$bin:\$PATH\"" ;;
  esac
}

uninstall_wfs() {
  local bin d
  for bin in "$HOME/.local/bin" "$HOME/bin" /opt/homebrew/bin /usr/local/bin; do
    [ -L "$bin/wfs" ] && rm -f "$bin/wfs"
  done
  rm -rf "$LIB"
  say "wfs удалён"

  # История устройств и кэши — данные владельца, а не установки. Уносить их
  # молча нельзя: человек мог просто переустанавливать.
  for d in "${DATA_DIRS[@]}"; do
    [ -d "$d" ] && say "оставлено: $d (удалить: rm -rf $d)"
  done
  return 0
}

case "${1:-install}" in
  install|"")       install_wfs ;;
  uninstall|remove) uninstall_wfs ;;
  *) die "неизвестная команда: $1 (доступно: install, uninstall)" ;;
esac
