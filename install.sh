#!/usr/bin/env bash
# FlowTrack installer — https://github.com/henzelis/flowtrack
#
#   curl -fsSL https://raw.githubusercontent.com/henzelis/flowtrack/main/install.sh | sudo bash
#
# Installs FlowTrack v2 (collector + ClickHouse + web UI) with its dependencies, asking a few
# questions on the way. Re-run the same command to upgrade, reconfigure or uninstall.
#
# Options:  --yes          no questions: defaults, or values from FT_* variables below
#           --upgrade      update code of an existing install, keep settings
#           --uninstall    remove FlowTrack (asks whether to keep the data)
#           --lang en|uk   installer language
# Variables for --yes:  FT_NETFLOW_PORT FT_WEB_PORT FT_EXPORTER_IP FT_VENDOR FT_DEVICE_NAME
#                       FT_WAN_IFS FT_CITY FT_COUNTRY FT_ADMIN_PASSWORD FT_OPEN_FIREWALL=yes|no
#                       FT_INSTALL_DOCKER=yes|no
# Source override (testing): FT_SOURCE=<tar.gz URL>  FT_REF=<branch or tag>
#
# Everything is wrapped in main() so a partially downloaded script never runs.

main() {
set -Eeuo pipefail

FT_REPO=${FT_REPO:-henzelis/flowtrack}
FT_REF=${FT_REF:-main}
FT_SOURCE=${FT_SOURCE:-https://codeload.github.com/$FT_REPO/tar.gz/refs/heads/$FT_REF}
PREFIX=/opt/flowtrack-v2
ETC=/etc/flowtrack-v2
STATE=/var/lib/flowtrack-v2
LOG=/var/log/flowtrack-install.log
CH_IMAGE=clickhouse/clickhouse-server:24.8
CH_NAME=flowtrack-ch
UNITS="flowtrack2-collector flowtrack2-web"

YES=0; MODE=""; LANG_SEL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --yes|-y) YES=1 ;;
    --upgrade) MODE=upgrade ;;
    --uninstall) MODE=uninstall ;;
    --lang) LANG_SEL=${2:-}; shift ;;
    --lang=*) LANG_SEL=${1#--lang=} ;;
    -h|--help) sed -n '2,20p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ------------------------------------------------------------------ output helpers
if [ -t 1 ]; then B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; C=$'\e[36m'; N=$'\e[0m'; else B= D= R= G= Y= C= N=; fi
# questions are read from the terminal even when the script itself arrives through a pipe
TTY=""
if [ "$YES" = 0 ]; then
  if [ -t 0 ]; then TTY=/dev/stdin
  elif { : < /dev/tty; } 2>/dev/null; then TTY=/dev/tty
  else YES=1; fi
fi
case "${LANG_SEL:-${LC_ALL:-${LANG:-}}}" in uk*|UK*) L=uk ;; *) L=en ;; esac
t() { if [ "$L" = uk ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say()  { printf '%s\n' "$*"; }
info() { printf '%s\n' "${C}›${N} $*"; }
ok()   { printf '%s\n' "${G}✓${N} $*"; }
warn() { printf '%s\n' "${Y}!${N} $*"; }
die()  { printf '%s\n' "${R}✗ $*${N}" >&2; exit 1; }
CURRENT_STEP=""
on_error() {
  local code=$?
  printf '\n%s\n' "${R}✗ $(t 'Installation stopped at step' 'Встановлення зупинилось на кроці'): ${CURRENT_STEP:-?}${N}" >&2
  printf '%s\n' "  $(t 'Details' 'Подробиці'): ${B}tail -n 40 $LOG${N}" >&2
  printf '%s\n' "  $(t 'You can safely run the installer again.' 'Інсталятор можна спокійно запустити ще раз.')" >&2
  exit "$code"
}
trap on_error ERR
# run a step: output goes to the log, the user sees one line
step() {
  CURRENT_STEP=$1; shift
  printf '%s' "${C}›${N} $CURRENT_STEP … "
  if "$@" >>"$LOG" 2>&1; then printf '%s\n' "${G}✓${N}"; else printf '%s\n' "${R}✗${N}"; return 1; fi
}

# ------------------------------------------------------------------ input helpers
# ask VAR "question" "default" validator "hint shown on bad input" [env var for --yes]
ask() {
  local __var=$1 q=$2 def=$3 check=$4 hint=$5 envv=${6:-} ans tries=0
  if [ "$YES" = 1 ]; then
    ans=${!envv:-$def}
    "$check" "$ans" || die "$q: $(t 'invalid value' 'некоректне значення') '$ans' — $hint"
    printf -v "$__var" '%s' "$ans"; return
  fi
  while :; do
    if [ -n "$def" ]; then printf '%s' "  ${B}$q${N} ${D}[$def]${N}: "; else printf '%s' "  ${B}$q${N}: "; fi
    IFS= read -r ans < "$TTY" || ans=""
    ans=$(printf '%s' "$ans" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [ -z "$ans" ] && ans=$def
    if "$check" "$ans"; then printf -v "$__var" '%s' "$ans"; return; fi
    tries=$((tries+1)); printf '%s\n' "    ${Y}$hint${N}"
    [ $tries -ge 6 ] && die "$(t 'Too many invalid answers' 'Забагато некоректних відповідей')"
  done
}
ask_yn() {   # ask_yn VAR "question" y|n [env var]
  local __var=$1 q=$2 def=$3 envv=${4:-} ans
  if [ "$YES" = 1 ]; then ans=${!envv:-$def}; case "$ans" in y*|Y*|1|t*|T*) ans=y ;; *) ans=n ;; esac; printf -v "$__var" '%s' "$ans"; return; fi
  while :; do
    printf '%s' "  ${B}$q${N} ${D}[$( [ "$def" = y ] && echo 'Y/n' || echo 'y/N')]${N}: "
    IFS= read -r ans < "$TTY" || ans=""
    case "${ans:-$def}" in y|Y|yes|Yes|т|Т|так|Так|д|Д) printf -v "$__var" y; return ;; n|N|no|No|н|Н|ні|Ні) printf -v "$__var" n; return ;; esac
    printf '%s\n' "    ${Y}$(t 'Answer y (yes) or n (no).' 'Відповідайте y (так) або n (ні).')${N}"
  done
}
ask_secret() {   # ask_secret VAR "question" [env var]  — empty answer keeps the default password
  local __var=$1 q=$2 envv=${3:-} a b
  if [ "$YES" = 1 ]; then a=${!envv:-}; [ -z "$a" ] || [ ${#a} -ge 8 ] || die "FT_ADMIN_PASSWORD: $(t 'at least 8 characters' 'щонайменше 8 символів')"; printf -v "$__var" '%s' "$a"; return; fi
  while :; do
    printf '%s' "  ${B}$q${N} ${D}[$(t 'Enter = keep "flowtrack"' 'Enter — залишити «flowtrack»')]${N}: "
    IFS= read -rs a < "$TTY" || a=""; printf '\n'
    [ -z "$a" ] && { printf -v "$__var" ''; return; }
    if [ ${#a} -lt 8 ]; then printf '%s\n' "    ${Y}$(t 'At least 8 characters, please.' 'Щонайменше 8 символів.')${N}"; continue; fi
    printf '%s' "  ${B}$(t 'Repeat the password' 'Повторіть пароль')${N}: "
    IFS= read -rs b < "$TTY" || b=""; printf '\n'
    [ "$a" = "$b" ] && { printf -v "$__var" '%s' "$a"; return; }
    printf '%s\n' "    ${Y}$(t 'Passwords do not match — try again.' 'Паролі не збігаються — спробуйте ще раз.')${N}"
  done
}

# ------------------------------------------------------------------ validators
is_port()   { [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }
is_ipv4()   { local IFS=.; local -a oct; [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1; read -ra oct <<< "$1"; for x in "${oct[@]}"; do [ "$x" -le 255 ] || return 1; done; }
is_ip()     { is_ipv4 "$1" || [[ $1 =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:.]*$ ]]; }
opt_ip()    { [ -z "$1" ] || [ "$1" = "-" ] || is_ip "$1"; }
opt_ints()  { [ -z "$1" ] || [ "$1" = "-" ] || [[ $1 =~ ^[0-9]+([[:space:]]*,[[:space:]]*[0-9]+)*$ ]]; }
opt_cc()    { [ -z "$1" ] || [ "$1" = "-" ] || [[ $1 =~ ^[A-Za-z]{2}$ ]]; }
opt_text()  { local re='["\\]'; [ ${#1} -le 64 ] && ! [[ $1 =~ $re ]]; }
is_choice() { [[ $1 =~ ^[1-6]$ ]]; }
udp_busy()  { [ -n "$(ss -Hlun "sport = :$1" 2>/dev/null)" ]; }
tcp_busy()  { [ -n "$(ss -Hltn "sport = :$1" 2>/dev/null)" ]; }
port_owner(){ ss -Hlpn "sport = :$2" 2>/dev/null | grep -i "^$1" | grep -o 'users:(("[^"]*"' | head -1 | sed 's/users:(("//' || true; }
free_from() { local kind=$1 p=$2; while "${kind}_busy" "$p"; do p=$((p+1)); done; echo "$p"; }
# a port is acceptable if free, or already used by our own service (upgrade / reconfigure)
NF_OWN=""; WEB_OWN=""
ok_udp() { is_port "$1" && { [ "$1" = "$NF_OWN" ] || ! udp_busy "$1"; }; }
ok_tcp() { is_port "$1" && { [ "$1" = "$WEB_OWN" ] || ! tcp_busy "$1"; }; }

# ------------------------------------------------------------------ preflight
[ "$(id -u)" = 0 ] || die "$(t 'Run as root:' 'Запустіть від root:') curl -fsSL https://raw.githubusercontent.com/$FT_REPO/main/install.sh | sudo bash"
: > "$LOG" 2>/dev/null || LOG=/tmp/flowtrack-install.log
echo "=== FlowTrack installer $(date -Is) mode=${MODE:-auto} ===" >> "$LOG"

if [ "$YES" = 0 ] && [ -z "$LANG_SEL" ]; then
  printf '%s' "${B}Language / Мова${N}: 1) English  2) Українська ${D}[$([ "$L" = uk ] && echo 2 || echo 1)]${N}: "
  IFS= read -r a < "$TTY" || a=""
  case "$a" in 1) L=en ;; 2) L=uk ;; esac
fi

say ""
say "${B}FlowTrack$(t ' installer' ' — встановлення')${N}  ${D}github.com/$FT_REPO${N}"
say "${D}$(t 'Log' 'Лог'): $LOG${N}"
say ""

if [ -r /etc/os-release ]; then . /etc/os-release; fi
OS_ID=${ID:-unknown}; OS_LIKE=${ID_LIKE:-}
if command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf >/dev/null 2>&1; then PKG=dnf
else die "$(t "Unsupported system ($OS_ID): need apt (Debian/Ubuntu) or dnf (Fedora/RHEL/Rocky/Alma). Manual steps: https://github.com/$FT_REPO#manual-install" "Непідтримувана система ($OS_ID): потрібен apt (Debian/Ubuntu) або dnf (Fedora/RHEL/Rocky/Alma). Ручне встановлення: https://github.com/$FT_REPO#manual-install")"; fi
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || die "$(t 'systemd is required.' 'Потрібен systemd.')"
ARCH=$(uname -m); case "$ARCH" in x86_64|aarch64|arm64) ;; *) die "$(t "Unsupported CPU architecture: $ARCH (ClickHouse needs x86_64 or arm64)" "Непідтримувана архітектура: $ARCH (ClickHouse потребує x86_64 або arm64)")" ;; esac
ok "$(t 'System' 'Система'): ${PRETTY_NAME:-$OS_ID} ($ARCH)"

EXISTING=0; [ -f "$ETC/env" ] && EXISTING=1
if [ "$EXISTING" = 1 ] && [ -z "$MODE" ]; then
  if [ "$YES" = 1 ]; then MODE=upgrade
  else
    say ""; say "$(t 'FlowTrack is already installed. What do you want to do?' 'FlowTrack уже встановлено. Що зробити?')"
    say "  1) $(t 'Upgrade to the latest version (keep settings)' 'Оновити до останньої версії (налаштування збережуться)')"
    say "  2) $(t 'Reconfigure (answer the questions again)' 'Переналаштувати (відповісти на питання знову)')"
    say "  3) $(t 'Uninstall' 'Видалити')"
    say "  4) $(t 'Exit' 'Вийти')"
    ask choice "$(t 'Choice' 'Ваш вибір')" 1 is_choice "$(t 'Enter 1, 2, 3 or 4.' 'Введіть 1, 2, 3 або 4.')"
    case "$choice" in 1) MODE=upgrade ;; 2) MODE=reconfigure ;; 3) MODE=uninstall ;; *) exit 0 ;; esac
  fi
fi
[ "$MODE" = upgrade ] && [ "$EXISTING" = 0 ] && MODE=""
[ "$MODE" = uninstall ] && { uninstall; exit 0; }

# ------------------------------------------------------------------ dependencies
pkg_install() {
  if [ "$PKG" = apt ]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q && apt-get install -yq curl ca-certificates python3 python3-venv python3-pip openssl iproute2 tar gzip
  else
    dnf install -yq curl ca-certificates python3 python3-pip openssl iproute tar gzip
  fi
}
step "$(t 'Installing system packages' 'Встановлення системних пакетів')" pkg_install
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || die "$(t "Python 3.8+ is required, found $PYV" "Потрібен Python 3.8+, знайдено $PYV")"
ok "Python $PYV"

if ! command -v docker >/dev/null 2>&1; then
  say ""; say "$(t 'FlowTrack stores flows in ClickHouse, which runs in Docker. Docker is not installed.' 'FlowTrack зберігає потоки в ClickHouse, який працює в Docker. Docker не встановлено.')"
  ask_yn want_docker "$(t 'Install Docker now (official get.docker.com script)?' 'Встановити Docker зараз (офіційний скрипт get.docker.com)?')" y FT_INSTALL_DOCKER
  [ "$want_docker" = y ] || die "$(t 'Docker is required. Install it and run this installer again.' 'Docker потрібен. Встановіть його й запустіть інсталятор ще раз.')"
  install_docker() { curl -fsSL https://get.docker.com | sh; }
  step "$(t 'Installing Docker' 'Встановлення Docker')" install_docker
fi
step "$(t 'Starting Docker' 'Запуск Docker')" systemctl enable --now docker
docker info >/dev/null 2>&1 || die "$(t 'Docker is installed but not responding. Check: systemctl status docker' 'Docker встановлено, але він не відповідає. Перевірте: systemctl status docker')"
ok "Docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo)"

# ------------------------------------------------------------------ configuration
LAN_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1)
[ -n "$LAN_IP" ] || LAN_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
envget() { [ -f "$ETC/env" ] || return 0; sed -n "s/^$1=//p" "$ETC/env" | tail -1; }

if [ "$MODE" = upgrade ]; then
  NF_PORT=$(envget FT_PORT); WEB_PORT=$(envget FT_WEB_PORT); CH_PORT=$(envget FT_CH_URL | sed -n 's/.*:\([0-9]*\)$/\1/p')
  NF_PORT=${NF_PORT:-2055}; WEB_PORT=${WEB_PORT:-3030}; CH_PORT=${CH_PORT:-8123}
  CH_PASSWORD=$(envget FT_CH_PASSWORD); ADMIN_PW=""; WRITE_DEVICE=n; OPEN_FW=n
  info "$(t 'Upgrading, settings are kept' 'Оновлення, налаштування збережено') (NetFlow UDP $NF_PORT, web $WEB_PORT)"
else
  if [ "$EXISTING" = 1 ]; then NF_OWN=$(envget FT_PORT); WEB_OWN=$(envget FT_WEB_PORT); fi
  say ""; say "${B}$(t 'A few questions — press Enter to accept the value in [brackets].' 'Кілька питань — Enter приймає значення в [дужках].')${N}"
  say ""
  say "${B}1/4 $(t 'Ports' 'Порти')${N}"
  def=${NF_OWN:-2055}; ok_udp "$def" || { o=$(port_owner udp "$def"); warn "$(t "UDP $def is in use${o:+ by $o}" "UDP $def зайнятий${o:+ програмою $o}")"; def=$(free_from udp "$def"); }
  ask NF_PORT "$(t 'UDP port for NetFlow/IPFIX from your devices' 'UDP-порт для NetFlow/IPFIX від ваших пристроїв')" "$def" ok_udp \
      "$(t 'Use a free port number 1–65535 (this one is invalid or busy).' 'Введіть вільний порт 1–65535 (цей некоректний або зайнятий).')" FT_NETFLOW_PORT
  def=${WEB_OWN:-3030}; ok_tcp "$def" || { o=$(port_owner tcp "$def"); warn "$(t "TCP $def is in use${o:+ by $o}" "TCP $def зайнятий${o:+ програмою $o}")"; def=$(free_from tcp "$def"); }
  ask WEB_PORT "$(t 'TCP port for the web interface' 'TCP-порт вебінтерфейсу')" "$def" ok_tcp \
      "$(t 'Use a free port number 1–65535 (this one is invalid or busy).' 'Введіть вільний порт 1–65535 (цей некоректний або зайнятий).')" FT_WEB_PORT

  say ""; say "${B}2/4 $(t 'Your exporter (router / firewall)' 'Ваш експортер (роутер / фаєрвол)')${N}"
  say "  1) FortiGate   2) Cisco   3) MikroTik   4) Juniper   5) Linux / pmacct   6) $(t 'Other / skip' 'Інше / пропустити')"
  def=1; case "${FT_VENDOR:-}" in [Ff]orti*) def=1 ;; [Cc]isco*) def=2 ;; [Mm]ikro*) def=3 ;; [Jj]uni*) def=4 ;; [Ll]inux*|pmacct) def=5 ;; ?*) def=6 ;; esac
  FT_VENDOR_N=$def
  ask vchoice "$(t 'Device type' 'Тип пристрою')" "$def" is_choice "$(t 'Enter a number from 1 to 6.' 'Введіть число від 1 до 6.')" FT_VENDOR_N
  VENDORS=(Fortinet Cisco MikroTik Juniper "Linux / pmacct" "")
  VENDOR=${VENDORS[$((vchoice-1))]}
  ask EXP_IP "$(t 'IP address the device sends NetFlow from (Enter = accept from any device)' 'IP-адреса, з якої пристрій надсилає NetFlow (Enter — приймати від будь-якого)')" "" opt_ip \
      "$(t 'An IPv4/IPv6 address like 10.0.0.1, or leave empty.' 'IPv4/IPv6-адреса на кшталт 10.0.0.1, або залиште порожнім.')" FT_EXPORTER_IP
  [ "$EXP_IP" = "-" ] && EXP_IP=""
  WRITE_DEVICE=n; DEV_NAME=""; WAN_IFS=""; CITY=""; COUNTRY=""
  if [ -n "$EXP_IP" ] && [ -n "$VENDOR" ]; then
    WRITE_DEVICE=y
    ask DEV_NAME "$(t 'Short name for the device' 'Коротка назва пристрою')" "fw-main" opt_text "$(t 'Up to 64 characters, no quotes.' 'До 64 символів, без лапок.')" FT_DEVICE_NAME
    case "$VENDOR" in
      Fortinet) wan_def=1; wan_hint=$(t 'FortiGate CLI: show system interface wan | grep snmp-index' 'FortiGate CLI: show system interface wan | grep snmp-index') ;;
      Cisco) wan_def=""; wan_hint="Cisco: show snmp mib ifmib ifindex" ;;
      MikroTik) wan_def=""; wan_hint="MikroTik: /interface print detail (ifindex)" ;;
      *) wan_def=""; wan_hint=$(t 'interface index of the internet uplink' 'індекс інтерфейсу, що веде в інтернет') ;;
    esac
    say "  ${D}$(t 'WAN interface index tells FlowTrack which traffic goes to the internet. Leave empty if unsure — private/public addresses are used instead.' 'Індекс WAN-інтерфейсу підказує FlowTrack, який трафік іде в інтернет. Якщо не впевнені — залиште порожнім, тоді напрямок визначиться за приватними/публічними адресами.')${N}"
    say "  ${D}$wan_hint${N}"
    ask WAN_IFS "$(t 'WAN interface index(es), comma-separated' 'Індекс(и) WAN-інтерфейсу через кому')" "$wan_def" opt_ints "$(t 'Numbers separated by commas, e.g. 1 or 1,5 — or leave empty.' 'Числа через кому, напр. 1 або 1,5 — або залиште порожнім.')" FT_WAN_IFS
    [ "$WAN_IFS" = "-" ] && WAN_IFS=""
    ask CITY "$(t 'City where the device is (for the map, optional)' 'Місто, де стоїть пристрій (для карти, необов’язково)')" "" opt_text "$(t 'Up to 64 characters, no quotes.' 'До 64 символів, без лапок.')" FT_CITY
    ask COUNTRY "$(t 'Country code, 2 letters (e.g. UA, optional)' 'Код країни, 2 літери (напр. UA, необов’язково)')" "" opt_cc "$(t 'Two Latin letters like UA, PL, DE — or leave empty.' 'Дві латинські літери, напр. UA, PL, DE — або залиште порожнім.')" FT_COUNTRY
    [ "$COUNTRY" = "-" ] && COUNTRY=""
    COUNTRY=$(printf '%s' "$COUNTRY" | tr '[:lower:]' '[:upper:]')
  fi

  say ""; say "${B}3/4 $(t 'Administrator password' 'Пароль адміністратора')${N}"
  say "  ${D}$(t 'Login is "admin". You can change the password later in the web interface.' 'Логін — «admin». Пароль можна змінити пізніше у вебінтерфейсі.')${N}"
  ask_secret ADMIN_PW "$(t 'New password (min. 8 characters)' 'Новий пароль (щонайменше 8 символів)')" FT_ADMIN_PASSWORD

  say ""; say "${B}4/4 $(t 'Firewall' 'Фаєрвол')${N}"
  OPEN_FW=n
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then FW=ufw
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then FW=firewalld
  else FW=""; fi
  if [ -n "$FW" ]; then
    ask_yn OPEN_FW "$(t "Open UDP $NF_PORT and TCP $WEB_PORT in $FW?" "Відкрити UDP $NF_PORT і TCP $WEB_PORT у $FW?")" y FT_OPEN_FIREWALL
  else say "  ${D}$(t 'No active firewall (ufw/firewalld) found — nothing to open.' 'Активного фаєрвола (ufw/firewalld) не знайдено — відкривати нічого.')${N}"; fi

  CH_PASSWORD=$(envget FT_CH_PASSWORD); [ -n "$CH_PASSWORD" ] || CH_PASSWORD=$(openssl rand -hex 16)
  CH_PORT=$(envget FT_CH_URL | sed -n 's/.*:\([0-9]*\)$/\1/p')
  if [ -z "$CH_PORT" ]; then CH_PORT=$(free_from tcp 8123); fi

  say ""; say "${B}$(t 'Summary' 'Підсумок')${N}"
  say "  NetFlow/IPFIX   UDP ${B}$NF_PORT${N}   $(t 'from' 'від') ${EXP_IP:-$(t 'any device' 'будь-якого пристрою')}"
  say "  $(t 'Web interface' 'Вебінтерфейс')    http://${LAN_IP:-<server>}:${B}$WEB_PORT${N}"
  [ "$WRITE_DEVICE" = y ] && say "  $(t 'Device' 'Пристрій')         $DEV_NAME ($VENDOR, $EXP_IP${WAN_IFS:+, WAN $WAN_IFS}${CITY:+, $CITY}${COUNTRY:+ $COUNTRY})"
  say "  $(t 'Admin password' 'Пароль admin')    $([ -n "$ADMIN_PW" ] && t 'set now' 'задано зараз' || t 'flowtrack (change it after login)' 'flowtrack (змініть після входу)')"
  say "  $(t 'Data' 'Дані')             $PREFIX, ClickHouse 127.0.0.1:$CH_PORT"
  if [ "$YES" = 0 ]; then ask_yn go "$(t 'Install now?' 'Встановлювати?')" y; [ "$go" = y ] || { say "$(t 'Cancelled.' 'Скасовано.')"; exit 0; }; fi
fi
say ""

# ------------------------------------------------------------------ install
step "$(t 'Creating service user and directories' 'Створення користувача й тек')" bash -c "
  id flowtrack >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin flowtrack
  mkdir -p '$PREFIX/clickhouse' '$PREFIX/geoip' '$ETC' '$STATE'
  chown flowtrack:flowtrack '$STATE'; chmod 750 '$STATE'"

fetch_code() {
  local src tmp
  src=""   # use the checkout next to this script only when it runs from a file, never via curl | bash
  if [ -f "${BASH_SOURCE[0]:-}" ]; then src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd); fi
  tmp=$(mktemp -d)
  if [ -n "$src" ] && [ -f "$src/v2/collector.py" ] && [ -z "${FT_FORCE_DOWNLOAD:-}" ]; then
    cp -a "$src/v2" "$tmp/v2"
  else
    curl -fsSL "$FT_SOURCE" | tar -xz -C "$tmp"
    local d; d=$(find "$tmp" -maxdepth 2 -type d -name v2 | head -1)
    [ -n "$d" ] && [ -f "$d/collector.py" ] || { echo "v2/ not found in $FT_SOURCE"; return 1; }
    mv "$d" "$tmp/v2"
  fi
  rm -rf "$PREFIX/app.new"; mv "$tmp/v2" "$PREFIX/app.new"
  rm -rf "$PREFIX/app.old"; [ -d "$PREFIX/app" ] && mv "$PREFIX/app" "$PREFIX/app.old"
  mv "$PREFIX/app.new" "$PREFIX/app"; rm -rf "$PREFIX/app.old" "$tmp"
  find "$PREFIX/app" -name __pycache__ -prune -exec rm -rf {} +
  chown -R root:root "$PREFIX/app"; chmod -R go-w "$PREFIX/app"; chmod +x "$PREFIX/app/deploy/geoip-update.sh"
}
step "$(t 'Downloading FlowTrack' 'Завантаження FlowTrack')" fetch_code

make_venv() {
  [ -x "$PREFIX/venv/bin/python" ] || python3 -m venv "$PREFIX/venv"
  "$PREFIX/venv/bin/pip" install -q --upgrade pip
  "$PREFIX/venv/bin/pip" install -q "netflow==0.12.2" "maxminddb>=2.2,<3"
}
step "$(t 'Python environment' 'Python-оточення')" make_venv

if [ ! -s "$PREFIX/geoip/dbip-city.mmdb" ] || [ "$MODE" = upgrade ]; then
  if ! step "$(t 'GeoIP databases (DB-IP Lite)' 'Бази GeoIP (DB-IP Lite)')" env FT_GEOIP_DIR="$PREFIX/geoip" "$PREFIX/app/deploy/geoip-update.sh"; then
    warn "$(t 'GeoIP download failed — FlowTrack works without countries/cities; the monthly timer will retry.' 'Не вдалося завантажити GeoIP — FlowTrack працює без країн/міст; щомісячний таймер спробує знову.')"
  fi
fi

if [ "$MODE" != upgrade ]; then
  write_config() {
    umask 027
    cat > "$ETC/env" <<ENV
FT_CH_URL=http://127.0.0.1:$CH_PORT
FT_CH_USER=flowtrack
FT_CH_PASSWORD=$CH_PASSWORD
FT_CH_DB=flowtrack
FT_BIND=0.0.0.0
FT_PORT=$NF_PORT
FT_EXPORTERS=$EXP_IP
FT_FORWARD=
FT_WEB_BIND=0.0.0.0
FT_WEB_PORT=$WEB_PORT
ENV
    chown root:flowtrack "$ETC/env"; chmod 640 "$ETC/env"
    [ -f "$ETC/hosts.json" ] || echo '{}' > "$ETC/hosts.json"
    if [ "$WRITE_DEVICE" = y ]; then
      "$PREFIX/venv/bin/python" - "$ETC/exporters.json" "$EXP_IP" "$DEV_NAME" "$VENDOR" "$WAN_IFS" "$CITY" "$COUNTRY" <<'PY'
import json, sys
path, ip, name, vendor, wan, city, cc = sys.argv[1:]
try:
    data = json.load(open(path))
except Exception:
    data = {}
cfg = data.get(ip, {})
cfg.update({'name': name or ip, 'vendor': vendor, 'wan_ifs': [int(x) for x in wan.replace(' ', '').split(',') if x],
            'city': city, 'country': cc.upper(), 'sampling': cfg.get('sampling', '1:1')})
if vendor == 'Fortinet':
    cfg.setdefault('local_if', 0)
data[ip] = cfg
json.dump(data, open(path, 'w'), indent=2, ensure_ascii=False)
PY
    else
      [ -f "$ETC/exporters.json" ] || echo '{}' > "$ETC/exporters.json"
    fi
    chown root:flowtrack "$ETC"/*.json; chmod 644 "$ETC"/*.json
  }
  step "$(t 'Writing configuration' 'Запис конфігурації')" write_config
fi

clickhouse_up() {
  local mem cur
  mem=$(awk '/MemTotal/ {m=int($2/1024/1024/4); if (m<1) m=1; if (m>4) m=4; print m}' /proc/meminfo)
  if docker inspect "$CH_NAME" >/dev/null 2>&1; then
    cur=$(docker inspect -f '{{.State.Running}}' "$CH_NAME")
    [ "$cur" = true ] || docker start "$CH_NAME"
  else
    docker pull -q "$CH_IMAGE"
    docker run -d --name "$CH_NAME" --restart unless-stopped -p "127.0.0.1:$CH_PORT:8123" --memory "${mem}g" \
      --ulimit nofile=262144:262144 -v "$PREFIX/clickhouse:/var/lib/clickhouse" \
      -e CLICKHOUSE_DB=flowtrack -e CLICKHOUSE_USER=flowtrack -e CLICKHOUSE_PASSWORD="$CH_PASSWORD" "$CH_IMAGE"
  fi
  for _ in $(seq 1 60); do
    curl -fsS -u "flowtrack:$CH_PASSWORD" "http://127.0.0.1:$CH_PORT/?query=SELECT%201" >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "ClickHouse did not answer within 120 s"; docker logs --tail 30 "$CH_NAME"; return 1
}
step "$(t 'Database (ClickHouse in Docker)' 'База даних (ClickHouse у Docker)')" clickhouse_up

install_units() {
  cp "$PREFIX/app/deploy/flowtrack2-collector.service" "$PREFIX/app/deploy/flowtrack2-web.service" \
     "$PREFIX/app/deploy/flowtrack2-geoip.service" "$PREFIX/app/deploy/flowtrack2-geoip.timer" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable -q flowtrack2-geoip.timer $UNITS
}
step "$(t 'System services' 'Системні сервіси')" install_units

if [ -n "${ADMIN_PW:-}" ]; then
  set_admin() {
    printf '%s' "$ADMIN_PW" | runuser -u flowtrack -- env FT_STATE_DIR="$STATE" "$PREFIX/venv/bin/python" -c '
import sys; sys.path.insert(0, "'"$PREFIX"'/app")
from auth import Auth
a = Auth(); a.update_user("admin", "admin", password=sys.stdin.read())'
  }
  step "$(t 'Setting the admin password' 'Встановлення пароля admin')" set_admin
fi

if [ "${OPEN_FW:-n}" = y ]; then
  open_fw() {
    if [ "$FW" = ufw ]; then ufw allow "$NF_PORT/udp" && ufw allow "$WEB_PORT/tcp"
    else firewall-cmd -q --permanent --add-port="$NF_PORT/udp" --add-port="$WEB_PORT/tcp" && firewall-cmd -q --reload; fi
  }
  step "$(t 'Opening firewall ports' 'Відкриття портів у фаєрволі')" open_fw
fi

start_all() {
  systemctl restart $UNITS
  systemctl start flowtrack2-geoip.timer
  for _ in $(seq 1 30); do
    if systemctl is-active -q flowtrack2-collector && curl -fsS -o /dev/null "http://127.0.0.1:$WEB_PORT/"; then return 0; fi
    sleep 1
  done
  systemctl status --no-pager $UNITS; journalctl -u flowtrack2-collector -u flowtrack2-web -n 30 --no-pager; return 1
}
step "$(t 'Starting FlowTrack' 'Запуск FlowTrack')" start_all

# ------------------------------------------------------------------ done
say ""
say "${G}${B}$(t 'FlowTrack is running.' 'FlowTrack працює.')${N}"
say ""
for ip in $(ip -4 -o addr show scope global 2>/dev/null | awk '$2 !~ /^(docker|br-|virbr|veth|cni|flannel)/ {split($4, a, "/"); print a[1]}'); do say "  ${B}http://$ip:$WEB_PORT${N}"; done
say "  $(t 'Login' 'Вхід'): ${B}admin${N} / ${B}$([ -n "${ADMIN_PW:-}" ] && t '(the password you set)' '(ваш пароль)' || echo flowtrack)${N}"
say ""
if [ "$MODE" != upgrade ]; then
  CIP=${LAN_IP:-<collector-ip>}
  say "${B}$(t 'Now point your device at the collector' 'Тепер налаштуйте пристрій на колектор'): $CIP UDP $NF_PORT${N}"
  case "${VENDOR:-}" in
    Fortinet) cat <<CFG
${D}config system netflow
    set active-flow-timeout 60
    config collectors
        edit 1
            set collector-ip $CIP
            set collector-port $NF_PORT
        next
    end
end
config system interface
    edit "wan1"
        set netflow-sampler both
    next
end${N}
CFG
    ;;
    Cisco) cat <<CFG
${D}flow exporter FLOWTRACK
 destination $CIP
 transport udp $NF_PORT
 template data timeout 60
flow monitor FT-MON
 exporter FLOWTRACK
 record netflow ipv4 original-input
interface GigabitEthernet0/0/0
 ip flow monitor FT-MON input
 ip flow monitor FT-MON output${N}
CFG
    ;;
    MikroTik) say "${D}/ip traffic-flow set enabled=yes interfaces=ether1 active-flow-timeout=1m"; say "/ip traffic-flow target add dst-address=$CIP port=$NF_PORT version=ipfix${N}" ;;
    *) say "  ${D}$(t 'The web interface shows snippets for each vendor: Devices → Connect device.' 'Готові налаштування для кожного виробника — у вебінтерфейсі: Пристрої → Підключити пристрій.')${N}" ;;
  esac
  say ""
fi
say "${D}$(t 'Status:' 'Стан:') systemctl status flowtrack2-collector flowtrack2-web"
say "$(t 'Logs:' 'Логи:')  journalctl -u flowtrack2-collector -f"
say "$(t 'Upgrade, reconfigure or remove: run the same install command again.' 'Оновити, переналаштувати чи видалити: запустіть ту саму команду встановлення ще раз.')${N}"
}

uninstall() {
  say ""; warn "$(t 'This removes the FlowTrack services and the ClickHouse container.' 'Буде видалено сервіси FlowTrack і контейнер ClickHouse.')"
  local sure keep
  if [ "$YES" = 1 ]; then sure=y; keep=${FT_KEEP_DATA:-y}
  else
    ask_yn sure "$(t 'Continue?' 'Продовжити?')" n
    [ "$sure" = y ] || { say "$(t 'Cancelled.' 'Скасовано.')"; return; }
    ask_yn keep "$(t "Keep collected data and settings ($PREFIX, $ETC, $STATE) for a later reinstall?" "Зберегти зібрані дані й налаштування ($PREFIX, $ETC, $STATE) для повторного встановлення?")" y
  fi
  remove_all() {
    systemctl disable --now flowtrack2-geoip.timer $UNITS 2>/dev/null || true
    rm -f /etc/systemd/system/flowtrack2-collector.service /etc/systemd/system/flowtrack2-web.service \
          /etc/systemd/system/flowtrack2-geoip.service /etc/systemd/system/flowtrack2-geoip.timer
    systemctl daemon-reload
    docker rm -f "$CH_NAME" 2>/dev/null || true
    if [ "$keep" != y ]; then rm -rf "$PREFIX" "$ETC" "$STATE"; userdel flowtrack 2>/dev/null || true
    else rm -rf "$PREFIX/app" "$PREFIX/venv"; fi
  }
  step "$(t 'Removing FlowTrack' 'Видалення FlowTrack')" remove_all
  ok "$(t 'FlowTrack removed.' 'FlowTrack видалено.')$([ "$keep" = y ] && t " Data kept in $PREFIX/clickhouse and $ETC." " Дані збережено в $PREFIX/clickhouse та $ETC.")"
}

main "$@"
