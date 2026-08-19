#!/usr/bin/env bash
# =============================================================================
#  Xray_Deployment.sh — Xray-core multi-protocol proxy for Ubuntu 22 / 24 / 26
#
#  Companion to iKev2_Deployment.sh and Singbox_Deployment.sh.
#
#  Installs the newest Xray-core and deploys any subset of protocols you pick
#  ("all" or a few). It finds free ports from a curated list per protocol,
#  generates every secret (UUIDs, passwords, REALITY keypair, ShadowSocks-2022
#  keys, post-quantum VLESS-Encryption keys), asks for your domain, writes a
#  schema-correct config for the CURRENT Xray, validates it with
#  `xray run -test` BEFORE restarting, tunes the kernel for TCP + QUIC, opens
#  the firewall, and emits ready-to-import client bundles:
#     * share links + base64 subscription (v2rayN / NekoBox / Shadowrocket ...)
#     * an Xray client config.json
#     * a sing-box client config.json (only the protocols sing-box can do)
#     * a mihomo / Clash.Meta YAML
#
#  Protocols (server side):
#     vless-reality      VLESS + Vision + REALITY (RAW/TCP)      no certificate
#     vless-xhttp-reality VLESS + XHTTP + REALITY                no certificate
#     vless-encryption   VLESS post-quantum Encryption + Vision  no certificate
#     vless-ws           VLESS + WebSocket + TLS
#     vless-xhttp        VLESS + XHTTP + TLS
#     vmess-ws           VMess + WebSocket + TLS
#     trojan             Trojan + TLS
#     hysteria2          Hysteria2 (QUIC/UDP) — native in Xray since v26.3.27
#     ss2022             Shadowsocks 2022
#
#  Port modes:
#     dedicated  (default) every protocol gets its own free port
#     fallback   VLESS-Vision owns TCP/443 with ONE certificate and routes
#                VLESS-ws / VMess-ws / Trojan-ws to loopback inbounds by path
#
#  Subcommands:
#     ./Xray_Deployment.sh                 deploy (interactive, sane defaults)
#     ./Xray_Deployment.sh info            reprint links / subscription / creds
#     ./Xray_Deployment.sh status          service + listening-port status
#     ./Xray_Deployment.sh check           re-run every health check
#     ./Xray_Deployment.sh update          upgrade Xray to the latest build
#     ./Xray_Deployment.sh regen-sub       rebuild client bundles from state
#     ./Xray_Deployment.sh uninstall       remove configuration
#
#  After deployment this file installs itself as /usr/local/sbin/xrayctl.
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# 0. Constants / cosmetics
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly STATE_DIR="/etc/xray-deploy"
readonly STATE_FILE="${STATE_DIR}/xray.env"
readonly XRAY_CONF_DIR="/usr/local/etc/xray"
readonly XRAY_CONF="${XRAY_CONF_DIR}/config.json"
readonly XRAY_CERT_DIR="${XRAY_CONF_DIR}/cert"
readonly XRAY_CERT_FULL="${XRAY_CERT_DIR}/fullchain.pem"
readonly XRAY_CERT_KEY="${XRAY_CERT_DIR}/privkey.pem"
readonly XRAY_RENEW_HOOK="${XRAY_CERT_DIR}/deploy-hook.sh"
readonly CLIENT_OUT_DIR="/root/xray-clients"
readonly LOGFILE="/var/log/xray-deploy.log"
readonly INSTALLER_URL="https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh"

if [[ -t 1 ]]; then
  C_RST=$'\033[0m'; C_R=$'\033[1;31m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'
  C_B=$'\033[1;34m'; C_C=$'\033[1;36m'; C_D=$'\033[2m'; C_BOLD=$'\033[1m'
else
  C_RST=""; C_R=""; C_G=""; C_Y=""; C_B=""; C_C=""; C_D=""; C_BOLD=""
fi

WARN_COUNT=0
FAIL_COUNT=0

log()  { printf '%s[*]%s %s\n' "$C_B" "$C_RST" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_G" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_RST" "$*"; WARN_COUNT=$((WARN_COUNT+1)); }
bad()  { printf '%s[x]%s %s\n' "$C_R" "$C_RST" "$*"; FAIL_COUNT=$((FAIL_COUNT+1)); }
die()  { printf '%s[FATAL]%s %s\n' "$C_R" "$C_RST" "$*" >&2; exit 1; }
hr()   { printf '%s%s%s\n' "$C_D" "----------------------------------------------------------------------" "$C_RST"; }
head1(){ printf '\n%s==>%s %s%s%s\n' "$C_C" "$C_RST" "$C_BOLD" "$*" "$C_RST"; }

on_err() {
  local rc=$? line=${1:-?}
  printf '\n%s[FATAL]%s Xray_Deployment.sh failed at line %s (exit %s).\n' "$C_R" "$C_RST" "$line" "$rc" >&2
  printf '        Log: %s\n' "$LOGFILE" >&2
  exit "$rc"
}
trap 'on_err $LINENO' ERR

# -----------------------------------------------------------------------------
# 1. Defaults
# -----------------------------------------------------------------------------
VPN_DOMAIN=""
VPN_IP=""
NODE_LABEL=""

# XTLS has not promoted a stable release since 2026-03-27 — every build since is
# flagged pre-release, so GitHub's "latest stable" pointer is months behind.
# "latest" therefore means `install --beta` (newest build of any kind).
INSTALL_CHANNEL="latest"      # latest | stable | pinned
PIN_VERSION=""                # exact tag, e.g. v26.7.28 (used when channel=pinned)

CERT_MODE="letsencrypt"       # letsencrypt | self
LE_EMAIL=""

PROTO_CHOICE="all"
SELECTED=""

PORT_MODE="dedicated"         # dedicated | fallback
FALLBACK_DEST=""              # catch-all decoy for fallback mode (host:port or port)

REALITY_SNI="www.microsoft.com"
SS_METHOD="2022-blake3-aes-128-gcm"

AUTO_PORTS="yes"
KERNEL_TUNING="yes"
FIREWALL="auto"

SUB_HOST="no"
SUB_PORT="8080"
SUB_TOKEN=""

ASSUME_YES="no"
SKIP_PREFLIGHT="no"
NIC=""

declare -A PORT

# Generated secrets
UUID=""
PASSWORD=""
SS_PASSWORD=""
REALITY_PRIVATE=""; REALITY_PUBLIC=""; REALITY_SHORTID=""
VLESS_ENC_DEC=""; VLESS_ENC_ENC=""
WS_PATH_VLESS=""; WS_PATH_VMESS=""; WS_PATH_TROJAN=""
XHTTP_PATH=""
CERT_PIN=""                   # base64 SHA-256 of the certificate (self-signed pinning)

XRAY_USER="nobody"
XRAY_VERSION=""

CMD="deploy"

# Canonical protocol catalogue --------------------------------------------------
readonly ALL_KEYS=(vless-reality vless-xhttp-reality vless-encryption vless-ws vless-xhttp vmess-ws trojan hysteria2 ss2022)

proto_l4() { case "$1" in
  hysteria2) echo udp ;;
  ss2022)    echo both ;;
  *)         echo tcp ;;
esac; }

proto_needs_cert() { case "$1" in
  vless-ws|vless-xhttp|vmess-ws|trojan|hysteria2) echo yes ;;
  *) echo no ;;
esac; }

proto_ports() { case "$1" in
  vless-reality)       echo "443 8443 2087" ;;
  vless-xhttp-reality) echo "8443 2096 2053" ;;
  vless-encryption)    echo "2087 8880 2052" ;;
  vless-ws)            echo "2053 8443 2083" ;;
  vless-xhttp)         echo "2096 8443 2087" ;;
  vmess-ws)            echo "2082 8080 2086" ;;
  trojan)              echo "443 8443 2083" ;;
  hysteria2)           echo "443 8443 2053" ;;
  ss2022)              echo "8388 9388 8389" ;;
esac; }

proto_desc() { case "$1" in
  vless-reality)       echo "VLESS + Vision + REALITY (RAW/TCP) — no cert, strongest against DPI" ;;
  vless-xhttp-reality) echo "VLESS + XHTTP + REALITY — no cert, the transport XTLS now promotes" ;;
  vless-encryption)    echo "VLESS post-quantum Encryption (ML-KEM-768) + Vision — no cert at all" ;;
  vless-ws)            echo "VLESS + WebSocket + TLS — CDN/nginx friendly" ;;
  vless-xhttp)         echo "VLESS + XHTTP + TLS — HTTP/2-shaped, CDN friendly" ;;
  vmess-ws)            echo "VMess + WebSocket + TLS — legacy client compatibility" ;;
  trojan)              echo "Trojan + TLS" ;;
  hysteria2)           echo "Hysteria2 (QUIC/UDP) — native in Xray since v26.3.27" ;;
  ss2022)              echo "Shadowsocks 2022 (TCP+UDP)" ;;
esac; }

# Protocols that can hide behind the shared-443 VLESS gateway (path-routed WS).
fallback_capable() { case "$1" in vless-ws|vmess-ws|trojan) return 0 ;; *) return 1 ;; esac; }

# -----------------------------------------------------------------------------
# 2. Small helpers
# -----------------------------------------------------------------------------
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "This script must run as root (use: sudo bash $0)"; }
have() { command -v "$1" >/dev/null 2>&1; }

INTERACTIVE="yes"
[[ -r /dev/tty ]] || INTERACTIVE="no"

ask() {
  local __var=$1 __q=$2 __def=$3 __hint=${4:-} __in=""
  if [[ $ASSUME_YES == yes || $INTERACTIVE == no ]]; then
    printf -v "$__var" '%s' "$__def"; return 0
  fi
  if [[ -n $__def ]]; then
    printf '%s?%s %s %s[%s]%s: ' "$C_C" "$C_RST" "$__q" "$C_D" "$__def" "$C_RST" >/dev/tty
  elif [[ -n $__hint ]]; then
    printf '%s?%s %s %s(%s)%s: ' "$C_C" "$C_RST" "$__q" "$C_Y" "$__hint" "$C_RST" >/dev/tty
  else
    printf '%s?%s %s: ' "$C_C" "$C_RST" "$__q" >/dev/tty
  fi
  if ! IFS= read -r __in </dev/tty; then
    __in=""; INTERACTIVE="no"; printf '\n' >/dev/tty
  fi
  printf -v "$__var" '%s' "${__in:-$__def}"
}

ask_valid() {
  local __var=$1 __q=$2 __def=$3 __fn=$4 __err=$5 __hint=${6:-} __tries=0
  while true; do
    ask "$__var" "$__q" "$__def" "$__hint"
    if "$__fn" "${!__var}"; then return 0; fi
    printf '   %s\n' "$__err"
    __tries=$((__tries + 1))
    if (( __tries >= 10 )); then die "Too many invalid answers for: ${__q}"; fi
    if [[ $INTERACTIVE == no || $ASSUME_YES == yes ]]; then
      [[ -z $__def ]] && die "No value given for '${__q}'. Supply it on the command line (see --help)."
      die "Default value '${__def}' is not valid for: ${__q}"
    fi
  done
}

ask_yn() {
  local __var=$1 __q=$2 __def=$3 __in=""
  if [[ $ASSUME_YES == yes || $INTERACTIVE == no ]]; then
    printf -v "$__var" '%s' "$__def"; return 0
  fi
  while true; do
    printf '%s?%s %s %s[%s]%s (y/n): ' "$C_C" "$C_RST" "$__q" "$C_D" "$__def" "$C_RST" >/dev/tty
    IFS= read -r __in </dev/tty || __in=""
    __in="${__in:-$__def}"
    case "${__in,,}" in
      y|yes) printf -v "$__var" '%s' "yes"; return 0 ;;
      n|no)  printf -v "$__var" '%s' "no";  return 0 ;;
      *) printf '   please answer y or n\n' >/dev/tty ;;
    esac
  done
}

ask_choice() {
  local __var=$1 __q=$2 __def=$3; shift 3
  local -a __opts=("$@"); local __i __in
  if [[ $ASSUME_YES == yes || $INTERACTIVE == no ]]; then
    printf -v "$__var" '%s' "$__def"; return 0
  fi
  printf '%s?%s %s\n' "$C_C" "$C_RST" "$__q" >/dev/tty
  for __i in "${!__opts[@]}"; do
    local mark=" "; [[ ${__opts[$__i]} == "$__def" ]] && mark="*"
    printf '    %s%s) %s\n' "$mark" "$((__i+1))" "${__opts[$__i]}" >/dev/tty
  done
  while true; do
    printf '   choice %s[%s]%s: ' "$C_D" "$__def" "$C_RST" >/dev/tty
    if ! IFS= read -r __in </dev/tty; then __in=""; INTERACTIVE="no"; printf '\n' >/dev/tty; fi
    if [[ -z $__in ]]; then printf -v "$__var" '%s' "$__def"; return 0; fi
    if [[ $__in =~ ^[0-9]+$ ]] && (( __in >= 1 && __in <= ${#__opts[@]} )); then
      printf -v "$__var" '%s' "${__opts[$((__in-1))]}"; return 0
    fi
    for __i in "${__opts[@]}"; do
      if [[ ${__in,,} == "${__i,,}" ]]; then printf -v "$__var" '%s' "$__i"; return 0; fi
    done
    printf '   invalid choice\n' >/dev/tty
  done
}

# Read a bounded number of random bytes FIRST, then filter — otherwise `head`
# closes the pipe, the producer dies of SIGPIPE and pipefail turns it into 141.
gen_pass() {
  local out
  out="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  [[ ${#out} -ge 24 ]] || out="$(LC_ALL=C head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  printf '%s' "${out:0:24}"
}

gen_uuid() {
  local u=""
  if have xray; then u="$(xray uuid 2>/dev/null | tr -d '[:space:]' || true)"; fi
  [[ $u =~ ^[0-9a-fA-F-]{36}$ ]] || { [[ -r /proc/sys/kernel/random/uuid ]] && u="$(cat /proc/sys/kernel/random/uuid)"; }
  [[ $u =~ ^[0-9a-fA-F-]{36}$ ]] || { have uuidgen && u="$(uuidgen)"; }
  if [[ ! $u =~ ^[0-9a-fA-F-]{36}$ ]]; then
    local h; h="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'a-f0-9')"; h="${h:0:32}"
    u="${h:0:8}-${h:8:4}-4${h:13:3}-a${h:17:3}-${h:20:12}"
  fi
  printf '%s' "$u"
}

gen_b64key() { openssl rand -base64 "${1:-16}" | tr -d '\n'; }
gen_hex()    { openssl rand -hex "${1:-8}"    | tr -d '\n'; }

urlenc() {
  local s=$1 o="" c i
  for (( i=0; i<${#s}; i++ )); do
    c=${s:i:1}
    case "$c" in
      [a-zA-Z0-9.~_-]) o+="$c" ;;
      *) printf -v c '%%%02X' "'$c"; o+="$c" ;;
    esac
  done
  printf '%s' "$o"
}

valid_ipv4() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  # 10#$o forces base-10: an octet like 08/09 would otherwise be read as octal.
  local o; for o in ${1//./ }; do (( 10#$o >= 0 && 10#$o <= 255 )) || return 1; done
  return 0
}
valid_domain()  { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; }
valid_label()   { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ ]]; }
valid_port_num(){ [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_email()   { [[ -z $1 || $1 =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
valid_tag()     { [[ $1 =~ ^v[0-9]{1,3}\.[0-9]{1,2}\.[0-9]{1,2}$ ]]; }

# Match the LOCAL address column (4). Matching the peer column makes every port
# look free.
port_listening() {
  local flag="-lun"; [[ $1 == tcp ]] && flag="-ltn"
  ss $flag 2>/dev/null | awk -v p=":$2\$" '$4 ~ p {f=1} END{exit !f}'
}

save_state() {
  install -d -m 0700 "$STATE_DIR"
  {
    printf '# generated by Xray_Deployment.sh v%s on %s\n' "$SCRIPT_VERSION" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local v
    for v in VPN_DOMAIN VPN_IP NODE_LABEL INSTALL_CHANNEL PIN_VERSION CERT_MODE LE_EMAIL \
             PROTO_CHOICE SELECTED PORT_MODE FALLBACK_DEST REALITY_SNI SS_METHOD \
             AUTO_PORTS KERNEL_TUNING FIREWALL SUB_HOST SUB_PORT SUB_TOKEN NIC \
             XRAY_USER XRAY_VERSION \
             UUID PASSWORD SS_PASSWORD REALITY_PRIVATE REALITY_PUBLIC REALITY_SHORTID \
             VLESS_ENC_DEC VLESS_ENC_ENC \
             WS_PATH_VLESS WS_PATH_VMESS WS_PATH_TROJAN XHTTP_PATH CERT_PIN; do
      # escape embedded single quotes so `source` cannot break on odd input
      printf "%s='%s'\n" "$v" "${!v//\'/\'\\\'\'}"
    done
    local k
    for k in "${!PORT[@]}"; do printf "PORT['%s']='%s'\n" "$k" "${PORT[$k]}"; done
  } >"$STATE_FILE"
  chmod 0600 "$STATE_FILE"
}

load_state() {
  if [[ -r $STATE_FILE ]]; then
    # shellcheck source=/dev/null
    source "$STATE_FILE" || warn "Could not parse ${STATE_FILE}; using defaults."
  fi
  return 0
}

start_logging() {
  exec > >(tee -a "$LOGFILE") 2>&1
  log "Logging this run to ${LOGFILE}"
}

addr() { printf '%s' "${VPN_DOMAIN:-$VPN_IP}"; }
insec()      { [[ ${CERT_MODE} == self ]] && printf '1' || printf '0'; }
selected_has() { [[ " $SELECTED " == *" $1 "* ]]; }
needs_any_cert() {
  local k
  # fallback mode always terminates TLS on the shared gateway
  [[ $PORT_MODE == fallback ]] && return 0
  for k in $SELECTED; do [[ $(proto_needs_cert "$k") == yes ]] && return 0; done
  return 1
}
# Is this protocol served from behind the shared-443 gateway?
behind_gateway() { [[ $PORT_MODE == fallback ]] && fallback_capable "$1"; }
# The port a client actually dials for this protocol.
client_port() { if behind_gateway "$1"; then printf '443'; else printf '%s' "${PORT[$1]}"; fi; }

usage() {
cat <<EOF
${C_BOLD}Xray_Deployment.sh v${SCRIPT_VERSION}${C_RST} — Xray-core multi-protocol proxy for Ubuntu 22/24/26

Usage:
  sudo bash Xray_Deployment.sh [subcommand] [options]

Subcommands:
  deploy                 (default) install and configure everything
  info                   reprint share links / subscription / credentials
  status                 service and listening-port status
  check                  re-run every health check
  update                 upgrade Xray to the newest build in the chosen channel
  regen-sub              rebuild client bundles from saved state
  uninstall              remove configuration

Common options:
  -y, --yes                    non-interactive; requires --domain
      --domain <fqdn>          REQUIRED, e.g. vpn.example.com
      --ip <ipv4>              public IPv4 (auto-detected if omitted)
      --channel <latest|stable|pinned>
                               latest = newest build incl. pre-release (default;
                               Xray has had no new *stable* tag since 2026-03)
      --version <tag>          exact tag for --channel pinned, e.g. v26.7.28
      --protocols <all|list>   e.g. all  OR  vless-reality,hysteria2,ss2022
      --port-mode <dedicated|fallback>
                               fallback = share TCP/443 + one cert via VLESS fallbacks
      --fallback-dest <target> catch-all decoy for fallback mode (port or host:port)
      --cert-mode <letsencrypt|self>
      --le-email <email>
      --reality-sni <host>     REALITY steal target (default: ${REALITY_SNI})
      --no-kernel-tuning
      --firewall <auto|ufw|iptables|none>
      --serve-sub              also serve the subscription over plain HTTP
      --skip-preflight

Protocol keys: ${ALL_KEYS[*]}
EOF
}

# -----------------------------------------------------------------------------
# 3. Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      deploy|info|status|check|update|regen-sub|uninstall) CMD="$1"; shift ;;
      -y|--yes)           ASSUME_YES="yes"; shift ;;
      --domain)           VPN_DOMAIN="$2"; shift 2 ;;
      --ip)               VPN_IP="$2"; shift 2 ;;
      --channel)          INSTALL_CHANNEL="$2"; shift 2 ;;
      --version)          PIN_VERSION="$2"; INSTALL_CHANNEL="pinned"; shift 2 ;;
      --protocols)        PROTO_CHOICE="$2"; shift 2 ;;
      --port-mode)        PORT_MODE="$2"; shift 2 ;;
      --fallback-dest)    FALLBACK_DEST="$2"; shift 2 ;;
      --cert-mode)        CERT_MODE="$2"; shift 2 ;;
      --le-email)         LE_EMAIL="$2"; shift 2 ;;
      --reality-sni)      REALITY_SNI="$2"; shift 2 ;;
      --no-kernel-tuning) KERNEL_TUNING="no"; shift ;;
      --firewall)         FIREWALL="$2"; shift 2 ;;
      --serve-sub)        SUB_HOST="yes"; shift ;;
      --skip-preflight)   SKIP_PREFLIGHT="yes"; shift ;;
      -h|--help)          usage; exit 0 ;;
      -*) die "Unknown option: $1  (try --help)" ;;
      *)  die "Unexpected argument: $1  (try --help)" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# 4. Protocol selection + port assignment
# -----------------------------------------------------------------------------
resolve_selection() {
  local choice="${PROTO_CHOICE,,}" out=() tok found k
  if [[ -z $choice || $choice == all || $choice == "*" ]]; then
    SELECTED="${ALL_KEYS[*]}"; return 0
  fi
  choice="${choice//,/ }"
  for tok in $choice; do
    case "$tok" in
      reality|vless)         tok="vless-reality" ;;
      xhttp-reality)         tok="vless-xhttp-reality" ;;
      encryption|vlessenc|pq) tok="vless-encryption" ;;
      ws|vlessws)            tok="vless-ws" ;;
      xhttp)                 tok="vless-xhttp" ;;
      vmess)                 tok="vmess-ws" ;;
      hy2|hysteria)          tok="hysteria2" ;;
      ss|shadowsocks)        tok="ss2022" ;;
    esac
    found=""
    for k in "${ALL_KEYS[@]}"; do [[ $k == "$tok" ]] && found="$k"; done
    [[ -n $found ]] || die "Unknown protocol '${tok}'. Valid keys: ${ALL_KEYS[*]}"
    [[ " ${out[*]} " == *" $found "* ]] || out+=("$found")
  done
  (( ${#out[@]} > 0 )) || die "No protocols selected."
  SELECTED="${out[*]}"
}

# Drop one key from SELECTED without leaving a stray blank entry.
deselect() {
  local drop=$1 k out=()
  for k in $SELECTED; do [[ $k == "$drop" ]] || out+=("$k"); done
  SELECTED="${out[*]}"
}

declare -A USED_TCP USED_UDP
_port_taken() {
  local l4=$1 n=$2
  if [[ $l4 == tcp || $l4 == both ]]; then [[ -n ${USED_TCP[$n]:-} ]] && return 0; port_listening tcp "$n" && return 0; fi
  if [[ $l4 == udp || $l4 == both ]]; then [[ -n ${USED_UDP[$n]:-} ]] && return 0; port_listening udp "$n" && return 0; fi
  return 1
}
# NOTE: the trailing `return 0` is load-bearing. Without it the final `[[ ]] &&`
# becomes the function's exit status, which is FALSE for a tcp-only reservation —
# and under `set -e` a bare call would then abort the whole deploy.
_port_reserve() { local l4=$1 n=$2; [[ $l4 == tcp || $l4 == both ]] && USED_TCP[$n]=1; [[ $l4 == udp || $l4 == both ]] && USED_UDP[$n]=1; return 0; }
_pick_free() {
  local l4=$1; shift; local n tries=0
  for n in "$@"; do if ! _port_taken "$l4" "$n"; then echo "$n"; return 0; fi; done
  while (( tries < 80 )); do n=$(( (RANDOM % 25000) + 20000 )); if ! _port_taken "$l4" "$n"; then echo "$n"; return 0; fi; tries=$((tries+1)); done
  return 1
}

assign_ports() {
  USED_TCP=(); USED_UDP=(); PORT=()
  local key l4 chosen

  # In fallback mode the gateway owns TCP/443 and the WS protocols live on
  # loopback ports behind it.
  if [[ $PORT_MODE == fallback ]]; then
    chosen="$(_pick_free tcp 443 || true)"
    [[ -n $chosen ]] || die "TCP/443 is already in use — free it or use --port-mode dedicated."
    PORT[gateway]="$chosen"; _port_reserve tcp "$chosen"
  fi

  for key in $SELECTED; do
    l4="$(proto_l4 "$key")"
    if behind_gateway "$key"; then
      chosen="$(_pick_free tcp $(seq 30000 30060) || true)"
      [[ -n $chosen ]] || die "Could not find a free loopback port for ${key}."
    else
      chosen="$(_pick_free "$l4" $(proto_ports "$key") || true)"
      [[ -n $chosen ]] || die "Could not find a free ${l4} port for ${key}."
    fi
    PORT[$key]="$chosen"; _port_reserve "$l4" "$chosen"
  done
}

review_ports() {
  local key p
  echo
  echo "  Ports selected (free on this host):"
  [[ $PORT_MODE == fallback ]] && printf '    %-22s %s\n' "gateway (shared TLS)" "tcp/${PORT[gateway]}"
  for key in $SELECTED; do
    if behind_gateway "$key"; then
      printf '    %-22s %s\n' "$key" "via gateway, loopback tcp/${PORT[$key]}"
    else
      printf '    %-22s %s\n' "$key" "$(proto_l4 "$key")/${PORT[$key]}"
    fi
  done
  [[ $AUTO_PORTS == yes ]] && return 0
  for key in $SELECTED; do
    behind_gateway "$key" && continue
    ask_valid p "Port for ${key} ($(proto_l4 "$key"))" "${PORT[$key]}" valid_port_num "must be 1..65535"
    PORT[$key]="$p"
  done
}

# -----------------------------------------------------------------------------
# 5. Interactive configuration
# -----------------------------------------------------------------------------
collect_config() {
  head1 "Configuration"
  echo "Press ENTER to accept the value in brackets."
  echo

  local ip_hint="auto-detected if left blank" detected=""
  detected="$(detect_public_ip || true)"
  [[ -n $detected ]] && ip_hint="detected: ${detected}"

  ask_valid VPN_DOMAIN "Server domain name (FQDN clients connect to / cert CN)" "$VPN_DOMAIN" \
    valid_domain "that does not look like a domain name" "required, e.g. vpn.example.com"
  ask VPN_IP "Server public IPv4 (blank = auto-detect)" "$VPN_IP" "$ip_hint"
  [[ -n $VPN_IP ]] || VPN_IP="$detected"
  valid_ipv4 "$VPN_IP" || warn "Could not determine a valid public IPv4 (${VPN_IP:-none}); links will use the domain."

  [[ -n $NODE_LABEL ]] || NODE_LABEL="${VPN_DOMAIN%%.*}"
  ask_valid NODE_LABEL "Short label prefixed to every generated node name" "$NODE_LABEL" \
    valid_label "letters, digits, dot, dash or underscore (max 32 chars)"

  echo
  echo "  ${C_BOLD}latest${C_RST} – newest build of any kind. Xray has published no new *stable*"
  echo "           tag since 2026-03, so this is what you almost certainly want."
  echo "  ${C_BOLD}stable${C_RST} – GitHub's latest non-prerelease (currently months old)."
  echo "  ${C_BOLD}pinned${C_RST} – an exact tag you name."
  ask_choice INSTALL_CHANNEL "Xray release channel" "$INSTALL_CHANNEL" latest stable pinned
  if [[ $INSTALL_CHANNEL == pinned ]]; then
    ask_valid PIN_VERSION "Exact Xray tag to install" "${PIN_VERSION:-v26.7.28}" \
      valid_tag "expected a tag like v26.7.28"
  fi

  echo
  echo "  Available protocols:"
  local i=1 k
  for k in "${ALL_KEYS[@]}"; do printf '    %2d) %-20s %s\n' "$i" "$k" "$(proto_desc "$k")"; i=$((i+1)); done
  echo
  echo "  Enter 'all', or a comma list of keys/numbers (e.g. vless-reality,hysteria2,ss2022)."
  ask PROTO_CHOICE "Which protocols" "$PROTO_CHOICE"
  if [[ $PROTO_CHOICE =~ [0-9] && $PROTO_CHOICE != all ]]; then
    local tok out=""
    for tok in ${PROTO_CHOICE//,/ }; do
      if [[ $tok =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=${#ALL_KEYS[@]} )); then out+="${ALL_KEYS[$((tok-1))]},"; else out+="$tok,"; fi
    done
    PROTO_CHOICE="${out%,}"
  fi
  resolve_selection
  echo "  Selected: ${SELECTED}"

  # --- port mode ---
  local can_fallback="no"
  for k in $SELECTED; do fallback_capable "$k" && can_fallback="yes"; done
  if [[ $can_fallback == yes ]]; then
    echo
    echo "  ${C_BOLD}dedicated${C_RST} – every protocol listens on its own port."
    echo "  ${C_BOLD}fallback${C_RST}  – VLESS-Vision owns TCP/443 with ONE certificate and routes"
    echo "              VLESS-ws / VMess-ws / Trojan-ws to loopback inbounds by path."
    echo "              To a probe the server looks like a single ordinary HTTPS site."
    echo "              REALITY, XHTTP, Hysteria2 and Shadowsocks always keep their own port."
    ask_choice PORT_MODE "Port layout" "$PORT_MODE" dedicated fallback
    if [[ $PORT_MODE == fallback ]]; then
      ask FALLBACK_DEST "Catch-all decoy for non-matching requests (blank = reject; e.g. 80)" "$FALLBACK_DEST"
    fi
  else
    PORT_MODE="dedicated"
  fi

  # --- certificate ---
  if needs_any_cert; then
    echo
    echo "  ${C_BOLD}letsencrypt${C_RST} – real cert via certbot (needs the A record pointing here + port 80 free)."
    echo "  ${C_BOLD}self${C_RST}        – self-signed; clients must pin the certificate or allow insecure."
    ask_choice CERT_MODE "TLS certificate source" "$CERT_MODE" letsencrypt self
    if [[ $CERT_MODE == letsencrypt ]]; then
      ask_valid LE_EMAIL "Let's Encrypt contact e-mail (blank = register without one)" "$LE_EMAIL" \
        valid_email "that does not look like an e-mail address"
    fi
  else
    CERT_MODE="self"
  fi

  if selected_has vless-reality || selected_has vless-xhttp-reality; then
    ask_valid REALITY_SNI "REALITY steal target (a real external TLS1.3 site)" "$REALITY_SNI" \
      valid_domain "must be a hostname, e.g. www.microsoft.com"
  fi

  ask_yn AUTO_PORTS "Auto-assign the first free curated port per protocol" "$AUTO_PORTS"
  ask_choice FIREWALL "Firewall backend" "$FIREWALL" auto ufw iptables none
  ask_yn KERNEL_TUNING "Apply kernel/sysctl tuning (BBR, QUIC buffers, fd limits)" "$KERNEL_TUNING"
  ask_yn SUB_HOST "Also serve the subscription over plain HTTP (secret path)" "$SUB_HOST"
  [[ $SUB_HOST == yes ]] && ask_valid SUB_PORT "HTTP port for the subscription server" "$SUB_PORT" valid_port_num "1..65535"

  assign_ports
  review_ports

  echo
  hr
  printf '  %-24s %s\n' "Domain / IP"   "${VPN_DOMAIN} / ${VPN_IP:-?}"
  printf '  %-24s %s\n' "Xray channel"  "$INSTALL_CHANNEL${PIN_VERSION:+ ($PIN_VERSION)}"
  printf '  %-24s %s\n' "Protocols"     "$SELECTED"
  printf '  %-24s %s\n' "Port mode"     "$PORT_MODE"
  needs_any_cert && printf '  %-24s %s\n' "TLS certificate" "$CERT_MODE"
  (selected_has vless-reality || selected_has vless-xhttp-reality) && printf '  %-24s %s\n' "REALITY SNI" "$REALITY_SNI"
  printf '  %-24s %s\n' "Firewall"      "$FIREWALL"
  printf '  %-24s %s\n' "Kernel tuning" "$KERNEL_TUNING"
  hr
  local go; ask_yn go "Proceed with these settings" "yes"
  [[ $go == yes ]] || die "Aborted by user."
}

# -----------------------------------------------------------------------------
# 6. Pre-flight
# -----------------------------------------------------------------------------
detect_public_ip() {
  local u ip=""
  for u in "https://api.ipify.org" "https://ifconfig.me/ip" "https://icanhazip.com"; do
    ip="$(curl -4 -fsS --max-time 5 "$u" 2>/dev/null | tr -d '[:space:]')" || ip=""
    if valid_ipv4 "$ip"; then printf '%s' "$ip"; return 0; fi
  done
  return 1
}

detect_nic() {
  NIC="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
  [[ -n $NIC ]] || NIC="$(ip -o link show 2>/dev/null | awk -F': ' '$2!="lo"{print $2; exit}' || true)"
  [[ -n $NIC ]] || warn "Could not determine the outbound network interface."
  return 0
}

# Ubuntu 26.04 ships kernel 7.0, so never compare kernel version strings — key
# off VERSION_ID instead.
preflight() {
  head1 "Pre-flight checks"
  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    case "${ID:-}:${VERSION_ID:-}" in
      ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ok "OS: ${PRETTY_NAME}" ;;
      ubuntu:*) warn "Ubuntu ${VERSION_ID:-?} is untested here (targets 22.04/24.04/26.04) — continuing." ;;
      *) warn "OS is '${PRETTY_NAME:-unknown}', this script targets Ubuntu — continuing anyway." ;;
    esac
  else
    warn "/etc/os-release missing; cannot verify the distribution."
  fi

  case "$(uname -m)" in
    x86_64|amd64|aarch64|arm64) ok "Architecture: $(uname -m)" ;;
    *) warn "Architecture $(uname -m) may lack a prebuilt Xray binary." ;;
  esac

  have systemd-detect-virt && ok "Virtualisation: $(systemd-detect-virt 2>/dev/null || echo none)"
  detect_nic
  [[ -n $NIC ]] && ok "Outbound interface: ${NIC}"

  local pub=""; pub="$(detect_public_ip || true)"
  [[ -n $pub ]] && ok "Detected public IPv4: ${pub}"

  if [[ $CERT_MODE == letsencrypt ]] && needs_any_cert && have dig; then
    local a; a="$(dig +short +time=3 A "$VPN_DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
    if [[ -n $a && ( $a == "$VPN_IP" || $a == "$pub" ) ]]; then ok "DNS: ${VPN_DOMAIN} -> ${a}"
    else warn "DNS: ${VPN_DOMAIN} -> ${a:-<none>} (expected ${VPN_IP:-$pub}); Let's Encrypt HTTP-01 may fail."; fi
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 7. Install Xray
# -----------------------------------------------------------------------------
install_deps() {
  head1 "Installing dependencies"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections 2>/dev/null || true
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections 2>/dev/null || true
  log "apt-get update ..."
  # A stalled mirror must not hang the whole deploy — bound it and retry once.
  if ! timeout 300 apt-get update -qq; then
    warn "apt-get update failed (slow mirrors?) — retrying once in 5s ..."
    sleep 5
    timeout 300 apt-get update -qq || warn "apt-get update reported errors."
  fi
  local base=(curl ca-certificates jq openssl unzip zip iproute2 dnsutils tar)
  timeout 900 apt-get install -y -qq "${base[@]}" >/dev/null 2>&1 || {
    warn "Batch dependency install failed; retrying individually."
    local p; for p in "${base[@]}"; do timeout 600 apt-get install -y -qq "$p" >/dev/null 2>&1 || warn "could not install $p"; done
  }
  have jq      || die "jq is required and could not be installed."
  have openssl || die "openssl is required and could not be installed."
  if [[ $CERT_MODE == letsencrypt ]] && needs_any_cert; then
    apt-get install -y -qq certbot >/dev/null 2>&1 || die "Failed to install certbot (needed for --cert-mode letsencrypt)."
  fi
  return 0
}

_arch_xray() { case "$(uname -m)" in x86_64|amd64) echo 64 ;; aarch64|arm64) echo arm64-v8a ;; armv7l) echo arm32-v7a ;; i386|i686) echo 32 ;; *) echo "" ;; esac; }

install_xray_manual() {
  local arch tag url tmp
  arch="$(_arch_xray)"; [[ -n $arch ]] || die "No prebuilt Xray for $(uname -m)."
  # `|| true` + swallowed jq errors: a bare `cmd | jq` assignment under
  # set -e + pipefail would fire the ERR trap on an API rate-limit (403) or a
  # network blip, preempting the graceful die below.
  case "$INSTALL_CHANNEL" in
    pinned) tag="$PIN_VERSION" ;;
    stable) tag="$(curl -fsSL 'https://api.github.com/repos/XTLS/Xray-core/releases/latest' 2>/dev/null | jq -r '.tag_name' 2>/dev/null || true)" ;;
    *)      tag="$(curl -fsSL 'https://api.github.com/repos/XTLS/Xray-core/releases?per_page=10' 2>/dev/null | jq -r '[.[].tag_name][0]' 2>/dev/null || true)" ;;
  esac
  [[ -n $tag && $tag != null ]] || die "Could not determine an Xray release tag (GitHub API unreachable or rate-limited). Retry, or use --version <tag>."
  url="https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-${arch}.zip"
  tmp="$(mktemp -d)"; log "Downloading ${url}"
  curl -fL -o "$tmp/xray.zip" "$url" || { rm -rf "$tmp"; die "Download failed: $url"; }
  unzip -o "$tmp/xray.zip" -d "$tmp/x" >/dev/null || { rm -rf "$tmp"; die "Could not unpack the Xray archive."; }
  install -m0755 "$tmp/x/xray" /usr/local/bin/xray
  install -d -m0755 /usr/local/share/xray
  # Geodata ships inside the release zip; a minimal server config never reads it,
  # but installing it keeps geoip:/geosite: routing available if you add rules.
  [[ -f "$tmp/x/geoip.dat"   ]] && install -m0644 "$tmp/x/geoip.dat"   /usr/local/share/xray/ || true
  [[ -f "$tmp/x/geosite.dat" ]] && install -m0644 "$tmp/x/geosite.dat" /usr/local/share/xray/ || true
  rm -rf "$tmp"
  install -d -m0755 "$XRAY_CONF_DIR"
  _install_fallback_unit
  ok "Installed Xray ${tag} from the GitHub release archive."
}

_install_fallback_unit() {
  id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray 2>/dev/null || true
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=xray
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
RuntimeDirectory=xray
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  return 0
}

install_xray() {
  head1 "Installing Xray-core (${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}})"
  local args=(install) tmp rc=1
  case "$INSTALL_CHANNEL" in
    latest) args+=(--beta) ;;
    pinned) args+=(--version "$PIN_VERSION") ;;
    stable) : ;;
  esac
  # Download the official installer to disk and run it, rather than curl|bash, so
  # a truncated download cannot execute as a partial script.
  tmp="$(mktemp)"
  if curl -fsSL -o "$tmp" "$INSTALLER_URL" 2>/dev/null && [[ -s $tmp ]]; then
    if bash "$tmp" "${args[@]}" >/dev/null 2>&1; then rc=0; fi
  fi
  rm -f "$tmp"
  if (( rc != 0 )) || ! have xray; then
    warn "Official installer did not complete; falling back to the GitHub release archive."
    install_xray_manual
  fi
  have xray || die "Xray could not be installed."
  install -d -m0755 "$XRAY_CONF_DIR"

  # The official unit runs Xray as `nobody` — it therefore cannot read a
  # root-owned private key. Detect the real user so the certs can be chowned.
  XRAY_USER="$(systemctl show -p User --value xray 2>/dev/null || true)"
  [[ -n $XRAY_USER ]] || XRAY_USER="nobody"
  id "$XRAY_USER" >/dev/null 2>&1 || XRAY_USER="root"
  XRAY_VERSION="$(xray version 2>/dev/null | awk 'NR==1{print $2}' || true)"
  ok "Xray version: ${XRAY_VERSION:-unknown}   (service runs as: ${XRAY_USER})"
  return 0
}

# -----------------------------------------------------------------------------
# 8. Credentials
# -----------------------------------------------------------------------------
gen_reality_keys() {
  local out
  out="$(xray x25519 2>/dev/null || true)"
  # Current Xray prints "PrivateKey:" / "Password:"; older builds printed
  # "Private key:" / "Public key:". Accept both.
  REALITY_PRIVATE="$(printf '%s\n' "$out" | grep -iE '^(PrivateKey|Private key)' | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  REALITY_PUBLIC="$(printf '%s\n'  "$out" | grep -iE '^(Password|PublicKey|Public key)' | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  [[ -n $REALITY_PRIVATE && -n $REALITY_PUBLIC ]] || die "\`xray x25519\` produced no REALITY keypair."
  return 0
}

gen_vless_encryption() {
  local out
  out="$(xray vlessenc 2>/dev/null || true)"
  # vlessenc prints an X25519 pair FIRST and an ML-KEM-768 (post-quantum) pair
  # SECOND. Take the last of each so the identity auth is post-quantum too.
  VLESS_ENC_DEC="$(printf '%s\n' "$out" | grep -o '"decryption": *"[^"]*"' | tail -1 | sed 's/.*: *"//; s/"$//' || true)"
  VLESS_ENC_ENC="$(printf '%s\n' "$out" | grep -o '"encryption": *"[^"]*"' | tail -1 | sed 's/.*: *"//; s/"$//' || true)"
  if [[ -z $VLESS_ENC_DEC || -z $VLESS_ENC_ENC ]]; then
    warn "\`xray vlessenc\` is unavailable in this build — dropping vless-encryption."
    warn "It needs Xray v25.9.5 or newer; try --channel latest."
    deselect vless-encryption
  fi
  return 0
}

gen_credentials() {
  head1 "Generating credentials"
  [[ -n $UUID ]]     || UUID="$(gen_uuid)"
  [[ -n $PASSWORD ]] || PASSWORD="$(gen_pass)"
  [[ -n $WS_PATH_VLESS ]]  || WS_PATH_VLESS="/$(gen_hex 6)"
  [[ -n $WS_PATH_VMESS ]]  || WS_PATH_VMESS="/$(gen_hex 6)"
  [[ -n $WS_PATH_TROJAN ]] || WS_PATH_TROJAN="/$(gen_hex 6)"
  [[ -n $XHTTP_PATH ]]     || XHTTP_PATH="/$(gen_hex 6)"

  if selected_has ss2022; then
    local bytes=16; [[ $SS_METHOD == *chacha20* || $SS_METHOD == *aes-256* ]] && bytes=32
    [[ -n $SS_PASSWORD ]] || SS_PASSWORD="$(gen_b64key "$bytes")"
  fi
  if selected_has vless-reality || selected_has vless-xhttp-reality; then
    [[ -n $REALITY_PRIVATE && -n $REALITY_PUBLIC ]] || gen_reality_keys
    [[ -n $REALITY_SHORTID ]] || REALITY_SHORTID="$(gen_hex 8)"
  fi
  if selected_has vless-encryption; then
    [[ -n $VLESS_ENC_DEC && -n $VLESS_ENC_ENC ]] || gen_vless_encryption
  fi
  ok "Secrets ready."
  return 0
}

# -----------------------------------------------------------------------------
# 9. Certificates
# -----------------------------------------------------------------------------
_chown_certs() {
  local grp; grp="$(id -gn "$XRAY_USER" 2>/dev/null || echo root)"
  install -d -m 0750 "$XRAY_CERT_DIR"
  chown -R "root:${grp}" "$XRAY_CERT_DIR" 2>/dev/null || true
  chmod 0644 "$XRAY_CERT_FULL" 2>/dev/null || true
  chmod 0640 "$XRAY_CERT_KEY"  2>/dev/null || true
  chown "root:${grp}" "$XRAY_CERT_FULL" "$XRAY_CERT_KEY" 2>/dev/null || true
  # pinnedPeerCertSha256 is a HEX STRING (not base64, and not an array) of
  # the SHA-256 over the whole DER certificate.
  CERT_PIN="$(openssl x509 -in "$XRAY_CERT_FULL" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' || true)"
  return 0
}

make_self_signed() {
  install -d -m 0750 "$XRAY_CERT_DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
    -days 3650 -subj "/CN=${VPN_DOMAIN}" -addext "subjectAltName=DNS:${VPN_DOMAIN}" \
    -keyout "$XRAY_CERT_KEY" -out "$XRAY_CERT_FULL" >/dev/null 2>&1 \
    || die "openssl failed to generate a self-signed certificate."
  _chown_certs
  ok "Self-signed certificate written to ${XRAY_CERT_DIR}."
  warn "Clients must pin this certificate (pcs) or enable 'allow insecure'."
  return 0
}

obtain_letsencrypt() {
  local email_arg="--register-unsafely-without-email"
  [[ -n $LE_EMAIL ]] && email_arg="-m ${LE_EMAIL}"
  systemctl stop xray >/dev/null 2>&1 || true
  # $email_arg must stay unquoted: it has to split into "-m" + address.
  if certbot certonly --standalone --non-interactive --agree-tos $email_arg \
       --http-01-port 80 -d "$VPN_DOMAIN" >/dev/null 2>&1; then
    install -d -m 0750 "$XRAY_CERT_DIR"
    # Part of the success condition: if certbot reported success but the live
    # directory is not readable, return 1 so setup_cert falls back to self-signed
    # instead of continuing with no certificate at all.
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "$XRAY_CERT_FULL" &&
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "$XRAY_CERT_KEY" || {
      warn "certbot succeeded but the issued certificate could not be copied."
      return 1
    }
    _chown_certs
    local grp; grp="$(id -gn "$XRAY_USER" 2>/dev/null || echo root)"
    cat >"$XRAY_RENEW_HOOK" <<EOF
#!/usr/bin/env bash
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "${XRAY_CERT_FULL}"
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "${XRAY_CERT_KEY}"
chown "root:${grp}" "${XRAY_CERT_FULL}" "${XRAY_CERT_KEY}"
chmod 0644 "${XRAY_CERT_FULL}"; chmod 0640 "${XRAY_CERT_KEY}"
systemctl restart xray
EOF
    chmod 0755 "$XRAY_RENEW_HOOK"
    install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    ln -sf "$XRAY_RENEW_HOOK" "/etc/letsencrypt/renewal-hooks/deploy/xray-${VPN_DOMAIN}.sh"
    ok "Let's Encrypt certificate obtained for ${VPN_DOMAIN}; auto-renew hook installed."
    return 0
  fi
  return 1
}

setup_cert() {
  needs_any_cert || { log "No TLS-certificate protocol selected; skipping certificates."; return 0; }
  head1 "TLS certificate (${CERT_MODE})"
  if [[ $CERT_MODE == letsencrypt ]]; then
    if ! obtain_letsencrypt; then
      warn "Let's Encrypt issuance failed (DNS not pointing here, or :80 blocked)."
      warn "Falling back to a self-signed certificate."
      CERT_MODE="self"; make_self_signed
    fi
  else
    make_self_signed
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 10. Xray server config
# -----------------------------------------------------------------------------
# NOTE ON FIELD NAMES: Xray renamed several keys (tcp->raw, network->method,
# clients->users, REALITY dest->target, freedom->direct ...) but kept BOTH forms
# working. This script deliberately emits the older, universally-accepted names
# so one config is valid on every channel, old or new. Exception: "xhttp", which
# has existed since v24.11 and is the only spelling worth using.

# $1 = compact JSON alpn array. WebSocket speaks HTTP/1.1 only, so advertising
# h2 there invites a client or CDN to negotiate h2 and break the Upgrade handshake.
_tls_obj() {
  local alpn="${1:-[\"h2\",\"http/1.1\"]}"
  jq -cn --arg sni "$VPN_DOMAIN" --arg c "$XRAY_CERT_FULL" --arg k "$XRAY_CERT_KEY" --argjson alpn "$alpn" \
    '{serverName:$sni,alpn:$alpn,certificates:[{certificateFile:$c,keyFile:$k}]}'
}

_reality_obj() {
  jq -cn --arg sni "$REALITY_SNI" --arg pk "$REALITY_PRIVATE" --arg sid "$REALITY_SHORTID" \
    '{dest:($sni+":443"),serverNames:[$sni],privateKey:$pk,shortIds:["",$sid]}'
}

ib_of() { # emit the compact inbound JSON for a protocol key
  # Each `local` must be its OWN statement: bash expands every word of a command
  # BEFORE the `local` builtin binds anything, so `local key=$1 port="${PORT[$key]}"`
  # would resolve $key against the *caller's* variable and silently pick the
  # wrong port (or fail under set -u).
  local key=$1
  local port="${PORT[$key]}"
  case "$key" in
    vless-reality)
      jq -cn --argjson port "$port" --arg uuid "$UUID" --argjson reality "$(_reality_obj)" '
        {tag:"vless-reality-in",listen:"0.0.0.0",port:$port,protocol:"vless",
         settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none"},
         streamSettings:{network:"tcp",security:"reality",realitySettings:$reality}}' ;;
    vless-xhttp-reality)
      jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$XHTTP_PATH" \
             --argjson reality "$(_reality_obj)" '
        {tag:"vless-xhttp-reality-in",listen:"0.0.0.0",port:$port,protocol:"vless",
         settings:{clients:[{id:$uuid}],decryption:"none"},
         streamSettings:{network:"xhttp",security:"reality",realitySettings:$reality,
                         xhttpSettings:{path:$path,mode:"stream-one"}}}' ;;
    vless-encryption)
      # VLESS Encryption replaces the TLS layer entirely, so security is "none".
      # Vision is still valid here (and recommended) because the encryption layer
      # presents a CommonConn that XTLS accepts.
      jq -cn --argjson port "$port" --arg uuid "$UUID" --arg dec "$VLESS_ENC_DEC" '
        {tag:"vless-encryption-in",listen:"0.0.0.0",port:$port,protocol:"vless",
         settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:$dec},
         streamSettings:{network:"tcp",security:"none"}}' ;;
    vless-ws)
      if behind_gateway "$key"; then
        jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$WS_PATH_VLESS" '
          {tag:"vless-ws-in",listen:"127.0.0.1",port:$port,protocol:"vless",
           settings:{clients:[{id:$uuid}],decryption:"none"},
           streamSettings:{network:"ws",security:"none",wsSettings:{path:$path}}}'
      else
        jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$WS_PATH_VLESS" \
               --argjson tls "$(_tls_obj '["http/1.1"]')" '
          {tag:"vless-ws-in",listen:"0.0.0.0",port:$port,protocol:"vless",
           settings:{clients:[{id:$uuid}],decryption:"none"},
           streamSettings:{network:"ws",security:"tls",tlsSettings:$tls,wsSettings:{path:$path}}}'
      fi ;;
    vless-xhttp)
      jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$XHTTP_PATH" \
             --argjson tls "$(_tls_obj '["h2"]')" '
        {tag:"vless-xhttp-in",listen:"0.0.0.0",port:$port,protocol:"vless",
         settings:{clients:[{id:$uuid}],decryption:"none"},
         streamSettings:{network:"xhttp",security:"tls",tlsSettings:$tls,
                         xhttpSettings:{path:$path,mode:"auto"}}}' ;;
    vmess-ws)
      if behind_gateway "$key"; then
        jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$WS_PATH_VMESS" '
          {tag:"vmess-ws-in",listen:"127.0.0.1",port:$port,protocol:"vmess",
           settings:{clients:[{id:$uuid}]},
           streamSettings:{network:"ws",security:"none",wsSettings:{path:$path}}}'
      else
        jq -cn --argjson port "$port" --arg uuid "$UUID" --arg path "$WS_PATH_VMESS" \
               --argjson tls "$(_tls_obj '["http/1.1"]')" '
          {tag:"vmess-ws-in",listen:"0.0.0.0",port:$port,protocol:"vmess",
           settings:{clients:[{id:$uuid}]},
           streamSettings:{network:"ws",security:"tls",tlsSettings:$tls,wsSettings:{path:$path}}}'
      fi ;;
    trojan)
      if behind_gateway "$key"; then
        jq -cn --argjson port "$port" --arg pw "$PASSWORD" --arg path "$WS_PATH_TROJAN" '
          {tag:"trojan-in",listen:"127.0.0.1",port:$port,protocol:"trojan",
           settings:{clients:[{password:$pw}]},
           streamSettings:{network:"ws",security:"none",wsSettings:{path:$path}}}'
      else
        jq -cn --argjson port "$port" --arg pw "$PASSWORD" --argjson tls "$(_tls_obj)" '
          {tag:"trojan-in",listen:"0.0.0.0",port:$port,protocol:"trojan",
           settings:{clients:[{password:$pw}]},
           streamSettings:{network:"tcp",security:"tls",tlsSettings:$tls}}'
      fi ;;
    hysteria2)
      # `version` MUST be 2 in BOTH settings and hysteriaSettings — Build()
      # opens with `if c.Version != 2 -> error`. The credential key is `auth`,
      # not `password`. Xray's Hysteria has NO obfs field, so Salamander is
      # deliberately absent here and in every client artefact.
      jq -cn --argjson port "$port" --arg pw "$PASSWORD" --argjson tls "$(_tls_obj '["h3"]')" '
        {tag:"hysteria2-in",listen:"0.0.0.0",port:$port,protocol:"hysteria",
         settings:{version:2,clients:[{auth:$pw}]},
         streamSettings:{network:"hysteria",security:"tls",tlsSettings:$tls,
                         hysteriaSettings:{version:2}}}' ;;
    ss2022)
      jq -cn --argjson port "$port" --arg m "$SS_METHOD" --arg pw "$SS_PASSWORD" '
        {tag:"ss2022-in",listen:"0.0.0.0",port:$port,protocol:"shadowsocks",
         settings:{method:$m,password:$pw,network:"tcp,udp"}}' ;;
  esac
}

# The shared-443 gateway: VLESS + Vision + TLS whose fallbacks route by path.
ib_gateway() {
  local fb=() key
  for key in $SELECTED; do
    behind_gateway "$key" || continue
    local p="" ; case "$key" in
      vless-ws) p="$WS_PATH_VLESS" ;; vmess-ws) p="$WS_PATH_VMESS" ;; trojan) p="$WS_PATH_TROJAN" ;;
    esac
    # Emit dest as "127.0.0.1:<port>", NOT a bare number: a numeric dest is
    # rewritten to "localhost:<port>", which can resolve to ::1 first on a
    # dual-stack host and miss an inbound bound to 127.0.0.1.
    fb+=("$(jq -cn --arg dest "127.0.0.1:${PORT[$key]}" --arg path "$p" '{dest:$dest,path:$path,xver:0}')")
  done
  # Catch-all decoy last: anything that matches no path is handed to a real web
  # service, so a probe just sees an ordinary site.
  if [[ -n $FALLBACK_DEST ]]; then
    if [[ $FALLBACK_DEST =~ ^[0-9]+$ ]]; then
      fb+=("$(jq -cn --argjson dest "$FALLBACK_DEST" '{dest:$dest,xver:0}')")
    else
      fb+=("$(jq -cn --arg dest "$FALLBACK_DEST" '{dest:$dest,xver:0}')")
    fi
  fi
  local fb_json; fb_json="$(printf '%s\n' "${fb[@]}" | jq -s '.')"
  jq -cn --argjson port "${PORT[gateway]}" --arg uuid "$UUID" \
         --argjson tls "$(_tls_obj)" --argjson fb "$fb_json" '
    {tag:"gateway-in",listen:"0.0.0.0",port:$port,protocol:"vless",
     settings:{clients:[{id:$uuid,flow:"xtls-rprx-vision"}],decryption:"none",fallbacks:$fb},
     streamSettings:{network:"tcp",security:"tls",tlsSettings:$tls}}'
}

build_inbounds() {
  local frags=() key
  [[ $PORT_MODE == fallback ]] && frags+=("$(ib_gateway)")
  for key in $SELECTED; do frags+=("$(ib_of "$key")"); done
  printf '%s\n' "${frags[@]}" | jq -s '.'
}

write_xray_config() {
  head1 "Writing ${XRAY_CONF}"
  local inbounds; inbounds="$(build_inbounds)"
  # loglevel without file paths -> journald, so the unprivileged service user
  # never needs write access to /var/log/xray.
  # Routing blocks clients from reaching this host's own private networks.
  # Explicit CIDRs are used rather than geoip:private so geodata is never needed.
  jq -n --argjson inbounds "$inbounds" '
    {log:{loglevel:"warning"},
     inbounds:$inbounds,
     outbounds:[{tag:"direct",protocol:"freedom"},{tag:"blocked",protocol:"blackhole"}],
     routing:{rules:[{type:"field",outboundTag:"blocked",
                      ip:["127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
                          "169.254.0.0/16","::1/128","fc00::/7","fe80::/10"]}]}}' >"$XRAY_CONF"
  local grp; grp="$(id -gn "$XRAY_USER" 2>/dev/null || echo root)"
  chown "root:${grp}" "$XRAY_CONF" 2>/dev/null || true
  chmod 0640 "$XRAY_CONF"
  # Validate with the installed binary before the service is ever restarted.
  # mktemp, not a fixed /tmp path: a local user could pre-create the latter and
  # have root truncate it, then see attacker-controlled text echoed into the log.
  local tlog; tlog="$(mktemp)"
  if xray run -test -c "$XRAY_CONF" >"$tlog" 2>&1; then
    rm -f "$tlog"; ok "Config validated by \`xray run -test\`."
  else
    sed 's/^/    /' "$tlog" >&2; rm -f "$tlog"
    die "Xray rejected the generated config (see above)."
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 11. Kernel tuning (TCP + QUIC; Xray gained native Hysteria2/QUIC in v26.3.27)
# -----------------------------------------------------------------------------
kernel_tuning() {
  [[ $KERNEL_TUNING == yes ]] || { log "Kernel tuning skipped."; return 0; }
  head1 "Kernel / sysctl tuning"

  local bbr_block=""
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    bbr_block=$'\n# --- congestion control (BBR + fair-queue pacing) ---\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr'
    echo "tcp_bbr" >/etc/modules-load.d/xray-bbr.conf
    ok "BBR available and enabled."
  else
    warn "BBR unavailable on this kernel; leaving congestion control unchanged."
  fi

  # A sysctl.d drop-in silently skips keys the running kernel does not know, so
  # obsolete keys from old guides (tcp_tw_recycle, tcp_low_latency, ...) are
  # simply absent here rather than being force-set.
  cat >/etc/sysctl.d/99-xray.conf <<EOF
# ---------------------------------------------------------------------------
# Xray-core proxy tuning (Xray_Deployment.sh) — TCP + QUIC (Hysteria2, XHTTP/3)
# ---------------------------------------------------------------------------

# rmem_max/wmem_max are CEILINGS on what a socket may request, not allocations:
# TCP autotuning uses tcp_rmem/tcp_wmem and ignores these entirely. Raising them
# costs nothing and is required by QUIC (quic-go asks for a large SO_RCVBUF and
# logs "failed to sufficiently increase receive buffer size" when capped).
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536

# TCP autotuning ceilings.
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 16384 16777216
net.ipv4.tcp_moderate_rcvbuf = 1

# Queues / backlogs for many concurrent connections.
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 16384
net.core.netdev_budget = 600
net.ipv4.tcp_max_syn_backlog = 8192

# Latency / throughput behaviour.
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535

# conntrack only exists when a NAT/stateful firewall loads the module; the keys
# are skipped otherwise. A busy proxy should not keep entries for five days.
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
${bbr_block}
EOF
  sysctl --system >/dev/null 2>&1 || warn "sysctl --system reported errors (unknown keys are skipped)."

  # The official unit already sets LimitNOFILE=1000000; this drop-in keeps the
  # limit if a fallback/tarball unit was used instead.
  install -d -m 0755 /etc/systemd/system/xray.service.d
  cat >/etc/systemd/system/xray.service.d/10-limits.conf <<'EOF'
[Service]
LimitNOFILE=1000000
EOF
  systemctl daemon-reload
  ok "Applied sysctl drop-in and confirmed LimitNOFILE for Xray."
  return 0
}

# -----------------------------------------------------------------------------
# 12. Firewall (userspace proxy: INPUT only — no forwarding or NAT needed)
# -----------------------------------------------------------------------------
_tcp_ports() {
  local key out=()
  [[ $PORT_MODE == fallback ]] && out+=("${PORT[gateway]}")
  for key in $SELECTED; do
    behind_gateway "$key" && continue      # loopback only; never exposed
    case "$(proto_l4 "$key")" in tcp|both) out+=("${PORT[$key]}") ;; esac
  done
  [[ $CERT_MODE == letsencrypt ]] && needs_any_cert && out+=("80")
  [[ $SUB_HOST == yes ]] && out+=("$SUB_PORT")
  printf '%s\n' "${out[@]}" | sort -un
}
_udp_ports() {
  local key out=()
  for key in $SELECTED; do
    behind_gateway "$key" && continue
    case "$(proto_l4 "$key")" in udp|both) out+=("${PORT[$key]}") ;; esac
  done
  printf '%s\n' "${out[@]}" | sort -un
}

# Must NEVER return empty: the callers feed this straight into `ufw allow`,
# and an empty value becomes `ufw allow /tcp`, which fails silently and then
# `ufw --force enable` locks the operator out of SSH. awk exits non-zero on a
# missing sshd_config, which under set -e would kill this subshell before the
# echo — hence `|| true` on every step and a hard 22 fallback.
ssh_port() {
  local p=""
  p="$(ss -ltnpH 2>/dev/null | awk '/sshd|ssh\.socket/{n=split($4,a,":"); print a[n]; exit}' || true)"
  if [[ ! $p =~ ^[0-9]+$ ]]; then
    p="$(awk '/^[Pp]ort[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)"
  fi
  [[ $p =~ ^[0-9]+$ ]] && (( 10#$p >= 1 && 10#$p <= 65535 )) || p=22
  printf '%s' "$p"
}

firewall_ufw() {
  local p
  ufw allow "$(ssh_port)/tcp" >/dev/null 2>&1 || true
  for p in $(_tcp_ports); do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  for p in $(_udp_ports); do ufw allow "${p}/udp" >/dev/null 2>&1 || true; done
  ufw --force enable >/dev/null 2>&1 || true
  ok "ufw rules applied."
  return 0
}

firewall_iptables() {
  local p
  # A single failing rule should degrade the firewall to a warning, not abort a
  # deploy whose services are already up.
  iptables -N XRAY_IN 2>/dev/null || iptables -F XRAY_IN || true
  iptables -C INPUT -j XRAY_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j XRAY_IN || true
  iptables -A XRAY_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || warn "conntrack rule not added (module missing?)."
  iptables -A XRAY_IN -p tcp --dport "$(ssh_port)" -j ACCEPT || true
  for p in $(_tcp_ports); do iptables -A XRAY_IN -p tcp --dport "$p" -j ACCEPT || true; done
  for p in $(_udp_ports); do iptables -A XRAY_IN -p udp --dport "$p" -j ACCEPT || true; done
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || \
    { apt-get install -y -qq iptables-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1; } || \
    warn "iptables rules are live but not persisted across reboot (install iptables-persistent)."
  ok "iptables rules applied."
  return 0
}

firewall_setup() {
  head1 "Firewall"
  local backend="$FIREWALL"
  if [[ $backend == auto ]]; then
    if have ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then backend="ufw"
    elif have iptables; then backend="iptables"; else backend="none"; fi
  fi
  log "Backend: ${backend}   tcp: $(_tcp_ports | tr '\n' ' ')  udp: $(_udp_ports | tr '\n' ' ')"
  case "$backend" in
    none)     warn "Firewall step skipped — open the listed ports yourself." ;;
    ufw)      have ufw || { warn "ufw not installed; using iptables."; firewall_iptables; return 0; }; firewall_ufw ;;
    iptables) firewall_iptables ;;
    *)        die "Unknown firewall backend '${backend}'." ;;
  esac
  return 0
}

# -----------------------------------------------------------------------------
# 13. Services
# -----------------------------------------------------------------------------
start_services() {
  head1 "Starting services"
  systemctl enable xray >/dev/null 2>&1 || true
  # `|| true` so the is-active check below owns the failure path and can print
  # the journal, instead of the ERR trap aborting with no diagnostics.
  systemctl restart xray || true
  sleep 2
  if systemctl is-active --quiet xray; then ok "Xray is running."
  else
    bad "Xray failed to start:"
    journalctl -u xray -n 20 --no-pager 2>/dev/null | sed 's/^/    /' >&2
    die "Fix the config and re-run."
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 14. Client artefacts
# -----------------------------------------------------------------------------
link_of() {
  local key=$1 a p ins
  a="$(addr)"; p="$(client_port "$key")"; ins="$(insec)"
  case "$key" in
    vless-reality)
      printf 'vless://%s@%s:%s?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&pbk=%s&sid=%s&fp=chrome&sni=%s&spx=%%2F#%s' \
        "$UUID" "$a" "$p" "$(urlenc "$REALITY_PUBLIC")" "$REALITY_SHORTID" "$(urlenc "$REALITY_SNI")" "$(urlenc "${NODE_LABEL}-reality")" ;;
    vless-xhttp-reality)
      printf 'vless://%s@%s:%s?type=xhttp&security=reality&encryption=none&path=%s&mode=stream-one&pbk=%s&sid=%s&fp=chrome&sni=%s&spx=%%2F#%s' \
        "$UUID" "$a" "$p" "$(urlenc "$XHTTP_PATH")" "$(urlenc "$REALITY_PUBLIC")" "$REALITY_SHORTID" "$(urlenc "$REALITY_SNI")" "$(urlenc "${NODE_LABEL}-xhttp-reality")" ;;
    vless-encryption)
      printf 'vless://%s@%s:%s?type=tcp&security=none&encryption=%s&flow=xtls-rprx-vision#%s' \
        "$UUID" "$a" "$p" "$(urlenc "$VLESS_ENC_ENC")" "$(urlenc "${NODE_LABEL}-vless-pq")" ;;
    vless-ws)
      printf 'vless://%s@%s:%s?type=ws&security=tls&encryption=none&host=%s&path=%s&sni=%s&fp=chrome&alpn=http%%2F1.1&allowInsecure=%s#%s' \
        "$UUID" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$(urlenc "$WS_PATH_VLESS")" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-vless-ws")" ;;
    vless-xhttp)
      printf 'vless://%s@%s:%s?type=xhttp&security=tls&encryption=none&host=%s&path=%s&mode=auto&sni=%s&fp=chrome&alpn=h2&allowInsecure=%s#%s' \
        "$UUID" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$(urlenc "$XHTTP_PATH")" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-vless-xhttp")" ;;
    vmess-ws)
      local j; j="$(jq -cn --arg add "$a" --arg port "$p" --arg id "$UUID" --arg host "$VPN_DOMAIN" \
                --arg path "$WS_PATH_VMESS" --arg ps "${NODE_LABEL}-vmess" \
                '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$host,alpn:"http/1.1",fp:"chrome"}')"
      printf 'vmess://%s' "$(printf '%s' "$j" | base64 -w0)" ;;
    trojan)
      if behind_gateway "$key"; then
        printf 'trojan://%s@%s:%s?security=tls&type=ws&host=%s&path=%s&sni=%s&fp=chrome&allowInsecure=%s#%s' \
          "$(urlenc "$PASSWORD")" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$(urlenc "$WS_PATH_TROJAN")" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-trojan")"
      else
        printf 'trojan://%s@%s:%s?security=tls&type=tcp&sni=%s&fp=chrome&alpn=h2%%2Chttp%%2F1.1&allowInsecure=%s#%s' \
          "$(urlenc "$PASSWORD")" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-trojan")"
      fi ;;
    hysteria2)
      printf 'hysteria2://%s@%s:%s/?sni=%s&insecure=%s#%s' \
        "$(urlenc "$PASSWORD")" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-hy2")" ;;
    ss2022)
      printf 'ss://%s:%s@%s:%s#%s' \
        "$SS_METHOD" "$(urlenc "$SS_PASSWORD")" "$a" "$p" "$(urlenc "${NODE_LABEL}-ss2022")" ;;
    *) return 1 ;;
  esac
}

# --- mihomo / Clash.Meta YAML ---
clash_of() {
  local key=$1 a p sci
  a="$(addr)"; p="$(client_port "$key")"
  sci="$([[ $CERT_MODE == self ]] && echo true || echo false)"
  case "$key" in
    vless-reality) cat <<EOF
  - name: "${NODE_LABEL}-reality"
    type: vless
    server: ${a}
    port: ${p}
    uuid: ${UUID}
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    packet-encoding: xudp
    servername: ${REALITY_SNI}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${REALITY_PUBLIC}
      short-id: ${REALITY_SHORTID}
EOF
;;
    vless-xhttp-reality) cat <<EOF
  - name: "${NODE_LABEL}-xhttp-reality"
    type: vless
    server: ${a}
    port: ${p}
    uuid: ${UUID}
    network: xhttp
    tls: true
    udp: true
    packet-encoding: xudp
    servername: ${REALITY_SNI}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${REALITY_PUBLIC}
      short-id: ${REALITY_SHORTID}
    xhttp-opts:
      path: "${XHTTP_PATH}"
      mode: "stream-one"
EOF
;;
    vless-ws) cat <<EOF
  - name: "${NODE_LABEL}-vless-ws"
    type: vless
    server: ${a}
    port: ${p}
    uuid: ${UUID}
    network: ws
    tls: true
    udp: true
    packet-encoding: xudp
    servername: ${VPN_DOMAIN}
    client-fingerprint: chrome
    skip-cert-verify: ${sci}
    alpn:
      - http/1.1
    ws-opts:
      path: ${WS_PATH_VLESS}
      headers:
        Host: ${VPN_DOMAIN}
EOF
;;
    vless-xhttp) cat <<EOF
  - name: "${NODE_LABEL}-vless-xhttp"
    type: vless
    server: ${a}
    port: ${p}
    uuid: ${UUID}
    network: xhttp
    tls: true
    udp: true
    packet-encoding: xudp
    servername: ${VPN_DOMAIN}
    client-fingerprint: chrome
    skip-cert-verify: ${sci}
    alpn:
      - h2
    xhttp-opts:
      path: "${XHTTP_PATH}"
      host: ${VPN_DOMAIN}
      mode: "stream-up"
EOF
;;
    vmess-ws) cat <<EOF
  - name: "${NODE_LABEL}-vmess"
    type: vmess
    server: ${a}
    port: ${p}
    uuid: ${UUID}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    servername: ${VPN_DOMAIN}
    client-fingerprint: chrome
    skip-cert-verify: ${sci}
    packet-encoding: xudp
    network: ws
    alpn:
      - http/1.1
    ws-opts:
      path: ${WS_PATH_VMESS}
      headers:
        Host: ${VPN_DOMAIN}
EOF
;;
    trojan)
      if behind_gateway "$key"; then cat <<EOF
  - name: "${NODE_LABEL}-trojan"
    type: trojan
    server: ${a}
    port: ${p}
    password: "${PASSWORD}"
    udp: true
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    client-fingerprint: chrome
    network: ws
    ws-opts:
      path: ${WS_PATH_TROJAN}
      headers:
        Host: ${VPN_DOMAIN}
EOF
      else cat <<EOF
  - name: "${NODE_LABEL}-trojan"
    type: trojan
    server: ${a}
    port: ${p}
    password: "${PASSWORD}"
    udp: true
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    client-fingerprint: chrome
    alpn:
      - h2
      - http/1.1
EOF
      fi ;;
    hysteria2) cat <<EOF
  - name: "${NODE_LABEL}-hy2"
    type: hysteria2
    server: ${a}
    port: ${p}
    password: "${PASSWORD}"
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    alpn:
      - h3
EOF
;;
    ss2022) cat <<EOF
  - name: "${NODE_LABEL}-ss2022"
    type: ss
    server: ${a}
    port: ${p}
    cipher: ${SS_METHOD}
    password: "${SS_PASSWORD}"
    udp: true
EOF
;;
    *) return 1 ;;   # vless-encryption: no mihomo mapping emitted
  esac
}

clash_name_of() { case "$1" in
  vless-reality) echo "${NODE_LABEL}-reality" ;;
  vless-xhttp-reality) echo "${NODE_LABEL}-xhttp-reality" ;;
  vless-ws) echo "${NODE_LABEL}-vless-ws" ;;
  vless-xhttp) echo "${NODE_LABEL}-vless-xhttp" ;;
  vmess-ws) echo "${NODE_LABEL}-vmess" ;;
  trojan) echo "${NODE_LABEL}-trojan" ;;
  hysteria2) echo "${NODE_LABEL}-hy2" ;;
  ss2022) echo "${NODE_LABEL}-ss2022" ;;
  *) return 1 ;;
esac; }

# --- sing-box client outbound (only what upstream sing-box can actually do) ---
# sing-box supports neither XHTTP nor VLESS Encryption, so those keys are skipped.
singbox_ob_of() {
  local key=$1 a p ins
  a="$(addr)"; p="$(client_port "$key")"
  ins="$([[ $CERT_MODE == self ]] && echo true || echo false)"
  case "$key" in
    vless-reality)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg sni "$REALITY_SNI" \
             --arg pk "$REALITY_PUBLIC" --arg sid "$REALITY_SHORTID" '
        {type:"vless",tag:"reality",server:$s,server_port:$p,uuid:$id,flow:"xtls-rprx-vision",
         packet_encoding:"xudp",
         tls:{enabled:true,server_name:$sni,utls:{enabled:true,fingerprint:"chrome"},
              reality:{enabled:true,public_key:$pk,short_id:$sid}}}' ;;
    vless-ws)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg sni "$VPN_DOMAIN" \
             --arg path "$WS_PATH_VLESS" --argjson ins "$ins" '
        {type:"vless",tag:"vless-ws",server:$s,server_port:$p,uuid:$id,packet_encoding:"xudp",
         tls:{enabled:true,server_name:$sni,insecure:$ins,utls:{enabled:true,fingerprint:"chrome"}},
         transport:{type:"ws",path:$path,headers:{Host:$sni}}}' ;;
    vmess-ws)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg sni "$VPN_DOMAIN" \
             --arg path "$WS_PATH_VMESS" --argjson ins "$ins" '
        {type:"vmess",tag:"vmess-ws",server:$s,server_port:$p,uuid:$id,security:"auto",
         tls:{enabled:true,server_name:$sni,insecure:$ins},
         transport:{type:"ws",path:$path,headers:{Host:$sni}}}' ;;
    trojan)
      if behind_gateway "$key"; then
        jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --arg sni "$VPN_DOMAIN" \
               --arg path "$WS_PATH_TROJAN" --argjson ins "$ins" '
          {type:"trojan",tag:"trojan",server:$s,server_port:$p,password:$pw,
           tls:{enabled:true,server_name:$sni,insecure:$ins},
           transport:{type:"ws",path:$path,headers:{Host:$sni}}}'
      else
        jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
          {type:"trojan",tag:"trojan",server:$s,server_port:$p,password:$pw,
           tls:{enabled:true,server_name:$sni,insecure:$ins}}'
      fi ;;
    hysteria2)
      jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" \
             --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
        {type:"hysteria2",tag:"hy2",server:$s,server_port:$p,password:$pw,
         tls:{enabled:true,server_name:$sni,insecure:$ins,alpn:["h3"]}}' ;;
    ss2022)
      jq -cn --arg s "$a" --argjson p "$p" --arg m "$SS_METHOD" --arg pw "$SS_PASSWORD" '
        {type:"shadowsocks",tag:"ss2022",server:$s,server_port:$p,method:$m,password:$pw}' ;;
    *) return 1 ;;
  esac
}
singbox_tag_of() { case "$1" in
  vless-reality) echo reality ;; vless-ws) echo vless-ws ;; vmess-ws) echo vmess-ws ;;
  trojan) echo trojan ;; hysteria2) echo hy2 ;; ss2022) echo ss2022 ;; *) return 1 ;;
esac; }

write_client_singbox() {
  local frags=() tags=() key ob tag
  for key in $SELECTED; do
    ob="$(singbox_ob_of "$key" 2>/dev/null || true)"; [[ -n $ob ]] || continue
    tag="$(singbox_tag_of "$key" 2>/dev/null || true)"
    [[ -n $tag ]] || continue          # keep outbound and tag lists in lockstep
    frags+=("$ob"); tags+=("$tag")
  done
  if (( ${#frags[@]} == 0 )); then
    warn "No selected protocol is supported by upstream sing-box; skipping its config."
    return 0
  fi
  local outbounds tags_json
  outbounds="$(printf '%s\n' "${frags[@]}" | jq -s '.')"
  tags_json="$(printf '%s\n' "${tags[@]}" | jq -R . | jq -s '.')"
  jq -n --argjson proxies "$outbounds" --argjson tags "$tags_json" '
    {log:{level:"warn",timestamp:true},
     dns:{servers:[{type:"https",tag:"dns-remote",server:"1.1.1.1",detour:"proxy"},
                   {type:"local",tag:"dns-local"}],
          final:"dns-remote",strategy:"prefer_ipv4"},
     inbounds:[{type:"tun",tag:"tun-in",address:["172.19.0.1/30","fdfe:dcba:9876::1/126"],
                mtu:9000,auto_route:true,strict_route:true,stack:"mixed"},
               {type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}],
     outbounds:( [ {type:"selector",tag:"proxy",outbounds:(["auto"]+$tags+["direct"]),default:"auto"},
                   {type:"urltest",tag:"auto",outbounds:$tags,url:"https://www.gstatic.com/generate_204",interval:"3m",tolerance:50} ]
                 + $proxies
                 + [ {type:"direct",tag:"direct"} ] ),
     route:{rules:[{action:"sniff"},{protocol:"dns",action:"hijack-dns"},{ip_is_private:true,outbound:"direct"}],
            final:"proxy",auto_detect_interface:true,default_domain_resolver:{server:"dns-local"}}}' \
    >"${CLIENT_OUT_DIR}/client-singbox.json"
  return 0
}

# --- Xray client config (understands every protocol this script deploys) ---
xray_ob_of() {
  local key=$1 a p
  a="$(addr)"; p="$(client_port "$key")"
  local tlsobj
  if [[ $CERT_MODE == self && -n $CERT_PIN ]]; then
    # allowInsecure is a hard error in current Xray; pin the certificate instead.
    tlsobj="$(jq -cn --arg sni "$VPN_DOMAIN" --arg pin "$CERT_PIN" \
      '{serverName:$sni,fingerprint:"chrome",pinnedPeerCertSha256:$pin}')"
  else
    tlsobj="$(jq -cn --arg sni "$VPN_DOMAIN" '{serverName:$sni,fingerprint:"chrome"}')"
  fi
  case "$key" in
    vless-reality)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg sni "$REALITY_SNI" \
             --arg pk "$REALITY_PUBLIC" --arg sid "$REALITY_SHORTID" '
        {tag:"reality",protocol:"vless",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,encryption:"none",flow:"xtls-rprx-vision"}]}]},
         streamSettings:{network:"tcp",security:"reality",
                         realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pk,shortId:$sid,spiderX:"/"}}}' ;;
    vless-xhttp-reality)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg sni "$REALITY_SNI" \
             --arg pk "$REALITY_PUBLIC" --arg sid "$REALITY_SHORTID" --arg path "$XHTTP_PATH" '
        {tag:"xhttp-reality",protocol:"vless",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,encryption:"none"}]}]},
         streamSettings:{network:"xhttp",security:"reality",
                         realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$pk,shortId:$sid,spiderX:"/"},
                         xhttpSettings:{path:$path,mode:"stream-one"}}}' ;;
    vless-encryption)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg enc "$VLESS_ENC_ENC" '
        {tag:"vless-pq",protocol:"vless",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,encryption:$enc,flow:"xtls-rprx-vision"}]}]},
         streamSettings:{network:"tcp",security:"none"}}' ;;
    vless-ws)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg path "$WS_PATH_VLESS" \
             --arg host "$VPN_DOMAIN" --argjson tls "$tlsobj" '
        {tag:"vless-ws",protocol:"vless",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,encryption:"none"}]}]},
         streamSettings:{network:"ws",security:"tls",tlsSettings:($tls+{alpn:["http/1.1"]}),
                         wsSettings:{path:$path,headers:{Host:$host}}}}' ;;
    vless-xhttp)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg path "$XHTTP_PATH" \
             --arg host "$VPN_DOMAIN" --argjson tls "$tlsobj" '
        {tag:"vless-xhttp",protocol:"vless",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,encryption:"none"}]}]},
         streamSettings:{network:"xhttp",security:"tls",tlsSettings:($tls+{alpn:["h2"]}),
                         xhttpSettings:{path:$path,host:$host,mode:"auto"}}}' ;;
    vmess-ws)
      jq -cn --arg s "$a" --argjson p "$p" --arg id "$UUID" --arg path "$WS_PATH_VMESS" \
             --arg host "$VPN_DOMAIN" --argjson tls "$tlsobj" '
        {tag:"vmess-ws",protocol:"vmess",
         settings:{vnext:[{address:$s,port:$p,users:[{id:$id,security:"auto"}]}]},
         streamSettings:{network:"ws",security:"tls",tlsSettings:($tls+{alpn:["http/1.1"]}),
                         wsSettings:{path:$path,headers:{Host:$host}}}}' ;;
    trojan)
      if behind_gateway "$key"; then
        jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --arg path "$WS_PATH_TROJAN" \
               --arg host "$VPN_DOMAIN" --argjson tls "$tlsobj" '
          {tag:"trojan",protocol:"trojan",
           settings:{servers:[{address:$s,port:$p,password:$pw}]},
           streamSettings:{network:"ws",security:"tls",tlsSettings:$tls,
                           wsSettings:{path:$path,headers:{Host:$host}}}}'
      else
        jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --argjson tls "$tlsobj" '
          {tag:"trojan",protocol:"trojan",
           settings:{servers:[{address:$s,port:$p,password:$pw}]},
           streamSettings:{network:"tcp",security:"tls",tlsSettings:$tls}}'
      fi ;;
    hysteria2)
      # The hysteria OUTBOUND takes address/port directly in settings (there is
      # no servers[]/vnext) and carries the credential as hysteriaSettings.auth.
      jq -cn --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --argjson tls "$tlsobj" '
        {tag:"hy2",protocol:"hysteria",
         settings:{version:2,address:$s,port:$p},
         streamSettings:{network:"hysteria",security:"tls",tlsSettings:($tls+{alpn:["h3"]}),
                         hysteriaSettings:{version:2,auth:$pw}}}' ;;
    ss2022)
      jq -cn --arg s "$a" --argjson p "$p" --arg m "$SS_METHOD" --arg pw "$SS_PASSWORD" '
        {tag:"ss2022",protocol:"shadowsocks",
         settings:{servers:[{address:$s,port:$p,method:$m,password:$pw}]}}' ;;
    *) return 1 ;;
  esac
}

write_client_xray() {
  local frags=() key ob
  for key in $SELECTED; do
    ob="$(xray_ob_of "$key" 2>/dev/null || true)"; [[ -n $ob ]] && frags+=("$ob")
  done
  (( ${#frags[@]} > 0 )) || return 0
  local outbounds; outbounds="$(printf '%s\n' "${frags[@]}" | jq -s '.')"
  # The first outbound is the default route; the rest are ready to select.
  jq -n --argjson obs "$outbounds" '
    {log:{loglevel:"warning"},
     inbounds:[{tag:"socks",port:10808,listen:"127.0.0.1",protocol:"socks",
                settings:{udp:true},sniffing:{enabled:true,destOverride:["http","tls"]}},
               {tag:"http",port:10809,listen:"127.0.0.1",protocol:"http"}],
     outbounds:( $obs + [{tag:"direct",protocol:"freedom"},{tag:"blocked",protocol:"blackhole"}] )}' \
    >"${CLIENT_OUT_DIR}/client-xray.json"
  return 0
}

write_client_clash() {
  local key names=() f="${CLIENT_OUT_DIR}/client-clash.yaml" n
  {
    echo "# mihomo / Clash.Meta config generated by Xray_Deployment.sh"
    echo "mixed-port: 7890"
    echo "allow-lan: false"
    echo "mode: rule"
    echo "log-level: info"
    echo "unified-delay: true"
    echo "tcp-concurrent: true"
    echo "external-controller: 127.0.0.1:9090"
    echo "dns:"
    echo "  enable: true"
    echo "  enhanced-mode: fake-ip"
    echo "  fake-ip-range: 198.18.0.1/16"
    echo "  nameserver:"
    echo "    - https://1.1.1.1/dns-query"
    echo "    - https://8.8.8.8/dns-query"
    echo "proxies:"
  } >"$f"
  for key in $SELECTED; do
    if clash_of "$key" >>"$f" 2>/dev/null; then
      n="$(clash_name_of "$key" 2>/dev/null || true)"; [[ -n $n ]] && names+=("$n")
    fi
  done
  {
    echo "proxy-groups:"
    echo "  - name: PROXY"
    echo "    type: select"
    echo "    proxies:"
    echo "      - AUTO"
    for n in "${names[@]}"; do echo "      - \"$n\""; done
    echo "      - DIRECT"
    echo "  - name: AUTO"
    echo "    type: url-test"
    echo "    url: https://www.gstatic.com/generate_204"
    echo "    interval: 300"
    echo "    tolerance: 50"
    echo "    proxies:"
    for n in "${names[@]}"; do echo "      - \"$n\""; done
    echo "rules:"
    echo "  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve"
    echo "  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"
    echo "  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve"
    echo "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve"
    echo "  - MATCH,PROXY"
  } >>"$f"
  return 0
}

write_readme() {
  local f="${CLIENT_OUT_DIR}/README.txt" key
  {
    echo "Xray node: ${NODE_LABEL}  (${VPN_DOMAIN} / ${VPN_IP})"
    echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "xray: ${XRAY_VERSION:-unknown}  channel=${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}}  cert=${CERT_MODE}  ports=${PORT_MODE}"
    echo
    echo "Files:"
    echo "  links.txt           one share link per line"
    echo "  subscription.txt    base64 subscription (v2rayN, NekoBox, Streisand, Shadowrocket)"
    echo "  client-xray.json    Xray client config — understands EVERY protocol here"
    echo "  client-singbox.json sing-box client config (subset — see limitations below)"
    echo "  client-clash.yaml   mihomo / Clash.Meta config"
    echo
    echo "Ports:"
    [[ $PORT_MODE == fallback ]] && echo "  gateway (shared TLS)  tcp/${PORT[gateway]}"
    for key in $SELECTED; do
      if behind_gateway "$key"; then
        printf '  %-20s via gateway tcp/%s  (loopback %s)\n' "$key" "$(client_port "$key")" "${PORT[$key]}"
      else
        printf '  %-20s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"
      fi
    done
    echo
    echo "Client limitations (upstream implementations, verified Aug 2026):"
    echo "  * sing-box cannot do XHTTP or VLESS Encryption -> those nodes are omitted"
    echo "    from client-singbox.json. Use client-xray.json for them."
    echo "  * mihomo supports XHTTP for VLESS only; it has no VLESS-Encryption node here."
    echo "  * VLESS Encryption needs an Xray-core client v25.9.5+ (v2rayN 7.14.9+)."
    if [[ $CERT_MODE == self ]]; then
      echo "  * Self-signed certificate: 'allowInsecure' is a HARD ERROR in current Xray,"
      echo "    so client-xray.json pins the certificate instead:"
      echo "      pinnedPeerCertSha256 = ${CERT_PIN}"
      echo "    Share links carry allowInsecure=1, which the GUI clients honour."
    fi
    echo
    echo "Credentials:"
    echo "  UUID     : ${UUID}"
    echo "  password : ${PASSWORD}"
    selected_has ss2022 && echo "  ss key   : ${SS_PASSWORD} (${SS_METHOD})"
    if selected_has vless-reality || selected_has vless-xhttp-reality; then
      echo "  reality public key : ${REALITY_PUBLIC}"
      echo "  reality short id   : ${REALITY_SHORTID}"
      echo "  reality SNI        : ${REALITY_SNI}"
    fi
    if selected_has vless-encryption; then
      echo "  vless encryption (client): ${VLESS_ENC_ENC}"
    fi
    echo
    echo "Paths: vless-ws=${WS_PATH_VLESS}  vmess-ws=${WS_PATH_VMESS}  trojan-ws=${WS_PATH_TROJAN}  xhttp=${XHTTP_PATH}"
  } >"$f"
  chmod 0600 "$f"
  return 0
}

gen_artifacts() {
  head1 "Generating client bundles"
  install -d -m 0700 "$CLIENT_OUT_DIR"
  local key links=() l
  for key in $SELECTED; do
    l="$(link_of "$key" 2>/dev/null || true)"; [[ -n $l ]] && links+=("$l")
  done
  printf '%s\n' "${links[@]}" >"${CLIENT_OUT_DIR}/links.txt"
  printf '%s\n' "${links[@]}" | base64 -w0 >"${CLIENT_OUT_DIR}/subscription.txt"
  write_client_xray
  write_client_singbox
  write_client_clash
  write_readme
  chmod 0600 "${CLIENT_OUT_DIR}"/*.txt "${CLIENT_OUT_DIR}"/*.json "${CLIENT_OUT_DIR}"/*.yaml 2>/dev/null || true
  ok "Bundles written to ${CLIENT_OUT_DIR}"
  setup_sub_server
  return 0
}

setup_sub_server() {
  [[ $SUB_HOST == yes ]] || return 0
  [[ -n $SUB_TOKEN ]] || SUB_TOKEN="$(gen_hex 12)"
  local root="/var/lib/xray-sub"
  install -d -m 0755 "$root"
  # The unit runs under DynamicUser=yes (a transient UID) which cannot
  # traverse /root (0700) nor read the 0600 bundles, so every request would
  # 404. Serve a world-readable staging copy instead; the secret token in the
  # URL remains the access control.
  install -d -m 0755 "${root}/pub"
  install -m 0644 "${CLIENT_OUT_DIR}/links.txt" "${CLIENT_OUT_DIR}/subscription.txt" "${root}/pub/" 2>/dev/null || true
  install -m 0644 "${CLIENT_OUT_DIR}/client-clash.yaml" "${root}/pub/" 2>/dev/null || true
  install -m 0644 "${CLIENT_OUT_DIR}"/client-*.json "${root}/pub/" 2>/dev/null || true
  local cgi="${root}/serve.py"
  cat >"$cgi" <<PYEOF
#!/usr/bin/env python3
import http.server, socketserver, os
TOKEN=os.environ.get("SUB_TOKEN","${SUB_TOKEN}")
DIR="${root}/pub"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if TOKEN not in self.path:
            self.send_error(404); return
        ua=self.headers.get("User-Agent","").lower()
        if "clash" in ua or "mihomo" in ua or "meta" in ua: fn,ct="client-clash.yaml","text/yaml; charset=utf-8"
        elif "sing-box" in ua or "sfa" in ua or "sfi" in ua:  fn,ct="client-singbox.json","application/json"
        elif "xray" in ua or "v2ray" in ua and "n" not in ua: fn,ct="client-xray.json","application/json"
        else: fn,ct="subscription.txt","text/plain; charset=utf-8"
        try: data=open(os.path.join(DIR,fn),"rb").read()
        except OSError: self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Profile-Update-Interval","24"); self.end_headers(); self.wfile.write(data)
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
with socketserver.TCPServer(("0.0.0.0",${SUB_PORT}),H) as s: s.serve_forever()
PYEOF
  cat >/etc/systemd/system/xray-sub.service <<EOF
[Unit]
Description=Xray subscription server
After=network-online.target

[Service]
Environment=SUB_TOKEN=${SUB_TOKEN}
ExecStart=/usr/bin/python3 ${cgi}
Restart=on-failure
DynamicUser=yes
ReadOnlyPaths=/var/lib/xray-sub/pub

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now xray-sub.service >/dev/null 2>&1 || warn "Could not start xray-sub.service."
  ok "Subscription served at:  http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
  return 0
}

# -----------------------------------------------------------------------------
# 15. Verify / status / summary
# -----------------------------------------------------------------------------
verify_all() {
  head1 "Health checks"; local rc=0
  have xray && ok "xray: ${XRAY_VERSION:-$(xray version 2>/dev/null | head -1 | awk '{print $2}')}" || { bad "xray binary missing"; rc=1; }
  if [[ -r $XRAY_CONF ]]; then
    xray run -test -c "$XRAY_CONF" >/dev/null 2>&1 && ok "config.json valid" || { bad "config.json fails \`xray run -test\`"; rc=1; }
  fi
  systemctl is-active --quiet xray && ok "xray.service active" || { bad "xray.service not active"; rc=1; }

  local key p l4
  if [[ $PORT_MODE == fallback ]]; then
    p="${PORT[gateway]}"
    port_listening tcp "$p" && ok "listening tcp/${p} (shared gateway)" || { bad "nothing on tcp/${p} (gateway)"; rc=1; }
  fi
  for key in $SELECTED; do
    p="${PORT[$key]:-}"; l4="$(proto_l4 "$key")"
    [[ -n $p ]] || { bad "no saved port for ${key} — re-run a deploy"; rc=1; continue; }
    if behind_gateway "$key"; then
      port_listening tcp "$p" && ok "loopback tcp/${p} (${key})" || { bad "nothing on loopback tcp/${p} (${key})"; rc=1; }
      continue
    fi
    case "$l4" in
      tcp)  port_listening tcp "$p" && ok "listening tcp/${p} (${key})" || { bad "nothing on tcp/${p} (${key})"; rc=1; } ;;
      udp)  port_listening udp "$p" && ok "listening udp/${p} (${key})" || { bad "nothing on udp/${p} (${key})"; rc=1; } ;;
      both) { port_listening tcp "$p" || port_listening udp "$p"; } && ok "listening ${p} (${key})" || { bad "nothing on ${p} (${key})"; rc=1; } ;;
    esac
  done
  return $rc
}

do_status() {
  head1 "Service"
  systemctl --no-pager status xray 2>/dev/null | head -8 || true
  head1 "Listening ports"
  ss -tulpnH 2>/dev/null | grep -E 'xray' || warn "No xray listeners found."
  return 0
}

summary() {
  echo
  printf '%s' "$C_G"
  cat <<'BANNER'
  +==========================================================+
  |             X R A Y   N O D E   I S   R E A D Y          |
  +==========================================================+
BANNER
  printf '%s' "$C_RST"; echo; hr
  printf '  %-22s %s\n' "Server"   "${VPN_DOMAIN} (${VPN_IP})"
  printf '  %-22s %s\n' "Xray"     "${XRAY_VERSION:-unknown} (${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}})"
  printf '  %-22s %s\n' "Port mode" "$PORT_MODE"
  needs_any_cert && printf '  %-22s %s\n' "TLS certificate" "$CERT_MODE"
  hr
  printf '  %sProtocols & ports%s\n' "$C_BOLD" "$C_RST"
  [[ $PORT_MODE == fallback ]] && printf '    %-22s %s\n' "gateway (shared TLS)" "tcp/${PORT[gateway]}"
  local key
  for key in $SELECTED; do
    if behind_gateway "$key"; then printf '    %-22s %s\n' "$key" "via gateway tcp/$(client_port "$key")"
    else printf '    %-22s %s\n' "$key" "$(proto_l4 "$key")/${PORT[$key]}"; fi
  done
  hr
  printf '  %sClient bundles%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "${CLIENT_OUT_DIR}/links.txt"
  printf '    %s\n' "${CLIENT_OUT_DIR}/subscription.txt"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-xray.json"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-singbox.json"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-clash.yaml"
  [[ $SUB_HOST == yes ]] && printf '    %s\n' "sub URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
  hr
  printf '  %sManage%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "xrayctl info        # reprint links / credentials"
  printf '    %s\n' "xrayctl status      # service + listening ports"
  printf '    %s\n' "xrayctl check       # health checks"
  printf '    %s\n' "xrayctl update      # upgrade Xray"
  printf '    %s\n' "journalctl -u xray -f"
  hr
  printf '    %sscp -r root@%s:%s .%s\n' "$C_D" "${VPN_IP:-$VPN_DOMAIN}" "$CLIENT_OUT_DIR" "$C_RST"
  hr
  (( WARN_COUNT > 0 )) && { printf '  %s%d warning(s) above — scroll up.%s\n' "$C_Y" "$WARN_COUNT" "$C_RST"; hr; }
  echo
  return 0
}

do_info() {
  [[ -r ${CLIENT_OUT_DIR}/links.txt ]] || die "No bundles found — run a deploy first."
  head1 "Share links"; cat "${CLIENT_OUT_DIR}/links.txt"
  echo; head1 "Base64 subscription"; cat "${CLIENT_OUT_DIR}/subscription.txt"; echo
  [[ $SUB_HOST == yes ]] && { echo; ok "Subscription URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"; }
  [[ -r ${CLIENT_OUT_DIR}/README.txt ]] && { echo; head1 "Full details"; cat "${CLIENT_OUT_DIR}/README.txt"; }
  return 0
}

do_update() {
  head1 "Updating Xray (${INSTALL_CHANNEL})"
  install_xray
  if [[ -r $XRAY_CONF ]] && xray run -test -c "$XRAY_CONF" >/dev/null 2>&1; then
    systemctl restart xray || true; sleep 2
    systemctl is-active --quiet xray && ok "Xray updated and restarted." || bad "Xray did not come back up."
  else
    warn "Existing config missing or invalid for the new version; not restarting."
  fi
  save_state
  return 0
}

do_uninstall() {
  local go; ask_yn go "Remove Xray configuration, certificates and firewall rules" "no"
  [[ $go == yes ]] || die "Aborted."
  systemctl disable --now xray >/dev/null 2>&1 || true
  systemctl disable --now xray-sub >/dev/null 2>&1 || true
  rm -f "$XRAY_CONF"
  rm -rf "$XRAY_CERT_DIR"
  rm -rf /etc/systemd/system/xray.service.d
  rm -f /etc/systemd/system/xray-sub.service
  rm -f /etc/sysctl.d/99-xray.conf /etc/modules-load.d/xray-bbr.conf
  iptables -D INPUT -j XRAY_IN 2>/dev/null || true
  iptables -F XRAY_IN 2>/dev/null || true; iptables -X XRAY_IN 2>/dev/null || true
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true
  ok "Removed. Kept: the xray binary, ${STATE_DIR} and ${CLIENT_OUT_DIR}."
  ok "Run 'bash <(curl -fsSL ${INSTALLER_URL}) remove --purge' to delete Xray itself."
  return 0
}

install_self() {
  local target="/usr/local/sbin/xrayctl"
  local src; src="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
  # Piping the script in (`bash <(curl ...)`, `curl ... | bash`) leaves
  # BASH_SOURCE pointing at a /dev/fd entry or a name that no longer exists, and
  # `install` then fails with "cannot stat". That must not look like a deploy
  # error — everything else has already succeeded by this point.
  if [[ -z $src || ! -f $src ]]; then
    warn "This script is not on disk as a regular file (piped in?), so ${target} was not installed."
    warn "Save it to the server and re-run to get the xrayctl helper, or call the file directly."
    return 0
  fi
  [[ $src == "$target" ]] && return 0
  if install -m 0700 "$src" "$target" 2>/dev/null; then
    ok "Installed as ${target}"
  else
    warn "Could not install ${target}; use the script directly instead."
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 16. Main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  need_root
  install -d -m 0700 "$STATE_DIR"

  case "$CMD" in
    info)      load_state; do_info; exit 0 ;;
    status)    load_state; do_status; exit 0 ;;
    check)     load_state; _rc=0; verify_all || _rc=$?; exit "$_rc" ;;
    update)    load_state; do_update; exit 0 ;;
    regen-sub) load_state; [[ -n $SELECTED ]] || die "No saved state — run a deploy first."; gen_artifacts; save_state; do_info; exit 0 ;;
    uninstall) load_state; do_uninstall; exit 0 ;;
    deploy)    : ;;
  esac

  printf '\n%s Xray-core multi-protocol deployment for Ubuntu 22/24/26 — v%s %s\n' "$C_BOLD" "$SCRIPT_VERSION" "$C_RST"
  printf '%s pick all protocols or a subset; every secret and subscription is generated %s\n\n' "$C_D" "$C_RST"

  load_state
  resolve_selection
  collect_config

  start_logging
  [[ $SKIP_PREFLIGHT == yes ]] || preflight

  install_deps
  install_xray
  gen_credentials
  # gen_credentials can only ever DROP a protocol (e.g. vlessenc unavailable).
  # Prune just that entry — re-running assign_ports here would reset PORT and
  # silently discard any ports the operator hand-picked in review_ports.
  for _k in "${!PORT[@]}"; do
    [[ $_k == gateway ]] && continue
    selected_has "$_k" || unset "PORT[$_k]"
  done
  unset _k
  setup_cert
  write_xray_config
  kernel_tuning
  firewall_setup
  start_services
  gen_artifacts

  save_state
  install_self
  verify_all || warn "Some health checks failed — review the output above."
  summary
}

main "$@"
