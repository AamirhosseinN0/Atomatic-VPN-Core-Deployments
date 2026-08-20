#!/usr/bin/env bash
# =============================================================================
#  Singbox_Deployment.sh — sing-box multi-protocol proxy for Ubuntu 22 / 24 / 26
#
#  Turns a fresh Ubuntu server into a sing-box proxy node speaking as many
#  protocols as you want. You pick "all" or a subset; the script finds free
#  ports from a curated list per protocol, generates every secret (UUIDs,
#  passwords, Reality keypair, Shadowsocks-2022 keys, obfs passwords, PSK),
#  writes a schema-correct config for the CURRENT sing-box (1.13.x stable, or
#  1.14 beta with --beta), tunes the kernel for TCP + QUIC, opens the firewall,
#  and emits ready-to-import client bundles:
#     * share links + base64 subscription (v2rayN / NekoBox / Shadowrocket ...)
#     * a sing-box client config.json
#     * a mihomo / Clash.Meta YAML
#
#  Protocols (server side):
#     vless-reality  vless-ws  vmess-ws  trojan  hysteria2  tuic
#     shadowtls(+ss2022)  ss2022  anytls  naive          (native sing-box)
#     snell  (v5 stable / v6 rc, via the standalone snell-server binary)
#
#  Subcommands:
#     ./Singbox_Deployment.sh                deploy (interactive, sane defaults)
#     ./Singbox_Deployment.sh info           reprint links / subscription / creds
#     ./Singbox_Deployment.sh status         service + listening-port status
#     ./Singbox_Deployment.sh check          re-run every health check
#     ./Singbox_Deployment.sh update         upgrade sing-box to the latest build
#     ./Singbox_Deployment.sh regen-sub      rebuild client bundles from state
#     ./Singbox_Deployment.sh uninstall      remove config (keeps the binary)
#
#  After deployment this file installs itself as /usr/local/sbin/singboxctl.
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# 0. Constants / cosmetics
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly STATE_DIR="/etc/singbox-deploy"
readonly STATE_FILE="${STATE_DIR}/singbox.env"
readonly SB_CONF_DIR="/etc/sing-box"
readonly SB_CONF="${SB_CONF_DIR}/config.json"
readonly SB_CERT_DIR="${SB_CONF_DIR}/cert"
readonly SB_CERT_FULL="${SB_CERT_DIR}/fullchain.pem"
readonly SB_CERT_KEY="${SB_CERT_DIR}/privkey.pem"
readonly SB_RENEW_HOOK="${SB_CERT_DIR}/deploy-hook.sh"
readonly SNELL_BIN="/usr/local/bin/snell-server"
readonly SNELL_CONF_DIR="/etc/snell"
readonly SNELL_CONF="${SNELL_CONF_DIR}/snell-server.conf"
readonly CLIENT_OUT_DIR="/root/singbox-clients"
readonly LOGFILE="/var/log/singbox-deploy.log"

# Latest known good versions (verified 2026-08-18). Stable is discovered live
# from GitHub at install time; these are only the fallbacks / snell pins.
readonly SNELL_V5_DEFAULT="v5.0.1"
readonly SNELL_V6_DEFAULT="v6.0.0rc2"

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
  printf '\n%s[FATAL]%s Singbox_Deployment.sh failed at line %s (exit %s).\n' "$C_R" "$C_RST" "$line" "$rc" >&2
  printf '        Log: %s\n' "$LOGFILE" >&2
  exit "$rc"
}
trap 'on_err $LINENO' ERR

# -----------------------------------------------------------------------------
# 1. Defaults (overridable via prompt or CLI flag)
# -----------------------------------------------------------------------------
# No default for domain/IP on purpose: they identify YOUR server.
VPN_DOMAIN=""
VPN_IP=""
NODE_LABEL=""                 # display prefix for generated nodes; default = domain label

INSTALL_CHANNEL="stable"      # stable | beta
CERT_MODE="letsencrypt"       # letsencrypt | self  (only used when a TLS-cert protocol is selected)
LE_EMAIL=""

# Protocol selection. PROTO_CHOICE is what the user typed ("all" or a list);
# SELECTED is the resolved, space-separated list of canonical keys.
PROTO_CHOICE="all"
SELECTED=""

# Reality / ShadowTLS steal-target (a real external TLS1.3+H2 site).
REALITY_SNI="www.microsoft.com"
SHADOWTLS_SNI="www.microsoft.com"

# Shadowsocks-2022 cipher (16-byte key). aes-128-gcm is the broadest.
SS_METHOD="2022-blake3-aes-128-gcm"

DNS_UPSTREAM="local"          # server-side resolver: 'local' = system resolv.conf

SNELL_VERSION="${SNELL_V5_DEFAULT}"   # v5.0.1 (stable) | v6.0.0rc2 (beta)
SNELL_OBFS="off"              # off | http     (v5 only; v6 has no obfs)

AUTO_PORTS="yes"              # auto-assign the first free curated port per protocol
KERNEL_TUNING="yes"
FIREWALL="auto"               # auto | ufw | iptables | none

SUB_HOST="no"                 # optionally serve the subscription over plain HTTP
SUB_PORT="8080"
SUB_TOKEN=""

ASSUME_YES="no"
SKIP_PREFLIGHT="no"
NIC=""

# Per-protocol ports (filled in by assign_ports / state).
declare -A PORT

# Generated secrets (filled in by gen_credentials / state).
UUID=""
PASSWORD=""
SS_PASSWORD=""
REALITY_PRIVATE=""; REALITY_PUBLIC=""; REALITY_SHORTID=""
HY2_OBFS_PASSWORD=""
SHADOWTLS_PASSWORD=""
SHADOWTLS_SS_METHOD="2022-blake3-aes-128-gcm"
SHADOWTLS_SS_PASSWORD=""
WS_PATH=""
SNELL_PSK=""

SB_USER="sing-box"            # user the sing-box unit runs as (detected later)

CMD="deploy"

# Canonical protocol catalogue -------------------------------------------------
# key | L4 (tcp|udp|both) | needs-cert | curated candidate ports | description
readonly ALL_KEYS=(vless-reality vless-ws vmess-ws trojan hysteria2 tuic shadowtls ss2022 anytls naive snell)

proto_l4() { case "$1" in
  vless-reality|vless-ws|vmess-ws|trojan|shadowtls|anytls|naive|snell) echo tcp ;;
  hysteria2|tuic) echo udp ;;
  ss2022) echo both ;;
esac; }

proto_needs_cert() { case "$1" in
  vless-ws|vmess-ws|trojan|hysteria2|tuic|anytls|naive) echo yes ;;
  *) echo no ;;
esac; }

proto_ports() { case "$1" in
  vless-reality) echo "443 8443 2087 2053" ;;
  vless-ws)      echo "8443 2083 2053 2096" ;;
  vmess-ws)      echo "2087 2096 8080 2082" ;;
  trojan)        echo "443 8443 2083" ;;
  hysteria2)     echo "443 8443 2053" ;;
  tuic)          echo "2083 8443 443" ;;
  shadowtls)     echo "443 8443 9443" ;;
  ss2022)        echo "8388 9388 8389" ;;
  anytls)        echo "2087 8443 2096" ;;
  naive)         echo "2096 8443 2087" ;;
  snell)         echo "6160 9102 6180" ;;
esac; }

proto_desc() { case "$1" in
  vless-reality) echo "VLESS + Reality (TCP, xtls-rprx-vision) — no cert, strongest against DPI" ;;
  vless-ws)      echo "VLESS + WebSocket + TLS — CDN/nginx friendly" ;;
  vmess-ws)      echo "VMess + WebSocket + TLS — legacy client compatibility" ;;
  trojan)        echo "Trojan + TLS (TCP)" ;;
  hysteria2)     echo "Hysteria2 (QUIC/UDP) — fast on lossy / high-latency links" ;;
  tuic)          echo "TUIC v5 (QUIC/UDP)" ;;
  shadowtls)     echo "ShadowTLS v3 wrapping Shadowsocks-2022 — mimics a real TLS site" ;;
  ss2022)        echo "Shadowsocks 2022 (TCP+UDP)" ;;
  anytls)        echo "AnyTLS (TCP) — TLS-in-TLS fingerprint resistant" ;;
  naive)         echo "NaiveProxy (HTTP/2 + TLS)" ;;
  snell)         echo "Snell v5/v6 (standalone snell-server) — Surge / Clash.Meta" ;;
esac; }

# -----------------------------------------------------------------------------
# 2. Small helpers
# -----------------------------------------------------------------------------
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "This script must run as root (use: sudo bash $0)"; }
have() { command -v "$1" >/dev/null 2>&1; }

INTERACTIVE="yes"
[[ -r /dev/tty ]] || INTERACTIVE="no"

ask() { # ask VARNAME "Question" "default" ["hint when no default"]
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

ask_valid() { # ... "default" validator "error" ["hint when no default"]
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

ask_yn() { # ask_yn VARNAME "Question" "yes|no"
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

ask_choice() { # ask_choice VARNAME "Question" "default" opt1 opt2 ...
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
gen_pass() { # 24 URL-safe chars, no shell/URI-special characters
  local out
  out="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  [[ ${#out} -ge 24 ]] || out="$(LC_ALL=C head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  printf '%s' "${out:0:24}"
}

gen_uuid() {
  local u=""
  if have sing-box; then u="$(sing-box generate uuid 2>/dev/null | tr -d '[:space:]')"; fi
  [[ $u =~ ^[0-9a-fA-F-]{36}$ ]] || { [[ -r /proc/sys/kernel/random/uuid ]] && u="$(cat /proc/sys/kernel/random/uuid)"; }
  [[ $u =~ ^[0-9a-fA-F-]{36}$ ]] || { have uuidgen && u="$(uuidgen)"; }
  if [[ ! $u =~ ^[0-9a-fA-F-]{36}$ ]]; then
    local h; h="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'a-f0-9')"; h="${h:0:32}"
    u="${h:0:8}-${h:8:4}-4${h:13:3}-a${h:17:3}-${h:20:12}"
  fi
  printf '%s' "$u"
}

gen_b64key() { openssl rand -base64 "${1:-16}" | tr -d '\n'; }   # ss-2022 / shadowtls key
gen_hex()    { openssl rand -hex "${1:-8}"    | tr -d '\n'; }     # reality short_id

# percent-encode for share-link userinfo / query values (RFC 3986 unreserved kept)
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
  # 10#$o forces base-10: an octet like 08/09 would otherwise be read as octal
  # and raise an arithmetic error, wrongly rejecting the address.
  local o; for o in ${1//./ }; do (( 10#$o >= 0 && 10#$o <= 255 )) || return 1; done
  return 0
}
valid_domain()  { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; }
valid_label()   { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ ]]; }
valid_port_num(){ [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_email()   { [[ -z $1 || $1 =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }

# Is <port> bound? Match the LOCAL address column (4), not the peer (5) — matching
# the peer makes every port look free.
port_listening() { # port_listening <udp|tcp> <port>
  local flag="-lun"; [[ $1 == tcp ]] && flag="-ltn"
  ss $flag 2>/dev/null | awk -v p=":$2\$" '$4 ~ p {f=1} END{exit !f}'
}

save_state() {
  install -d -m 0700 "$STATE_DIR"
  {
    printf '# generated by Singbox_Deployment.sh v%s on %s\n' "$SCRIPT_VERSION" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    for v in VPN_DOMAIN VPN_IP NODE_LABEL INSTALL_CHANNEL CERT_MODE LE_EMAIL \
             PROTO_CHOICE SELECTED REALITY_SNI SHADOWTLS_SNI SS_METHOD DNS_UPSTREAM \
             SNELL_VERSION SNELL_OBFS AUTO_PORTS KERNEL_TUNING FIREWALL \
             SUB_HOST SUB_PORT SUB_TOKEN NIC SB_USER \
             UUID PASSWORD SS_PASSWORD REALITY_PRIVATE REALITY_PUBLIC REALITY_SHORTID \
             HY2_OBFS_PASSWORD SHADOWTLS_PASSWORD SHADOWTLS_SS_METHOD SHADOWTLS_SS_PASSWORD \
             WS_PATH SNELL_PSK; do
      printf "%s='%s'\n" "$v" "${!v}"
    done
    # per-protocol ports (associative array serialised as PORT_<key>)
    local k
    for k in "${!PORT[@]}"; do
      printf "PORT['%s']='%s'\n" "$k" "${PORT[$k]}"
    done
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

# server address used in client links (domain preferred, IP as fallback)
addr() { printf '%s' "${VPN_DOMAIN:-$VPN_IP}"; }
# 1 (skip cert verify) for self-signed, 0 for a real Let's Encrypt cert
insec()      { [[ ${CERT_MODE} == self ]] && printf '1' || printf '0'; }
insec_bool() { [[ ${CERT_MODE} == self ]] && printf 'true' || printf 'false'; }
selected_has() { [[ " $SELECTED " == *" $1 "* ]]; }
needs_any_cert() { local k; for k in $SELECTED; do [[ $(proto_needs_cert "$k") == yes ]] && return 0; done; return 1; }
# Remove a protocol from SELECTED, rebuilt from a clean array so no stray double
# space is left behind (which would otherwise be saved into the state file).
deselect() { local out=() k; for k in $SELECTED; do [[ $k == "$1" ]] || out+=("$k"); done; SELECTED="${out[*]}"; }

usage() {
cat <<EOF
${C_BOLD}Singbox_Deployment.sh v${SCRIPT_VERSION}${C_RST} — sing-box multi-protocol proxy for Ubuntu 22/24/26

Usage:
  sudo bash Singbox_Deployment.sh [subcommand] [options]

Subcommands:
  deploy                 (default) install and configure everything
  info                   reprint share links / subscription paths / credentials
  status                 sing-box + snell service and listening-port status
  check                  re-run every health check
  update                 upgrade sing-box to the latest build in the chosen channel
  regen-sub              rebuild client bundles from saved state
  uninstall              remove configuration (the sing-box binary is kept)

Common options:
  -y, --yes                    non-interactive; requires --domain
      --domain <fqdn>          REQUIRED, e.g. vpn.example.com
      --ip <ipv4>              public IPv4 (auto-detected if omitted)
      --channel <stable|beta>  sing-box release channel (default: ${INSTALL_CHANNEL})
      --protocols <all|list>   e.g. all  OR  vless-reality,hysteria2,tuic,snell
      --cert-mode <letsencrypt|self>
      --le-email <email>
      --reality-sni <host>     Reality/ShadowTLS steal target (default: ${REALITY_SNI})
      --snell-version <v5|v6>  snell-server release (default: v5)
      --dns <local|host>       server-side resolver (default: ${DNS_UPSTREAM})
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
      -y|--yes)          ASSUME_YES="yes"; shift ;;
      --domain)          VPN_DOMAIN="$2"; shift 2 ;;
      --ip)              VPN_IP="$2"; shift 2 ;;
      --channel)         INSTALL_CHANNEL="$2"; shift 2 ;;
      --protocols)       PROTO_CHOICE="$2"; shift 2 ;;
      --cert-mode)       CERT_MODE="$2"; shift 2 ;;
      --le-email)        LE_EMAIL="$2"; shift 2 ;;
      --reality-sni)     REALITY_SNI="$2"; SHADOWTLS_SNI="$2"; shift 2 ;;
      --snell-version)   case "$2" in v5|5) SNELL_VERSION="$SNELL_V5_DEFAULT";; v6|6) SNELL_VERSION="$SNELL_V6_DEFAULT";; *) SNELL_VERSION="$2";; esac; shift 2 ;;
      --dns)             DNS_UPSTREAM="$2"; shift 2 ;;
      --no-kernel-tuning) KERNEL_TUNING="no"; shift ;;
      --firewall)        FIREWALL="$2"; shift 2 ;;
      --serve-sub)       SUB_HOST="yes"; shift ;;
      --skip-preflight)  SKIP_PREFLIGHT="yes"; shift ;;
      -h|--help)         usage; exit 0 ;;
      -*) die "Unknown option: $1  (try --help)" ;;
      *)  die "Unexpected argument: $1  (try --help)" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# 4. Protocol selection + port assignment
# -----------------------------------------------------------------------------
resolve_selection() { # turns PROTO_CHOICE into SELECTED (validated canonical keys)
  local choice="${PROTO_CHOICE,,}" out=() tok found k
  if [[ -z $choice || $choice == all || $choice == "*" ]]; then
    SELECTED="${ALL_KEYS[*]}"; return 0
  fi
  choice="${choice//,/ }"
  for tok in $choice; do
    # allow a few friendly aliases
    case "$tok" in
      reality|vless) tok="vless-reality" ;;
      ws|vlessws)    tok="vless-ws" ;;
      vmess)         tok="vmess-ws" ;;
      hy2|hysteria)  tok="hysteria2" ;;
      ss|ss2022|shadowsocks) tok="ss2022" ;;
      stls|shadow-tls) tok="shadowtls" ;;
    esac
    found=""
    for k in "${ALL_KEYS[@]}"; do [[ $k == "$tok" ]] && found="$k"; done
    [[ -n $found ]] || die "Unknown protocol '${tok}'. Valid keys: ${ALL_KEYS[*]}"
    [[ " ${out[*]} " == *" $found "* ]] || out+=("$found")
  done
  (( ${#out[@]} > 0 )) || die "No protocols selected."
  SELECTED="${out[*]}"
}

# Track ports already handed out this run, per L4 protocol (tcp/udp are separate
# namespaces so tcp/443 and udp/443 can coexist).
declare -A USED_TCP USED_UDP
_port_taken() { # _port_taken <tcp|udp|both> <port>
  local l4=$1 n=$2
  if [[ $l4 == tcp || $l4 == both ]]; then [[ -n ${USED_TCP[$n]:-} ]] && return 0; port_listening tcp "$n" && return 0; fi
  if [[ $l4 == udp || $l4 == both ]]; then [[ -n ${USED_UDP[$n]:-} ]] && return 0; port_listening udp "$n" && return 0; fi
  return 1
}
# NOTE: the trailing `return 0` is load-bearing. Without it the final `[[ ]] &&`
# is the function's exit status, which is FALSE for a tcp-only reservation — and
# under `set -e` a bare `_port_reserve tcp <n>` call would then fire the ERR trap
# and abort the whole deploy on the very first TCP protocol.
_port_reserve() { local l4=$1 n=$2; [[ $l4 == tcp || $l4 == both ]] && USED_TCP[$n]=1; [[ $l4 == udp || $l4 == both ]] && USED_UDP[$n]=1; return 0; }
_pick_free() { # _pick_free <l4> <candidate ports...> ; echoes a free port
  local l4=$1; shift; local n tries=0
  for n in "$@"; do if ! _port_taken "$l4" "$n"; then echo "$n"; return 0; fi; done
  while (( tries < 80 )); do n=$(( (RANDOM % 25000) + 20000 )); if ! _port_taken "$l4" "$n"; then echo "$n"; return 0; fi; tries=$((tries+1)); done
  return 1
}

assign_ports() {
  USED_TCP=(); USED_UDP=(); PORT=()
  local key l4 chosen
  for key in $SELECTED; do
    l4="$(proto_l4 "$key")"
    chosen="$(_pick_free "$l4" $(proto_ports "$key") || true)"
    [[ -n $chosen ]] || die "Could not find a free ${l4} port for ${key}."
    PORT[$key]="$chosen"; _port_reserve "$l4" "$chosen"
  done
  # ShadowTLS needs a loopback Shadowsocks backend on its own internal TCP port.
  if selected_has shadowtls; then
    chosen="$(_pick_free tcp 30000 30001 30002 $(seq 30003 30050) || true)"
    [[ -n $chosen ]] || die "Could not find a free loopback port for the ShadowTLS backend."
    PORT[shadowtls-ss]="$chosen"; _port_reserve tcp "$chosen"
  fi
}

# Let the user override any auto-assigned port.
review_ports() {
  local key p
  echo
  echo "  Ports selected (free on this host):"
  for key in $SELECTED; do printf '    %-16s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"; done
  [[ $AUTO_PORTS == yes ]] && return 0
  for key in $SELECTED; do
    ask_valid p "Port for ${key} (${key}/$(proto_l4 "$key"))" "${PORT[$key]}" valid_port_num "must be 1..65535"
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
  [[ -n $VPN_IP ]] || VPN_IP="$(detect_public_ip || true)"
  valid_ipv4 "$VPN_IP" || warn "Could not determine a valid public IPv4 (${VPN_IP:-none}); links will still use the domain."

  [[ -n $NODE_LABEL ]] || NODE_LABEL="${VPN_DOMAIN%%.*}"
  ask_valid NODE_LABEL "Short label prefixed to every generated node name" "$NODE_LABEL" \
    valid_label "letters, digits, dot, dash or underscore (max 32 chars)"

  ask_choice INSTALL_CHANNEL "sing-box release channel" "$INSTALL_CHANNEL" stable beta

  # --- protocol selection ---
  echo
  echo "  Available protocols:"
  local i=1 k
  for k in "${ALL_KEYS[@]}"; do printf '    %2d) %-14s %s\n' "$i" "$k" "$(proto_desc "$k")"; i=$((i+1)); done
  echo
  echo "  Enter 'all', or a comma list of keys/numbers (e.g. vless-reality,hysteria2,tuic,snell)."
  ask PROTO_CHOICE "Which protocols" "$PROTO_CHOICE"
  # numbers -> keys
  if [[ $PROTO_CHOICE =~ [0-9] && $PROTO_CHOICE != all ]]; then
    local tok out=""
    for tok in ${PROTO_CHOICE//,/ }; do
      if [[ $tok =~ ^[0-9]+$ ]] && (( tok>=1 && tok<=${#ALL_KEYS[@]} )); then out+="${ALL_KEYS[$((tok-1))]},"; else out+="$tok,"; fi
    done
    PROTO_CHOICE="${out%,}"
  fi
  resolve_selection
  echo "  Selected: ${SELECTED}"

  # --- snell version if selected ---
  if selected_has snell; then
    local sv="v5"; [[ $SNELL_VERSION == "$SNELL_V6_DEFAULT" ]] && sv="v6"
    ask_choice sv "Snell protocol version (v5 = stable; v6 = release candidate)" "$sv" v5 v6
    if [[ $sv == v6 ]]; then SNELL_VERSION="$SNELL_V6_DEFAULT"; SNELL_OBFS="off";
    else SNELL_VERSION="$SNELL_V5_DEFAULT"; ask_choice SNELL_OBFS "Snell v5 obfuscation" "$SNELL_OBFS" off http; fi
  fi

  # --- certificate (only if a TLS-cert protocol is selected) ---
  if needs_any_cert; then
    echo
    echo "  ${C_BOLD}letsencrypt${C_RST} – real cert via certbot (needs the domain's A record pointing here + port 80 free)."
    echo "  ${C_BOLD}self${C_RST}        – self-signed cert; clients must allow insecure / skip-cert-verify."
    ask_choice CERT_MODE "TLS certificate source" "$CERT_MODE" letsencrypt self
    if [[ $CERT_MODE == letsencrypt ]]; then
      ask_valid LE_EMAIL "Let's Encrypt contact e-mail (blank = register without one)" "$LE_EMAIL" \
        valid_email "that does not look like an e-mail address"
    fi
  else
    CERT_MODE="self"
  fi

  # --- reality / shadowtls steal target ---
  if selected_has vless-reality || selected_has shadowtls; then
    ask_valid REALITY_SNI "Reality/ShadowTLS steal target (a real external TLS1.3 site)" "$REALITY_SNI" \
      valid_domain "must be a hostname, e.g. www.microsoft.com"
    SHADOWTLS_SNI="$REALITY_SNI"
  fi

  ask_choice DNS_UPSTREAM "Server-side DNS resolver" "$DNS_UPSTREAM" local host
  ask_yn AUTO_PORTS "Auto-assign the first free curated port per protocol" "$AUTO_PORTS"
  ask_choice FIREWALL "Firewall backend" "$FIREWALL" auto ufw iptables none
  ask_yn KERNEL_TUNING "Apply kernel/sysctl tuning (BBR, QUIC buffers, fd limits)" "$KERNEL_TUNING"
  ask_yn SUB_HOST "Also serve the subscription over plain HTTP (secret path)" "$SUB_HOST"
  [[ $SUB_HOST == yes ]] && ask_valid SUB_PORT "HTTP port for the subscription server" "$SUB_PORT" valid_port_num "1..65535"

  assign_ports
  review_ports

  echo
  hr
  printf '  %-24s %s\n' "Domain / IP"     "${VPN_DOMAIN} / ${VPN_IP:-?}"
  printf '  %-24s %s\n' "sing-box channel" "$INSTALL_CHANNEL"
  printf '  %-24s %s\n' "Protocols"       "$SELECTED"
  needs_any_cert && printf '  %-24s %s\n' "TLS certificate" "$CERT_MODE"
  (selected_has vless-reality || selected_has shadowtls) && printf '  %-24s %s\n' "Reality/STLS SNI" "$REALITY_SNI"
  selected_has snell && printf '  %-24s %s\n' "Snell version" "$SNELL_VERSION (obfs=$SNELL_OBFS)"
  printf '  %-24s %s\n' "Firewall"        "$FIREWALL"
  printf '  %-24s %s\n' "Kernel tuning"   "$KERNEL_TUNING"
  printf '  %-24s %s\n' "Serve sub"       "$SUB_HOST"
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
  [[ -n $NIC ]] || NIC="$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}')"
  [[ -n $NIC ]] || warn "Could not determine the outbound network interface."
}

# Version-agnostic Ubuntu gate: kernel numbering jumped 6.x -> 7.x on 26.04, so
# never compare kernel strings; key off VERSION_ID instead.
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
    *) warn "Architecture $(uname -m) may lack prebuilt sing-box/snell binaries." ;;
  esac

  local virt="none"; have systemd-detect-virt && virt="$(systemd-detect-virt 2>/dev/null || echo none)"
  ok "Virtualisation: ${virt}   (a userspace proxy works fine in containers, unlike IPsec)"

  detect_nic
  [[ -n $NIC ]] && ok "Outbound interface: ${NIC}"

  local pub=""; pub="$(detect_public_ip || true)"
  [[ -n $pub ]] && ok "Detected public IPv4: ${pub}"

  # DNS: only meaningful for Let's Encrypt.
  if [[ $CERT_MODE == letsencrypt ]] && needs_any_cert && have dig; then
    local a; a="$(dig +short +time=3 A "$VPN_DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
    if [[ -n $a && ( $a == "$VPN_IP" || $a == "$pub" ) ]]; then ok "DNS: ${VPN_DOMAIN} -> ${a}"
    else warn "DNS: ${VPN_DOMAIN} -> ${a:-<none>} (expected ${VPN_IP:-$pub}); Let's Encrypt HTTP-01 may fail."; fi
  fi
}

# -----------------------------------------------------------------------------
# 7. Package + sing-box install
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
  have jq || die "jq is required and could not be installed."
  have openssl || die "openssl is required and could not be installed."
  if [[ $CERT_MODE == letsencrypt ]] && needs_any_cert; then
    apt-get install -y -qq certbot >/dev/null 2>&1 || die "Failed to install certbot (needed for --cert-mode letsencrypt)."
  fi
}

_arch_deb() { case "$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo arm64 ;; armv7l) echo armv7 ;; *) echo "" ;; esac; }

install_singbox_manual() {
  local arch tag url tmp
  arch="$(_arch_deb)"; [[ -n $arch ]] || die "No prebuilt sing-box for $(uname -m)."
  # `|| true` + swallowed jq errors are required: a bare `cmd | jq` assignment
  # under set -e+pipefail would fire the ERR trap on an API rate-limit/403 or a
  # network blip, preempting the graceful `die` below.
  if [[ $INSTALL_CHANNEL == beta ]]; then
    tag="$(curl -fsSL 'https://api.github.com/repos/SagerNet/sing-box/releases?per_page=10' 2>/dev/null | jq -r '[.[].tag_name][0]' 2>/dev/null || true)"
  else
    tag="$(curl -fsSL 'https://api.github.com/repos/SagerNet/sing-box/releases/latest' 2>/dev/null | jq -r '.tag_name' 2>/dev/null || true)"
  fi
  [[ -n $tag && $tag != null ]] || die "Could not determine the sing-box release tag from GitHub."
  local ver="${tag#v}"
  url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box_${ver}_linux_${arch}.deb"
  tmp="$(mktemp -d)"; log "Downloading ${url}"
  if curl -fL -o "$tmp/sb.deb" "$url" && dpkg -i "$tmp/sb.deb" >/dev/null 2>&1; then
    ok "Installed sing-box ${tag} from the GitHub .deb"
  else
    warn "deb install failed; falling back to the static tarball."
    url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${arch}.tar.gz"
    curl -fL -o "$tmp/sb.tgz" "$url" || die "Tarball download failed: $url"
    tar -xzf "$tmp/sb.tgz" -C "$tmp"
    install -m0755 "$tmp"/sing-box-*/sing-box /usr/local/bin/sing-box
    _install_fallback_unit
  fi
  rm -rf "$tmp"
}

# Only used when sing-box arrived as a bare tarball (no packaged unit / user).
_install_fallback_unit() {
  id sing-box >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sing-box 2>/dev/null || true
  install -d -m 0755 -o sing-box -g sing-box /var/lib/sing-box 2>/dev/null || install -d -m0755 /var/lib/sing-box
  cat >/etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
User=sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/usr/local/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

install_singbox() {
  head1 "Installing sing-box (${INSTALL_CHANNEL})"
  local args=""; [[ $INSTALL_CHANNEL == beta ]] && args="--beta"
  # The official one-liner installs the matching .deb/.rpm and the systemd unit.
  if curl -fsSL https://sing-box.app/install.sh 2>/dev/null | sh -s -- $args >/dev/null 2>&1 && have sing-box; then
    ok "sing-box installed via the official script."
  else
    warn "Official install script unavailable; using the GitHub release directly."
    install_singbox_manual
  fi
  have sing-box || install_singbox_manual
  have sing-box || die "sing-box could not be installed."
  install -d -m 0755 "$SB_CONF_DIR"
  # Detect the user the unit runs as (deb uses 'sing-box'); certs must be readable by it.
  SB_USER="$(systemctl show -p User --value sing-box 2>/dev/null || true)"
  [[ -n $SB_USER ]] || SB_USER="root"
  id "$SB_USER" >/dev/null 2>&1 || SB_USER="root"
  ok "sing-box version: $(sing-box version 2>/dev/null | awk 'NR==1{print $NF}')   (runs as: ${SB_USER})"
}

# -----------------------------------------------------------------------------
# 8. Snell (standalone binary — sing-box only ships a snell inbound on 1.14 beta)
# -----------------------------------------------------------------------------
_arch_snell() { case "$(uname -m)" in x86_64|amd64) echo amd64 ;; aarch64|arm64) echo aarch64 ;; i386|i686) echo i386 ;; *) echo "" ;; esac; }

install_snell() {
  selected_has snell || return 0
  head1 "Installing snell-server (${SNELL_VERSION})"
  local arch url tmp; arch="$(_arch_snell)"
  [[ -n $arch ]] || { warn "No snell-server binary for $(uname -m); skipping snell."; deselect snell; return 0; }
  url="https://dl.nssurge.com/snell/snell-server-${SNELL_VERSION}-linux-${arch}.zip"
  tmp="$(mktemp -d)"; log "Downloading ${url}"
  if ! curl -fL -o "$tmp/snell.zip" "$url"; then
    warn "snell download failed (${url}); dropping snell from this deployment."
    deselect snell; rm -rf "$tmp"; return 0
  fi
  unzip -o "$tmp/snell.zip" -d "$tmp" >/dev/null
  install -m0755 "$tmp/snell-server" "$SNELL_BIN"
  rm -rf "$tmp"
  id snell >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin snell 2>/dev/null || true
  ok "snell-server: $("$SNELL_BIN" --v 2>/dev/null | head -1 || echo "$SNELL_VERSION")"
}

write_snell_config() {
  selected_has snell || return 0
  install -d -m 0755 "$SNELL_CONF_DIR"
  local port="${PORT[snell]}"
  {
    echo "[snell-server]"
    echo "listen = ::0:${port}"
    echo "psk = ${SNELL_PSK}"
    echo "ipv6 = true"
    if [[ $SNELL_VERSION == "$SNELL_V6_DEFAULT" ]]; then
      echo "mode = default"
    else
      echo "obfs = ${SNELL_OBFS}"
      [[ $SNELL_OBFS == http ]] && echo "obfs-host = ${REALITY_SNI}"
    fi
    echo "dns = 1.1.1.1, 8.8.8.8"
  } >"$SNELL_CONF"
  chmod 0644 "$SNELL_CONF"

  cat >/etc/systemd/system/snell.service <<EOF
[Unit]
Description=Snell Proxy Service (${SNELL_VERSION})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=snell
Group=snell
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
ExecStart=${SNELL_BIN} -c ${SNELL_CONF}
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now snell.service >/dev/null 2>&1 || warn "Could not start snell.service."
}

# -----------------------------------------------------------------------------
# 9. Credentials
# -----------------------------------------------------------------------------
gen_credentials() {
  head1 "Generating credentials"
  [[ -n $UUID ]]     || UUID="$(gen_uuid)"
  [[ -n $PASSWORD ]] || PASSWORD="$(gen_pass)"
  [[ -n $WS_PATH ]]  || WS_PATH="/$(gen_hex 6)"

  if selected_has ss2022; then
    local bytes=16; [[ $SS_METHOD == *chacha20* || $SS_METHOD == *aes-256* ]] && bytes=32
    [[ -n $SS_PASSWORD ]] || SS_PASSWORD="$(gen_b64key "$bytes")"
  fi
  if selected_has vless-reality; then
    if [[ -z $REALITY_PRIVATE || -z $REALITY_PUBLIC ]]; then
      local kp; kp="$(sing-box generate reality-keypair 2>/dev/null || true)"
      REALITY_PRIVATE="$(printf '%s\n' "$kp" | awk '/PrivateKey/{print $NF}')"
      REALITY_PUBLIC="$(printf '%s\n' "$kp" | awk '/PublicKey/{print $NF}')"
    fi
    [[ -n $REALITY_PRIVATE && -n $REALITY_PUBLIC ]] || die "sing-box generate reality-keypair produced no keys."
    [[ -n $REALITY_SHORTID ]] || REALITY_SHORTID="$(gen_hex 8)"
  fi
  if selected_has hysteria2; then
    [[ -n $HY2_OBFS_PASSWORD ]] || HY2_OBFS_PASSWORD="$(gen_pass)"
  fi
  if selected_has shadowtls; then
    [[ -n $SHADOWTLS_PASSWORD ]]    || SHADOWTLS_PASSWORD="$(gen_b64key 16)"
    [[ -n $SHADOWTLS_SS_PASSWORD ]] || SHADOWTLS_SS_PASSWORD="$(gen_b64key 16)"
  fi
  if selected_has snell; then
    [[ -n $SNELL_PSK ]] || SNELL_PSK="$(gen_pass)"
  fi
  ok "Secrets ready (UUID, passwords$(selected_has vless-reality && echo ', Reality keypair')$(selected_has ss2022 && echo ', SS-2022 key')$(selected_has snell && echo ', Snell PSK'))."
}

# -----------------------------------------------------------------------------
# 10. Certificates
# -----------------------------------------------------------------------------
_chown_certs() {
  install -d -m 0750 "$SB_CERT_DIR"
  chown -R "root:${SB_USER}" "$SB_CERT_DIR" 2>/dev/null || true
  chmod 0644 "$SB_CERT_FULL" 2>/dev/null || true
  chmod 0640 "$SB_CERT_KEY"  2>/dev/null || true
  chown "root:${SB_USER}" "$SB_CERT_FULL" "$SB_CERT_KEY" 2>/dev/null || true
}

make_self_signed() {
  install -d -m 0750 "$SB_CERT_DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
    -days 3650 -subj "/CN=${VPN_DOMAIN}" -addext "subjectAltName=DNS:${VPN_DOMAIN}" \
    -keyout "$SB_CERT_KEY" -out "$SB_CERT_FULL" >/dev/null 2>&1 \
    || die "openssl failed to generate a self-signed certificate."
  _chown_certs
  ok "Self-signed certificate written to ${SB_CERT_DIR} (clients must allow insecure)."
}

obtain_letsencrypt() {
  # certbot standalone binds :80 briefly; the deploy hook copies renewed certs
  # into ${SB_CERT_DIR} (readable by ${SB_USER}) and reloads sing-box.
  local email_arg="--register-unsafely-without-email"
  [[ -n $LE_EMAIL ]] && email_arg="-m ${LE_EMAIL}"
  systemctl stop sing-box >/dev/null 2>&1 || true
  if certbot certonly --standalone --non-interactive --agree-tos $email_arg \
       --http-01-port 80 -d "$VPN_DOMAIN" >/dev/null 2>&1; then
    install -d -m 0750 "$SB_CERT_DIR"
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "$SB_CERT_FULL"
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "$SB_CERT_KEY"
    _chown_certs
    cat >"$SB_RENEW_HOOK" <<EOF
#!/usr/bin/env bash
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "${SB_CERT_FULL}"
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "${SB_CERT_KEY}"
chown "root:${SB_USER}" "${SB_CERT_FULL}" "${SB_CERT_KEY}"
chmod 0644 "${SB_CERT_FULL}"; chmod 0640 "${SB_CERT_KEY}"
systemctl restart sing-box
EOF
    chmod 0755 "$SB_RENEW_HOOK"
    install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    ln -sf "$SB_RENEW_HOOK" "/etc/letsencrypt/renewal-hooks/deploy/singbox-${VPN_DOMAIN}.sh"
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
      warn "Falling back to a self-signed certificate; clients must allow insecure."
      CERT_MODE="self"; make_self_signed
    fi
  else
    make_self_signed
  fi
}

# -----------------------------------------------------------------------------
# 11. sing-box config
# -----------------------------------------------------------------------------
# TLS object for cert-based inbounds. $1 = optional compact JSON alpn array.
_tls_cert() {
  local alpn="${1:-}"
  if [[ -n $alpn ]]; then
    jq -cn --arg sni "$VPN_DOMAIN" --arg c "$SB_CERT_FULL" --arg k "$SB_CERT_KEY" --argjson alpn "$alpn" \
      '{enabled:true,server_name:$sni,alpn:$alpn,certificate_path:$c,key_path:$k}'
  else
    jq -cn --arg sni "$VPN_DOMAIN" --arg c "$SB_CERT_FULL" --arg k "$SB_CERT_KEY" \
      '{enabled:true,server_name:$sni,certificate_path:$c,key_path:$k}'
  fi
}

ib_of() { # emit the compact inbound JSON for a protocol key
  local key=$1
  case "$key" in
    vless-reality)
      jq -cn --argjson port "${PORT[$key]}" --arg uuid "$UUID" --arg sni "$REALITY_SNI" \
             --arg pk "$REALITY_PRIVATE" --arg sid "$REALITY_SHORTID" '
        {type:"vless",tag:"vless-reality-in",listen:"::",listen_port:$port,
         users:[{name:"main",uuid:$uuid,flow:"xtls-rprx-vision"}],
         tls:{enabled:true,server_name:$sni,
              reality:{enabled:true,handshake:{server:$sni,server_port:443},
                       private_key:$pk,short_id:[$sid]}}}' ;;
    vless-ws)
      jq -cn --argjson port "${PORT[$key]}" --arg uuid "$UUID" --arg path "$WS_PATH" \
             --argjson tls "$(_tls_cert)" '
        {type:"vless",tag:"vless-ws-in",listen:"::",listen_port:$port,
         users:[{name:"main",uuid:$uuid}],tls:$tls,
         transport:{type:"ws",path:$path}}' ;;
    vmess-ws)
      jq -cn --argjson port "${PORT[$key]}" --arg uuid "$UUID" --arg path "$WS_PATH" \
             --argjson tls "$(_tls_cert)" '
        {type:"vmess",tag:"vmess-ws-in",listen:"::",listen_port:$port,
         users:[{name:"main",uuid:$uuid}],tls:$tls,
         transport:{type:"ws",path:$path}}' ;;
    trojan)
      jq -cn --argjson port "${PORT[$key]}" --arg pw "$PASSWORD" --argjson tls "$(_tls_cert)" '
        {type:"trojan",tag:"trojan-in",listen:"::",listen_port:$port,
         users:[{name:"main",password:$pw}],tls:$tls}' ;;
    hysteria2)
      jq -cn --argjson port "${PORT[$key]}" --arg pw "$PASSWORD" --arg obfs "$HY2_OBFS_PASSWORD" \
             --argjson tls "$(_tls_cert '["h3"]')" '
        {type:"hysteria2",tag:"hysteria2-in",listen:"::",listen_port:$port,
         users:[{name:"main",password:$pw}],
         obfs:{type:"salamander",password:$obfs},
         masquerade:"https://www.microsoft.com",tls:$tls}' ;;
    tuic)
      jq -cn --argjson port "${PORT[$key]}" --arg uuid "$UUID" --arg pw "$PASSWORD" \
             --argjson tls "$(_tls_cert '["h3"]')" '
        {type:"tuic",tag:"tuic-in",listen:"::",listen_port:$port,
         users:[{name:"main",uuid:$uuid,password:$pw}],
         congestion_control:"bbr",tls:$tls}' ;;
    shadowtls)
      jq -cn --argjson port "${PORT[$key]}" --arg pw "$SHADOWTLS_PASSWORD" --arg sni "$SHADOWTLS_SNI" '
        {type:"shadowtls",tag:"shadowtls-in",listen:"::",listen_port:$port,version:3,
         users:[{name:"main",password:$pw}],
         handshake:{server:$sni,server_port:443},strict_mode:true,detour:"shadowtls-ss-in"}' ;;
    ss2022)
      jq -cn --argjson port "${PORT[$key]}" --arg method "$SS_METHOD" --arg pw "$SS_PASSWORD" '
        {type:"shadowsocks",tag:"ss2022-in",listen:"::",listen_port:$port,method:$method,password:$pw}' ;;
    anytls)
      jq -cn --argjson port "${PORT[$key]}" --arg pw "$PASSWORD" --argjson tls "$(_tls_cert)" '
        {type:"anytls",tag:"anytls-in",listen:"::",listen_port:$port,
         users:[{name:"main",password:$pw}],tls:$tls}' ;;
    naive)
      jq -cn --argjson port "${PORT[$key]}" --arg pw "$PASSWORD" --argjson tls "$(_tls_cert)" '
        {type:"naive",tag:"naive-in",listen:"::",listen_port:$port,
         users:[{username:"main",password:$pw}],tls:$tls}' ;;
  esac
}

# ShadowTLS relays a real handshake and forwards the inner stream to a loopback
# Shadowsocks-2022 inbound via detour.
ib_shadowtls_backend() {
  jq -cn --argjson port "${PORT[shadowtls-ss]}" --arg method "$SHADOWTLS_SS_METHOD" --arg pw "$SHADOWTLS_SS_PASSWORD" '
    {type:"shadowsocks",tag:"shadowtls-ss-in",listen:"127.0.0.1",listen_port:$port,method:$method,password:$pw}'
}

build_inbounds() {
  local frags=() key
  for key in $SELECTED; do
    [[ $key == snell ]] && continue          # snell is a separate daemon
    frags+=("$(ib_of "$key")")
    [[ $key == shadowtls ]] && frags+=("$(ib_shadowtls_backend)")
  done
  printf '%s\n' "${frags[@]}" | jq -s '.'
}

write_singbox_config() {
  head1 "Writing ${SB_CONF}"
  local inbounds dns_server
  inbounds="$(build_inbounds)"
  if [[ $DNS_UPSTREAM == host ]]; then
    dns_server='{"type":"udp","tag":"dns-upstream","server":"1.1.1.1"}'
  else
    dns_server='{"type":"local","tag":"dns-upstream"}'
  fi
  jq -n --argjson inbounds "$inbounds" --argjson dns "$dns_server" '
    {log:{level:"info",timestamp:true},
     dns:{servers:[$dns],final:"dns-upstream"},
     inbounds:$inbounds,
     outbounds:[{type:"direct",tag:"direct"}],
     route:{rules:[{action:"sniff"}],final:"direct",
            default_domain_resolver:{server:"dns-upstream"}}}' >"$SB_CONF"
  chown "root:${SB_USER}" "$SB_CONF" 2>/dev/null || true
  chmod 0640 "$SB_CONF"
  # Validate against the installed sing-box before we ever (re)start the service.
  if sing-box check -c "$SB_CONF" >/tmp/sb-check.log 2>&1; then
    ok "Config validated by sing-box check."
  else
    cat /tmp/sb-check.log >&2
    die "sing-box rejected the generated config (see above)."
  fi
}

# -----------------------------------------------------------------------------
# 12. Kernel tuning  (TCP + QUIC; values verified against quic-go / hysteria2 docs)
# -----------------------------------------------------------------------------
kernel_tuning() {
  [[ $KERNEL_TUNING == yes ]] || { log "Kernel tuning skipped."; return 0; }
  head1 "Kernel / sysctl tuning"

  local bbr_block=""
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    bbr_block=$'\n# --- congestion control (BBR + fair-queue pacing) ---\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr'
    echo "tcp_bbr" >/etc/modules-load.d/singbox-bbr.conf
    ok "BBR available and enabled."
  else
    warn "BBR unavailable on this kernel; leaving congestion control unchanged."
  fi

  # A sysctl.d drop-in silently skips keys the running kernel does not know, so
  # obsolete keys from old guides (tcp_tw_recycle, tcp_low_latency, ...) simply
  # do not appear here rather than being force-set.
  cat >/etc/sysctl.d/99-singbox.conf <<EOF
# ---------------------------------------------------------------------------
# sing-box proxy tuning (Singbox_Deployment.sh) — TCP proxies + QUIC (hy2/tuic)
# ---------------------------------------------------------------------------

# QUIC needs large UDP socket buffers; 16 MiB satisfies both the hysteria2 docs
# (16 MiB) and quic-go (~7.5 MiB) and silences quic-go's "failed to sufficiently
# increase receive buffer size" warning.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536

# TCP autotuning ceilings (~1 Gbps at typical RTT).
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Queues / backlogs for many concurrent connections.
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192

# Latency / throughput behaviour.
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535

# conntrack only exists when a NAT/stateful firewall loads the module; harmless
# (skipped) otherwise. A busy proxy should not keep an entry for 5 days.
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
${bbr_block}
EOF
  sysctl --system >/dev/null 2>&1 || warn "sysctl --system reported errors (unknown keys are skipped)."

  # Raise the file-descriptor ceiling for the sing-box unit (the deb already sets
  # infinity; a tarball fallback or an old override may not).
  install -d -m 0755 /etc/systemd/system/sing-box.service.d
  cat >/etc/systemd/system/sing-box.service.d/10-limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
  systemctl daemon-reload
  ok "Applied sysctl drop-in and raised LimitNOFILE for sing-box."
}

# -----------------------------------------------------------------------------
# 13. Firewall  (userspace proxy: INPUT only — no forwarding / NAT needed)
# -----------------------------------------------------------------------------
_tcp_ports() { # every TCP port to open
  local key out=(); for key in $SELECTED; do
    case "$(proto_l4 "$key")" in tcp|both) out+=("${PORT[$key]}") ;; esac
  done
  [[ $CERT_MODE == letsencrypt ]] && needs_any_cert && out+=("80")
  [[ $SUB_HOST == yes ]] && out+=("$SUB_PORT")
  printf '%s\n' "${out[@]}" | sort -un
}
_udp_ports() { local key out=(); for key in $SELECTED; do
    case "$(proto_l4 "$key")" in udp|both) out+=("${PORT[$key]}") ;; esac
  done; printf '%s\n' "${out[@]}" | sort -un; }

ssh_port() { local p; p="$(ss -ltnH 'sport = :22' 2>/dev/null | head -1)"; [[ -n $p ]] && { echo 22; return; }
  p="$(awk '/^[Pp]ort[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)"; echo "${p:-22}"; }

firewall_ufw() {
  local p
  ufw allow "$(ssh_port)/tcp" >/dev/null 2>&1 || true
  for p in $(_tcp_ports); do ufw allow "${p}/tcp" >/dev/null 2>&1 || true; done
  for p in $(_udp_ports); do ufw allow "${p}/udp" >/dev/null 2>&1 || true; done
  ufw --force enable >/dev/null 2>&1 || true
  ok "ufw rules applied for $(_tcp_ports | tr '\n' ' ')(tcp) $(_udp_ports | tr '\n' ' ')(udp)."
}

firewall_iptables() {
  local p
  # A single failing rule (e.g. the conntrack module absent) should degrade the
  # firewall to a warning, not abort a deploy whose services are already up — so
  # every rule tolerates failure rather than tripping the ERR trap.
  iptables -N SINGBOX_IN 2>/dev/null || iptables -F SINGBOX_IN || true
  iptables -C INPUT -j SINGBOX_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j SINGBOX_IN || true
  iptables -A SINGBOX_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || warn "conntrack rule not added (module missing?)."
  iptables -A SINGBOX_IN -p tcp --dport "$(ssh_port)" -j ACCEPT || true
  for p in $(_tcp_ports); do iptables -A SINGBOX_IN -p tcp --dport "$p" -j ACCEPT || true; done
  for p in $(_udp_ports); do iptables -A SINGBOX_IN -p udp --dport "$p" -j ACCEPT || true; done
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || \
    { apt-get install -y -qq iptables-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1; } || \
    warn "iptables rules are live but not persisted across reboot (install iptables-persistent)."
  ok "iptables rules applied for $(_tcp_ports | tr '\n' ' ')(tcp) $(_udp_ports | tr '\n' ' ')(udp)."
}

firewall_setup() {
  head1 "Firewall"
  local backend="$FIREWALL"
  if [[ $backend == auto ]]; then
    if have ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then backend="ufw"
    elif have iptables; then backend="iptables"; else backend="none"; fi
  fi
  case "$backend" in
    none)     warn "Firewall step skipped — open the listed ports yourself." ;;
    ufw)      have ufw || { warn "ufw not installed; using iptables."; firewall_iptables; return; }; firewall_ufw ;;
    iptables) firewall_iptables ;;
    *)        die "Unknown firewall backend '${backend}'." ;;
  esac
}

# -----------------------------------------------------------------------------
# 14. Services
# -----------------------------------------------------------------------------
start_services() {
  head1 "Starting services"
  systemctl enable sing-box >/dev/null 2>&1 || true
  # `|| true` so the is-active check below owns the failure path and prints the
  # journal, instead of the ERR trap aborting with no diagnostics.
  systemctl restart sing-box || true
  sleep 2
  if systemctl is-active --quiet sing-box; then ok "sing-box is running."
  else bad "sing-box failed to start:"; journalctl -u sing-box -n 20 --no-pager 2>/dev/null | sed 's/^/    /' >&2; die "Fix the config and re-run."; fi
  if selected_has snell && systemctl is-active --quiet snell; then ok "snell is running."; fi
}

# -----------------------------------------------------------------------------
# 15. Client artefacts — share links, base64 sub, sing-box JSON, Clash YAML
# -----------------------------------------------------------------------------
# --- share links (only protocols with a portable URI form) ---
link_of() {
  local key=$1 a; a="$(addr)"; local ins; ins="$(insec)"
  case "$key" in
    vless-reality)
      printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&flow=xtls-rprx-vision#%s' \
        "$UUID" "$a" "${PORT[$key]}" "$(urlenc "$REALITY_SNI")" "$(urlenc "$REALITY_PUBLIC")" "$REALITY_SHORTID" "$(urlenc "${NODE_LABEL}-reality")" ;;
    vless-ws)
      printf 'vless://%s@%s:%s?encryption=none&security=tls&type=ws&host=%s&path=%s&sni=%s&fp=chrome&allowInsecure=%s#%s' \
        "$UUID" "$a" "${PORT[$key]}" "$(urlenc "$VPN_DOMAIN")" "$(urlenc "$WS_PATH")" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-vless-ws")" ;;
    vmess-ws)
      local j; j="$(jq -cn --arg add "$a" --arg port "${PORT[$key]}" --arg id "$UUID" --arg host "$VPN_DOMAIN" \
                --arg path "$WS_PATH" --arg ps "${NODE_LABEL}-vmess" \
                '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:"ws",type:"none",host:$host,path:$path,tls:"tls",sni:$host,fp:"chrome"}')"
      printf 'vmess://%s' "$(printf '%s' "$j" | base64 -w0)" ;;
    trojan)
      printf 'trojan://%s@%s:%s?security=tls&sni=%s&type=tcp&allowInsecure=%s#%s' \
        "$(urlenc "$PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-trojan")" ;;
    hysteria2)
      printf 'hysteria2://%s@%s:%s/?sni=%s&obfs=salamander&obfs-password=%s&insecure=%s#%s' \
        "$(urlenc "$PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "$VPN_DOMAIN")" "$(urlenc "$HY2_OBFS_PASSWORD")" "$ins" "$(urlenc "${NODE_LABEL}-hy2")" ;;
    tuic)
      printf 'tuic://%s:%s@%s:%s?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=%s&allow_insecure=%s#%s' \
        "$(urlenc "$UUID")" "$(urlenc "$PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-tuic")" ;;
    ss2022)
      printf 'ss://%s:%s@%s:%s#%s' \
        "$SS_METHOD" "$(urlenc "$SS_PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "${NODE_LABEL}-ss2022")" ;;
    anytls)
      printf 'anytls://%s@%s:%s/?sni=%s&insecure=%s#%s' \
        "$(urlenc "$PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "$VPN_DOMAIN")" "$ins" "$(urlenc "${NODE_LABEL}-anytls")" ;;
    naive)
      printf 'naive+https://%s:%s@%s:%s#%s' \
        "main" "$(urlenc "$PASSWORD")" "$a" "${PORT[$key]}" "$(urlenc "${NODE_LABEL}-naive")" ;;
    *) return 1 ;;   # shadowtls / snell have no portable link
  esac
}

# --- Clash / mihomo YAML proxy block (2-space indented, ready to nest) ---
clash_of() {
  local key=$1 a; a="$(addr)"; local sci; sci="$([[ $CERT_MODE == self ]] && echo true || echo false)"
  case "$key" in
    vless-reality) cat <<EOF
  - name: "${NODE_LABEL}-reality"
    type: vless
    server: ${a}
    port: ${PORT[$key]}
    uuid: ${UUID}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: ${REALITY_SNI}
    client-fingerprint: chrome
    reality-opts:
      public-key: ${REALITY_PUBLIC}
      short-id: ${REALITY_SHORTID}
EOF
;;
    vless-ws) cat <<EOF
  - name: "${NODE_LABEL}-vless-ws"
    type: vless
    server: ${a}
    port: ${PORT[$key]}
    uuid: ${UUID}
    udp: true
    tls: true
    servername: ${VPN_DOMAIN}
    client-fingerprint: chrome
    skip-cert-verify: ${sci}
    network: ws
    ws-opts:
      path: ${WS_PATH}
      headers:
        Host: ${VPN_DOMAIN}
EOF
;;
    vmess-ws) cat <<EOF
  - name: "${NODE_LABEL}-vmess"
    type: vmess
    server: ${a}
    port: ${PORT[$key]}
    uuid: ${UUID}
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    servername: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    network: ws
    ws-opts:
      path: ${WS_PATH}
      headers:
        Host: ${VPN_DOMAIN}
EOF
;;
    trojan) cat <<EOF
  - name: "${NODE_LABEL}-trojan"
    type: trojan
    server: ${a}
    port: ${PORT[$key]}
    password: ${PASSWORD}
    udp: true
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    client-fingerprint: chrome
EOF
;;
    hysteria2) cat <<EOF
  - name: "${NODE_LABEL}-hy2"
    type: hysteria2
    server: ${a}
    port: ${PORT[$key]}
    password: ${PASSWORD}
    obfs: salamander
    obfs-password: ${HY2_OBFS_PASSWORD}
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    alpn:
      - h3
EOF
;;
    tuic) cat <<EOF
  - name: "${NODE_LABEL}-tuic"
    type: tuic
    server: ${a}
    port: ${PORT[$key]}
    uuid: ${UUID}
    password: ${PASSWORD}
    alpn:
      - h3
    udp-relay-mode: native
    congestion-controller: bbr
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
EOF
;;
    shadowtls) cat <<EOF
  - name: "${NODE_LABEL}-shadowtls"
    type: ss
    server: ${a}
    port: ${PORT[$key]}
    cipher: ${SHADOWTLS_SS_METHOD}
    password: "${SHADOWTLS_SS_PASSWORD}"
    udp: true
    plugin: shadow-tls
    client-fingerprint: chrome
    plugin-opts:
      host: "${SHADOWTLS_SNI}"
      password: "${SHADOWTLS_PASSWORD}"
      version: 3
EOF
;;
    ss2022) cat <<EOF
  - name: "${NODE_LABEL}-ss2022"
    type: ss
    server: ${a}
    port: ${PORT[$key]}
    cipher: ${SS_METHOD}
    password: "${SS_PASSWORD}"
    udp: true
EOF
;;
    anytls) cat <<EOF
  - name: "${NODE_LABEL}-anytls"
    type: anytls
    server: ${a}
    port: ${PORT[$key]}
    password: "${PASSWORD}"
    client-fingerprint: chrome
    udp: true
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
EOF
;;
    snell)
      # mihomo supports snell up to v5; a v6 server can't be described here.
      if [[ $SNELL_VERSION == "$SNELL_V6_DEFAULT" ]]; then return 1; fi
      cat <<EOF
  - name: "${NODE_LABEL}-snell"
    type: snell
    server: ${a}
    port: ${PORT[$key]}
    psk: ${SNELL_PSK}
    version: 5
    udp: true
EOF
      if [[ $SNELL_OBFS == http ]]; then cat <<EOF
    obfs-opts:
      mode: http
      host: ${REALITY_SNI}
EOF
      fi ;;
    *) return 1 ;;
  esac
}

# --- sing-box client outbound (everything except naive/snell) ---
ob_of() {
  local key=$1 a; a="$(addr)"; local ins; ins="$(insec_bool)"
  case "$key" in
    vless-reality)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg id "$UUID" --arg sni "$REALITY_SNI" \
             --arg pk "$REALITY_PUBLIC" --arg sid "$REALITY_SHORTID" '
        {type:"vless",tag:"reality",server:$s,server_port:$p,uuid:$id,flow:"xtls-rprx-vision",
         tls:{enabled:true,server_name:$sni,utls:{enabled:true,fingerprint:"chrome"},
              reality:{enabled:true,public_key:$pk,short_id:$sid}}}' ;;
    vless-ws)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg id "$UUID" --arg sni "$VPN_DOMAIN" \
             --arg path "$WS_PATH" --argjson ins "$ins" '
        {type:"vless",tag:"vless-ws",server:$s,server_port:$p,uuid:$id,
         tls:{enabled:true,server_name:$sni,insecure:$ins,utls:{enabled:true,fingerprint:"chrome"}},
         transport:{type:"ws",path:$path,headers:{Host:$sni}}}' ;;
    vmess-ws)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg id "$UUID" --arg sni "$VPN_DOMAIN" \
             --arg path "$WS_PATH" --argjson ins "$ins" '
        {type:"vmess",tag:"vmess-ws",server:$s,server_port:$p,uuid:$id,security:"auto",
         tls:{enabled:true,server_name:$sni,insecure:$ins},
         transport:{type:"ws",path:$path,headers:{Host:$sni}}}' ;;
    trojan)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg pw "$PASSWORD" --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
        {type:"trojan",tag:"trojan",server:$s,server_port:$p,password:$pw,
         tls:{enabled:true,server_name:$sni,insecure:$ins}}' ;;
    hysteria2)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg pw "$PASSWORD" --arg obfs "$HY2_OBFS_PASSWORD" \
             --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
        {type:"hysteria2",tag:"hy2",server:$s,server_port:$p,password:$pw,
         obfs:{type:"salamander",password:$obfs},
         tls:{enabled:true,server_name:$sni,insecure:$ins,alpn:["h3"]}}' ;;
    tuic)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg id "$UUID" --arg pw "$PASSWORD" \
             --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
        {type:"tuic",tag:"tuic",server:$s,server_port:$p,uuid:$id,password:$pw,
         congestion_control:"bbr",udp_relay_mode:"native",
         tls:{enabled:true,server_name:$sni,insecure:$ins,alpn:["h3"]}}' ;;
    ss2022)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg m "$SS_METHOD" --arg pw "$SS_PASSWORD" '
        {type:"shadowsocks",tag:"ss2022",server:$s,server_port:$p,method:$m,password:$pw}' ;;
    shadowtls)
      # two outbounds: the shadowtls transport + the ss that detours through it
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg pw "$SHADOWTLS_PASSWORD" --arg sni "$SHADOWTLS_SNI" '
        {type:"shadowtls",tag:"shadowtls-tls",server:$s,server_port:$p,version:3,password:$pw,
         tls:{enabled:true,server_name:$sni,utls:{enabled:true,fingerprint:"chrome"}}}'
      jq -cn --arg m "$SHADOWTLS_SS_METHOD" --arg pw "$SHADOWTLS_SS_PASSWORD" '
        {type:"shadowsocks",tag:"shadowtls",method:$m,password:$pw,detour:"shadowtls-tls"}' ;;
    anytls)
      jq -cn --arg s "$a" --argjson p "${PORT[$key]}" --arg pw "$PASSWORD" --arg sni "$VPN_DOMAIN" --argjson ins "$ins" '
        {type:"anytls",tag:"anytls",server:$s,server_port:$p,password:$pw,
         tls:{enabled:true,server_name:$sni,insecure:$ins}}' ;;
    *) return 1 ;;   # naive/snell: no sing-box outbound emitted
  esac
}

# user-selectable proxy tags in the client config (matches ob_of tags)
_client_tags() {
  local key out=() ; for key in $SELECTED; do case "$key" in
    vless-reality) out+=(reality);; vless-ws) out+=(vless-ws);; vmess-ws) out+=(vmess-ws);;
    trojan) out+=(trojan);; hysteria2) out+=(hy2);; tuic) out+=(tuic);; ss2022) out+=(ss2022);;
    shadowtls) out+=(shadowtls);; anytls) out+=(anytls);; esac; done
  printf '%s\n' "${out[@]}"
}

write_client_singbox() {
  local frags=() key
  for key in $SELECTED; do
    case "$key" in naive|snell) continue;; esac
    while IFS= read -r line; do [[ -n $line ]] && frags+=("$line"); done < <(ob_of "$key" || true)
  done
  local outbounds tags_json
  outbounds="$(printf '%s\n' "${frags[@]}" | jq -s '.')"
  tags_json="$(_client_tags | jq -R . | jq -s '.')"
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
}

write_client_clash() {
  local key names=() f="${CLIENT_OUT_DIR}/client-clash.yaml"
  {
    echo "# mihomo / Clash.Meta config generated by Singbox_Deployment.sh"
    echo "mixed-port: 7890"
    echo "allow-lan: false"
    echo "mode: rule"
    # silent log + no tcp-concurrent + no IPv6: the client keeps no log buffer,
    # opens one socket per dial instead of one per resolved address, and never
    # waits out a dead AAAA path. Plain-UDP resolvers, no DoH/DoT and no
    # '#PROXY' fragment, so DNS answers without the tunnel having to be up.
    echo "log-level: silent"
    echo "ipv6: false"
    echo "unified-delay: true"
    echo "tcp-concurrent: false"
    echo "external-controller: 127.0.0.1:9090"
    echo "dns:"
    echo "  enable: true"
    echo "  ipv6: false"
    echo "  prefer-h3: false"
    echo "  enhanced-mode: fake-ip"
    echo "  fake-ip-range: 198.18.0.1/16"
    echo "  default-nameserver:"
    echo "    - 1.1.1.1"
    echo "    - 8.8.8.8"
    echo "    - 9.9.9.9"
    echo "  proxy-server-nameserver:"
    echo "    - 1.1.1.1"
    echo "    - 8.8.8.8"
    echo "    - 9.9.9.9"
    echo "  nameserver:"
    echo "    - 1.1.1.1"
    echo "    - 8.8.8.8"
    echo "    - 9.9.9.9"
    echo "proxies:"
  } >"$f"
  for key in $SELECTED; do
    if clash_of "$key" >>"$f" 2>/dev/null; then
      case "$key" in
        vless-reality) names+=("${NODE_LABEL}-reality");; vless-ws) names+=("${NODE_LABEL}-vless-ws");;
        vmess-ws) names+=("${NODE_LABEL}-vmess");; trojan) names+=("${NODE_LABEL}-trojan");;
        hysteria2) names+=("${NODE_LABEL}-hy2");; tuic) names+=("${NODE_LABEL}-tuic");;
        shadowtls) names+=("${NODE_LABEL}-shadowtls");; ss2022) names+=("${NODE_LABEL}-ss2022");;
        anytls) names+=("${NODE_LABEL}-anytls");;
        snell) [[ $SNELL_VERSION != "$SNELL_V6_DEFAULT" ]] && names+=("${NODE_LABEL}-snell");;
      esac
    fi
  done
  {
    echo "proxy-groups:"
    echo "  - name: PROXY"
    echo "    type: select"
    echo "    proxies:"
    echo "      - AUTO"
    local n; for n in "${names[@]}"; do echo "      - \"$n\""; done
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
}

write_readme() {
  local f="${CLIENT_OUT_DIR}/README.txt" key
  {
    echo "sing-box node: ${NODE_LABEL}  (${VPN_DOMAIN} / ${VPN_IP})"
    echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')  channel=${INSTALL_CHANNEL}  cert=${CERT_MODE}"
    echo
    echo "Files:"
    echo "  links.txt           one share link per line (import individually)"
    echo "  subscription.txt    base64 subscription (paste the URL/file into v2rayN, NekoBox, Streisand)"
    echo "  client-singbox.json sing-box client config (SFA/SFI/SFM, NekoBox sing-box core, Hiddify, Karing)"
    echo "  client-clash.yaml   mihomo / Clash.Meta config"
    echo
    echo "Per-protocol ports:"
    for key in $SELECTED; do printf '  %-16s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"; done
    echo
    if selected_has shadowtls; then
      echo "ShadowTLS has no share-link form — use client-clash.yaml or client-singbox.json."
      echo "  ShadowTLS password : ${SHADOWTLS_PASSWORD}"
      echo "  inner SS cipher    : ${SHADOWTLS_SS_METHOD}"
      echo "  inner SS password  : ${SHADOWTLS_SS_PASSWORD}"
      echo "  handshake SNI      : ${SHADOWTLS_SNI}"
      echo
    fi
    if selected_has snell; then
      echo "Snell (${SNELL_VERSION}) — Surge line (Surge supports v1..v6):"
      local sv=5; [[ $SNELL_VERSION == "$SNELL_V6_DEFAULT" ]] && sv=6
      if [[ $sv == 6 ]]; then
        echo "  ${NODE_LABEL}-snell = snell, $(addr), ${PORT[snell]}, psk=${SNELL_PSK}, version=6, mode=default, reuse=true, tfo=true"
        echo "  (Snell v6 is not yet supported by mihomo/Clash — Surge only.)"
      else
        local obfs_extra=""; [[ $SNELL_OBFS == http ]] && obfs_extra=", obfs=http, obfs-host=${REALITY_SNI}"
        echo "  ${NODE_LABEL}-snell = snell, $(addr), ${PORT[snell]}, psk=${SNELL_PSK}, version=5${obfs_extra}, reuse=true, tfo=true"
      fi
      echo "  PSK: ${SNELL_PSK}"
      echo
    fi
    echo "Shared credentials:"
    echo "  UUID     : ${UUID}"
    echo "  password : ${PASSWORD}"
    selected_has ss2022 && echo "  ss key   : ${SS_PASSWORD} (${SS_METHOD})"
    selected_has vless-reality && { echo "  reality public key: ${REALITY_PUBLIC}"; echo "  reality short id  : ${REALITY_SHORTID}"; }
  } >"$f"
  chmod 0600 "$f"
}

gen_artifacts() {
  head1 "Generating client bundles"
  install -d -m 0700 "$CLIENT_OUT_DIR"
  local key links=()
  for key in $SELECTED; do
    local l; l="$(link_of "$key" 2>/dev/null || true)"; [[ -n $l ]] && links+=("$l")
  done
  printf '%s\n' "${links[@]}" >"${CLIENT_OUT_DIR}/links.txt"
  printf '%s\n' "${links[@]}" | base64 -w0 >"${CLIENT_OUT_DIR}/subscription.txt"
  write_client_singbox
  write_client_clash
  write_readme
  chmod 0600 "${CLIENT_OUT_DIR}"/*.txt "${CLIENT_OUT_DIR}"/*.json "${CLIENT_OUT_DIR}"/*.yaml 2>/dev/null || true
  ok "Bundles written to ${CLIENT_OUT_DIR} (links.txt, subscription.txt, client-singbox.json, client-clash.yaml)."
  setup_sub_server
}

# Optional: serve the three subscription flavours over plain HTTP at a secret
# path, content-negotiated by User-Agent (clash -> yaml, sing-box -> json, else base64).
setup_sub_server() {
  [[ $SUB_HOST == yes ]] || return 0
  [[ -n $SUB_TOKEN ]] || SUB_TOKEN="$(gen_hex 12)"
  local root="/var/lib/singbox-sub"
  install -d -m 0755 "$root"
  local cgi="${root}/serve.py"
  cat >"$cgi" <<PYEOF
#!/usr/bin/env python3
import http.server, socketserver, os
TOKEN=os.environ.get("SUB_TOKEN","${SUB_TOKEN}")
DIR="${CLIENT_OUT_DIR}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if TOKEN not in self.path:
            self.send_error(404); return
        ua=self.headers.get("User-Agent","").lower()
        if "clash" in ua or "mihomo" in ua or "meta" in ua: fn,ct="client-clash.yaml","text/yaml; charset=utf-8"
        elif "sing-box" in ua or "sfa" in ua or "sfi" in ua:  fn,ct="client-singbox.json","application/json"
        else: fn,ct="subscription.txt","text/plain; charset=utf-8"
        try: data=open(os.path.join(DIR,fn),"rb").read()
        except OSError: self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Profile-Update-Interval","24"); self.end_headers(); self.wfile.write(data)
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
with socketserver.TCPServer(("0.0.0.0",${SUB_PORT}),H) as s: s.serve_forever()
PYEOF
  cat >/etc/systemd/system/singbox-sub.service <<EOF
[Unit]
Description=sing-box subscription server
After=network-online.target

[Service]
Environment=SUB_TOKEN=${SUB_TOKEN}
ExecStart=/usr/bin/python3 ${cgi}
Restart=on-failure
DynamicUser=yes
ReadOnlyPaths=${CLIENT_OUT_DIR}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now singbox-sub.service >/dev/null 2>&1 || warn "Could not start singbox-sub.service."
  ok "Subscription served at:  http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
}

# -----------------------------------------------------------------------------
# 16. Verify / status / summary
# -----------------------------------------------------------------------------
verify_all() {
  head1 "Health checks"; local rc=0
  have sing-box && ok "sing-box: $(sing-box version 2>/dev/null | awk 'NR==1{print $NF}')" || { bad "sing-box binary missing"; rc=1; }
  if [[ -r $SB_CONF ]]; then
    sing-box check -c "$SB_CONF" >/dev/null 2>&1 && ok "config.json valid" || { bad "config.json fails sing-box check"; rc=1; }
  fi
  systemctl is-active --quiet sing-box && ok "sing-box.service active" || { bad "sing-box.service not active"; rc=1; }
  selected_has snell && { systemctl is-active --quiet snell && ok "snell.service active" || bad "snell.service not active"; }
  local key l4 p
  for key in $SELECTED; do
    p="${PORT[$key]}"; l4="$(proto_l4 "$key")"
    case "$l4" in
      tcp)  port_listening tcp "$p" && ok "listening tcp/${p} (${key})" || { bad "nothing on tcp/${p} (${key})"; rc=1; } ;;
      udp)  port_listening udp "$p" && ok "listening udp/${p} (${key})" || { bad "nothing on udp/${p} (${key})"; rc=1; } ;;
      both) { port_listening tcp "$p" || port_listening udp "$p"; } && ok "listening ${p} (${key})" || { bad "nothing on ${p} (${key})"; rc=1; } ;;
    esac
  done
  return $rc
}

do_status() {
  head1 "Services"
  systemctl --no-pager status sing-box 2>/dev/null | head -6 || true
  selected_has snell && { echo; systemctl --no-pager status snell 2>/dev/null | head -6 || true; }
  head1 "Listening ports"
  ss -tulpnH 2>/dev/null | grep -E 'sing-box|snell' || warn "No sing-box/snell listeners found."
}

summary() {
  echo
  printf '%s' "$C_G"
  cat <<'BANNER'
  +==========================================================+
  |          S I N G - B O X   N O D E   I S   R E A D Y      |
  +==========================================================+
BANNER
  printf '%s' "$C_RST"; echo; hr
  printf '  %-22s %s\n' "Server"    "${VPN_DOMAIN} (${VPN_IP})"
  printf '  %-22s %s\n' "sing-box"  "$(sing-box version 2>/dev/null | awk 'NR==1{print $NF}') (${INSTALL_CHANNEL})"
  needs_any_cert && printf '  %-22s %s\n' "TLS certificate" "$CERT_MODE"
  hr
  printf '  %sProtocols & ports%s\n' "$C_BOLD" "$C_RST"
  local key; for key in $SELECTED; do printf '    %-16s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"; done
  hr
  printf '  %sClient bundles%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "${CLIENT_OUT_DIR}/links.txt          (individual share links)"
  printf '    %s\n' "${CLIENT_OUT_DIR}/subscription.txt   (base64 subscription)"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-singbox.json"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-clash.yaml"
  [[ $SUB_HOST == yes ]] && printf '    %s\n' "sub URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
  hr
  printf '  %sManage%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "singboxctl info        # reprint links / credentials"
  printf '    %s\n' "singboxctl status      # services + listening ports"
  printf '    %s\n' "singboxctl check       # health checks"
  printf '    %s\n' "singboxctl update      # upgrade sing-box"
  printf '    %s\n' "journalctl -u sing-box -f"
  hr
  printf '  %sCopy the bundle to your PC%s\n' "$C_BOLD" "$C_RST"
  printf '    %sscp -r root@%s:%s .%s\n' "$C_D" "${VPN_IP:-$VPN_DOMAIN}" "$CLIENT_OUT_DIR" "$C_RST"
  hr
  (( WARN_COUNT > 0 )) && { printf '  %s%d warning(s) above — scroll up.%s\n' "$C_Y" "$WARN_COUNT" "$C_RST"; hr; }
  echo
}

do_info() {
  [[ -r ${CLIENT_OUT_DIR}/links.txt ]] || die "No bundles found — run a deploy first."
  head1 "Share links"; cat "${CLIENT_OUT_DIR}/links.txt"
  echo; head1 "Base64 subscription (file: ${CLIENT_OUT_DIR}/subscription.txt)"; cat "${CLIENT_OUT_DIR}/subscription.txt"; echo
  [[ $SUB_HOST == yes ]] && { echo; ok "Subscription URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"; }
  echo; head1 "Full details"; cat "${CLIENT_OUT_DIR}/README.txt"
}

do_update() {
  head1 "Updating sing-box (${INSTALL_CHANNEL})"
  install_singbox
  if [[ -r $SB_CONF ]] && sing-box check -c "$SB_CONF" >/dev/null 2>&1; then
    systemctl restart sing-box; sleep 2
    systemctl is-active --quiet sing-box && ok "sing-box updated and restarted." || bad "sing-box did not come back up."
  else
    warn "Existing config missing or invalid for the new version; not restarting."
  fi
}

do_uninstall() {
  local go; ask_yn go "Remove sing-box config, certs, snell and firewall rules (binary is kept)" "no"
  [[ $go == yes ]] || die "Aborted."
  systemctl disable --now sing-box >/dev/null 2>&1 || true
  systemctl disable --now snell >/dev/null 2>&1 || true
  systemctl disable --now singbox-sub >/dev/null 2>&1 || true
  rm -f "$SB_CONF"
  rm -rf "$SB_CERT_DIR"
  rm -rf /etc/systemd/system/sing-box.service.d
  rm -f /etc/systemd/system/snell.service /etc/systemd/system/singbox-sub.service
  rm -f "$SNELL_CONF"
  rm -f /etc/sysctl.d/99-singbox.conf /etc/modules-load.d/singbox-bbr.conf
  iptables -D INPUT -j SINGBOX_IN 2>/dev/null || true
  iptables -F SINGBOX_IN 2>/dev/null || true; iptables -X SINGBOX_IN 2>/dev/null || true
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true
  ok "Removed. Kept: the sing-box/snell binaries, ${STATE_DIR} and ${CLIENT_OUT_DIR}."
  ok "Delete those by hand if you want them gone."
}

install_self() {
  local target="/usr/local/sbin/singboxctl"
  local src; src="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
  # Piping the script in (`bash <(curl ...)`, `curl ... | bash`) leaves
  # BASH_SOURCE pointing at a /dev/fd entry or a name that no longer exists, and
  # `install` then fails with "cannot stat". That must not look like a deploy
  # error — everything else has already succeeded by this point.
  if [[ -z $src || ! -f $src ]]; then
    warn "This script is not on disk as a regular file (piped in?), so ${target} was not installed."
    warn "Save it to the server and re-run to get the singboxctl helper, or call the file directly."
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
# 17. Main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  need_root
  install -d -m 0700 "$STATE_DIR"

  case "$CMD" in
    info)      load_state; do_info; exit 0 ;;
    status)    load_state; do_status; exit 0 ;;
    check)     load_state; verify_all; exit $? ;;
    update)    load_state; do_update; exit 0 ;;
    regen-sub) load_state; [[ -n $SELECTED ]] || die "No saved state — run a deploy first."; gen_artifacts; save_state; do_info; exit 0 ;;
    uninstall) load_state; do_uninstall; exit 0 ;;
    deploy)    : ;;
  esac

  printf '\n%s sing-box multi-protocol deployment for Ubuntu 22/24/26 — v%s %s\n' "$C_BOLD" "$SCRIPT_VERSION" "$C_RST"
  printf '%s pick all protocols or a subset; every secret and sub is generated for you %s\n\n' "$C_D" "$C_RST"

  load_state
  resolve_selection      # honour --protocols before the questionnaire
  collect_config

  start_logging
  [[ $SKIP_PREFLIGHT == yes ]] || preflight

  install_deps
  install_singbox
  install_snell
  gen_credentials
  setup_cert
  write_singbox_config
  write_snell_config
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
