#!/usr/bin/env bash
# =============================================================================
#  iKev2_Deployment.sh — strongSwan IKEv2/IPsec VPN for Ubuntu 22.04 LTS
#
#  Targets Windows 10/11 (native "IKEv2" client) and Android (strongSwan app).
#  Supports BOTH authentication styles:
#     * EAP-MSCHAPv2  (username + password)  -> required for Windows built-in UI
#     * Certificate   (PKCS#12 / machine cert)
#  Separate virtual-IP pools per auth type / platform.
#
#  Subcommands:
#     ./iKev2_Deployment.sh                  deploy (interactive, sane defaults)
#     ./iKev2_Deployment.sh add-client       create a new Windows/Android client
#     ./iKev2_Deployment.sh list-clients     list issued clients / EAP users
#     ./iKev2_Deployment.sh revoke-client    revoke a certificate or delete a user
#     ./iKev2_Deployment.sh status           live SAs
#     ./iKev2_Deployment.sh check            re-run all health checks
#     ./iKev2_Deployment.sh uninstall        remove config (keeps packages)
#
#  After deployment this file is installed as /usr/local/sbin/ikev2ctl
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# 0. Constants / cosmetics
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly STATE_DIR="/etc/ikev2"
readonly STATE_FILE="${STATE_DIR}/ikev2.env"
readonly PKI_DIR="${STATE_DIR}/pki"
readonly EAP_DB="${STATE_DIR}/eap-users"
readonly CLIENT_OUT_DIR="/root/ikev2-clients"
readonly SWANCTL_DIR="/etc/swanctl"
readonly CONFD="${SWANCTL_DIR}/conf.d"
readonly OSSL_LEGACY_CNF="${STATE_DIR}/openssl-legacy.cnf"
readonly LOGFILE="/var/log/ikev2-deploy.log"

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
  printf '\n%s[FATAL]%s iKev2_Deployment.sh failed at line %s (exit %s).\n' "$C_R" "$C_RST" "$line" "$rc" >&2
  printf '        Log: %s\n' "$LOGFILE" >&2
  exit "$rc"
}
trap 'on_err $LINENO' ERR

# -----------------------------------------------------------------------------
# 1. Defaults  (everything here is overridable via prompt or CLI flag)
# -----------------------------------------------------------------------------
# No defaults on purpose: these identify YOUR server and must be supplied every
# time, either at the prompt or with --domain / --ip.
VPN_DOMAIN=""
VPN_IP=""

CERT_MODE="self"            # self | letsencrypt
LE_EMAIL=""

KEY_TYPE="rsa"              # rsa | ecdsa   (Windows accepts RSA, P-256, P-384 only)
RSA_BITS="3072"
EC_CURVE="P-384"
CA_DAYS="3650"
SRV_DAYS="1825"
CLIENT_DAYS="1825"
ORG_NAME=""                 # empty -> derived from the domain you enter
COUNTRY="XX"

CRYPTO_PROFILE="compat"     # compat | balanced | strict

POOL_EAP="10.20.10.0/24"
POOL_CERT_WIN="10.20.11.0/24"
POOL_CERT_AND="10.20.12.0/24"
ENABLE_IPV6="no"
POOL_V6="fd42:1ke:v2::/64"

DNS_SERVERS="1.1.1.1,8.8.8.8"
SPLIT_INCLUDE=""            # empty = full tunnel; else e.g. "10.0.0.0/8,192.168.0.0/16"

CLIENT_MTU="1400"
MSS_CLAMP="1360"

FIREWALL="auto"             # auto | ufw | iptables | none
KERNEL_TUNING="yes"
ENABLE_BBR="yes"
ALLOW_CLIENT_TO_CLIENT="no"
FORCE_ENCAP="no"

FIRST_CLIENT="client1"
FIRST_PLATFORM="both"       # windows | android | both
FIRST_AUTH="both"           # eap | cert | both

ASSUME_YES="no"
SKIP_PREFLIGHT="no"
NIC=""

# add-client / revoke-client arguments
ARG_NAME=""
ARG_PLATFORM=""
ARG_AUTH=""

CMD="deploy"

# -----------------------------------------------------------------------------
# 2. Small helpers
# -----------------------------------------------------------------------------
need_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "This script must run as root (use: sudo bash $0)"; }

have() { command -v "$1" >/dev/null 2>&1; }

INTERACTIVE="yes"
[[ -r /dev/tty ]] || INTERACTIVE="no"

ask() { # ask VARNAME "Question" "default" ["hint shown when there is no default"]
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
    # stdin closed / EOF: stop asking and take defaults from here on, otherwise
    # any validation loop would spin forever.
    __in=""; INTERACTIVE="no"; printf '\n' >/dev/tty
  fi
  printf -v "$__var" '%s' "${__in:-$__def}"
}

# ask_valid VARNAME "Question" "default" validator_fn "error message"
#
# Never pass "$VAR" as its own default inside a hand-written retry loop: ask()
# assigns the rejected answer back to VAR, so the next round would offer the bad
# value as the default and an empty answer would re-accept it forever. This
# helper keeps the original default and is bounded.
ask_valid() { # ... "default" validator "error" ["hint when there is no default"]
  local __var=$1 __q=$2 __def=$3 __fn=$4 __err=$5 __hint=${6:-} __tries=0
  while true; do
    ask "$__var" "$__q" "$__def" "$__hint"
    if "$__fn" "${!__var}"; then return 0; fi
    printf '   %s\n' "$__err"
    __tries=$((__tries + 1))
    if (( __tries >= 10 )); then
      die "Too many invalid answers for: ${__q}"
    fi
    if [[ $INTERACTIVE == no || $ASSUME_YES == yes ]]; then
      if [[ -z $__def ]]; then
        die "No value given for '${__q}'. This field is required — supply it on the command line (see --help)."
      fi
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
  local -a __opts=("$@")
  local __i __in
  if [[ $ASSUME_YES == yes || $INTERACTIVE == no ]]; then
    printf -v "$__var" '%s' "$__def"; return 0
  fi
  printf '%s?%s %s\n' "$C_C" "$C_RST" "$__q" >/dev/tty
  for __i in "${!__opts[@]}"; do
    local mark=" "
    [[ ${__opts[$__i]} == "$__def" ]] && mark="*"
    printf '    %s%s) %s\n' "$mark" "$((__i+1))" "${__opts[$__i]}" >/dev/tty
  done
  while true; do
    printf '   choice %s[%s]%s: ' "$C_D" "$__def" "$C_RST" >/dev/tty
    if ! IFS= read -r __in </dev/tty; then
      __in=""; INTERACTIVE="no"; printf '\n' >/dev/tty
    fi
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

# NOTE: never write `tr </dev/urandom | head -c N`. head closes the pipe, tr dies
# of SIGPIPE, and `set -o pipefail` turns that into exit 141 for the whole script.
# Read a bounded number of bytes FIRST, then filter.
gen_pass() { # 20 chars, alnum only -> safe for MSCHAPv2, config files and shells
  local out
  out="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  [[ ${#out} -ge 20 ]] || out="$(LC_ALL=C head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9')"
  printf '%s' "${out:0:20}"
}

# The strongSwan Android app rejects a profile whose "uuid" is absent or not a
# valid RFC 4122 string, so never let this return empty.
gen_uuid() {
  local u=""
  [[ -r /proc/sys/kernel/random/uuid ]] && u="$(cat /proc/sys/kernel/random/uuid)"
  if [[ ! $u =~ ^[0-9a-fA-F-]{36}$ ]] && command -v uuidgen >/dev/null 2>&1; then
    u="$(uuidgen)"
  fi
  if [[ ! $u =~ ^[0-9a-fA-F-]{36}$ ]]; then
    local h; h="$(LC_ALL=C head -c 512 /dev/urandom | LC_ALL=C tr -dc 'a-f0-9')"
    h="${h:0:32}"
    u="${h:0:8}-${h:8:4}-4${h:13:3}-a${h:17:3}-${h:20:12}"
  fi
  printf '%s' "$u"
}

valid_ipv4() {
  [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o; for o in ${1//./ }; do (( o >= 0 && o <= 255 )) || return 1; done
  return 0
}
valid_cidr4() {
  [[ $1 =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3})/([0-9]{1,2})$ ]] || return 1
  # capture FIRST: valid_ipv4 runs its own =~ and overwrites BASH_REMATCH
  local ip="${BASH_REMATCH[1]}" plen="${BASH_REMATCH[3]}"
  valid_ipv4 "$ip" || return 1
  (( 10#$plen >= 8 && 10#$plen <= 30 )) || return 1
  return 0
}
valid_name()    { [[ $1 =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$ ]]; }
valid_domain()  { [[ $1 =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$ ]]; }
valid_country() { [[ $1 =~ ^[A-Za-z]{2}$ ]]; }
valid_days()    { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 > 0 )); }
valid_port_num(){ [[ $1 =~ ^[0-9]{2,5}$ ]] && (( 10#$1 >= 576 && 10#$1 <= 9000 )); }

# normalise "a, b ,c" -> "a, b, c"
csv_norm() { printf '%s' "$1" | tr -d ' ' | sed 's/,/, /g'; }

save_state() {
  install -d -m 0700 "$STATE_DIR"
  cat >"$STATE_FILE" <<EOF
# generated by iKev2_Deployment.sh v${SCRIPT_VERSION} on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
VPN_DOMAIN='${VPN_DOMAIN}'
VPN_IP='${VPN_IP}'
CERT_MODE='${CERT_MODE}'
LE_EMAIL='${LE_EMAIL}'
KEY_TYPE='${KEY_TYPE}'
RSA_BITS='${RSA_BITS}'
EC_CURVE='${EC_CURVE}'
CA_DAYS='${CA_DAYS}'
SRV_DAYS='${SRV_DAYS}'
CLIENT_DAYS='${CLIENT_DAYS}'
ORG_NAME='${ORG_NAME}'
COUNTRY='${COUNTRY}'
CRYPTO_PROFILE='${CRYPTO_PROFILE}'
POOL_EAP='${POOL_EAP}'
POOL_CERT_WIN='${POOL_CERT_WIN}'
POOL_CERT_AND='${POOL_CERT_AND}'
ENABLE_IPV6='${ENABLE_IPV6}'
POOL_V6='${POOL_V6}'
DNS_SERVERS='${DNS_SERVERS}'
SPLIT_INCLUDE='${SPLIT_INCLUDE}'
CLIENT_MTU='${CLIENT_MTU}'
MSS_CLAMP='${MSS_CLAMP}'
FIREWALL='${FIREWALL}'
KERNEL_TUNING='${KERNEL_TUNING}'
ENABLE_BBR='${ENABLE_BBR}'
ALLOW_CLIENT_TO_CLIENT='${ALLOW_CLIENT_TO_CLIENT}'
FORCE_ENCAP='${FORCE_ENCAP}'
NIC='${NIC}'
EOF
  chmod 0600 "$STATE_FILE"
}

load_state() {
  # MUST return 0 even when the file is absent: this runs under `set -e`, and on
  # a fresh server there is no state file yet.
  if [[ -r $STATE_FILE ]]; then
    # shellcheck source=/dev/null
    source "$STATE_FILE" || warn "Could not parse ${STATE_FILE}; using defaults."
  fi
  [[ -n ${ORG_NAME:-} ]] || ORG_NAME="${VPN_DOMAIN:-IKEv2} VPN"
  return 0
}

start_logging() {
  exec > >(tee -a "$LOGFILE") 2>&1
  log "Logging this run to ${LOGFILE}"
}

# Is <port> bound? `ss` column positions are not stable enough to trust
# (the local address is $4, NOT $5 — getting that wrong makes every port look
# free), so ask ss to filter, and only fall back to column parsing.
port_listening() { # port_listening <udp|tcp> <port>
  local flag="-lun"
  [[ $1 == tcp ]] && flag="-ltn"
  # Column 4 is "Local Address:Port". Matching column 5 (the peer, always
  # 0.0.0.0:*) is what made every port look free. A header line may or may not
  # be present, so match on the field rather than on the row number.
  ss $flag 2>/dev/null | awk -v p=":$2\$" '$4 ~ p {f=1} END{exit !f}'
}

port_listener_name() { # port_listener_name <udp|tcp> <port>
  local flag="-lunp"
  [[ $1 == tcp ]] && flag="-ltnp"
  ss $flag 2>/dev/null | awk -v p=":$2\$" '$4 ~ p {print; exit}' \
    | grep -oE 'users:\(\("[^"]+' | head -1 | sed 's/.*"//'
}

SS_SERVICE=""
detect_service() {
  # On Ubuntu 22.04 "strongswan.service" is an ALIAS for strongswan-starter (the
  # legacy stroke daemon), and that alias disappears once the starter is
  # disabled. Never pick a unit by name alone — pick the one that actually
  # executes charon-systemd, which is the daemon swanctl talks to.
  local u
  SS_SERVICE=""
  for u in strongswan-swanctl.service strongswan.service; do
    if systemctl cat "$u" 2>/dev/null | grep -qE 'ExecStart=.*charon-systemd'; then
      SS_SERVICE="$u"; return 0
    fi
  done
  for u in strongswan-swanctl.service strongswan.service; do
    if systemctl list-unit-files --no-legend "$u" 2>/dev/null | grep -q .; then
      SS_SERVICE="$u"; return 0
    fi
  done
  SS_SERVICE="strongswan.service"
}

reload_config() {
  swanctl --load-all --noprompt >/dev/null 2>&1 \
    || swanctl --load-all >/dev/null 2>&1 \
    || warn "swanctl --load-all reported an error (run it manually to see why)"
}

usage() {
cat <<EOF
${C_BOLD}iKev2_Deployment.sh v${SCRIPT_VERSION}${C_RST} — strongSwan IKEv2 for Ubuntu 22.04 (Windows + Android)

Usage:
  sudo bash iKev2_Deployment.sh [subcommand] [options]

Subcommands:
  deploy                 (default) install and configure everything
  add-client             create a new client bundle
  list-clients           show issued certificates and EAP users
  revoke-client          revoke a client certificate / delete an EAP user
  status                 show live IKE/CHILD SAs
  check                  re-run every health check
  repair-md4             re-apply the MD4/EAP-MSCHAPv2 fix and restart charon
  uninstall              remove configuration (packages are kept)

Common options:
  -y, --yes                    non-interactive; requires --domain and --ip
      --domain <fqdn>          REQUIRED, e.g. vpn.example.com
      --ip <ipv4>              REQUIRED, the server's public IPv4 address
      --cert-mode <self|letsencrypt>
      --le-email <email>
      --key-type <rsa|ecdsa>
      --profile <compat|balanced|strict>
      --pool-eap <cidr>        default: ${POOL_EAP}
      --pool-cert-win <cidr>   default: ${POOL_CERT_WIN}
      --pool-cert-android <cidr> default: ${POOL_CERT_AND}
      --dns <a,b>              default: ${DNS_SERVERS}
      --ipv6 <yes|no>
      --firewall <auto|ufw|iptables|none>
      --no-kernel-tuning
      --skip-preflight
  add-client options:
      --name <name> --platform <windows|android|both> --auth <eap|cert|both>
  revoke-client options:
      --name <name>
EOF
}

# -----------------------------------------------------------------------------
# 3. Argument parsing
# -----------------------------------------------------------------------------
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      deploy|add-client|list-clients|revoke-client|status|check|uninstall|repair-md4) CMD="$1"; shift ;;
      -y|--yes)              ASSUME_YES="yes"; shift ;;
      --domain)              VPN_DOMAIN="$2"; shift 2 ;;
      --ip)                  VPN_IP="$2"; shift 2 ;;
      --cert-mode)           CERT_MODE="$2"; shift 2 ;;
      --le-email)            LE_EMAIL="$2"; shift 2 ;;
      --key-type)            KEY_TYPE="$2"; shift 2 ;;
      --profile)             CRYPTO_PROFILE="$2"; shift 2 ;;
      --pool-eap)            POOL_EAP="$2"; shift 2 ;;
      --pool-cert-win)       POOL_CERT_WIN="$2"; shift 2 ;;
      --pool-cert-android)   POOL_CERT_AND="$2"; shift 2 ;;
      --dns)                 DNS_SERVERS="$2"; shift 2 ;;
      --ipv6)                ENABLE_IPV6="$2"; shift 2 ;;
      --firewall)            FIREWALL="$2"; shift 2 ;;
      --no-kernel-tuning)    KERNEL_TUNING="no"; shift ;;
      --skip-preflight)      SKIP_PREFLIGHT="yes"; shift ;;
      --name)                ARG_NAME="$2"; shift 2 ;;
      --platform)            ARG_PLATFORM="$2"; shift 2 ;;
      --auth)                ARG_AUTH="$2"; shift 2 ;;
      -h|--help)             usage; exit 0 ;;
      -*) die "Unknown option: $1  (try --help)" ;;
      *)
        # bare word = client name, so `ikev2ctl add-client laptop` just works
        if [[ -z $ARG_NAME ]]; then ARG_NAME="$1"; shift
        else die "Unexpected argument: $1  (try --help)"; fi ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# 4. Interactive configuration
# -----------------------------------------------------------------------------
collect_config() {
  head1 "Configuration"
  echo "Press ENTER to accept the value in brackets."
  echo

  local ip_hint="required, e.g. 203.0.113.10" detected=""
  if [[ -z $VPN_IP ]]; then
    detected="$(detect_public_ip || true)"
    [[ -n $detected ]] && ip_hint="required — this host appears to be ${detected}"
  fi

  ask_valid VPN_DOMAIN "Server domain name (the FQDN clients will type)" "$VPN_DOMAIN" \
    valid_domain "that does not look like a domain name" \
    "required, e.g. vpn.example.com"
  ask_valid VPN_IP "Server public IPv4 address" "$VPN_IP" \
    valid_ipv4 "that is not a valid IPv4 address" \
    "$ip_hint"

  # Certificate organisation defaults to the domain rather than being hardcoded.
  [[ -n $ORG_NAME ]] || ORG_NAME="${VPN_DOMAIN} VPN"

  ask_choice CERT_MODE "Server certificate source" "$CERT_MODE" self letsencrypt
  if [[ $CERT_MODE == letsencrypt ]]; then
    ask LE_EMAIL "Let's Encrypt contact e-mail (blank = register without one)" "$LE_EMAIL"
  fi

  ask_choice KEY_TYPE "Key algorithm (Windows accepts RSA, P-256 and P-384 only)" "$KEY_TYPE" rsa ecdsa
  if [[ $KEY_TYPE == rsa ]]; then
    ask_choice RSA_BITS "RSA key size" "$RSA_BITS" 2048 3072 4096
  else
    ask_choice EC_CURVE "ECDSA curve" "$EC_CURVE" P-256 P-384
  fi

  echo
  echo "  ${C_BOLD}compat${C_RST}   – accepts stock Windows defaults (incl. modp1024/3DES). Nothing to configure on the PC."
  echo "  ${C_BOLD}balanced${C_RST} – AES-256 + SHA-256 + modp2048/ECP384. Windows needs the generated .ps1 (it applies it for you)."
  echo "  ${C_BOLD}strict${C_RST}   – AES-256-GCM + ECP384 only. Windows MUST use the generated .ps1."
  ask_choice CRYPTO_PROFILE "Crypto profile" "$CRYPTO_PROFILE" compat balanced strict

  echo
  echo "  Three separate virtual-IP pools are created so you can tell traffic apart:"
  ask_valid POOL_EAP      "Pool for username/password (EAP) clients" "$POOL_EAP" \
    valid_cidr4 "expected a private CIDR with a /8../30 prefix, e.g. 10.20.10.0/24"
  ask_valid POOL_CERT_WIN "Pool for Windows certificate clients"     "$POOL_CERT_WIN" \
    valid_cidr4 "expected a private CIDR with a /8../30 prefix, e.g. 10.20.11.0/24"
  ask_valid POOL_CERT_AND "Pool for Android certificate clients"     "$POOL_CERT_AND" \
    valid_cidr4 "expected a private CIDR with a /8../30 prefix, e.g. 10.20.12.0/24"
  if [[ $POOL_EAP == "$POOL_CERT_WIN" || $POOL_EAP == "$POOL_CERT_AND" || $POOL_CERT_WIN == "$POOL_CERT_AND" ]]; then
    die "The three pools must use different subnets (got ${POOL_EAP}, ${POOL_CERT_WIN}, ${POOL_CERT_AND})."
  fi

  ask DNS_SERVERS "DNS servers pushed to clients (comma separated)" "$DNS_SERVERS"
  DNS_SERVERS="$(csv_norm "$DNS_SERVERS")"

  ask SPLIT_INCLUDE "Split-tunnel subnets (blank = full tunnel / route everything)" "$SPLIT_INCLUDE"
  ask_yn ENABLE_IPV6 "Also hand out IPv6 addresses" "$ENABLE_IPV6"
  [[ $ENABLE_IPV6 == yes ]] && ask POOL_V6 "IPv6 ULA pool" "$POOL_V6"

  ask_valid CLIENT_MTU "MTU advertised to Android clients" "$CLIENT_MTU" \
    valid_port_num "expected a number between 576 and 9000"
  ask_valid MSS_CLAMP "TCP MSS clamp for forwarded VPN traffic" "$MSS_CLAMP" \
    valid_port_num "expected a number between 576 and 9000"

  ask_choice FIREWALL "Firewall backend" "$FIREWALL" auto ufw iptables none
  ask_yn KERNEL_TUNING "Apply kernel/sysctl tuning" "$KERNEL_TUNING"
  [[ $KERNEL_TUNING == yes ]] && ask_yn ENABLE_BBR "Enable BBR congestion control + fq qdisc" "$ENABLE_BBR"
  ask_yn ALLOW_CLIENT_TO_CLIENT "Allow VPN clients to reach each other" "$ALLOW_CLIENT_TO_CLIENT"
  ask_yn FORCE_ENCAP "Force UDP-encapsulation of ESP (helps on hostile networks)" "$FORCE_ENCAP"

  echo
  local adv="no"
  ask_yn adv "Show advanced options (certificate naming and lifetimes)" "no"
  if [[ $adv == yes ]]; then
    ask ORG_NAME "Organisation name written into the certificates" "$ORG_NAME"
    ask_valid COUNTRY "Two-letter country code for the certificates" "$COUNTRY" \
      valid_country "must be exactly two letters (for example DE, NL, US)"
    COUNTRY="${COUNTRY^^}"
    ask_valid CA_DAYS     "CA certificate lifetime in days"     "$CA_DAYS"     valid_days "must be a positive whole number"
    ask_valid SRV_DAYS    "Server certificate lifetime in days" "$SRV_DAYS"    valid_days "must be a positive whole number"
    ask_valid CLIENT_DAYS "Client certificate lifetime in days" "$CLIENT_DAYS" valid_days "must be a positive whole number"
    ask_yn SKIP_PREFLIGHT "Skip the pre-flight checks (not recommended)" "$SKIP_PREFLIGHT"
  fi

  echo
  ask_valid FIRST_CLIENT "Name of the first client to create" "$FIRST_CLIENT" \
    valid_name "use letters, digits, dot, dash or underscore (max 32 characters)"
  ask_choice FIRST_PLATFORM "First client platform" "$FIRST_PLATFORM" both windows android
  ask_choice FIRST_AUTH "First client authentication" "$FIRST_AUTH" both eap cert

  echo
  hr
  printf '  %-26s %s\n' "Domain"            "$VPN_DOMAIN"
  printf '  %-26s %s\n' "Public IP"         "$VPN_IP"
  printf '  %-26s %s\n' "Server cert"       "$CERT_MODE"
  printf '  %-26s %s\n' "Key"               "$([[ $KEY_TYPE == rsa ]] && echo "RSA-${RSA_BITS}" || echo "ECDSA-${EC_CURVE}")"
  printf '  %-26s %s\n' "Crypto profile"    "$CRYPTO_PROFILE"
  printf '  %-26s %s\n' "Pool EAP"          "$POOL_EAP"
  printf '  %-26s %s\n' "Pool cert/Windows" "$POOL_CERT_WIN"
  printf '  %-26s %s\n' "Pool cert/Android" "$POOL_CERT_AND"
  printf '  %-26s %s\n' "DNS"               "$DNS_SERVERS"
  printf '  %-26s %s\n' "IPv6"              "$ENABLE_IPV6"
  printf '  %-26s %s\n' "Firewall"          "$FIREWALL"
  printf '  %-26s %s\n' "Kernel tuning"     "$KERNEL_TUNING"
  hr
  local go
  ask_yn go "Proceed with these settings" "yes"
  [[ $go == yes ]] || die "Aborted by user."
}

# -----------------------------------------------------------------------------
# 5. Pre-flight checks (terminal verification of domain / IP / DNS / clock)
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
  NIC="$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')"
  [[ -n $NIC ]] || NIC="$(ip -o link show | awk -F': ' '$2!="lo"{print $2; exit}')"
  [[ -n $NIC ]] || die "Could not determine the outbound network interface."
}

preflight() {
  head1 "Pre-flight checks"

  # --- OS ---------------------------------------------------------------
  if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    if [[ ${ID:-} == ubuntu && ${VERSION_ID:-} == "22.04" ]]; then
      ok "OS: ${PRETTY_NAME:-Ubuntu 22.04}"
    else
      warn "OS is '${PRETTY_NAME:-unknown}', this script targets Ubuntu 22.04 — continuing anyway."
    fi
  else
    warn "/etc/os-release missing; cannot verify the distribution."
  fi

  # --- architecture / virtualisation ------------------------------------
  local virt="none"
  have systemd-detect-virt && virt="$(systemd-detect-virt 2>/dev/null || echo none)"
  case "$virt" in
    openvz|lxc|lxc-libvirt|docker|podman)
      warn "Virtualisation is '${virt}'. Containers usually lack the XFRM/IPsec kernel stack."
      warn "If the VPN never establishes, you need a KVM/Xen VPS instead." ;;
    *) ok "Virtualisation: ${virt}" ;;
  esac

  # --- kernel IPsec support --------------------------------------------
  modprobe af_key    >/dev/null 2>&1 || true
  modprobe xfrm_user >/dev/null 2>&1 || true
  modprobe esp4      >/dev/null 2>&1 || true
  modprobe xt_policy >/dev/null 2>&1 || true
  if [[ -e /proc/net/xfrm_stat ]]; then
    ok "Kernel XFRM (IPsec) stack present."
  else
    bad "/proc/net/xfrm_stat is missing — this kernel cannot do IPsec."
    [[ $SKIP_PREFLIGHT == yes ]] || die "Aborting (use --skip-preflight to override)."
  fi

  # --- network interface ------------------------------------------------
  detect_nic
  ok "Outbound interface: ${NIC}"
  local local_ips; local_ips="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
  ok "Local IPv4 address(es): ${local_ips:-none}"

  # --- real public IP ---------------------------------------------------
  local pub=""; pub="$(detect_public_ip || true)"
  if [[ -n $pub ]]; then
    if [[ $pub == "$VPN_IP" ]]; then
      ok "Public IP confirmed: ${pub}"
    else
      warn "Detected public IP is ${pub} but you configured ${VPN_IP}."
      warn "That is fine if this box is behind 1:1 NAT — otherwise fix --ip."
    fi
  else
    warn "Could not determine the public IP (no outbound HTTPS?)."
  fi

  if [[ " $local_ips " == *" $VPN_IP "* ]]; then
    ok "${VPN_IP} is bound locally on this host."
  else
    warn "${VPN_IP} is not bound to a local interface — assuming NAT / floating IP."
  fi

  # --- DNS --------------------------------------------------------------
  if have dig; then
    local resolvers=("1.1.1.1" "8.8.8.8" "9.9.9.9") r answer all_ok=1 seen=""
    for r in "${resolvers[@]}"; do
      answer="$(dig +short +time=3 +tries=2 A "$VPN_DOMAIN" "@${r}" 2>/dev/null | grep -E '^[0-9.]+$' | tr '\n' ' ' || true)"
      answer="$(printf '%s' "$answer" | sed 's/ *$//')"
      if [[ -z $answer ]]; then
        warn "DNS @${r}: ${VPN_DOMAIN} has no A record."
        all_ok=0
      elif [[ " $answer " == *" $VPN_IP "* ]]; then
        ok "DNS @${r}: ${VPN_DOMAIN} -> ${answer}"
      else
        warn "DNS @${r}: ${VPN_DOMAIN} -> ${answer} (expected ${VPN_IP})"
        all_ok=0
      fi
      seen="$seen $answer"
    done

    # Cloudflare-proxy detection: IKEv2 is UDP, Cloudflare's proxy cannot carry it.
    if printf '%s' "$seen" | grep -qE '(^| )(104\.(1[6-9]|2[0-9]|3[01])\.|172\.6[4-9]\.|172\.7[0-1]\.|188\.114\.9[6-9]\.|162\.15[89]\.|198\.41\.|190\.93\.|197\.234\.24[0-3]\.|103\.21\.24[4-7]\.|141\.101\.6[4-9]\.|108\.162\.19[2-9]\.)'; then
      bad "${VPN_DOMAIN} resolves to a Cloudflare proxy address."
      bad "IKEv2 is UDP/500 + UDP/4500 — Cloudflare's orange cloud CANNOT proxy it."
      bad "In the Cloudflare dashboard set the A record to 'DNS only' (grey cloud)."
      all_ok=0
    fi

    if [[ $all_ok -eq 1 ]]; then
      ok "Domain ${VPN_DOMAIN} correctly points at ${VPN_IP} on all resolvers."
    else
      warn "DNS is not fully consistent. Certificate clients can still connect by IP,"
      warn "but Let's Encrypt issuance will fail until DNS is correct."
    fi
  else
    warn "'dig' not installed yet — DNS will be re-checked after package installation."
  fi

  # --- ports free -------------------------------------------------------
  local p
  for p in 500 4500; do
    if port_listening udp "$p"; then
      local who; who="$(port_listener_name udp "$p")"
      if [[ $who == charon* || $who == starter* ]]; then
        ok "UDP/${p} already held by ${who} (re-run / reconfigure)."
      else
        warn "UDP/${p} is already in use by '${who:-unknown}'."
      fi
    else
      ok "UDP/${p} is free."
    fi
  done
  if [[ $CERT_MODE == letsencrypt ]]; then
    if port_listening tcp 80; then
      bad "TCP/80 is in use — certbot --standalone needs it. Stop that service first."
    else
      ok "TCP/80 free for the Let's Encrypt HTTP-01 challenge."
    fi
  fi

  # --- clock ------------------------------------------------------------
  local synced="unknown"
  if have timedatectl; then
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  fi
  case "$synced" in
    yes) ok "Clock is NTP-synchronised: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" ;;
    no)  warn "Clock is NOT NTP-synchronised. Certificate validation is time sensitive."
         warn "chrony will be installed to fix this." ;;
    *)   warn "Cannot verify clock sync; current UTC time: $(date -u '+%Y-%m-%d %H:%M:%S')" ;;
  esac

  # --- entropy / disk ---------------------------------------------------
  local avail; avail="$(df -Pm / | awk 'NR==2{print $4}')"
  if (( avail < 512 )); then warn "Only ${avail} MB free on / — installation may fail."
  else ok "Free disk space on /: ${avail} MB"; fi

  echo
  if (( FAIL_COUNT > 0 )) && [[ $SKIP_PREFLIGHT != yes ]]; then
    local go
    ask_yn go "There are ${FAIL_COUNT} hard failure(s) above. Continue anyway" "no"
    [[ $go == yes ]] || die "Aborted after pre-flight failures."
  fi
  FAIL_COUNT=0
}

# -----------------------------------------------------------------------------
# 6. Packages
# -----------------------------------------------------------------------------
install_packages() {
  head1 "Installing packages"
  export DEBIAN_FRONTEND=noninteractive

  echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections

  log "apt-get update ..."
  apt-get update -qq

  local base=(
    strongswan strongswan-swanctl strongswan-pki
    libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins
    openssl ca-certificates curl dnsutils iproute2 iptables
    zip unzip uuid-runtime chrony
  )
  log "Installing: ${base[*]}"
  if ! apt-get install -y -qq "${base[@]}" >/dev/null 2>&1; then
    warn "Batch install failed — retrying package by package to isolate the problem."
    local pkg missing=()
    for pkg in "${base[@]}"; do
      apt-get install -y -qq "$pkg" >/dev/null 2>&1 || missing+=("$pkg")
    done
    if (( ${#missing[@]} > 0 )); then
      warn "Could not install: ${missing[*]}"
      for pkg in "${missing[@]}"; do
        case "$pkg" in
          strongswan|strongswan-swanctl|strongswan-pki|openssl)
            die "'${pkg}' is essential and could not be installed. Fix apt, then re-run." ;;
        esac
      done
    fi
  fi

  # charon-systemd is a separate binary package on jammy
  if apt-cache show charon-systemd >/dev/null 2>&1; then
    apt-get install -y -qq charon-systemd >/dev/null || warn "charon-systemd could not be installed."
  fi

  if [[ $FIREWALL == iptables || $FIREWALL == auto ]]; then
    apt-get install -y -qq iptables-persistent >/dev/null 2>&1 \
      || warn "iptables-persistent not installed; rules will not survive reboot without it."
  fi

  if [[ $CERT_MODE == letsencrypt ]]; then
    apt-get install -y -qq certbot >/dev/null || die "Failed to install certbot."
  fi

  systemctl enable --now chrony >/dev/null 2>&1 || systemctl enable --now chronyd >/dev/null 2>&1 || true

  ok "strongSwan version: $(ipsec --version 2>/dev/null | head -1 || echo unknown)"
  ok "OpenSSL version:    $(openssl version)"
}

# strongSwan's legacy `ipsec`/starter daemon fights charon-systemd over UDP/500.
disable_starter() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^strongswan-starter\.service'; then
    systemctl disable --now strongswan-starter.service >/dev/null 2>&1 || true
    ok "Disabled legacy strongswan-starter.service (swanctl/charon-systemd is used)."
  fi
}

# -----------------------------------------------------------------------------
# 7. OpenSSL legacy provider — required for MD4 (EAP-MSCHAPv2) on OpenSSL 3.x
# -----------------------------------------------------------------------------
setup_openssl_legacy() {
  head1 "OpenSSL legacy provider (MD4 / EAP-MSCHAPv2)"
  install -d -m 0755 "$STATE_DIR"
  cat >"$OSSL_LEGACY_CNF" <<'EOF'
# Minimal OpenSSL configuration used ONLY by the strongSwan daemon.
# OpenSSL 3.x moved MD4 into the "legacy" provider; EAP-MSCHAPv2 needs MD4.
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy  = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
EOF
  chmod 0644 "$OSSL_LEGACY_CNF"

  detect_service
  # Write the drop-in for EVERY strongSwan unit that exists. Picking one name is
  # fragile: on Jammy "strongswan.service" is an alias for strongswan-starter and
  # vanishes when the starter is disabled, which would leave the drop-in attached
  # to a unit that never runs — and charon would silently lose MD4.
  local u dropdir wrote=""
  for u in strongswan-swanctl.service strongswan.service; do
    systemctl list-unit-files --no-legend "$u" >/dev/null 2>&1 || continue
    systemctl cat "$u" >/dev/null 2>&1 || continue
    dropdir="/etc/systemd/system/${u}.d"
    install -d -m 0755 "$dropdir"
    cat >"${dropdir}/10-openssl-legacy.conf" <<EOF
[Service]
Environment=OPENSSL_CONF=${OSSL_LEGACY_CNF}
EOF
    wrote="${wrote} ${u}"
  done
  systemctl daemon-reload
  if [[ -n $wrote ]]; then
    ok "Legacy provider enabled for:${wrote} (system-wide TLS untouched)."
  else
    warn "No strongSwan systemd unit found yet for the OPENSSL_CONF drop-in."
  fi
}

# -----------------------------------------------------------------------------
# 8. PKI
# -----------------------------------------------------------------------------
gen_key() { # gen_key <outfile>
  local out=$1
  if [[ $KEY_TYPE == rsa ]]; then
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${RSA_BITS}" -out "$out" 2>/dev/null
  else
    local curve="prime256v1"
    [[ $EC_CURVE == P-384 ]] && curve="secp384r1"
    openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve}" \
      -pkeyopt ec_param_enc:named_curve -out "$out" 2>/dev/null
  fi
  chmod 0600 "$out"
}

write_openssl_cnf() {
  local ku_srv ku_cli
  if [[ $KEY_TYPE == rsa ]]; then
    ku_srv="critical, digitalSignature, keyEncipherment"
    ku_cli="critical, digitalSignature, keyEncipherment"
  else
    ku_srv="critical, digitalSignature"
    ku_cli="critical, digitalSignature"
  fi

  # subjectAltName for the gateway.
  #  * strongSwan docs: put the IP literal in a DNS: entry too, otherwise the
  #    Windows client raises error 13801 when the user types the bare IP.
  cat >"${PKI_DIR}/openssl.cnf" <<EOF
# Generated by iKev2_Deployment.sh — CA for ${VPN_DOMAIN}
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = ${PKI_DIR}
database          = \$dir/db/index.txt
serial            = \$dir/db/serial
crlnumber         = \$dir/db/crlnumber
new_certs_dir     = \$dir/db/newcerts
certificate       = \$dir/ca/ca-cert.pem
private_key       = \$dir/ca/ca-key.pem
default_md        = sha256
default_days      = ${CLIENT_DAYS}
default_crl_days  = 365
preserve          = no
policy            = policy_loose
unique_subject    = no
copy_extensions   = none
email_in_dn       = no
name_opt          = ca_default
cert_opt          = ca_default

[ policy_loose ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ req ]
default_md         = sha256
distinguished_name = req_dn
string_mask        = utf8only
prompt             = no

[ req_dn ]
CN = placeholder

[ v3_ca ]
basicConstraints       = critical, CA:TRUE, pathlen:0
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
keyUsage               = critical, keyCertSign, cRLSign

[ v3_server ]
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
keyUsage               = ${ku_srv}
# serverAuth is mandatory for Windows; 1.3.6.1.5.5.8.2.2 == ikeIntermediate
extendedKeyUsage       = serverAuth, 1.3.6.1.5.5.8.2.2
subjectAltName         = @srv_alt

[ srv_alt ]
DNS.1 = ${VPN_DOMAIN}
DNS.2 = ${VPN_IP}
IP.1  = ${VPN_IP}
EOF
  chmod 0640 "${PKI_DIR}/openssl.cnf"

  # Client extensions live in their own file, written per client with a concrete
  # subjectAltName. They deliberately do NOT live in openssl.cnf: OpenSSL expands
  # every \${ENV::...} reference when it *loads* the config, so a placeholder
  # there makes every unrelated openssl invocation fail with
  # "variable has no value".
  printf '%s\n' "$ku_cli" >"${PKI_DIR}/.client_ku"
}

write_client_ext() { # write_client_ext <outfile> <rfc822-identity>
  local out=$1 ident=$2 ku
  ku="$(cat "${PKI_DIR}/.client_ku" 2>/dev/null || echo 'critical, digitalSignature, keyEncipherment')"
  cat >"$out" <<EOF
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
keyUsage               = ${ku}
# Windows rejects a client certificate whose EKU does not contain clientAuth
extendedKeyUsage       = clientAuth, 1.3.6.1.5.5.8.2.2
subjectAltName         = email:${ident}
EOF
}

pki_init() {
  head1 "Building the PKI"
  install -d -m 0700 "$PKI_DIR" "${PKI_DIR}/ca" "${PKI_DIR}/server" \
                     "${PKI_DIR}/clients" "${PKI_DIR}/db" "${PKI_DIR}/db/newcerts" \
                     "${PKI_DIR}/csr"

  [[ -f ${PKI_DIR}/db/index.txt ]]      || : >"${PKI_DIR}/db/index.txt"
  [[ -f ${PKI_DIR}/db/index.txt.attr ]] || echo "unique_subject = no" >"${PKI_DIR}/db/index.txt.attr"
  [[ -f ${PKI_DIR}/db/serial ]]         || echo "01" >"${PKI_DIR}/db/serial"
  [[ -f ${PKI_DIR}/db/crlnumber ]]      || echo "01" >"${PKI_DIR}/db/crlnumber"

  write_openssl_cnf

  if [[ -f ${PKI_DIR}/ca/ca-cert.pem && -f ${PKI_DIR}/ca/ca-key.pem ]]; then
    ok "Re-using the existing CA (issued clients stay valid)."
  else
    log "Generating CA key ..."
    gen_key "${PKI_DIR}/ca/ca-key.pem"
    log "Self-signing the CA certificate (${CA_DAYS} days) ..."
    openssl req -new -x509 -sha256 -days "$CA_DAYS" \
      -config "${PKI_DIR}/openssl.cnf" -extensions v3_ca \
      -key "${PKI_DIR}/ca/ca-key.pem" \
      -out "${PKI_DIR}/ca/ca-cert.pem" \
      -subj "/C=${COUNTRY}/O=${ORG_NAME}/CN=${ORG_NAME} Root CA" \
      || die "Failed to self-sign the CA certificate (see the openssl error above)."
    chmod 0600 "${PKI_DIR}/ca/ca-key.pem"
    chmod 0644 "${PKI_DIR}/ca/ca-cert.pem"
    ok "CA created: $(openssl x509 -noout -subject -in "${PKI_DIR}/ca/ca-cert.pem" | sed 's/^subject= *//')"
  fi

  pki_gen_crl
}

pki_gen_crl() {
  openssl ca -config "${PKI_DIR}/openssl.cnf" -gencrl -batch \
    -out "${PKI_DIR}/ca/crl.pem" >/dev/null 2>&1 \
    || { warn "Could not generate the CRL."; return 0; }
  install -d -m 0755 "${SWANCTL_DIR}/x509crl"
  install -m 0644 "${PKI_DIR}/ca/crl.pem" "${SWANCTL_DIR}/x509crl/ca.crl.pem"
}

pki_server_cert() {
  head1 "Server certificate"
  if [[ $CERT_MODE == letsencrypt ]]; then
    issue_letsencrypt
    return
  fi

  local key="${PKI_DIR}/server/server-key.pem"
  local crt="${PKI_DIR}/server/server-cert.pem"
  local csr="${PKI_DIR}/csr/server.csr"

  local regen="yes"
  if [[ -f $crt && -f $key ]]; then
    if openssl x509 -in "$crt" -noout -checkend 2592000 >/dev/null 2>&1 \
       && openssl x509 -in "$crt" -noout -text | grep -q "DNS:${VPN_DOMAIN}\b"; then
      regen="no"
    fi
  fi

  if [[ $regen == yes ]]; then
    log "Generating server key + certificate for ${VPN_DOMAIN} ..."
    gen_key "$key"
    openssl req -new -sha256 -config "${PKI_DIR}/openssl.cnf" -key "$key" -out "$csr" \
      -subj "/C=${COUNTRY}/O=${ORG_NAME}/CN=${VPN_DOMAIN}" \
      || die "Failed to create the server CSR."
    rm -f "$crt"
    openssl ca -config "${PKI_DIR}/openssl.cnf" -batch -notext \
      -extensions v3_server -days "$SRV_DAYS" -md sha256 \
      -in "$csr" -out "$crt" \
      || die "Failed to sign the server certificate."
    ok "Server certificate issued (${SRV_DAYS} days)."
  else
    ok "Existing server certificate is still valid and matches ${VPN_DOMAIN}."
  fi

  install -d -m 0755 "${SWANCTL_DIR}/x509" "${SWANCTL_DIR}/x509ca"
  install -d -m 0700 "${SWANCTL_DIR}/private"
  install -m 0644 "$crt" "${SWANCTL_DIR}/x509/server-cert.pem"
  install -m 0644 "${PKI_DIR}/ca/ca-cert.pem" "${SWANCTL_DIR}/x509ca/ca-cert.pem"
  install -m 0600 "$key" "${SWANCTL_DIR}/private/server-key.pem"
  rm -f "${SWANCTL_DIR}/x509ca/le-chain.pem"
}

issue_letsencrypt() {
  log "Requesting a Let's Encrypt certificate for ${VPN_DOMAIN} ..."
  local live="/etc/letsencrypt/live/${VPN_DOMAIN}"

  # port 80 must be reachable for HTTP-01
  open_port80_temporarily

  if [[ ! -d $live ]]; then
    local emailargs=(--register-unsafely-without-email)
    [[ -n $LE_EMAIL ]] && emailargs=(--email "$LE_EMAIL")
    certbot certonly --standalone --non-interactive --agree-tos \
      "${emailargs[@]}" -d "$VPN_DOMAIN" --preferred-challenges http \
      || die "Let's Encrypt issuance failed. Check that ${VPN_DOMAIN} resolves to ${VPN_IP} and TCP/80 is open."
  else
    certbot renew --quiet >/dev/null 2>&1 || true
  fi
  [[ -f "${live}/cert.pem" ]] || die "Certbot did not produce ${live}/cert.pem"

  install -d -m 0755 "${SWANCTL_DIR}/x509" "${SWANCTL_DIR}/x509ca"
  install -d -m 0700 "${SWANCTL_DIR}/private"
  install -m 0644 "${live}/cert.pem"  "${SWANCTL_DIR}/x509/server-cert.pem"
  install -m 0644 "${live}/chain.pem" "${SWANCTL_DIR}/x509ca/le-chain.pem"
  install -m 0644 "${PKI_DIR}/ca/ca-cert.pem" "${SWANCTL_DIR}/x509ca/ca-cert.pem"
  install -m 0600 "${live}/privkey.pem" "${SWANCTL_DIR}/private/server-key.pem"

  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  cat >/etc/letsencrypt/renewal-hooks/deploy/99-ikev2 <<EOF
#!/bin/sh
# installed by iKev2_Deployment.sh — refresh strongSwan after a renewal
set -e
D="${VPN_DOMAIN}"
L="/etc/letsencrypt/live/\${D}"
[ -f "\${L}/cert.pem" ] || exit 0
install -m 0644 "\${L}/cert.pem"  ${SWANCTL_DIR}/x509/server-cert.pem
install -m 0644 "\${L}/chain.pem" ${SWANCTL_DIR}/x509ca/le-chain.pem
install -m 0600 "\${L}/privkey.pem" ${SWANCTL_DIR}/private/server-key.pem
swanctl --load-creds >/dev/null 2>&1 || true
EOF
  chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/99-ikev2
  ok "Let's Encrypt certificate installed; renewal hook in place."
  warn "Keep TCP/80 open — certbot's standalone renewal needs it."
}

open_port80_temporarily() {
  iptables -C INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 \
    || iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true
  if have ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
  fi
}

# -----------------------------------------------------------------------------
# 9. Crypto proposals
# -----------------------------------------------------------------------------
#  Facts these lists are built on (strongSwan "Windows Clients" interop doc):
#    * stock Windows 7..11 IKE  : 3des/aes128/aes192/aes256 + sha1/sha256/sha384 + modp1024
#      (Windows 11 also offers aes128gcm16/aes256gcm16 — still with modp1024)
#    * stock Windows 7..11 ESP  : aes256/aes128/3des/des/null + **sha1 only**
#    * modp2048 must be the FIRST DH group we list, otherwise a server-initiated
#      IKE_SA rekey fails on Windows.
#    * ESP proposals without a DH group must come first: if the gateway proposes a
#      KE method the client has not configured, Windows dies with error 13816.
set_proposals() {
  case "$CRYPTO_PROFILE" in
    compat)
      IKE_PROP="aes256-sha256-modp2048,aes256-sha384-modp2048,aes256-sha1-modp2048,\
aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-modp2048,\
aes256-sha256-ecp384,aes256-sha256-ecp256,aes256-sha256-modp3072,\
aes256-sha256-modp1024,aes256-sha384-modp1024,aes256-sha1-modp1024,\
aes192-sha256-modp1024,aes192-sha1-modp1024,\
aes128-sha256-modp2048,aes128-sha256-modp1024,aes128-sha1-modp1024,\
aes256gcm16-prfsha384-modp1024,aes128gcm16-prfsha256-modp1024,\
3des-sha1-modp1024"
      ESP_PROP="aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,\
aes256gcm16,aes128gcm16,\
aes256-sha256-modp2048,aes256-sha1-modp2048,aes256gcm16-ecp384,\
3des-sha1"
      WIN_IPSEC_PS="none"
      AND_IKE="aes256-sha256-modp2048"; AND_ESP="aes256-sha256"
      ;;
    balanced)
      IKE_PROP="aes256-sha256-modp2048,aes256-sha384-modp2048,\
aes256gcm16-prfsha384-ecp384,aes256-sha384-ecp384,aes256-sha256-ecp384,\
aes256-sha256-ecp256,aes256-sha256-modp3072,aes256-sha384-modp3072,\
aes128-sha256-modp2048"
      ESP_PROP="aes256-sha256,aes256-sha1,aes256gcm16,aes128gcm16,\
aes256-sha256-modp2048,aes256gcm16-ecp384,aes128-sha256"
      WIN_IPSEC_PS="-AuthenticationTransformConstants SHA256128 -CipherTransformConstants AES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA256 -DHGroup Group14 -PfsGroup PFS2048"
      AND_IKE="aes256-sha256-modp2048"; AND_ESP="aes256-sha256-modp2048"
      ;;
    strict)
      IKE_PROP="aes256gcm16-prfsha384-ecp384,aes256-sha384-ecp384,aes256-sha256-modp3072"
      ESP_PROP="aes256gcm16-ecp384,aes256gcm16,aes256-sha384-ecp384,aes256-sha256-modp3072"
      WIN_IPSEC_PS="-AuthenticationTransformConstants GCMAES256 -CipherTransformConstants GCMAES256 -EncryptionMethod AES256 -IntegrityCheckMethod SHA384 -DHGroup ECP384 -PfsGroup ECP384"
      AND_IKE="aes256gcm16-prfsha384-ecp384"; AND_ESP="aes256gcm16-ecp384"
      ;;
    *) die "Unknown crypto profile '${CRYPTO_PROFILE}'" ;;
  esac
}

# -----------------------------------------------------------------------------
# 10. strongswan.conf / charon settings
# -----------------------------------------------------------------------------
write_strongswan_conf() {
  head1 "charon daemon settings"
  local body
  body=$(cat <<EOF
    # -- generated by iKev2_Deployment.sh -------------------------------------
    # Road-warrior gateway: local_ts is 0.0.0.0/0, so letting charon install
    # its own routes would hijack the server's own default route.
    install_routes = no
    install_virtual_ip = yes

    # Windows retransmits slowly on lossy mobile links.
    retransmit_timeout = 4.0
    retransmit_base = 1.8
    retransmit_tries = 5

    # IKEv2 fragmentation: Windows supports it since 10/1803, Android always.
    fragment_size = 1280

    # Windows never sends an IDr; connections are matched by auth method.
    send_vendor_id = yes

    # RSASSA-PSS is not understood by the Windows built-in client.
    rsa_pss = no

    # Do not tear down a working SA while its replacement is negotiated.
    make_before_break = yes

    syslog {
        daemon {
            default = 1
        }
    }
    filelog {
        charon {
            path = /var/log/strongswan.log
            time_format = %b %e %T
            ike_name = yes
            append = yes
            default = 1
            flush_line = yes
        }
    }
    plugins {
        socket-default {
            set_source = yes
            set_sourceif = yes
        }
    }
EOF
)
  # Ubuntu ships /etc/strongswan.conf with "include strongswan.d/*.conf".
  # Both possible daemon section names get the same settings so the file works
  # whether charon-systemd or the classic charon is the one that starts.
  install -d -m 0755 /etc/strongswan.d /etc/logrotate.d
  cat >/etc/strongswan.d/99-ikev2-vpn.conf <<EOF
charon {
${body}
}

charon-systemd {
${body}
}
EOF
  chmod 0644 /etc/strongswan.d/99-ikev2-vpn.conf

  cat >/etc/logrotate.d/strongswan-ikev2 <<'EOF'
/var/log/strongswan.log {
    weekly
    rotate 4
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
}
EOF
  ok "Wrote /etc/strongswan.d/99-ikev2-vpn.conf"
}

# -----------------------------------------------------------------------------
# 11. swanctl configuration
# -----------------------------------------------------------------------------
write_swanctl_config() {
  head1 "swanctl configuration"
  install -d -m 0755 "$CONFD"

  local local_ts="0.0.0.0/0"
  local v6_pools=""
  if [[ $ENABLE_IPV6 == yes ]]; then
    local_ts="0.0.0.0/0, ::/0"
    v6_pools=", pool-v6"
  fi

  local split_line=""
  if [[ -n $SPLIT_INCLUDE ]]; then
    split_line="        split_include = $(csv_norm "$SPLIT_INCLUDE")"
  fi

  local encap_line="        encap = no"
  [[ $FORCE_ENCAP == yes ]] && encap_line="        encap = yes"

  # ---- pools ----------------------------------------------------------
  {
    echo "# generated by iKev2_Deployment.sh — virtual IP pools"
    echo "pools {"
    local p
    for p in "pool-eap:${POOL_EAP}" "pool-cert-win:${POOL_CERT_WIN}" "pool-cert-android:${POOL_CERT_AND}"; do
      echo "    ${p%%:*} {"
      echo "        addrs = ${p##*:}"
      echo "        dns = ${DNS_SERVERS}"
      [[ -n $split_line ]] && echo "$split_line"
      echo "    }"
    done
    if [[ $ENABLE_IPV6 == yes ]]; then
      echo "    pool-v6 {"
      echo "        addrs = ${POOL_V6}"
      echo "    }"
    fi
    echo "}"
  } >"${CONFD}/10-pools.conf"
  chmod 0644 "${CONFD}/10-pools.conf"

  # ---- connections ----------------------------------------------------
  cat >"${CONFD}/20-connections.conf" <<EOF
# generated by iKev2_Deployment.sh — IKEv2 road-warrior connections
#
#   ikev2-eap            username + password (EAP-MSCHAPv2)  -> ${POOL_EAP}
#   ikev2-cert-android   certificate, IDi *@android.${VPN_DOMAIN} -> ${POOL_CERT_AND}
#   ikev2-cert-win       certificate, any other IDi          -> ${POOL_CERT_WIN}
#
# charon prefers the most specific remote identity match, so Android profiles
# (which pin local.id in the .sswan file) always land in their own pool and
# everything else that authenticates with a certificate lands in the Windows pool.

connections {

    ikev2-eap {
        version = 2
        local_addrs  = %any
        remote_addrs = %any
        proposals = ${IKE_PROP}
        pools = pool-eap${v6_pools}
        rekey_time = 4h
        over_time = 30m
        dpd_delay = 30s
        dpd_timeout = 120s
        fragmentation = yes
        mobike = yes
        unique = never
        send_cert = always
        send_certreq = no
${encap_line}

        local-gw {
            auth = pubkey
            certs = server-cert.pem
            id = ${VPN_DOMAIN}
        }
        remote-eap {
            auth = eap-mschapv2
            eap_id = %any
        }

        children {
            net {
                local_ts = ${local_ts}
                esp_proposals = ${ESP_PROP}
                # A gateway-initiated CHILD_SA rekey makes NATed Windows clients
                # fail with 12345 / ERROR_IPSEC_IKE_INVALID_SITUATION, so let the
                # client drive rekeying instead.
                rekey_time = 0
                life_time = 0
                dpd_action = clear
                start_action = none
            }
        }
    }

    ikev2-cert-android {
        version = 2
        local_addrs  = %any
        remote_addrs = %any
        proposals = ${IKE_PROP}
        pools = pool-cert-android${v6_pools}
        rekey_time = 4h
        over_time = 30m
        dpd_delay = 30s
        dpd_timeout = 120s
        fragmentation = yes
        mobike = yes
        unique = never
        send_cert = always
        send_certreq = yes
${encap_line}

        local-gw {
            auth = pubkey
            certs = server-cert.pem
            id = ${VPN_DOMAIN}
        }
        remote-cert {
            auth = pubkey
            cacerts = ca-cert.pem
            id = *@android.${VPN_DOMAIN}
        }

        children {
            net {
                local_ts = ${local_ts}
                esp_proposals = ${ESP_PROP}
                rekey_time = 50m
                dpd_action = clear
                start_action = none
            }
        }
    }

    ikev2-cert-win {
        version = 2
        local_addrs  = %any
        remote_addrs = %any
        proposals = ${IKE_PROP}
        pools = pool-cert-win${v6_pools}
        rekey_time = 4h
        over_time = 30m
        dpd_delay = 30s
        dpd_timeout = 120s
        fragmentation = yes
        mobike = yes
        unique = never
        send_cert = always
        send_certreq = yes
${encap_line}

        local-gw {
            auth = pubkey
            certs = server-cert.pem
            id = ${VPN_DOMAIN}
        }
        remote-cert {
            auth = pubkey
            cacerts = ca-cert.pem
            id = %any
        }

        children {
            net {
                local_ts = ${local_ts}
                esp_proposals = ${ESP_PROP}
                rekey_time = 0
                life_time = 0
                dpd_action = clear
                start_action = none
            }
        }
    }
}
EOF
  chmod 0644 "${CONFD}/20-connections.conf"

  # ---- top level swanctl.conf ----------------------------------------
  cat >"${SWANCTL_DIR}/swanctl.conf" <<'EOF'
# generated by iKev2_Deployment.sh — do not edit; drop files into /etc/swanctl/conf.d/
include conf.d/*.conf
EOF
  chmod 0644 "${SWANCTL_DIR}/swanctl.conf"

  rebuild_eap_secrets
  ok "Wrote ${CONFD}/10-pools.conf, 20-connections.conf, 30-secrets.conf"
}

rebuild_eap_secrets() {
  install -d -m 0755 "$CONFD"
  install -d -m 0700 "$STATE_DIR"
  [[ -f $EAP_DB ]] || { : >"$EAP_DB"; chmod 0600 "$EAP_DB"; }

  {
    echo "# generated by iKev2_Deployment.sh — EAP-MSCHAPv2 credentials"
    echo "secrets {"
    local line user pass
    while IFS=: read -r user pass; do
      [[ -z ${user// } || ${user:0:1} == "#" ]] && continue
      echo "    eap-${user} {"
      echo "        id = ${user}"
      echo "        secret = \"${pass}\""
      echo "    }"
    done <"$EAP_DB"
    echo "}"
  } >"${CONFD}/30-secrets.conf"
  chmod 0600 "${CONFD}/30-secrets.conf"
}

# -----------------------------------------------------------------------------
# 12. Kernel tuning
# -----------------------------------------------------------------------------
kernel_tuning() {
  [[ $KERNEL_TUNING == yes ]] || { log "Kernel tuning skipped."; return 0; }
  head1 "Kernel / sysctl tuning"

  local bbr_block=""
  if [[ $ENABLE_BBR == yes ]]; then
    modprobe tcp_bbr >/dev/null 2>&1 || true
    if grep -q bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      bbr_block=$'\n# --- congestion control ---\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr'
      echo "tcp_bbr" >/etc/modules-load.d/ikev2-bbr.conf
      ok "BBR available and enabled."
    else
      warn "BBR is not available in this kernel; leaving congestion control alone."
    fi
  fi

  local v6_block="# --- IPv6 forwarding disabled ---
net.ipv6.conf.all.forwarding = 0"
  if [[ $ENABLE_IPV6 == yes ]]; then
    v6_block="# --- IPv6 forwarding ---
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1"
  fi

  cat >/etc/sysctl.d/99-ikev2-vpn.conf <<EOF
# ============================================================================
# Kernel tuning for the strongSwan IKEv2 gateway (iKev2_Deployment.sh)
# ============================================================================

# --- routing: mandatory for a VPN gateway ---
net.ipv4.ip_forward = 1

${v6_block}

# --- IPsec + policy routing needs loose/off reverse-path filtering, otherwise
#     decapsulated packets arriving on the wrong interface get dropped ---
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# --- do not act as a router for ICMP redirects (hardening) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 0

# --- path MTU: VPN payloads are already smaller, probe instead of guessing ---
net.ipv4.tcp_mtu_probing = 1

# --- socket buffers: raise the ceiling for high-BDP mobile links ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 65536
net.core.netdev_max_backlog = 16384
net.core.somaxconn = 8192
net.ipv4.tcp_rmem = 4096 1048576 16777216
net.ipv4.tcp_wmem = 4096 1048576 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# --- TCP behaviour for many short-lived forwarded flows ---
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.ip_local_port_range = 10240 65535

# --- connection tracking: one NAT entry per client flow ---
net.netfilter.nf_conntrack_max = 262144
net.netfilter.nf_conntrack_tcp_timeout_established = 7440
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_udp_timeout_stream = 180

# --- file descriptors ---
fs.file-max = 1000000
${bbr_block}
EOF

  modprobe nf_conntrack >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || warn "sysctl --system reported errors (some keys may not exist on this kernel)."

  cat >/etc/security/limits.d/99-ikev2.conf <<'EOF'
*   soft nofile 1048576
*   hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  ok "ip_forward=$(sysctl -n net.ipv4.ip_forward)  rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter)  cc=$(sysctl -n net.ipv4.tcp_congestion_control)"
}

# -----------------------------------------------------------------------------
# 13. Firewall
# -----------------------------------------------------------------------------
ssh_port() {
  local p
  p="$(awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config 2>/dev/null || true)"
  printf '%s' "${p:-22}"
}

firewall_setup() {
  head1 "Firewall"
  local backend="$FIREWALL"
  if [[ $backend == auto ]]; then
    if have ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then backend="ufw"; else backend="iptables"; fi
  fi
  log "Backend: ${backend}"

  case "$backend" in
    none)     warn "Firewall configuration skipped — you must open UDP/500, UDP/4500 and set up NAT yourself." ;;
    ufw)      firewall_ufw ;;
    iptables) firewall_iptables ;;
    *)        die "Unknown firewall backend '${backend}'" ;;
  esac
}

pools_all() {
  printf '%s %s %s' "$POOL_EAP" "$POOL_CERT_WIN" "$POOL_CERT_AND"
}

firewall_iptables() {
  local p
  # --- dedicated chains so the rules are idempotent and do not clobber others
  iptables -N IKEV2_IN    2>/dev/null || iptables -F IKEV2_IN
  iptables -N IKEV2_FWD   2>/dev/null || iptables -F IKEV2_FWD
  iptables -t nat    -N IKEV2_NAT  2>/dev/null || iptables -t nat    -F IKEV2_NAT
  iptables -t mangle -N IKEV2_MSS  2>/dev/null || iptables -t mangle -F IKEV2_MSS

  iptables -C INPUT -j IKEV2_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j IKEV2_IN
  iptables -C FORWARD -j IKEV2_FWD >/dev/null 2>&1 || iptables -I FORWARD 1 -j IKEV2_FWD
  iptables -t nat -C POSTROUTING -j IKEV2_NAT >/dev/null 2>&1 || iptables -t nat -I POSTROUTING 1 -j IKEV2_NAT
  iptables -t mangle -C FORWARD -j IKEV2_MSS >/dev/null 2>&1 || iptables -t mangle -I FORWARD 1 -j IKEV2_MSS

  # --- INPUT ---
  iptables -A IKEV2_IN -p udp --dport 500  -j ACCEPT
  iptables -A IKEV2_IN -p udp --dport 4500 -j ACCEPT
  iptables -A IKEV2_IN -p esp -j ACCEPT
  iptables -A IKEV2_IN -p ah  -j ACCEPT
  iptables -A IKEV2_IN -p tcp --dport "$(ssh_port)" -j ACCEPT
  [[ $CERT_MODE == letsencrypt ]] && iptables -A IKEV2_IN -p tcp --dport 80 -j ACCEPT

  # --- FORWARD ---
  iptables -A IKEV2_FWD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  for p in $(pools_all); do
    if [[ $ALLOW_CLIENT_TO_CLIENT != yes ]]; then
      # block pool <-> pool before allowing pool -> internet
      local q
      for q in $(pools_all); do
        iptables -A IKEV2_FWD -s "$p" -d "$q" -j DROP
      done
    fi
    iptables -A IKEV2_FWD -s "$p" -m policy --pol ipsec --dir in  -j ACCEPT
    iptables -A IKEV2_FWD -d "$p" -m policy --pol ipsec --dir out -j ACCEPT
    iptables -A IKEV2_FWD -s "$p" -o "$NIC" -j ACCEPT
    iptables -A IKEV2_FWD -d "$p" -i "$NIC" -j ACCEPT
  done

  # --- NAT (do not masquerade traffic that is still inside an IPsec tunnel) ---
  for p in $(pools_all); do
    iptables -t nat -A IKEV2_NAT -s "$p" -o "$NIC" -m policy --pol ipsec --dir out -j ACCEPT
    iptables -t nat -A IKEV2_NAT -s "$p" -o "$NIC" -j MASQUERADE
  done

  # --- MSS clamp: ESP overhead otherwise breaks large TCP segments ---
  for p in $(pools_all); do
    iptables -t mangle -A IKEV2_MSS -s "$p" -p tcp --tcp-flags SYN,RST SYN \
      -m tcpmss --mss "$((MSS_CLAMP+1)):65495" -j TCPMSS --set-mss "$MSS_CLAMP"
    iptables -t mangle -A IKEV2_MSS -d "$p" -p tcp --tcp-flags SYN,RST SYN \
      -m tcpmss --mss "$((MSS_CLAMP+1)):65495" -j TCPMSS --set-mss "$MSS_CLAMP"
  done

  if [[ $ENABLE_IPV6 == yes ]] && have ip6tables; then
    ip6tables -N IKEV2_FWD6 2>/dev/null || ip6tables -F IKEV2_FWD6
    ip6tables -C FORWARD -j IKEV2_FWD6 >/dev/null 2>&1 || ip6tables -I FORWARD 1 -j IKEV2_FWD6
    ip6tables -A IKEV2_FWD6 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    ip6tables -A IKEV2_FWD6 -s "$POOL_V6" -j ACCEPT
    ip6tables -A IKEV2_FWD6 -d "$POOL_V6" -j ACCEPT
    ip6tables -t nat -C POSTROUTING -s "$POOL_V6" -o "$NIC" -j MASQUERADE >/dev/null 2>&1 \
      || ip6tables -t nat -A POSTROUTING -s "$POOL_V6" -o "$NIC" -j MASQUERADE 2>/dev/null || true
  fi

  if have netfilter-persistent; then
    netfilter-persistent save >/dev/null 2>&1 && ok "Rules saved (netfilter-persistent)." \
      || warn "netfilter-persistent save failed; rules are active but not persistent."
  else
    install -d -m 0755 /etc/iptables
    iptables-save  >/etc/iptables/rules.v4 2>/dev/null || true
    ip6tables-save >/etc/iptables/rules.v6 2>/dev/null || true
    warn "iptables-persistent is not installed — rules saved to /etc/iptables but may not reload at boot."
  fi
  ok "iptables rules installed on ${NIC} (SSH port $(ssh_port) explicitly allowed)."
}

firewall_ufw() {
  local marker_start="# BEGIN IKEV2 (iKev2_Deployment.sh)"
  local marker_end="# END IKEV2 (iKev2_Deployment.sh)"

  ufw allow "$(ssh_port)/tcp"  >/dev/null 2>&1 || true
  ufw allow 500/udp  >/dev/null 2>&1 || true
  ufw allow 4500/udp >/dev/null 2>&1 || true
  [[ $CERT_MODE == letsencrypt ]] && ufw allow 80/tcp >/dev/null 2>&1 || true

  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

  # remove any previous managed block, then prepend a fresh one
  if grep -qF "$marker_start" /etc/ufw/before.rules 2>/dev/null; then
    sed -i "/$(printf '%s' "$marker_start" | sed 's/[][\.*^$/]/\\&/g')/,/$(printf '%s' "$marker_end" | sed 's/[][\.*^$/]/\\&/g')/d" /etc/ufw/before.rules
  fi

  local nat_block="${marker_start}
*nat
:POSTROUTING ACCEPT [0:0]"
  local p
  for p in $(pools_all); do
    nat_block="${nat_block}
-A POSTROUTING -s ${p} -o ${NIC} -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s ${p} -o ${NIC} -j MASQUERADE"
  done
  nat_block="${nat_block}
COMMIT

*mangle
:FORWARD - [0:0]"
  for p in $(pools_all); do
    nat_block="${nat_block}
-A FORWARD -s ${p} -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss $((MSS_CLAMP+1)):65495 -j TCPMSS --set-mss ${MSS_CLAMP}"
  done
  nat_block="${nat_block}
COMMIT
${marker_end}"

  printf '%s\n\n%s\n' "$nat_block" "$(cat /etc/ufw/before.rules)" >/etc/ufw/before.rules.new
  mv /etc/ufw/before.rules.new /etc/ufw/before.rules

  for p in $(pools_all); do
    ufw route allow from "$p" to any    >/dev/null 2>&1 || true
    ufw route allow from any to "$p"    >/dev/null 2>&1 || true
  done

  ufw --force reload >/dev/null 2>&1 || ufw --force enable >/dev/null 2>&1 || warn "ufw reload failed."
  ok "ufw configured (NAT + MSS block written to /etc/ufw/before.rules)."
}

# -----------------------------------------------------------------------------
# 14. Service start
# -----------------------------------------------------------------------------
start_services() {
  head1 "Starting strongSwan"
  # Disable the legacy starter FIRST: while it is enabled, "strongswan.service"
  # is an alias pointing at it, and detect_service would latch onto the wrong
  # unit (and then restart the stroke daemon instead of charon-systemd).
  disable_starter
  detect_service
  log "Using unit: ${SS_SERVICE}"
  systemctl enable "$SS_SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SS_SERVICE"
  sleep 2
  if systemctl is-active --quiet "$SS_SERVICE"; then
    ok "${SS_SERVICE} is active."
  else
    bad "${SS_SERVICE} failed to start. Last log lines:"
    journalctl -u "$SS_SERVICE" -n 30 --no-pager || true
    die "strongSwan did not start."
  fi
  reload_config
}

# -----------------------------------------------------------------------------
# 15. Client management
# -----------------------------------------------------------------------------
b64() { base64 -w0 <"$1"; }

# Build a PKCS#12 that Windows can actually import.
# Windows only understands PBES1 (pbeWithSHA1And3-KeyTripleDES-CBC); OpenSSL 3.x
# defaults to PBES2/AES-256-CBC, which the Windows certificate importer rejects.
make_p12() { # make_p12 <key> <cert> <ca> <out> <password> <friendlyname>
  local key=$1 crt=$2 ca=$3 out=$4 pw=$5 fn=$6
  local common=(-export -inkey "$key" -in "$crt" -certfile "$ca"
                -name "$fn" -caname "${ORG_NAME} Root CA"
                -passout "pass:${pw}" -out "$out")

  if openssl pkcs12 "${common[@]}" \
        -certpbe PBE-SHA1-3DES -keypbe PBE-SHA1-3DES -macalg sha1 >/dev/null 2>&1 \
     && openssl pkcs12 -in "$out" -noout -passin "pass:${pw}" >/dev/null 2>&1; then
    printf 'PBE-SHA1-3DES'
    return 0
  fi
  if OPENSSL_CONF="$OSSL_LEGACY_CNF" openssl pkcs12 "${common[@]}" -legacy >/dev/null 2>&1 \
     && openssl pkcs12 -in "$out" -noout -passin "pass:${pw}" >/dev/null 2>&1; then
    printf 'legacy'
    return 0
  fi
  openssl pkcs12 "${common[@]}" >/dev/null 2>&1 || return 1
  printf 'default(PBES2 — may not import on Windows)'
}

client_issue_cert() { # client_issue_cert <name> <platform-tag>  -> sets CLI_KEY / CLI_CRT
  local name=$1 tag=$2
  local dir="${PKI_DIR}/clients/${name}-${tag}"
  install -d -m 0700 "$dir"
  CLI_KEY="${dir}/key.pem"
  CLI_CRT="${dir}/cert.pem"
  local csr="${dir}/req.csr"
  local ext="${dir}/ext.cnf"
  local ident="${name}@${tag}.${VPN_DOMAIN}"

  gen_key "$CLI_KEY"
  openssl req -new -sha256 -config "${PKI_DIR}/openssl.cnf" -key "$CLI_KEY" -out "$csr" \
    -subj "/C=${COUNTRY}/O=${ORG_NAME}/OU=${tag}/CN=${ident}" >/dev/null 2>&1 \
    || die "Could not create a CSR for ${name}."
  write_client_ext "$ext" "$ident"
  openssl ca -config "${PKI_DIR}/openssl.cnf" -batch -notext \
      -extfile "$ext" -days "$CLIENT_DAYS" -md sha256 \
      -in "$csr" -out "$CLI_CRT" >/dev/null 2>&1 \
    || die "Could not sign the client certificate for ${name}."
  CLI_ID="$ident"
}

eap_user_add() { # eap_user_add <user> <pass>
  local u=$1 p=$2
  [[ -f $EAP_DB ]] || { : >"$EAP_DB"; chmod 0600 "$EAP_DB"; }
  sed -i "/^${u}:/d" "$EAP_DB"
  printf '%s:%s\n' "$u" "$p" >>"$EAP_DB"
  chmod 0600 "$EAP_DB"
  rebuild_eap_secrets
}

write_windows_ps1() { # write_windows_ps1 <outfile> <name> <auth> <p12file> <p12pass> <eapuser> <eappass>
  local out=$1 name=$2 auth=$3 p12=$4 p12pw=$5 eu=$6 ep=$7
  local conn_name="${VPN_DOMAIN} IKEv2"

  {
  cat <<PSEOF
#Requires -RunAsAdministrator
<#
  ${VPN_DOMAIN} IKEv2 — Windows 10/11 installer for client "${name}"
  Right-click this file -> "Run with PowerShell", or from an elevated prompt:
      Set-ExecutionPolicy -Scope Process Bypass -Force
      .\\$(basename "$out")
#>
\$ErrorActionPreference = 'Stop'
\$Here       = Split-Path -Parent \$MyInvocation.MyCommand.Definition
\$ConnName   = '${conn_name}'
\$Server     = '${VPN_DOMAIN}'

Write-Host "== ${VPN_DOMAIN} IKEv2 setup ==" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. Root CA
\$CaFile = Join-Path \$Here 'ca.crt'
if (Test-Path \$CaFile) {
    Write-Host "[1/4] Importing the VPN root CA into LocalMachine\\Root ..."
    Import-Certificate -FilePath \$CaFile -CertStoreLocation Cert:\\LocalMachine\\Root | Out-Null
} else {
    Write-Host "[1/4] ca.crt not found next to this script - skipping (fine for Let's Encrypt)." -ForegroundColor Yellow
}
PSEOF

  if [[ $auth == cert ]]; then
  cat <<PSEOF

# ------------------------------------------------------- 2. Client certificate
\$Pfx = Join-Path \$Here '$(basename "$p12")'
Write-Host "[2/4] Importing the client certificate into LocalMachine\\My ..."
\$PfxPw = ConvertTo-SecureString -String '${p12pw}' -AsPlainText -Force
Import-PfxCertificate -FilePath \$Pfx -CertStoreLocation Cert:\\LocalMachine\\My -Password \$PfxPw | Out-Null
\$AuthMethod = 'MachineCertificate'
PSEOF
  else
  cat <<PSEOF

# ------------------------------------------------------------- 2. Credentials
Write-Host "[2/4] This profile uses username + password (EAP-MSCHAPv2)."
Write-Host "      Username: ${eu}"
Write-Host "      Password: ${ep}"
\$AuthMethod = 'MSChapv2'
PSEOF
  fi

  cat <<PSEOF

# --------------------------------------------------------- 3. VPN connection
Write-Host "[3/4] Creating the VPN connection '\$ConnName' ..."
Get-VpnConnection -AllUserConnection -Name \$ConnName -ErrorAction SilentlyContinue |
    Remove-VpnConnection -Force -AllUserConnection -ErrorAction SilentlyContinue

Add-VpnConnection -Name \$ConnName -ServerAddress \$Server \`
    -TunnelType Ikev2 -AuthenticationMethod \$AuthMethod \`
    -EncryptionLevel Required -AllUserConnection \`
    -SplitTunneling:\$false -RememberCredential -PassThru | Out-Null
PSEOF

  if [[ $WIN_IPSEC_PS != none ]]; then
  cat <<PSEOF

Write-Host "      Applying the '${CRYPTO_PROFILE}' IPsec policy ..."
Set-VpnConnectionIPsecConfiguration -ConnectionName \$ConnName \`
    ${WIN_IPSEC_PS} \`
    -AllUserConnection -Force | Out-Null
PSEOF
  else
  cat <<PSEOF

Write-Host "      Server profile is 'compat' - Windows default ciphers are accepted, nothing to set."
PSEOF
  fi

  cat <<PSEOF

# ------------------------------------------------------------- 4. NAT-T fix
# Needed when the PC (or the server) sits behind NAT. 2 = both sides may be NATed.
Write-Host "[4/4] Applying the NAT-T registry fix ..."
\$Key = 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent'
if (-not (Test-Path \$Key)) { New-Item -Path \$Key -Force | Out-Null }
\$Existing = (Get-ItemProperty -Path \$Key -Name AssumeUDPEncapsulationContextOnSendRule -ErrorAction SilentlyContinue).AssumeUDPEncapsulationContextOnSendRule
New-ItemProperty -Path \$Key -Name AssumeUDPEncapsulationContextOnSendRule -PropertyType DWord -Value 2 -Force | Out-Null
if (\$Existing -ne 2) {
    Write-Host "      Registry changed - a REBOOT is required for this to take effect." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Connect from Settings > Network & Internet > VPN > '\$ConnName'." -ForegroundColor Green
PSEOF

  if [[ $auth != cert ]]; then
  cat <<PSEOF
Write-Host "Username: ${eu}"
Write-Host "Password: ${ep}"
PSEOF
  fi

  cat <<'PSEOF'
Write-Host ""
Write-Host "Troubleshooting: rasdial to see the raw error code, or"
Write-Host "  Get-VpnConnection -AllUserConnection | Format-List *"
PSEOF
  } >"$out"
}

write_sswan() { # write_sswan <out> <name> <type> <p12b64> <cab64> <eapuser> <eappass> <localid>
  local out=$1 name=$2 typ=$3 p12b64=$4 cab64=$5 eu=$6 ep=$7 lid=$8
  local uuid; uuid="$(gen_uuid)"

  {
    printf '{\n'
    printf '  "uuid": "%s",\n' "$uuid"
    printf '  "name": "%s (%s)",\n' "$VPN_DOMAIN" "$name"
    printf '  "type": "%s",\n' "$typ"
    printf '  "remote": {\n'
    printf '    "addr": "%s",\n' "$VPN_DOMAIN"
    printf '    "id": "%s",\n' "$VPN_DOMAIN"
    if [[ -n $cab64 ]]; then
      printf '    "cert": "%s",\n' "$cab64"
    fi
    printf '    "certreq": true\n'
    printf '  },\n'
    printf '  "local": {\n'
    if [[ $typ == "ikev2-cert" ]]; then
      printf '    "id": "%s",\n' "$lid"
      printf '    "p12": "%s"\n' "$p12b64"
    else
      printf '    "eap_id": "%s",\n' "$eu"
      printf '    "shared_secret": "%s"\n' "$ep"
    fi
    printf '  },\n'
    printf '  "ike-proposal": "%s",\n' "$AND_IKE"
    printf '  "esp-proposal": "%s",\n' "$AND_ESP"
    printf '  "mtu": %s,\n' "$CLIENT_MTU"
    printf '  "nat-keepalive": 45,\n'
    printf '  "split-tunneling": {\n'
    printf '    "block-ipv4": false,\n'
    printf '    "block-ipv6": true\n'
    printf '  }\n'
    printf '}\n'
  } >"$out"
}

client_add() {
  local name=${1:-} platform=${2:-} auth=${3:-}

  if [[ -z $name ]]; then
    ask_valid name "Client name (letters, digits, - _ .)" "client1" \
      valid_name "use letters, digits, dot, dash or underscore (max 32 characters)"
  fi
  valid_name "$name" || die "Invalid client name '${name}'."
  if [[ -d ${CLIENT_OUT_DIR}/${name} ]]; then
    local overwrite="no"
    ask_yn overwrite "Client '${name}' already exists — regenerate it" "no"
    [[ $overwrite == yes ]] || die "Aborted; pick another name."
  fi
  [[ -z $platform ]] && ask_choice platform "Platform" "both" both windows android
  [[ -z $auth ]] && ask_choice auth "Authentication" "both" both eap cert

  set_proposals
  local outdir="${CLIENT_OUT_DIR}/${name}"
  install -d -m 0700 "$CLIENT_OUT_DIR"
  rm -rf "$outdir"; install -d -m 0700 "$outdir"

  head1 "Creating client '${name}'  (platform=${platform}, auth=${auth})"

  # --- CA copy (skip for Let's Encrypt: Windows/Android already trust ISRG) --
  local cab64=""
  if [[ $CERT_MODE == self ]]; then
    install -m 0644 "${PKI_DIR}/ca/ca-cert.pem" "${outdir}/ca.crt"
    cab64="$(openssl x509 -in "${PKI_DIR}/ca/ca-cert.pem" -outform der | base64 -w0)"
  else
    cab64=""
  fi

  # --- EAP credentials -------------------------------------------------
  local eu="" ep=""
  if [[ $auth == eap || $auth == both ]]; then
    eu="$name"
    ep="$(gen_pass)"
    eap_user_add "$eu" "$ep"
    ok "EAP-MSCHAPv2 user created: ${eu}"
  fi

  # --- Windows artefacts -----------------------------------------------
  local win_p12="" win_p12pw="" p12mode=""
  if [[ $platform == windows || $platform == both ]]; then
    if [[ $auth == cert || $auth == both ]]; then
      client_issue_cert "$name" "win"
      win_p12="${outdir}/${name}-windows.p12"
      win_p12pw="$(gen_pass)"
      p12mode="$(make_p12 "$CLI_KEY" "$CLI_CRT" "${PKI_DIR}/ca/ca-cert.pem" \
                          "$win_p12" "$win_p12pw" "${name} @ ${VPN_DOMAIN}")" \
        || die "PKCS#12 creation failed for ${name} (windows)."
      chmod 0600 "$win_p12"
      ok "Windows PKCS#12 written (encryption: ${p12mode})."
      write_windows_ps1 "${outdir}/${name}-windows-cert.ps1" "$name" cert "$win_p12" "$win_p12pw" "" ""
    fi
    if [[ $auth == eap || $auth == both ]]; then
      write_windows_ps1 "${outdir}/${name}-windows-userpass.ps1" "$name" eap "" "" "$eu" "$ep"
    fi
  fi

  # --- Android artefacts -----------------------------------------------
  local and_p12="" and_p12pw=""
  if [[ $platform == android || $platform == both ]]; then
    if [[ $auth == eap || $auth == both ]]; then
      write_sswan "${outdir}/${name}-android-userpass.sswan" "$name" "ikev2-eap" "" "$cab64" "$eu" "$ep" ""
      chmod 0600 "${outdir}/${name}-android-userpass.sswan"
    fi
    if [[ $auth == cert || $auth == both ]]; then
      client_issue_cert "$name" "android"
      and_p12="${outdir}/${name}-android.p12"
      and_p12pw="$(gen_pass)"
      make_p12 "$CLI_KEY" "$CLI_CRT" "${PKI_DIR}/ca/ca-cert.pem" \
               "$and_p12" "$and_p12pw" "${name} @ ${VPN_DOMAIN}" >/dev/null \
        || die "PKCS#12 creation failed for ${name} (android)."
      chmod 0600 "$and_p12"
      write_sswan "${outdir}/${name}-android-cert.sswan" "$name" "ikev2-cert" \
                  "$(b64 "$and_p12")" "$cab64" "" "" "$CLI_ID"
      chmod 0600 "${outdir}/${name}-android-cert.sswan"
      # the .sswan embeds the p12, but the app asks for its password on import
      printf '%s\n' "$and_p12pw" >"${outdir}/${name}-android-p12-password.txt"
      chmod 0600 "${outdir}/${name}-android-p12-password.txt"
    fi
  fi

  write_client_readme "$outdir" "$name" "$platform" "$auth" "$eu" "$ep" "$win_p12pw" "$and_p12pw"

  if have zip; then
    ( cd "$CLIENT_OUT_DIR" && zip -qr "${name}.zip" "$name" ) && ok "Bundle: ${CLIENT_OUT_DIR}/${name}.zip"
  fi

  reload_config
  pki_gen_crl
  swanctl --load-creds >/dev/null 2>&1 || true

  echo
  hr
  printf '  %sClient "%s" is ready%s\n' "$C_BOLD" "$name" "$C_RST"
  printf '  Files: %s\n' "$outdir"
  [[ -n $eu ]] && printf '  EAP username / password : %s%s%s / %s%s%s\n' "$C_G" "$eu" "$C_RST" "$C_G" "$ep" "$C_RST"
  [[ -n $win_p12pw ]] && printf '  Windows .p12 password   : %s%s%s\n' "$C_G" "$win_p12pw" "$C_RST"
  [[ -n $and_p12pw ]] && printf '  Android .p12 password   : %s%s%s\n' "$C_G" "$and_p12pw" "$C_RST"
  hr
  printf '  Copy the bundle to your PC with, e.g.:\n'
  printf '    %sscp root@%s:%s/%s.zip .%s\n' "$C_D" "$VPN_IP" "$CLIENT_OUT_DIR" "$name" "$C_RST"
  echo
}

write_client_readme() { # dir name platform auth eapuser eappass winp12pw andp12pw
  local dir=$1 name=$2 platform=$3 auth=$4 eu=$5 ep=$6 wpw=$7 apw=$8
  cat >"${dir}/README.txt" <<EOF
================================================================================
 ${VPN_DOMAIN} — IKEv2/IPsec client "${name}"
 server ${VPN_DOMAIN} (${VPN_IP})   crypto profile: ${CRYPTO_PROFILE}
================================================================================

WHAT IS IN THIS FOLDER
$(ls -1 "$dir" | sed 's/^/  - /')

--------------------------------------------------------------------------------
WINDOWS 10 / 11
--------------------------------------------------------------------------------
Automatic (recommended)
  1. Copy this whole folder to the PC.
  2. Right-click the .ps1 file you want and choose "Run with PowerShell",
     or from an ELEVATED PowerShell prompt:
         Set-ExecutionPolicy -Scope Process Bypass -Force
         .\\${name}-windows-userpass.ps1      # username + password
         .\\${name}-windows-cert.ps1          # certificate
  3. Reboot if the script says the NAT-T registry value changed.
  4. Settings > Network & Internet > VPN > "${VPN_DOMAIN} IKEv2" > Connect.

Manual (username + password)
  1. Double-click ca.crt > Install Certificate > Local Machine >
     "Place all certificates in the following store" >
     "Trusted Root Certification Authorities".
  2. Settings > VPN > Add a VPN connection
        VPN provider  : Windows (built-in)
        Connection name: ${VPN_DOMAIN} IKEv2
        Server name    : ${VPN_DOMAIN}
        VPN type       : IKEv2
        Sign-in info   : User name and password
        User name      : ${eu:-<none - certificate profile>}
        Password       : ${ep:-<none>}
     IMPORTANT: type the server name EXACTLY as "${VPN_DOMAIN}".
     The certificate's SAN contains ${VPN_DOMAIN} and ${VPN_IP}; anything else
     produces error 13801 (IKE authentication credentials are unacceptable).

Passwords
  EAP user      : ${eu:-(n/a)}
  EAP password  : ${ep:-(n/a)}
  .p12 password : ${wpw:-(n/a)}

If it will not connect
  * error 809  -> NAT-T. Reboot after the .ps1 set
                  HKLM\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent
                  \\AssumeUDPEncapsulationContextOnSendRule = 2 (DWORD)
  * error 13801-> server name typed does not match the certificate SAN,
                  or ca.crt is not in "Trusted Root Certification Authorities"
                  of the LOCAL MACHINE (not the user) store.
  * error 13806-> ca.crt was not imported at all.
  * error 812  -> the server rejected the credentials (wrong user/password).

--------------------------------------------------------------------------------
ANDROID  (strongSwan VPN Client from Google Play / F-Droid)
--------------------------------------------------------------------------------
  1. Copy the .sswan file to the phone (or e-mail it to yourself).
  2. Open the strongSwan app > "..." menu > "Import VPN profile" > pick the file.
     ${name}-android-userpass.sswan  = username + password (nothing else to type)
     ${name}-android-cert.sswan      = certificate; the app asks for the
                                       PKCS#12 password: ${apw:-(n/a)}
  3. Tap the imported profile to connect.

  The profile already contains the server address, the CA, the proposals
  (${AND_IKE} / ${AND_ESP}) and MTU ${CLIENT_MTU}.

--------------------------------------------------------------------------------
WHICH IP POOL THIS CLIENT LANDS IN
--------------------------------------------------------------------------------
  username/password (EAP)        -> ${POOL_EAP}
  certificate, Windows           -> ${POOL_CERT_WIN}
  certificate, Android           -> ${POOL_CERT_AND}

--------------------------------------------------------------------------------
KEEP THIS FOLDER PRIVATE — it contains private keys and passwords.
================================================================================
EOF
  chmod 0600 "${dir}/README.txt"
}

client_list() {
  head1 "EAP users (username + password)"
  if [[ -s $EAP_DB ]]; then
    printf '  %-24s %s\n' "USER" "PASSWORD"
    while IFS=: read -r u p; do
      [[ -z ${u// } || ${u:0:1} == "#" ]] && continue
      printf '  %-24s %s\n' "$u" "$p"
    done <"$EAP_DB"
  else
    echo "  (none)"
  fi

  head1 "Issued client certificates"
  if [[ -s ${PKI_DIR}/db/index.txt ]]; then
    printf '  %-8s %-14s %s\n' "STATUS" "EXPIRES" "SUBJECT"
    # NB: "exp" is an awk built-in function name — do not use it as a variable.
    awk -F'\t' '{
      st = ($1=="V") ? "valid" : (($1=="R") ? "REVOKED" : $1);
      d  = $2;
      yy = substr(d,1,2); mm = substr(d,3,2); dd = substr(d,5,2);
      printf "  %-8s %-14s %s\n", st, "20" yy "-" mm "-" dd, $NF
    }' "${PKI_DIR}/db/index.txt"
  else
    echo "  (none)"
  fi

  head1 "Client bundles"
  if [[ -d $CLIENT_OUT_DIR ]]; then
    find "$CLIENT_OUT_DIR" -maxdepth 1 -mindepth 1 -type d -printf '  %f\n' | sort || true
  else
    echo "  (none)"
  fi
}

client_revoke() {
  local name=${1:-}
  [[ -z $name ]] && ask name "Client name to revoke" ""
  [[ -n $name ]] || die "No client name given."

  head1 "Revoking '${name}'"

  # 1. EAP user
  if grep -q "^${name}:" "$EAP_DB" 2>/dev/null; then
    sed -i "/^${name}:/d" "$EAP_DB"
    rebuild_eap_secrets
    ok "EAP user '${name}' deleted."
  fi

  # 2. certificates (windows + android variants)
  local tag found=0
  for tag in win android; do
    local crt="${PKI_DIR}/clients/${name}-${tag}/cert.pem"
    if [[ -f $crt ]]; then
      if openssl ca -config "${PKI_DIR}/openssl.cnf" -batch -revoke "$crt" >/dev/null 2>&1; then
        ok "Certificate ${name}-${tag} revoked."
      else
        warn "Certificate ${name}-${tag} was already revoked (or could not be revoked)."
      fi
      found=1
    fi
  done
  [[ $found -eq 1 ]] && pki_gen_crl

  # 3. reload + kick live sessions
  reload_config
  swanctl --load-creds >/dev/null 2>&1 || true
  swanctl --terminate --ike-id "$(swanctl --list-sas 2>/dev/null | grep -i "$name" | head -1 | sed -n 's/.*#\([0-9]\+\).*/\1/p')" >/dev/null 2>&1 || true

  rm -rf "${CLIENT_OUT_DIR:?}/${name}" "${CLIENT_OUT_DIR:?}/${name}.zip"
  ok "Bundle removed. CRL regenerated and reloaded."
}

# -----------------------------------------------------------------------------
# 16. Verification
# -----------------------------------------------------------------------------
verify_all() {
  head1 "Verification"
  local rc=0
  detect_service

  # service
  if systemctl is-active --quiet "$SS_SERVICE"; then ok "${SS_SERVICE} running"
  else bad "${SS_SERVICE} is NOT running"; rc=1; fi

  # listening sockets
  local p
  for p in 500 4500; do
    if port_listening udp "$p"; then
      ok "listening on UDP/${p} ($(port_listener_name udp "$p" || echo charon))"
    else
      bad "nothing is listening on UDP/${p}"
      bad "  check: ss -lunp | grep -E ':500|:4500'   and   journalctl -u ${SS_SERVICE} -n 40"
      rc=1
    fi
  done

  # plugins: eap-mschapv2 + an MD4 provider are what make Windows
  # username/password authentication work at all.
  local plugins; plugins="$(swanctl --stats 2>/dev/null | tr ' ,' '\n\n' || true)"
  if printf '%s\n' "$plugins" | grep -qx "eap-mschapv2"; then
    ok "plugin eap-mschapv2 loaded"
  else
    bad "plugin eap-mschapv2 NOT loaded — username/password auth will fail"
    bad "  fix: apt-get install -y libcharon-extauth-plugins && systemctl restart ${SS_SERVICE}"
    rc=1
  fi
  # What matters is whether *charon* can compute MD4, not whether the openssl
  # CLI can. If the md4 plugin is absent, the legacy provider must actually be
  # in the running unit's environment.
  if printf '%s\n' "$plugins" | grep -qx "md4"; then
    ok "plugin md4 loaded (native MD4 for MSCHAPv2)"
  elif systemctl show -p Environment "$SS_SERVICE" 2>/dev/null | grep -qF "OPENSSL_CONF=${OSSL_LEGACY_CNF}" \
       && OPENSSL_CONF="$OSSL_LEGACY_CNF" openssl dgst -md4 /dev/null >/dev/null 2>&1; then
    ok "MD4 via the OpenSSL legacy provider, active on ${SS_SERVICE}"
  else
    bad "charon has no MD4 — EAP-MSCHAPv2 (Windows username/password) will fail."
    bad "  the OPENSSL_CONF drop-in is not in effect for ${SS_SERVICE}"
    bad "  fix: ikev2ctl repair-md4"
    rc=1
  fi

  # connections + pools
  # connection names sit at column 0; indented lines are children/auth rounds
  local conns nconn
  conns="$(swanctl --list-conns 2>/dev/null | grep -oE '^[A-Za-z0-9_-]+:' | tr -d ':' | tr '\n' ' ' || true)"
  nconn="$(printf '%s' "$conns" | wc -w)"
  if [[ ${nconn:-0} -ge 3 ]]; then ok "${nconn} connections loaded: ${conns}"
  else bad "only ${nconn:-0} connections loaded (${conns:-none}) — check ${CONFD}/20-connections.conf"; rc=1; fi

  if swanctl --list-pools 2>/dev/null | grep -q "pool-eap"; then ok "virtual IP pools loaded"
  else bad "pools were not loaded"; rc=1; fi

  # server certificate
  local sc="${SWANCTL_DIR}/x509/server-cert.pem"
  if [[ -f $sc ]]; then
    local txt; txt="$(openssl x509 -in "$sc" -noout -text)"
    local sans; sans="$(printf '%s' "$txt" | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^ *//')"
    local eku;  eku="$(printf '%s' "$txt"  | grep -A1 'Extended Key Usage'       | tail -1 | sed 's/^ *//')"
    printf '%s' "$sans" | grep -q "DNS:${VPN_DOMAIN}" \
      && ok "server cert SAN contains DNS:${VPN_DOMAIN}" \
      || { bad "server cert SAN is missing DNS:${VPN_DOMAIN} -> Windows error 13801"; rc=1; }
    if [[ $CERT_MODE == self ]]; then
      printf '%s' "$sans" | grep -q "DNS:${VPN_IP}" \
        && ok "server cert SAN contains DNS:${VPN_IP} (lets Windows connect by IP)" \
        || warn "server cert SAN has no DNS:${VPN_IP} entry"
    fi
    printf '%s' "$eku" | grep -qi "TLS Web Server Authentication" \
      && ok "server cert EKU includes serverAuth" \
      || { bad "server cert EKU is missing serverAuth — Windows will reject it"; rc=1; }
    printf '%s' "$eku" | grep -q "1.3.6.1.5.5.8.2.2" \
      && ok "server cert EKU includes ikeIntermediate" \
      || warn "server cert has no ikeIntermediate EKU (harmless on Windows 10/11)"
    if openssl x509 -in "$sc" -noout -checkend 604800 >/dev/null 2>&1; then
      ok "server cert valid until $(openssl x509 -in "$sc" -noout -enddate | cut -d= -f2)"
    else
      bad "server cert expires within 7 days"; rc=1
    fi
    # key/cert pair must match
    local m1 m2
    m1="$(openssl x509 -in "$sc" -noout -pubkey 2>/dev/null | openssl sha256 | awk '{print $NF}')"
    m2="$(openssl pkey -in "${SWANCTL_DIR}/private/server-key.pem" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}')"
    [[ -n $m1 && $m1 == "$m2" ]] && ok "server key matches the server certificate" \
      || { bad "server key does NOT match the certificate"; rc=1; }
  else
    bad "${sc} is missing"; rc=1
  fi

  # CA loaded into charon. The type token is "x509ca" (no underscore); passing an
  # invalid one makes swanctl print nothing and the check silently false-negative.
  local cacn; cacn="$(openssl x509 -in "${SWANCTL_DIR}/x509ca/ca-cert.pem" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')"
  if swanctl --list-certs --type x509ca 2>/dev/null | grep -q . \
     || swanctl --list-certs 2>/dev/null | grep -qiF "${cacn:-__none__}"; then
    ok "CA certificate loaded into charon${cacn:+ (${cacn})}"
  else
    warn "charon lists no CA certificate — run: swanctl --load-creds"
  fi

  # forwarding + NAT
  [[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]] \
    && ok "net.ipv4.ip_forward = 1" || { bad "IP forwarding is off — clients get no internet"; rc=1; }

  if iptables -t nat -S 2>/dev/null | grep -q "MASQUERADE"; then ok "NAT/MASQUERADE rule present"
  else bad "no MASQUERADE rule — clients will connect but have no internet"; rc=1; fi

  if iptables -S 2>/dev/null | grep -q -- "--dport 500" || \
     ( have ufw && ufw status 2>/dev/null | grep -q "500/udp" ); then
    ok "firewall allows UDP/500"
  else
    warn "could not confirm a UDP/500 allow rule"
  fi

  # DNS re-check now that dig is definitely installed
  if have dig; then
    local a; a="$(dig +short +time=3 A "$VPN_DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
    if [[ $a == "$VPN_IP" ]]; then ok "DNS ${VPN_DOMAIN} -> ${a}"
    elif [[ -z $a ]]; then warn "DNS: ${VPN_DOMAIN} has no A record"
    else warn "DNS: ${VPN_DOMAIN} -> ${a} (expected ${VPN_IP})"; fi
  fi

  # clock
  local sync; sync="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  [[ $sync == yes ]] && ok "clock synchronised" || warn "clock not confirmed synchronised (cert validation is time sensitive)"

  echo
  if [[ $rc -eq 0 ]]; then ok "All critical checks passed."
  else bad "Some critical checks FAILED — see the lines marked [x] above."; fi
  return 0
}

# -----------------------------------------------------------------------------
# 17. Summary
# -----------------------------------------------------------------------------
summary() {
  local bundle="${CLIENT_OUT_DIR}/${FIRST_CLIENT}"
  echo
  printf '%s' "$C_G"
  cat <<'BANNER'
  +==========================================================+
  |            I K E v 2   V P N   I S   R E A D Y           |
  +==========================================================+
BANNER
  printf '%s' "$C_RST"
  echo
  hr
  printf '  %-24s %s\n' "Server"            "${VPN_DOMAIN} (${VPN_IP})"
  printf '  %-24s %s\n' "Protocol"          "IKEv2/IPsec — UDP 500 + UDP 4500, ESP"
  printf '  %-24s %s\n' "Server cert"       "$([[ $CERT_MODE == letsencrypt ]] && echo "Let's Encrypt" || echo 'private CA (import ca.crt on clients)')"
  printf '  %-24s %s\n' "Key"               "$([[ $KEY_TYPE == rsa ]] && echo "RSA-${RSA_BITS}" || echo "ECDSA-${EC_CURVE}")"
  printf '  %-24s %s\n' "Crypto profile"    "$CRYPTO_PROFILE"
  printf '  %-24s %s\n' "IKE proposals"     "$(printf '%s' "$IKE_PROP" | cut -c1-60)..."
  printf '  %-24s %s\n' "ESP proposals"     "$(printf '%s' "$ESP_PROP" | cut -c1-60)..."
  hr
  printf '  %sPools%s\n' "$C_BOLD" "$C_RST"
  printf '    %-30s %s\n' "username/password (EAP)"  "$POOL_EAP"
  printf '    %-30s %s\n' "certificate / Windows"    "$POOL_CERT_WIN"
  printf '    %-30s %s\n' "certificate / Android"    "$POOL_CERT_AND"
  [[ $ENABLE_IPV6 == yes ]] && printf '    %-30s %s\n' "IPv6 (all connections)" "$POOL_V6"
  printf '    %-30s %s\n' "DNS pushed to clients"    "$DNS_SERVERS"
  hr
  printf '  %sFirst client "%s"%s\n' "$C_BOLD" "$FIRST_CLIENT" "$C_RST"
  printf '    %-30s %s\n' "bundle directory" "$bundle"
  printf '    %-30s %s\n' "zip archive"      "${CLIENT_OUT_DIR}/${FIRST_CLIENT}.zip"
  if [[ -f $EAP_DB ]] && grep -q "^${FIRST_CLIENT}:" "$EAP_DB"; then
    printf '    %-30s %s%s%s\n' "EAP username" "$C_G" "$FIRST_CLIENT" "$C_RST"
    printf '    %-30s %s%s%s\n' "EAP password" "$C_G" "$(grep "^${FIRST_CLIENT}:" "$EAP_DB" | cut -d: -f2)" "$C_RST"
  fi
  hr
  printf '  %sManage the server%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "ikev2ctl add-client            # new Windows / Android client"
  printf '    %s\n' "ikev2ctl list-clients          # users, certs, bundles"
  printf '    %s\n' "ikev2ctl revoke-client --name X"
  printf '    %s\n' "ikev2ctl status                # live sessions"
  printf '    %s\n' "ikev2ctl check                 # re-run every health check"
  printf '    %s\n' "journalctl -u ${SS_SERVICE} -f   /   tail -f /var/log/strongswan.log"
  hr
  printf '  %sGet the bundle onto your PC%s\n' "$C_BOLD" "$C_RST"
  printf '    %sscp root@%s:%s/%s.zip .%s\n' "$C_D" "$VPN_IP" "$CLIENT_OUT_DIR" "$FIRST_CLIENT" "$C_RST"
  hr
  if (( WARN_COUNT > 0 )); then
    printf '  %s%d warning(s) were printed above — scroll up and read them.%s\n' "$C_Y" "$WARN_COUNT" "$C_RST"
    hr
  fi
  echo
}

install_self() {
  local target="/usr/local/sbin/ikev2ctl"
  local src; src="$(readlink -f "${BASH_SOURCE[0]}")"
  if [[ $src != "$target" ]]; then
    install -m 0700 "$src" "$target"
    ok "Installed as ${target}"
  fi
}

# -----------------------------------------------------------------------------
# 18. Uninstall
# -----------------------------------------------------------------------------
do_uninstall() {
  local go
  ask_yn go "Remove all IKEv2 configuration, certificates and clients" "no"
  [[ $go == yes ]] || die "Aborted."
  detect_service
  systemctl stop "$SS_SERVICE" >/dev/null 2>&1 || true
  systemctl disable "$SS_SERVICE" >/dev/null 2>&1 || true
  rm -f "${CONFD}/10-pools.conf" "${CONFD}/20-connections.conf" "${CONFD}/30-secrets.conf"
  rm -f /etc/strongswan.d/99-ikev2-vpn.conf /etc/sysctl.d/99-ikev2-vpn.conf
  rm -f /etc/logrotate.d/strongswan-ikev2 /etc/modules-load.d/ikev2-bbr.conf
  rm -f /etc/security/limits.d/99-ikev2.conf
  rm -rf "/etc/systemd/system/${SS_SERVICE}.d"
  rm -f "${SWANCTL_DIR}/x509/server-cert.pem" "${SWANCTL_DIR}/x509ca/ca-cert.pem" \
        "${SWANCTL_DIR}/x509ca/le-chain.pem" "${SWANCTL_DIR}/private/server-key.pem" \
        "${SWANCTL_DIR}/x509crl/ca.crl.pem"
  for c in IKEV2_IN IKEV2_FWD; do
    iptables -D INPUT   -j "$c" 2>/dev/null || true
    iptables -D FORWARD -j "$c" 2>/dev/null || true
    iptables -F "$c" 2>/dev/null || true; iptables -X "$c" 2>/dev/null || true
  done
  iptables -t nat    -D POSTROUTING -j IKEV2_NAT 2>/dev/null || true
  iptables -t nat    -F IKEV2_NAT 2>/dev/null || true; iptables -t nat -X IKEV2_NAT 2>/dev/null || true
  iptables -t mangle -D FORWARD -j IKEV2_MSS 2>/dev/null || true
  iptables -t mangle -F IKEV2_MSS 2>/dev/null || true; iptables -t mangle -X IKEV2_MSS 2>/dev/null || true
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  systemctl daemon-reload
  sysctl --system >/dev/null 2>&1 || true
  ok "Configuration removed. ${STATE_DIR} and ${CLIENT_OUT_DIR} were kept —"
  ok "delete them by hand if you really want the CA gone."
}

# -----------------------------------------------------------------------------
# 19. Main
# -----------------------------------------------------------------------------
main() {
  parse_args "$@"
  need_root
  install -d -m 0700 "$STATE_DIR"

  case "$CMD" in
    add-client)
      load_state; detect_nic; set_proposals
      [[ -d $PKI_DIR ]] || die "No PKI found — run './iKev2_Deployment.sh' first."
      client_add "$ARG_NAME" "$ARG_PLATFORM" "$ARG_AUTH"
      exit 0 ;;
    list-clients)
      load_state; client_list; exit 0 ;;
    revoke-client)
      load_state; set_proposals; client_revoke "$ARG_NAME"; exit 0 ;;
    status)
      load_state
      head1 "IKE security associations"; swanctl --list-sas || true
      head1 "Virtual IP pools";          swanctl --list-pools --leases || true
      exit 0 ;;
    check)
      load_state; set_proposals; verify_all; exit 0 ;;
    repair-md4)
      load_state
      head1 "Repairing MD4 / EAP-MSCHAPv2 support"
      apt-get install -y -qq libcharon-extauth-plugins libstrongswan-extra-plugins >/dev/null 2>&1 || true
      setup_openssl_legacy
      disable_starter
      detect_service
      log "Restarting ${SS_SERVICE} ..."
      systemctl restart "$SS_SERVICE"
      sleep 2
      reload_config
      set_proposals
      verify_all
      exit 0 ;;
    uninstall)
      load_state; do_uninstall; exit 0 ;;
    deploy) : ;;
  esac

  printf '\n%s strongSwan IKEv2 deployment for Ubuntu 22.04 — v%s %s\n' "$C_BOLD" "$SCRIPT_VERSION" "$C_RST"
  printf '%s Windows 10/11 + Android, certificate and username/password %s\n\n' "$C_D" "$C_RST"

  load_state          # re-deploy keeps previous answers as defaults
  collect_config

  # Logging starts only now. While the questionnaire is running stdout must stay
  # attached to the real terminal: piping it through tee makes bash block-buffer
  # its output, so question text would appear after the prompt it belongs to.
  start_logging

  [[ $SKIP_PREFLIGHT == yes ]] || preflight
  detect_nic
  set_proposals

  install_packages
  disable_starter
  setup_openssl_legacy

  # DNS could not be checked before dnsutils existed — do it now.
  if [[ $SKIP_PREFLIGHT != yes ]] && have dig; then
    local a; a="$(dig +short +time=3 A "$VPN_DOMAIN" @1.1.1.1 2>/dev/null | grep -E '^[0-9.]+$' | head -1 || true)"
    [[ $a == "$VPN_IP" ]] && ok "DNS re-check: ${VPN_DOMAIN} -> ${a}" \
      || warn "DNS re-check: ${VPN_DOMAIN} -> ${a:-<none>} (expected ${VPN_IP})"
  fi

  pki_init
  pki_server_cert
  write_strongswan_conf
  write_swanctl_config
  kernel_tuning
  firewall_setup
  start_services

  save_state
  install_self

  client_add "$FIRST_CLIENT" "$FIRST_PLATFORM" "$FIRST_AUTH"

  verify_all
  summary
}

main "$@"
