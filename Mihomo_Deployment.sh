#!/usr/bin/env bash
# =============================================================================
#  Mihomo_Deployment.sh — mihomo (Clash.Meta) multi-protocol proxy
#                         for Ubuntu 22 / 24 / 26
#
#  Companion to iKev2_Deployment.sh, Singbox_Deployment.sh and Xray_Deployment.sh.
#
#  mihomo is the only widely-used core that speaks ShadowQUIC, Mieru, Sudoku,
#  TrustTunnel, RestLS and JLS server-side, on top of the usual VLESS / VMess /
#  Trojan / Hysteria2 / TUIC / AnyTLS / Snell / Shadowsocks family.  This script
#  enumerates EVERY valid protocol x transport x security-layer combination the
#  core actually implements, finds a free port for each one, generates every
#  secret, writes a schema-correct config.yaml, validates it with `mihomo -t`
#  BEFORE restarting, tunes the kernel for TCP + QUIC, opens the firewall and
#  emits ready-to-import client bundles:
#     * a mihomo / Clash.Meta client YAML  — every proxy node in one file
#     * share links + base64 subscription  — the subset that has a URI form
#     * a sing-box client config.json      — the subset sing-box can do
#
#  The combination space (74 listeners with --protocols all):
#     vless    tcp | xhttp                  x  tls | reality | shadowtls
#                                              | restls | jls
#              ws     (no reality), grpc (no restls)                      (18)
#     vmess    tcp                          x  the above five             (5)
#              ws     (no reality), grpc (no restls)                      (8)
#              mkcp (UDP, no TLS), mekya (h2-over-kcp inside TLS)         (2)
#     trojan   tcp                          x  the above five             (5)
#              ws     (no reality), grpc (no restls)                      (8)
#     anytls   tls | shadowtls | restls | jls                              (4)
#     ss       plain x (none|shadowtls|restls|jls), obfs-http, obfs-tls,
#              kcptun                                                      (7)
#     snell    plain x (none|shadowtls|restls|jls), obfs-http, obfs-tls     (6)
#     hysteria2, hysteria2-obfs, hysteria2-realm                           (3)
#     tuic, shadowquic                                                     (2)
#     mieru-tcp, mieru-udp                                                 (2)
#     sudoku, sudoku-httpmask                                              (2)
#     trusttunnel-tcp, trusttunnel-quic                                    (2)
#
#  Every combination emitted here is source-verified against MetaCubeX/mihomo
#  (listener/inbound/*.go struct tags, listener/parse.go, the *_interop_test.go
#  fixtures) and was booted end-to-end against mihomo v1.19.30 — all 78 bind and
#  carry traffic.  Combinations the core rejects or cannot actually use — two
#  security layers on one listener, mkcp with shadow-tls, kcptun with a security
#  layer, mekya with ws/grpc, and WebSocket with REALITY (see build_catalogue) —
#  are deliberately absent.
#
#  Subcommands:
#     ./Mihomo_Deployment.sh                deploy (interactive, sane defaults)
#     ./Mihomo_Deployment.sh info           reprint links / subscription / creds
#     ./Mihomo_Deployment.sh status         service + listening-port status
#     ./Mihomo_Deployment.sh check          re-run every health check
#     ./Mihomo_Deployment.sh update         upgrade mihomo to the latest build
#     ./Mihomo_Deployment.sh regen-sub      rebuild client bundles from state
#     ./Mihomo_Deployment.sh uninstall      remove configuration
#
#  After deployment this file installs itself as /usr/local/sbin/mihomoctl.
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# 0. Constants / cosmetics
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="1.0.0"
readonly STATE_DIR="/etc/mihomo-deploy"
readonly STATE_FILE="${STATE_DIR}/mihomo.env"
readonly MH_HOME="/etc/mihomo"
readonly MH_CONF="${MH_HOME}/config.yaml"
readonly MH_CERT_DIR="${MH_HOME}/cert"
readonly MH_CERT_FULL="${MH_CERT_DIR}/fullchain.pem"
readonly MH_CERT_KEY="${MH_CERT_DIR}/privkey.pem"
readonly MH_RENEW_HOOK="${MH_CERT_DIR}/deploy-hook.sh"
readonly MH_BIN="/usr/local/bin/mihomo"
readonly CLIENT_OUT_DIR="/root/mihomo-clients"
readonly LOGFILE="/var/log/mihomo-deploy.log"
readonly GH_API="https://api.github.com/repos/MetaCubeX/mihomo"
readonly GH_DL="https://github.com/MetaCubeX/mihomo/releases/download"

# Latest known good stable (verified 2026-08-19). The live tag is discovered
# from GitHub at install time; this is only the fallback.
readonly MH_STABLE_FALLBACK="v1.19.30"

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
  printf '\n%s[FATAL]%s Mihomo_Deployment.sh failed at line %s (exit %s).\n' "$C_R" "$C_RST" "$line" "$rc" >&2
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
NODE_LABEL=""                 # display prefix for generated nodes

INSTALL_CHANNEL="stable"      # stable | alpha | pinned
PIN_VERSION=""                # exact tag, e.g. v1.19.30
AMD64_LEVEL="auto"            # auto | v1 | v2 | v3   (see _amd64_level)

CERT_MODE="letsencrypt"       # letsencrypt | self
LE_EMAIL=""

PROTO_CHOICE="all"
SELECTED=""

LISTEN_ADDR="::"              # bare IP only; '::' is dual-stack, '0.0.0.0' v4-only

# Camouflage targets. REALITY steals a real TLS1.3 site's handshake; the
# shadow-tls / res-tls / jls / tlsmirror layers forward unauthenticated traffic
# to a real site, so an active prober sees exactly that site.
REALITY_SNI="www.microsoft.com"
STEAL_SNI="www.apple.com"

SS_METHOD="2022-blake3-aes-128-gcm"
SNELL_VERSION="4"             # mihomo's snell listener speaks v1..v4
HY2_OBFS="salamander"         # used by the hysteria2-obfs node only

API_LISTEN="127.0.0.1:9090"   # RESTful controller; loopback only by default
API_SECRET=""

AUTO_PORTS="yes"
KERNEL_TUNING="yes"
FIREWALL="auto"

SUB_HOST="no"
SUB_PORT="8080"
SUB_TOKEN=""

ASSUME_YES="no"
SKIP_PREFLIGHT="no"
NIC=""

MH_USER="mihomo"
MH_VERSION=""

CMD="deploy"

# Per-protocol ports (filled in by assign_ports / state).
declare -A PORT

# Generated secrets (filled in by gen_credentials / state).
UUID=""
PASSWORD=""
SS_PASSWORD=""
SNELL_PSK=""
REALITY_PRIVATE=""; REALITY_PUBLIC=""; REALITY_SHORTID=""
SHADOWTLS_PASSWORD=""
RESTLS_PASSWORD=""
JLS_USER=""; JLS_PASSWORD=""
TLSMIRROR_KEY=""
SQ_USER=""; SQ_PASSWORD=""
MIERU_USER=""; MIERU_PASSWORD=""
SUDOKU_PUB=""; SUDOKU_PRIV=""
TT_USER=""; TT_PASSWORD=""
TUIC_UUID=""; TUIC_PASSWORD=""
HY2_OBFS_PASSWORD=""
REALM_TOKEN=""
WS_PATH=""; GRPC_SVC=""; XHTTP_PATH=""; MKCP_SEED=""; OBFS_HOST=""
CERT_PIN=""

# =============================================================================
#  Canonical protocol catalogue
#
#  Rather than a hand-written list, the catalogue is the CROSS PRODUCT of three
#  axes — base protocol, transport, security layer — minus the combinations the
#  core rejects.  Every entry gets a key, and the key is what you pass to
#  --protocols.  K_BASE / K_XPORT / K_SEC decompose a key again at emit time.
#
#  Constraints encoded below (all from mihomo source):
#    * At most ONE security layer per listener — vless/vmess/trojan/anytls build
#      a securityModes slice and hard-error on len>1.
#    * vmess: mkcp XOR {shadow-tls,res-tls,jls} ("only supports TCP transports");
#      mkcp + reality/tlsmirror is not rejected but is untested upstream, so it
#      is not generated.  mekya XOR {ws,grpc}, and mekya needs a certificate.
#    * shadowsocks: kcp-tun replaces the TCP listener, so a security layer on
#      top would silently never apply.  Same for simple-obfs.
#    * vless/trojan/anytls MUST carry one of certificate/reality/shadow-tls/
#      res-tls/jls (or decryption/ss/allow-insecure) or the listener refuses to
#      start — hence no "plain" variants for them.
#    * xhttp is VLESS-only; mkcp/mekya/tlsmirror are VMess-only; kcp-tun and
#      simple-obfs are Shadowsocks-only; obfs-opts is Snell-only.
# =============================================================================
declare -a ALL_KEYS=()
declare -A K_BASE=() K_XPORT=() K_SEC=() K_PORTS=()

# _cat_add <key> <base> <transport> <security> <candidate ports...>
_cat_add() {
  local key=$1 base=$2 xport=$3 sec=$4; shift 4
  ALL_KEYS+=("$key")
  K_BASE[$key]="$base"; K_XPORT[$key]="$xport"; K_SEC[$key]="$sec"
  K_PORTS[$key]="$*"
}

# Candidate ports are drawn from a per-family band so that a full 81-listener
# deployment stays readable in `ss -tulpn`; three candidates each, then
# _pick_free falls back to a random high port.
_band() { local base=$1 n=$2; printf '%s %s %s' "$((base+n))" "$((base+300+n))" "$((base+600+n))"; }

build_catalogue() {
  ALL_KEYS=(); K_BASE=(); K_XPORT=(); K_SEC=(); K_PORTS=()
  local x s n

  # grpc + restls is absent everywhere below too. Both halves work on their own
  # -- grpc carries tls / reality / shadow-tls / jls fine, and restls carries
  # tcp / ws / anytls / snell / shadowsocks fine -- but combined the connection
  # hangs with no error on either side. gun (the gRPC transport) skips its
  # negotiated-ALPN check for restls precisely because restls does not report
  # one (transport/gun/gun.go:282), and the h2 framing then never establishes.
  # Reproduced on an isolated three-listener rig where vless-tcp-restls and
  # vless-grpc-jls both passed in the same run, before and after.
  #
  # ws + reality is deliberately absent everywhere below. The listener accepts
  # it and binds, but NO mihomo client can use it: the `case "ws"` branch of
  # adapter/outbound/{vless,vmess,trojan}.go builds a plain tls.Config and never
  # passes `Reality` (unlike the tcp / grpc / xhttp branches, which do). The
  # REALITY handshake therefore never happens, the server treats the client as
  # an unauthenticated prober and proxies it to the decoy site — the connection
  # comes back as "unexpected status: 200 OK". Verified end-to-end against
  # mihomo v1.19.30 for all three protocols.

  # --- VLESS: tcp/grpc/xhttp x 5 layers, ws x 4 = 19 ------------------------
  n=0
  for x in tcp ws grpc xhttp; do
    for s in tls reality shadowtls restls jls; do
      [[ $x == ws && $s == reality ]] && continue
      [[ $x == grpc && $s == restls ]] && continue
      _cat_add "vless-${x}-${s}" vless "$x" "$s" "$(_band 30000 $n)"
      n=$((n+1))
    done
  done

  # tlsmirror is also absent, for a different reason. It is a valid VMess-only
  # security mode and the listener binds happily, but a working connection needs
  # the CLIENT to carry an `embedded-traffic-generator` — a hand-authored steps
  # profile of HTTP requests that drives the mirrored carrier connection against
  # that specific decoy. Upstream only ever exercises it against a controlled
  # carrier and a v2ray peer. Without a matching generator the client simply
  # hangs (no error, on either side), so a generated node would be a trap.
  # Configure it by hand if you need it.

  # --- VMess: tcp x 5, grpc x 5, ws x 4, plus mkcp and mekya = 16 -----------
  n=0
  for s in tls reality shadowtls restls jls; do
    _cat_add "vmess-tcp-${s}" vmess tcp "$s" "$(_band 31000 $n)"; n=$((n+1))
  done
  for x in ws grpc; do
    for s in tls reality shadowtls restls jls; do
      [[ $x == ws && $s == reality ]] && continue
      [[ $x == grpc && $s == restls ]] && continue
      _cat_add "vmess-${x}-${s}" vmess "$x" "$s" "$(_band 31000 $n)"; n=$((n+1))
    done
  done
  _cat_add vmess-mkcp  vmess mkcp  none "$(_band 31000 $n)"; n=$((n+1))
  _cat_add vmess-mekya vmess mekya tls  "$(_band 31000 $n)"

  # --- Trojan: tcp/grpc x 5, ws x 4 = 14 ------------------------------------
  n=0
  for x in tcp ws grpc; do
    for s in tls reality shadowtls restls jls; do
      [[ $x == ws && $s == reality ]] && continue
      [[ $x == grpc && $s == restls ]] && continue
      _cat_add "trojan-${x}-${s}" trojan "$x" "$s" "$(_band 32000 $n)"; n=$((n+1))
    done
  done

  # --- AnyTLS: 4 security layers (no transport axis) ------------------------
  n=0
  for s in tls shadowtls restls jls; do
    _cat_add "anytls-${s}" anytls tcp "$s" "$(_band 33000 $n)"; n=$((n+1))
  done

  # --- Shadowsocks: 4 security layers + 2 obfs modes + kcptun = 7 -----------
  _cat_add ss-plain     ss plain     none      "$(_band 34000 0)"
  _cat_add ss-shadowtls ss plain     shadowtls "$(_band 34000 1)"
  _cat_add ss-restls    ss plain     restls    "$(_band 34000 2)"
  _cat_add ss-jls       ss plain     jls       "$(_band 34000 3)"
  _cat_add ss-obfs-http ss obfs-http none      "$(_band 34000 4)"
  _cat_add ss-obfs-tls  ss obfs-tls  none      "$(_band 34000 5)"
  _cat_add ss-kcptun    ss kcptun    none      "$(_band 34000 6)"

  # --- Snell: 4 security layers + 2 obfs modes = 6 --------------------------
  _cat_add snell-plain     snell plain     none      "$(_band 35000 0)"
  _cat_add snell-shadowtls snell plain     shadowtls "$(_band 35000 1)"
  _cat_add snell-restls    snell plain     restls    "$(_band 35000 2)"
  _cat_add snell-jls       snell plain     jls       "$(_band 35000 3)"
  _cat_add snell-obfs-http snell obfs-http none      "$(_band 35000 4)"
  _cat_add snell-obfs-tls  snell obfs-tls  none      "$(_band 35000 5)"

  # --- QUIC family (each carries its own TLS; no transport axis) ------------
  _cat_add hysteria2       hysteria2  quic tls  "443 8443 36000"
  _cat_add hysteria2-obfs  hysteria2  quic obfs "36001 36301 36601"
  # A realm server is the HTTPS rendezvous endpoint hysteria2 nodes register
  # with — a coordination service, not a proxy inbound. It listens on TCP.
  _cat_add hysteria2-realm realm      tcp  tls  "36002 36302 36602"
  _cat_add tuic            tuic       quic tls  "8443 36003 36303"
  _cat_add shadowquic      shadowquic quic jls  "36004 36304 36604"

  # --- mihomo-only protocols ------------------------------------------------
  _cat_add mieru-tcp       mieru tcp  none "$(_band 37000 0)"
  _cat_add mieru-udp       mieru udp  none "$(_band 37000 1)"
  _cat_add sudoku          sudoku raw      none "$(_band 37000 2)"
  _cat_add sudoku-httpmask sudoku httpmask none "$(_band 37000 3)"
  _cat_add trusttunnel-tcp  trusttunnel tcp  tls "$(_band 37000 4)"
  _cat_add trusttunnel-quic trusttunnel quic tls "$(_band 37000 5)"
  return 0
}
build_catalogue

# A curated subset for people who do not want all 81 nodes at once.
readonly RECOMMENDED_KEYS="vless-tcp-reality vless-ws-tls vless-grpc-reality vless-xhttp-reality vmess-ws-tls trojan-tcp-tls anytls-tls ss-plain snell-plain hysteria2 hysteria2-obfs tuic shadowquic sudoku"
# The "classic" set, i.e. what the sing-box / Xray scripts also offer.
readonly CORE_KEYS="vless-tcp-reality vless-ws-tls vmess-ws-tls trojan-tcp-tls anytls-tls ss-plain hysteria2 tuic"

# --- derived per-key properties ----------------------------------------------
# L4 a key listens on. QUIC and mkcp/kcptun are UDP; shadowsocks and snell keep
# their UDP relay socket alongside TCP.
proto_l4() {
  local key=$1
  case "${K_BASE[$key]}" in
    hysteria2|tuic|shadowquic) echo udp; return ;;
    realm)       echo tcp; return ;;
    mieru)       [[ ${K_XPORT[$key]} == udp ]] && echo udp || echo tcp; return ;;
    trusttunnel) [[ ${K_XPORT[$key]} == quic ]] && echo udp || echo tcp; return ;;
    vmess)       [[ ${K_XPORT[$key]} == mkcp ]] && echo udp || echo tcp; return ;;
    ss)          [[ ${K_XPORT[$key]} == kcptun ]] && echo udp || echo both; return ;;
    snell)       echo both; return ;;
    *)           echo tcp ;;
  esac
}

# Which keys need a real certificate on disk. REALITY / shadow-tls / res-tls /
# jls / tlsmirror deliberately need none — they borrow another site's identity.
proto_needs_cert() {
  local key=$1
  case "${K_BASE[$key]}" in
    hysteria2|tuic|trusttunnel|realm) echo yes; return ;;
  esac
  [[ ${K_SEC[$key]} == tls ]] && echo yes || echo no
}

proto_desc() {
  local key=$1
  local b="${K_BASE[$key]}" x="${K_XPORT[$key]}" s="${K_SEC[$key]}"
  local xd sd
  case "$x" in
    tcp)       xd="raw TCP" ;;
    ws)        xd="WebSocket" ;;
    grpc)      xd="gRPC" ;;
    xhttp)     xd="XHTTP" ;;
    mkcp)      xd="mKCP (UDP)" ;;
    mekya)     xd="Mekya (h2 over KCP)" ;;
    plain)     xd="raw TCP" ;;
    obfs-http) xd="simple-obfs http" ;;
    obfs-tls)  xd="simple-obfs tls" ;;
    kcptun)    xd="KCPTun (UDP)" ;;
    quic)      xd="QUIC" ;;
    raw)       xd="raw TCP" ;;
    httpmask)  xd="HTTP-masked" ;;
    udp)       xd="UDP" ;;
    *)         xd="$x" ;;
  esac
  case "$s" in
    tls)       sd="TLS certificate" ;;
    reality)   sd="REALITY (no cert)" ;;
    shadowtls) sd="ShadowTLS v3 (no cert)" ;;
    restls)    sd="RestLS (no cert)" ;;
    jls)       sd="JLS (no cert)" ;;
    tlsmirror) sd="TLS-mirror (no cert)" ;;
    obfs)      sd="salamander obfs" ;;
    none)      sd="native encryption" ;;
    *)         sd="$s" ;;
  esac
  printf '%-12s %-22s %-24s' "$b" "$xd" "$sd"
}

# The mihomo listener `type:` for a key (several keys share one type).
mh_type() {
  case "${K_BASE[$1]}" in
    ss)    echo shadowsocks ;;
    realm) echo hysteria2-realm ;;
    *)     echo "${K_BASE[$1]}" ;;
  esac
}

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
  if have mihomo; then u="$(mihomo generate uuid 2>/dev/null | tr -d '[:space:]' || true)"; fi
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
valid_tag()     { [[ $1 =~ ^v[0-9]{1,3}\.[0-9]{1,2}\.[0-9]{1,3}$ ]]; }
valid_listen()  { [[ $1 == "::" || $1 == "0.0.0.0" ]] || valid_ipv4 "$1"; }

# Match the LOCAL address column (4). Matching the peer column makes every port
# look free.
port_listening() {
  local flag="-lun"; [[ $1 == tcp ]] && flag="-ltn"
  ss $flag 2>/dev/null | awk -v p=":$2\$" '$4 ~ p {f=1} END{exit !f}'
}

save_state() {
  install -d -m 0700 "$STATE_DIR"
  {
    printf '# generated by Mihomo_Deployment.sh v%s on %s\n' "$SCRIPT_VERSION" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local v
    for v in VPN_DOMAIN VPN_IP NODE_LABEL INSTALL_CHANNEL PIN_VERSION AMD64_LEVEL \
             CERT_MODE LE_EMAIL PROTO_CHOICE SELECTED LISTEN_ADDR \
             REALITY_SNI STEAL_SNI SS_METHOD SNELL_VERSION HY2_OBFS \
             API_LISTEN API_SECRET \
             AUTO_PORTS KERNEL_TUNING FIREWALL SUB_HOST SUB_PORT SUB_TOKEN NIC \
             MH_USER MH_VERSION \
             UUID PASSWORD SS_PASSWORD SNELL_PSK \
             REALITY_PRIVATE REALITY_PUBLIC REALITY_SHORTID \
             SHADOWTLS_PASSWORD RESTLS_PASSWORD JLS_USER JLS_PASSWORD TLSMIRROR_KEY \
             SQ_USER SQ_PASSWORD MIERU_USER MIERU_PASSWORD SUDOKU_PUB SUDOKU_PRIV \
             TT_USER TT_PASSWORD TUIC_UUID TUIC_PASSWORD HY2_OBFS_PASSWORD REALM_TOKEN \
             WS_PATH GRPC_SVC XHTTP_PATH MKCP_SEED OBFS_HOST CERT_PIN; do
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
insec_bool() { [[ ${CERT_MODE} == self ]] && printf 'true' || printf 'false'; }
selected_has() { [[ " $SELECTED " == *" $1 "* ]]; }
selected_count() { local n=0 k; for k in $SELECTED; do n=$((n+1)); done; printf '%s' "$n"; }
needs_any_cert() {
  local k
  for k in $SELECTED; do [[ $(proto_needs_cert "$k") == yes ]] && return 0; done
  return 1
}
# Does any selected key borrow a real external site's TLS identity?
uses_steal_site() {
  local k
  for k in $SELECTED; do
    case "${K_SEC[$k]}" in shadowtls|restls|jls|tlsmirror) return 0 ;; esac
    [[ ${K_BASE[$k]} == shadowquic ]] && return 0
  done
  return 1
}

# Drop one key from SELECTED without leaving a stray blank entry.
deselect() {
  local drop=$1 k out=()
  for k in $SELECTED; do [[ $k == "$drop" ]] || out+=("$k"); done
  SELECTED="${out[*]}"
}

# Display name of a node, used in YAML, links and proxy-groups alike.
node_name() { printf '%s-%s' "$NODE_LABEL" "$1"; }

usage() {
cat <<EOF
${C_BOLD}Mihomo_Deployment.sh v${SCRIPT_VERSION}${C_RST} — mihomo (Clash.Meta) multi-protocol proxy for Ubuntu 22/24/26

Usage:
  sudo bash Mihomo_Deployment.sh [subcommand] [options]

Subcommands:
  deploy                 (default) install and configure everything
  info                   reprint share links / subscription / credentials
  status                 service and listening-port status
  check                  re-run every health check
  update                 upgrade mihomo to the newest build in the chosen channel
  regen-sub              rebuild client bundles from saved state
  uninstall              remove configuration

Common options:
  -y, --yes                    non-interactive; requires --domain
      --domain <fqdn>          REQUIRED, e.g. vpn.example.com
      --ip <ipv4>              public IPv4 (auto-detected if omitted)
      --channel <stable|alpha|pinned>
                               alpha = the rolling Prerelease-Alpha build
      --version <tag>          exact tag for --channel pinned, e.g. ${MH_STABLE_FALLBACK}
      --amd64-level <auto|v1|v2|v3>
                               GOAMD64 build to fetch. 'auto' probes /proc/cpuinfo;
                               the plain 'amd64' asset upstream is a v3 build and
                               SIGILLs on pre-Haswell CPUs, hence this flag.
      --protocols <all|recommended|core|list>
                               'all' = every valid combination (${#ALL_KEYS[@]} listeners)
                               a list may name keys, families (vless, vmess, trojan,
                               anytls, ss, snell, quic, exotic) or security layers
                               (reality, shadowtls, restls, jls, tls).
                               A family name that is also a key ('hysteria2',
                               'sudoku') expands to the whole family.
      --listen <addr>          bare IP the listeners bind (default: ${LISTEN_ADDR})
      --cert-mode <letsencrypt|self>
      --le-email <email>
      --reality-sni <host>     REALITY steal target (default: ${REALITY_SNI})
      --steal-sni <host>       ShadowTLS/RestLS/JLS/TLS-mirror decoy (default: ${STEAL_SNI})
      --ss-method <cipher>     Shadowsocks cipher (default: ${SS_METHOD})
      --snell-version <1..4>   Snell protocol version (default: ${SNELL_VERSION})
      --api-listen <ip:port>   RESTful controller (default: ${API_LISTEN}; '' disables)
      --no-kernel-tuning
      --firewall <auto|ufw|iptables|none>
      --serve-sub              also serve the subscription over plain HTTP
      --skip-preflight

Run '${0##*/} --list-protocols' to print the full catalogue.
EOF
}

list_protocols() {
  local k i=1
  printf '     %s%-26s %-5s %-12s %-22s %-24s %s%s\n' "$C_BOLD" "key" "l4" "protocol" "transport" "security" "cert" "$C_RST"
  for k in "${ALL_KEYS[@]}"; do
    printf '%3d) %-26s %-5s %s %s\n' "$i" "$k" "$(proto_l4 "$k")" "$(proto_desc "$k")" "$(proto_needs_cert "$k")"
    i=$((i+1))
  done
  printf '\n%d combinations total.\n' "${#ALL_KEYS[@]}"
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
      --amd64-level)      AMD64_LEVEL="$2"; shift 2 ;;
      --protocols)        PROTO_CHOICE="$2"; shift 2 ;;
      --listen)           LISTEN_ADDR="$2"; shift 2 ;;
      --cert-mode)        CERT_MODE="$2"; shift 2 ;;
      --le-email)         LE_EMAIL="$2"; shift 2 ;;
      --reality-sni)      REALITY_SNI="$2"; shift 2 ;;
      --steal-sni)        STEAL_SNI="$2"; shift 2 ;;
      --ss-method)        SS_METHOD="$2"; shift 2 ;;
      --snell-version)    SNELL_VERSION="$2"; shift 2 ;;
      --api-listen)       API_LISTEN="$2"; shift 2 ;;
      --no-kernel-tuning) KERNEL_TUNING="no"; shift ;;
      --firewall)         FIREWALL="$2"; shift 2 ;;
      --serve-sub)        SUB_HOST="yes"; shift ;;
      --skip-preflight)   SKIP_PREFLIGHT="yes"; shift ;;
      --list-protocols)   list_protocols; exit 0 ;;
      -h|--help)          usage; exit 0 ;;
      -*) die "Unknown option: $1  (try --help)" ;;
      *)  die "Unexpected argument: $1  (try --help)" ;;
    esac
  done
}

# -----------------------------------------------------------------------------
# 4. Protocol selection + port assignment
# -----------------------------------------------------------------------------
# Expand one selection token into zero or more catalogue keys.
_expand_token() {
  local tok=$1 k out=()
  case "$tok" in
    all|"*")        printf '%s\n' "${ALL_KEYS[@]}"; return 0 ;;
    recommended|rec) printf '%s\n' $RECOMMENDED_KEYS; return 0 ;;
    core|classic)   printf '%s\n' $CORE_KEYS; return 0 ;;
    # families by base protocol
    vless|vmess|trojan|anytls|snell|mieru|sudoku|trusttunnel|shadowquic)
      for k in "${ALL_KEYS[@]}"; do [[ ${K_BASE[$k]} == "$tok" ]] && out+=("$k"); done ;;
    ss|shadowsocks)
      for k in "${ALL_KEYS[@]}"; do [[ ${K_BASE[$k]} == ss ]] && out+=("$k"); done ;;
    hysteria2|hy2)
      for k in "${ALL_KEYS[@]}"; do [[ ${K_BASE[$k]} == hysteria2 ]] && out+=("$k"); done ;;
    quic)
      for k in "${ALL_KEYS[@]}"; do [[ $(proto_l4 "$k") == udp ]] && out+=("$k"); done ;;
    exotic)
      for k in "${ALL_KEYS[@]}"; do
        case "${K_BASE[$k]}" in shadowquic|mieru|sudoku|trusttunnel|realm) out+=("$k") ;; esac
      done ;;
    # families by security layer
    reality|shadowtls|restls|jls|tls)
      for k in "${ALL_KEYS[@]}"; do [[ ${K_SEC[$k]} == "$tok" ]] && out+=("$k"); done ;;
    # families by transport
    ws|grpc|xhttp|mkcp|mekya|kcptun)
      for k in "${ALL_KEYS[@]}"; do [[ ${K_XPORT[$k]} == "$tok" ]] && out+=("$k"); done ;;
    *)
      for k in "${ALL_KEYS[@]}"; do [[ $k == "$tok" ]] && out+=("$k"); done ;;
  esac
  (( ${#out[@]} > 0 )) || return 1
  printf '%s\n' "${out[@]}"
}

resolve_selection() {
  local choice="${PROTO_CHOICE,,}" out=() tok exp k
  [[ -n $choice ]] || choice="all"
  choice="${choice//,/ }"
  for tok in $choice; do
    if ! exp="$(_expand_token "$tok")"; then
      die "Unknown protocol / family '${tok}'. Run '$0 --list-protocols' for the catalogue."
    fi
    for k in $exp; do
      [[ " ${out[*]-} " == *" $k "* ]] || out+=("$k")
    done
  done
  (( ${#out[@]} > 0 )) || die "No protocols selected."
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
  while (( tries < 200 )); do n=$(( (RANDOM % 25000) + 20000 )); if ! _port_taken "$l4" "$n"; then echo "$n"; return 0; fi; tries=$((tries+1)); done
  return 1
}

assign_ports() {
  USED_TCP=(); USED_UDP=(); PORT=()
  local key l4 chosen
  # Never hand out the port sshd is on, whatever the curated lists say.
  _port_reserve tcp "$(ssh_port)"
  for key in $SELECTED; do
    l4="$(proto_l4 "$key")"
    chosen="$(_pick_free "$l4" ${K_PORTS[$key]} || true)"
    [[ -n $chosen ]] || die "Could not find a free ${l4} port for ${key}."
    PORT[$key]="$chosen"; _port_reserve "$l4" "$chosen"
  done
}

review_ports() {
  local key p n
  n="$(selected_count)"
  echo
  echo "  Ports selected (free on this host) — ${n} listener(s):"
  if (( n > 20 )); then
    echo "    (showing the first 20; the full map lands in ${CLIENT_OUT_DIR}/README.txt)"
    local i=0
    for key in $SELECTED; do
      (( i < 20 )) || break
      printf '    %-26s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"
      i=$((i+1))
    done
  else
    for key in $SELECTED; do
      printf '    %-26s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"
    done
  fi
  [[ $AUTO_PORTS == yes ]] && return 0
  for key in $SELECTED; do
    ask_valid p "Port for ${key} ($(proto_l4 "$key"))" "${PORT[$key]}" valid_port_num "must be 1..65535"
    PORT[$key]="$p"
  done
  return 0
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
  echo "  ${C_BOLD}stable${C_RST} – the newest tagged release (currently ${MH_STABLE_FALLBACK}). Recommended."
  echo "  ${C_BOLD}alpha${C_RST}  – the rolling Prerelease-Alpha build of the Alpha branch."
  echo "           Its listener set is identical to stable today; it moves faster."
  echo "  ${C_BOLD}pinned${C_RST} – an exact tag you name."
  ask_choice INSTALL_CHANNEL "mihomo release channel" "$INSTALL_CHANNEL" stable alpha pinned
  if [[ $INSTALL_CHANNEL == pinned ]]; then
    ask_valid PIN_VERSION "Exact mihomo tag to install" "${PIN_VERSION:-$MH_STABLE_FALLBACK}" \
      valid_tag "expected a tag like ${MH_STABLE_FALLBACK}"
  fi

  echo
  echo "  Protocol selection. The catalogue holds ${#ALL_KEYS[@]} valid combinations of"
  echo "  base protocol x transport x security layer."
  echo
  echo "    ${C_BOLD}all${C_RST}          every combination (${#ALL_KEYS[@]} listeners, ${#ALL_KEYS[@]} ports)"
  echo "    ${C_BOLD}recommended${C_RST}  a curated 14 that cover every distinct technique"
  echo "    ${C_BOLD}core${C_RST}         the 8 classics also offered by the sing-box / Xray scripts"
  echo
  echo "  Or a comma list of families and keys, e.g.:"
  echo "    reality,jls,hysteria2,shadowquic     vless,quic     vless-tcp-reality,tuic"
  echo "  Families: vless vmess trojan anytls ss snell quic exotic"
  echo "            reality shadowtls restls jls tls ws grpc xhttp mkcp mekya kcptun"
  echo "  (run '$0 --list-protocols' for every key)"
  ask PROTO_CHOICE "Which protocols" "$PROTO_CHOICE"
  resolve_selection
  local n; n="$(selected_count)"
  echo "  Selected: ${n} listener(s)."
  if (( n > 40 )); then
    warn "That is ${n} listening sockets and ${n} firewall openings on one host."
    warn "It works, but 'recommended' is the saner default for a production node."
  fi

  # --- certificate ---
  if needs_any_cert; then
    echo
    echo "  ${C_BOLD}letsencrypt${C_RST} – real cert via certbot (needs the A record pointing here + port 80 free)."
    echo "  ${C_BOLD}self${C_RST}        – self-signed; clients must allow insecure or pin the fingerprint."
    ask_choice CERT_MODE "TLS certificate source" "$CERT_MODE" letsencrypt self
    if [[ $CERT_MODE == letsencrypt ]]; then
      ask_valid LE_EMAIL "Let's Encrypt contact e-mail (blank = register without one)" "$LE_EMAIL" \
        valid_email "that does not look like an e-mail address"
    fi
  else
    CERT_MODE="self"
  fi

  local k has_reality="no"
  for k in $SELECTED; do [[ ${K_SEC[$k]} == reality ]] && has_reality="yes"; done
  if [[ $has_reality == yes ]]; then
    ask_valid REALITY_SNI "REALITY steal target (a real external TLS1.3 site)" "$REALITY_SNI" \
      valid_domain "must be a hostname, e.g. www.microsoft.com"
  fi
  if uses_steal_site; then
    echo
    echo "  ShadowTLS / RestLS / JLS / TLS-mirror / ShadowQUIC forward every"
    echo "  unauthenticated connection to a real site, so an active prober sees"
    echo "  that site and nothing else. Pick a busy host that is NOT blocked where"
    echo "  your clients are, and ideally not the same one as the REALITY target."
    ask_valid STEAL_SNI "Decoy site for the certificate-less layers" "$STEAL_SNI" \
      valid_domain "must be a hostname, e.g. www.apple.com"
  fi

  ask_valid LISTEN_ADDR "Address the listeners bind ('::' = dual-stack)" "$LISTEN_ADDR" \
    valid_listen "must be a bare IP: '::', '0.0.0.0' or an IPv4 address"
  ask_yn AUTO_PORTS "Auto-assign the first free curated port per listener" "$AUTO_PORTS"
  ask_choice FIREWALL "Firewall backend" "$FIREWALL" auto ufw iptables none
  ask_yn KERNEL_TUNING "Apply kernel/sysctl tuning (BBR, QUIC buffers, fd limits)" "$KERNEL_TUNING"
  ask_yn SUB_HOST "Also serve the subscription over plain HTTP (secret path)" "$SUB_HOST"
  [[ $SUB_HOST == yes ]] && ask_valid SUB_PORT "HTTP port for the subscription server" "$SUB_PORT" valid_port_num "1..65535"

  assign_ports
  review_ports

  echo
  hr
  printf '  %-24s %s\n' "Domain / IP"     "${VPN_DOMAIN} / ${VPN_IP:-?}"
  printf '  %-24s %s\n' "mihomo channel"  "$INSTALL_CHANNEL${PIN_VERSION:+ ($PIN_VERSION)}"
  printf '  %-24s %s\n' "Listeners"       "$(selected_count)"
  printf '  %-24s %s\n' "Bind address"    "$LISTEN_ADDR"
  needs_any_cert && printf '  %-24s %s\n' "TLS certificate" "$CERT_MODE"
  [[ $has_reality == yes ]] && printf '  %-24s %s\n' "REALITY SNI" "$REALITY_SNI"
  uses_steal_site && printf '  %-24s %s\n' "Decoy site" "$STEAL_SNI"
  printf '  %-24s %s\n' "Firewall"        "$FIREWALL"
  printf '  %-24s %s\n' "Kernel tuning"   "$KERNEL_TUNING"
  hr
  local go; ask_yn go "Proceed with these settings" "yes"
  [[ $go == yes ]] || die "Aborted by user."
  return 0
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
    x86_64|amd64) ok "Architecture: $(uname -m) (GOAMD64 level: $(_amd64_level))" ;;
    aarch64|arm64|armv7l) ok "Architecture: $(uname -m)" ;;
    *) warn "Architecture $(uname -m) may lack a prebuilt mihomo binary." ;;
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

  # The decoy sites must actually be reachable from THIS host: the camouflage
  # layers proxy unauthenticated traffic to them at connect time.
  local host
  for host in $( { [[ -n $REALITY_SNI ]] && echo "$REALITY_SNI"; uses_steal_site && echo "$STEAL_SNI"; } | sort -u ); do
    if curl -fsS --max-time 6 -o /dev/null "https://${host}/" 2>/dev/null; then
      ok "Decoy reachable: https://${host}"
    else
      warn "Could not reach https://${host} from this server — camouflage fallbacks will fail."
    fi
  done
  return 0
}

# -----------------------------------------------------------------------------
# 7. Install mihomo
# -----------------------------------------------------------------------------
install_deps() {
  head1 "Installing dependencies"
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a NEEDRESTART_SUSPEND=1
  echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections 2>/dev/null || true
  echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections 2>/dev/null || true
  log "apt-get update ..."; apt-get update -qq || warn "apt-get update reported errors."
  local base=(curl ca-certificates jq openssl gzip zip iproute2 dnsutils)
  apt-get install -y -qq "${base[@]}" >/dev/null 2>&1 || {
    warn "Batch dependency install failed; retrying individually."
    local p; for p in "${base[@]}"; do apt-get install -y -qq "$p" >/dev/null 2>&1 || warn "could not install $p"; done
  }
  have jq      || die "jq is required and could not be installed."
  have openssl || die "openssl is required and could not be installed."
  if [[ $CERT_MODE == letsencrypt ]] && needs_any_cert; then
    apt-get install -y -qq certbot >/dev/null 2>&1 || die "Failed to install certbot (needed for --cert-mode letsencrypt)."
  fi
  return 0
}

# GOAMD64 microarchitecture level of THIS cpu. Upstream ships the plain
# "mihomo-linux-amd64-<ver>.gz" asset as a GOAMD64=v3 build, which SIGILLs on
# anything older than Haswell/Excavator and on VPS hosts that mask AVX2 — so
# the level is probed and the explicit -v1/-v2/-v3 asset name is used instead.
_amd64_level() {
  if [[ $AMD64_LEVEL != auto ]]; then printf '%s' "$AMD64_LEVEL"; return 0; fi
  local f=""
  [[ -r /proc/cpuinfo ]] && f="$(awk -F': ' '/^flags/{print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
  local have_v2=1 have_v3=1 x
  for x in cx16 lahf_lm popcnt pni sse4_1 sse4_2 ssse3; do
    [[ " $f " == *" $x "* ]] || have_v2=0
  done
  for x in avx avx2 bmi1 bmi2 f16c fma lzcnt movbe xsave; do
    [[ " $f " == *" $x "* ]] || have_v3=0
  done
  if (( have_v2 && have_v3 )); then printf 'v3'
  elif (( have_v2 ));            then printf 'v2'
  else                                printf 'v1'; fi
}

# Release-asset infix for this machine. Upstream naming:
#   mihomo-linux-<infix>-<VERSION>.gz     (a bare gzipped ELF, NOT a tarball)
_arch_mihomo() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64-%s' "$(_amd64_level)" ;;
    aarch64|arm64) echo arm64 ;;
    armv7l)        echo armv7 ;;
    armv6l)        echo armv6 ;;
    i386|i686)     echo 386 ;;
    riscv64)       echo riscv64 ;;
    *)             echo "" ;;
  esac
}

# Resolve the release tag and the VERSION string that appears in asset names.
# For stable they are the same (v1.19.30); for the rolling prerelease the tag is
# "Prerelease-Alpha" while the assets carry "alpha-<short-sha>".
_resolve_release() {
  local tag ver json
  case "$INSTALL_CHANNEL" in
    pinned)
      tag="$PIN_VERSION"; ver="$PIN_VERSION" ;;
    alpha)
      tag="Prerelease-Alpha"
      # `|| true` + swallowed jq errors: a bare `cmd | jq` assignment under
      # set -e + pipefail would fire the ERR trap on an API rate-limit (403).
      json="$(curl -fsSL "${GH_API}/releases/tags/Prerelease-Alpha" 2>/dev/null || true)"
      # The asset VERSION is "alpha-<short-sha>". Anchor on that shape rather than
      # a wildcard: the release also carries mihomo-linux-arm64-go1NN-alpha-*.gz
      # old-toolchain builds, and a greedy match would happily return "go124-alpha-…".
      ver="$(printf '%s' "$json" | jq -r '[.assets[].name | capture("^mihomo-linux-arm64-(?<v>alpha-[0-9a-f]+)\\.gz$").v][0]' 2>/dev/null || true)"
      [[ -n $ver && $ver != null ]] || ver=""
      ;;
    *)
      json="$(curl -fsSL "${GH_API}/releases/latest" 2>/dev/null || true)"
      tag="$(printf '%s' "$json" | jq -r '.tag_name' 2>/dev/null || true)"
      [[ -n $tag && $tag != null ]] || tag="$MH_STABLE_FALLBACK"
      ver="$tag" ;;
  esac
  [[ -n $tag && $tag != null ]] || die "Could not determine a mihomo release tag (GitHub API unreachable or rate-limited). Retry, or use --version <tag>."
  [[ -n $ver ]] || die "Could not determine the asset version string for channel '${INSTALL_CHANNEL}'."
  printf '%s %s' "$tag" "$ver"
}

install_mihomo() {
  head1 "Installing mihomo (${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}})"
  local arch tag ver url tmp rel
  arch="$(_arch_mihomo)"; [[ -n $arch ]] || die "No prebuilt mihomo for $(uname -m)."
  rel="$(_resolve_release)"; tag="${rel%% *}"; ver="${rel##* }"
  url="${GH_DL}/${tag}/mihomo-linux-${arch}-${ver}.gz"

  tmp="$(mktemp -d)"
  log "Downloading ${url}"
  if ! curl -fL --retry 2 -o "$tmp/mihomo.gz" "$url"; then
    # amd64-v1 has only existed since the naming rework; fall back to the
    # legacy "amd64-compatible" name, which is the same GOAMD64=v1 build.
    if [[ $arch == amd64-v1 ]]; then
      url="${GH_DL}/${tag}/mihomo-linux-amd64-compatible-${ver}.gz"
      log "Retrying with the legacy name: ${url}"
      curl -fL --retry 2 -o "$tmp/mihomo.gz" "$url" || { rm -rf "$tmp"; die "Download failed: $url"; }
    else
      rm -rf "$tmp"; die "Download failed: $url"
    fi
  fi
  # The asset is a single gzipped ELF, not a tarball — `tar xzf` would fail.
  gzip -dc "$tmp/mihomo.gz" >"$tmp/mihomo" || { rm -rf "$tmp"; die "Could not decompress the mihomo archive."; }
  [[ -s $tmp/mihomo ]] || { rm -rf "$tmp"; die "Decompressed mihomo binary is empty."; }
  install -m0755 "$tmp/mihomo" "$MH_BIN"
  rm -rf "$tmp"

  # A wrong GOAMD64 level shows up here as "Illegal instruction", not at runtime
  # three steps later.
  if ! MH_VERSION="$("$MH_BIN" -v 2>/dev/null | awk 'NR==1{print $3}')"; then
    die "The installed mihomo binary will not run (wrong GOAMD64 level? try --amd64-level v1)."
  fi
  [[ -n $MH_VERSION ]] || MH_VERSION="$ver"

  id "$MH_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin "$MH_USER" 2>/dev/null || MH_USER="root"
  id "$MH_USER" >/dev/null 2>&1 || MH_USER="root"
  install -d -o root -g "$MH_USER" -m 0750 "$MH_HOME"
  # cache.db (selector state) is written into the home dir; give the service
  # user ownership so ProtectSystem=strict + ReadWritePaths works cleanly.
  chown "$MH_USER":"$MH_USER" "$MH_HOME" 2>/dev/null || true
  install_unit
  ok "mihomo ${MH_VERSION} installed to ${MH_BIN} (asset: linux-${arch}, service user: ${MH_USER})."
  return 0
}

# A server-only node needs neither TUN nor tproxy nor process matching, so the
# upstream unit's capability set (NET_ADMIN, NET_RAW, SYS_TIME, SYS_PTRACE,
# DAC_OVERRIDE...) is dropped to just NET_BIND_SERVICE. The QUIC receive-buffer
# ceiling that NET_ADMIN would otherwise force is raised via sysctl instead.
install_unit() {
  cat >/etc/systemd/system/mihomo.service <<EOF
[Unit]
Description=mihomo Daemon (server node)
Documentation=https://wiki.metacubex.one
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=${MH_USER}
Group=${MH_USER}
ExecStart=${MH_BIN} -d ${MH_HOME}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
LimitNOFILE=1048576
LimitNPROC=10000

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${MH_HOME}
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources @obsolete @mount @debug @cpu-emulation @swap

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  return 0
}

# -----------------------------------------------------------------------------
# 8. Credentials
# -----------------------------------------------------------------------------
gen_reality_keys() {
  local out
  out="$("$MH_BIN" generate reality-keypair 2>/dev/null || true)"
  REALITY_PRIVATE="$(printf '%s\n' "$out" | grep -i '^PrivateKey' | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  REALITY_PUBLIC="$(printf '%s\n'  "$out" | grep -i '^PublicKey'  | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  [[ -n $REALITY_PRIVATE && -n $REALITY_PUBLIC ]] || die "\`mihomo generate reality-keypair\` produced no keypair."
  return 0
}

gen_sudoku_keys() {
  local out
  out="$("$MH_BIN" generate sudoku-keypair 2>/dev/null || true)"
  # PublicKey is the server's master key; PrivateKey is what a client presents.
  SUDOKU_PRIV="$(printf '%s\n' "$out" | grep -i '^PrivateKey' | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  SUDOKU_PUB="$(printf '%s\n'  "$out" | grep -i '^PublicKey'  | head -1 | sed 's/.*: *//' | tr -d '[:space:]' || true)"
  if [[ -z $SUDOKU_PRIV || -z $SUDOKU_PUB ]]; then
    warn "\`mihomo generate sudoku-keypair\` is unavailable in this build — dropping the sudoku nodes."
    deselect sudoku; deselect sudoku-httpmask
  fi
  return 0
}

_sec_used() { # _sec_used <security layer>  -> true if any selected key uses it
  local want=$1 k
  for k in $SELECTED; do [[ ${K_SEC[$k]} == "$want" ]] && return 0; done
  return 1
}
_base_used() { # _base_used <base protocol>
  local want=$1 k
  for k in $SELECTED; do [[ ${K_BASE[$k]} == "$want" ]] && return 0; done
  return 1
}
_xport_used() { # _xport_used <transport>
  local want=$1 k
  for k in $SELECTED; do [[ ${K_XPORT[$k]} == "$want" ]] && return 0; done
  return 1
}

gen_credentials() {
  head1 "Generating credentials"
  [[ -n $UUID ]]       || UUID="$(gen_uuid)"
  [[ -n $PASSWORD ]]   || PASSWORD="$(gen_pass)"
  [[ -n $WS_PATH ]]    || WS_PATH="/$(gen_hex 6)"
  [[ -n $GRPC_SVC ]]   || GRPC_SVC="$(gen_hex 5)"
  [[ -n $XHTTP_PATH ]] || XHTTP_PATH="/$(gen_hex 6)"
  [[ -n $MKCP_SEED ]]  || MKCP_SEED="$(gen_hex 8)"
  [[ -n $OBFS_HOST ]]  || OBFS_HOST="$STEAL_SNI"
  [[ -n $API_SECRET ]] || API_SECRET="$(gen_pass)"

  if _base_used ss; then
    local bytes=16; [[ $SS_METHOD == *chacha20* || $SS_METHOD == *aes-256* ]] && bytes=32
    [[ -n $SS_PASSWORD ]] || SS_PASSWORD="$(gen_b64key "$bytes")"
  fi
  _base_used snell      && { [[ -n $SNELL_PSK ]] || SNELL_PSK="$(gen_pass)"; }
  _base_used tuic       && { [[ -n $TUIC_UUID ]] || TUIC_UUID="$(gen_uuid)"; [[ -n $TUIC_PASSWORD ]] || TUIC_PASSWORD="$(gen_pass)"; }
  _base_used shadowquic && { [[ -n $SQ_USER ]] || SQ_USER="u$(gen_hex 3)"; [[ -n $SQ_PASSWORD ]] || SQ_PASSWORD="$(gen_pass)"; }
  _base_used mieru      && { [[ -n $MIERU_USER ]] || MIERU_USER="u$(gen_hex 3)"; [[ -n $MIERU_PASSWORD ]] || MIERU_PASSWORD="$(gen_pass)"; }
  _base_used trusttunnel && { [[ -n $TT_USER ]] || TT_USER="u$(gen_hex 3)"; [[ -n $TT_PASSWORD ]] || TT_PASSWORD="$(gen_pass)"; }
  _base_used realm      && { [[ -n $REALM_TOKEN ]] || REALM_TOKEN="$(gen_pass)"; }
  selected_has hysteria2-obfs && { [[ -n $HY2_OBFS_PASSWORD ]] || HY2_OBFS_PASSWORD="$(gen_pass)"; }

  _sec_used shadowtls && { [[ -n $SHADOWTLS_PASSWORD ]] || SHADOWTLS_PASSWORD="$(gen_pass)"; }
  _sec_used restls    && { [[ -n $RESTLS_PASSWORD ]] || RESTLS_PASSWORD="$(gen_pass)"; }
  if _sec_used jls || _base_used shadowquic; then
    [[ -n $JLS_USER ]]     || JLS_USER="u$(gen_hex 3)"
    [[ -n $JLS_PASSWORD ]] || JLS_PASSWORD="$(gen_pass)"
  fi
  # tlsmirror's primary key is 32 raw bytes in standard base64 (DecodePrimaryKey
  # accepts nothing else at that length).
  _sec_used tlsmirror && { [[ -n $TLSMIRROR_KEY ]] || TLSMIRROR_KEY="$(gen_b64key 32)"; }

  if _sec_used reality; then
    [[ -n $REALITY_PRIVATE && -n $REALITY_PUBLIC ]] || gen_reality_keys
    # Two short-ids are published: "" (any) plus a real one, so clients that omit
    # sid still connect.
    [[ -n $REALITY_SHORTID ]] || REALITY_SHORTID="$(gen_hex 8)"
  fi
  if _base_used sudoku; then
    [[ -n $SUDOKU_PUB && -n $SUDOKU_PRIV ]] || gen_sudoku_keys
  fi
  ok "Secrets ready."
  return 0
}

# -----------------------------------------------------------------------------
# 9. Certificates
# -----------------------------------------------------------------------------
# mihomo rejects any config file path outside its home dir unless SAFE_PATHS is
# set, so the certificate is always COPIED into ${MH_HOME}/cert rather than
# referenced in /etc/letsencrypt. The renew hook re-copies it.
_chown_certs() {
  install -d -m 0750 "$MH_CERT_DIR"
  chown -R "root:${MH_USER}" "$MH_CERT_DIR" 2>/dev/null || true
  chmod 0644 "$MH_CERT_FULL" 2>/dev/null || true
  chmod 0640 "$MH_CERT_KEY"  2>/dev/null || true
  chown "root:${MH_USER}" "$MH_CERT_FULL" "$MH_CERT_KEY" 2>/dev/null || true
  # mihomo clients pin with `fingerprint:` — the hex SHA-256 over the DER cert.
  CERT_PIN="$(openssl x509 -in "$MH_CERT_FULL" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null | awk '{print $NF}' || true)"
  return 0
}

make_self_signed() {
  install -d -m 0750 "$MH_CERT_DIR"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -sha256 -nodes \
    -days 3650 -subj "/CN=${VPN_DOMAIN}" -addext "subjectAltName=DNS:${VPN_DOMAIN}" \
    -keyout "$MH_CERT_KEY" -out "$MH_CERT_FULL" >/dev/null 2>&1 \
    || die "openssl failed to generate a self-signed certificate."
  _chown_certs
  ok "Self-signed certificate written to ${MH_CERT_DIR}."
  warn "Clients must set skip-cert-verify: true, or pin fingerprint: ${CERT_PIN}"
  return 0
}

# certbot's HTTP-01 challenge needs inbound tcp/80, but firewall_setup does not
# run until after the certificate step. On a host where ufw is ALREADY active —
# precisely the case `--firewall auto` detects — the challenge would be dropped,
# issuance would fail, and the deploy would fall back to a self-signed cert for
# no good reason. So open :80 for the duration of the request and close it again
# afterwards; firewall_setup re-adds it permanently if issuance succeeded.
HTTP80_OPENED="no"
_http01_open() {
  HTTP80_OPENED="no"
  if have ufw && ufw status 2>/dev/null | grep -q "^Status: active"; then
    ufw allow 80/tcp >/dev/null 2>&1 && HTTP80_OPENED="ufw"
  elif have iptables && iptables -S INPUT 2>/dev/null | grep -qE '^-P INPUT (DROP|REJECT)'; then
    iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 && HTTP80_OPENED="iptables"
  fi
  [[ $HTTP80_OPENED != no ]] && log "Temporarily allowed tcp/80 for the ACME challenge (${HTTP80_OPENED})."
  return 0
}
_http01_close() {
  case "$HTTP80_OPENED" in
    ufw)      ufw delete allow 80/tcp >/dev/null 2>&1 || true ;;
    iptables) iptables -D INPUT -p tcp --dport 80 -j ACCEPT >/dev/null 2>&1 || true ;;
  esac
  HTTP80_OPENED="no"
  return 0
}

obtain_letsencrypt() {
  local email_arg="--register-unsafely-without-email"
  [[ -n $LE_EMAIL ]] && email_arg="-m ${LE_EMAIL}"
  systemctl stop mihomo >/dev/null 2>&1 || true
  _http01_open
  local rc=0
  # $email_arg must stay unquoted: it has to split into "-m" + address.
  certbot certonly --standalone --non-interactive --agree-tos $email_arg \
       --http-01-port 80 -d "$VPN_DOMAIN" >/dev/null 2>&1 || rc=$?
  _http01_close
  if (( rc == 0 )); then
    install -d -m 0750 "$MH_CERT_DIR"
    # Part of the success condition: if certbot reported success but the live
    # directory is not readable, return 1 so setup_cert falls back to self-signed
    # instead of continuing with no certificate at all.
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "$MH_CERT_FULL" &&
    cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "$MH_CERT_KEY" || {
      warn "certbot succeeded but the issued certificate could not be copied."
      return 1
    }
    _chown_certs
    cat >"$MH_RENEW_HOOK" <<EOF
#!/usr/bin/env bash
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/fullchain.pem" "${MH_CERT_FULL}"
cp -L "/etc/letsencrypt/live/${VPN_DOMAIN}/privkey.pem"   "${MH_CERT_KEY}"
chown "root:${MH_USER}" "${MH_CERT_FULL}" "${MH_CERT_KEY}"
chmod 0644 "${MH_CERT_FULL}"; chmod 0640 "${MH_CERT_KEY}"
# mihomo fswatches both files and reloads them in place, but a HUP is free.
systemctl reload-or-restart mihomo
EOF
    chmod 0755 "$MH_RENEW_HOOK"
    install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    ln -sf "$MH_RENEW_HOOK" "/etc/letsencrypt/renewal-hooks/deploy/mihomo-${VPN_DOMAIN}.sh"
    ok "Let's Encrypt certificate obtained for ${VPN_DOMAIN}; auto-renew hook installed."
    return 0
  fi
  return 1
}

setup_cert() {
  needs_any_cert || { log "No certificate-bearing protocol selected; skipping certificates."; return 0; }
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
# 10. mihomo server config
#
# NOTES ON THE SCHEMA (all verified against listener/inbound/*.go struct tags):
#  * `name` has no `omitempty` => mandatory, and must be unique across listeners.
#  * `listen` must be a BARE IP. "0.0.0.0:443" and hostnames are rejected.
#  * `port` is a range expression parsed as a string; an absent/empty port makes
#    mihomo bind a RANDOM ephemeral port and report success, so it is always set.
#  * `users` has four different shapes: a list of {username,uuid[,flow|alterId]}
#    for vless/vmess, {username,password} for trojan/shadowquic/trusttunnel, and
#    a plain map name->password for hysteria2/tuic/anytls/mieru.
#  * certificate/private-key are NOT omitempty on hysteria2/tuic/trusttunnel, so
#    the keys must appear even when empty.
#  * At most ONE security layer per listener (the core builds a securityModes
#    slice and hard-errors on more than one) — hence one listener per combination.
# -----------------------------------------------------------------------------
_cert_lines() {   # 4-space indented certificate pair
  printf '    certificate: %s\n    private-key: %s\n' "$MH_CERT_FULL" "$MH_CERT_KEY"
}

# The security layer. Only ever ONE of these per listener.
_sec_block() {
  local key=$1
  case "${K_SEC[$key]}" in
    tls) _cert_lines ;;
    reality)
      cat <<EOF
    reality-config:
      dest: ${REALITY_SNI}:443
      private-key: ${REALITY_PRIVATE}
      short-id:
        - ""
        - ${REALITY_SHORTID}
      server-names:
        - ${REALITY_SNI}
EOF
      ;;
    shadowtls)
      # v3 is the only version with per-user keys; it REQUIRES a users list, and
      # `version` has no default (version 0 is a hard error).
      cat <<EOF
    shadow-tls:
      enable: true
      version: 3
      users:
        - name: ${NODE_LABEL}
          password: ${SHADOWTLS_PASSWORD}
      handshake:
        dest: ${STEAL_SNI}:443
      strict-mode: true
EOF
      ;;
    restls)
      cat <<EOF
    res-tls:
      enable: true
      dest: ${STEAL_SNI}:443
      password: ${RESTLS_PASSWORD}
EOF
      ;;
    jls)
      cat <<EOF
    jls-config:
      enable: true
      dest: ${STEAL_SNI}:443
      sni: ${STEAL_SNI}
      users:
        - username: ${JLS_USER}
          password: ${JLS_PASSWORD}
EOF
      ;;
    # Retained for hand-editing /etc/mihomo/config.yaml; no catalogue key
    # selects it (see build_catalogue for why).
    tlsmirror)
      cat <<EOF
    tlsmirror-config:
      primary-key: ${TLSMIRROR_KEY}
      dest: ${STEAL_SNI}:443
      transport-layer-padding:
        enabled: true
      sequence-watermarking-enabled: true
EOF
      ;;
    *) : ;;
  esac
  return 0
}

# The transport layer, orthogonal to the security layer above.
_xport_block() {
  local key=$1
  case "${K_XPORT[$key]}" in
    ws)   printf '    ws-path: %s\n' "$WS_PATH" ;;
    grpc) printf '    grpc-service-name: %s\n' "$GRPC_SVC" ;;
    xhttp)
      cat <<EOF
    xhttp-config:
      path: ${XHTTP_PATH}
      host: ${VPN_DOMAIN}
      mode: auto
EOF
      ;;
    mkcp)
      # mKCP is a UDP transport with no TLS of any kind; `seed` is the shared
      # obfuscation secret and `header` disguises the packets as SRTP.
      cat <<EOF
    mkcp-config:
      enable: true
      seed: ${MKCP_SEED}
      header: srtp
      mtu: 1350
      tti: 50
      uplink-capacity: 12
      downlink-capacity: 100
      congestion: false
EOF
      ;;
    mekya)
      # h2-over-KCP inside real TLS. Parameters follow the upstream interop test.
      cat <<EOF
    mekya-config:
      enable: true
      max-write-size: 10485760
      max-write-duration-ms: 500
      max-simultaneous-write-connection: 128
      packet-writing-buffer: 65536
      kcp:
        mtu: 1350
        tti: 15
        uplink-capacity: 40
        downlink-capacity: 2000
        write-buffer: 67108864
        read-buffer: 67108864
EOF
      ;;
    obfs-http|obfs-tls)
      local mode="${K_XPORT[$key]#obfs-}"
      if [[ ${K_BASE[$key]} == snell ]]; then
        # snell's obfs-opts sub-struct is tagged `obfs:` not `inbound:`, so the
        # decoder falls back to field names AND loses omitempty — both keys must
        # be present.
        cat <<EOF
    obfs-opts:
      mode: ${mode}
      host: ${OBFS_HOST}
EOF
      else
        cat <<EOF
    simple-obfs:
      enable: true
      mode: ${mode}
EOF
      fi
      ;;
    kcptun)
      # kcp-tun REPLACES the TCP listener with a UDP one, which is why it never
      # appears alongside a security layer here.
      cat <<EOF
    kcp-tun:
      enable: true
      key: ${PASSWORD}
      crypt: aes-128
      mode: fast
      mtu: 1350
      sndwnd: 1024
      rcvwnd: 1024
      datashard: 10
      parityshard: 3
EOF
      ;;
    *) : ;;
  esac
  return 0
}

# One complete `listeners:` entry.
lst_of() {
  local key=$1
  local port="${PORT[$key]}"
  local typ; typ="$(mh_type "$key")"
  printf '  - name: %s\n    type: %s\n    listen: "%s"\n    port: %s\n' \
    "$key" "$typ" "$LISTEN_ADDR" "$port"

  case "${K_BASE[$key]}" in
    vless)
      printf '    users:\n      - username: %s\n        uuid: %s\n' "$NODE_LABEL" "$UUID"
      # XTLS Vision needs a real TLS record layer under it and raw TCP above it.
      if [[ ${K_XPORT[$key]} == tcp && ( ${K_SEC[$key]} == tls || ${K_SEC[$key]} == reality ) ]]; then
        printf '        flow: xtls-rprx-vision\n'
      fi
      _xport_block "$key"; _sec_block "$key" ;;
    vmess)
      printf '    users:\n      - username: %s\n        uuid: %s\n        alterId: 0\n' "$NODE_LABEL" "$UUID"
      _xport_block "$key"; _sec_block "$key" ;;
    trojan)
      printf '    users:\n      - username: %s\n        password: %s\n' "$NODE_LABEL" "$PASSWORD"
      _xport_block "$key"; _sec_block "$key" ;;
    anytls)
      printf '    users:\n      %s: %s\n    padding-scheme: ""\n' "$NODE_LABEL" "$PASSWORD"
      _sec_block "$key" ;;
    ss)
      printf '    password: %s\n    cipher: %s\n    udp: true\n' "$SS_PASSWORD" "$SS_METHOD"
      _xport_block "$key"; _sec_block "$key" ;;
    snell)
      printf '    psk: %s\n    version: %s\n    udp: true\n' "$SNELL_PSK" "$SNELL_VERSION"
      _xport_block "$key"; _sec_block "$key" ;;
    hysteria2)
      printf '    users:\n      %s: %s\n' "$NODE_LABEL" "$PASSWORD"
      if [[ ${K_SEC[$key]} == obfs ]]; then
        printf '    obfs: %s\n    obfs-password: %s\n' "$HY2_OBFS" "$HY2_OBFS_PASSWORD"
      fi
      # Masquerade turns an unauthenticated probe of the HTTP/3 endpoint into a
      # plain reverse proxy of the decoy site.
      printf '    masquerade: https://%s\n' "$STEAL_SNI"
      _cert_lines ;;
    tuic)
      printf '    users:\n      %s: %s\n' "$TUIC_UUID" "$TUIC_PASSWORD"
      _cert_lines ;;
    shadowquic)
      # No certificate keys exist on this listener: JLS authenticates the peer
      # and the QUIC handshake runs under a self-generated P-256 pair.
      cat <<EOF
    users:
      - username: ${SQ_USER}
        password: ${SQ_PASSWORD}
    jls-upstream:
      addr: ${STEAL_SNI}:443
      sni: ${STEAL_SNI}
    zero-rtt: true
    congestion-controller: bbr
EOF
      ;;
    mieru)
      local mt="TCP"; [[ ${K_XPORT[$key]} == udp ]] && mt="UDP"
      printf '    transport: %s\n    users:\n      %s: %s\n' "$mt" "$MIERU_USER" "$MIERU_PASSWORD"
      ;;
    sudoku)
      # The server holds the master PUBLIC key; each client presents the private
      # half. HTTP-mask wraps the stream in ordinary-looking HTTP requests.
      printf '    key: %s\n' "$SUDOKU_PUB"
      if [[ ${K_XPORT[$key]} == httpmask ]]; then
        printf '    http-mask-mode: stream\n    path-root: %s\n    fallback: %s:443\n' \
          "${XHTTP_PATH#/}" "$STEAL_SNI"
      else
        printf '    disable-http-mask: true\n'
      fi
      ;;
    trusttunnel)
      local net="tcp"; [[ ${K_XPORT[$key]} == quic ]] && net="udp"
      printf '    users:\n      - username: %s\n        password: %s\n    network:\n      - %s\n' \
        "$TT_USER" "$TT_PASSWORD" "$net"
      [[ $net == udp ]] && printf '    congestion-controller: bbr\n'
      _cert_lines ;;
    realm)
      printf '    token: %s\n' "$REALM_TOKEN"
      _cert_lines ;;
  esac
  return 0
}

write_mihomo_config() {
  head1 "Writing ${MH_CONF}"
  install -d -o root -g "$MH_USER" -m 0750 "$MH_HOME"
  local key
  {
    cat <<EOF
# =============================================================================
#  mihomo server node — generated by Mihomo_Deployment.sh v${SCRIPT_VERSION}
#  ${VPN_DOMAIN} on $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
#  This box only ACCEPTS connections; it never proxies through anything else.
#  mode: rule with an empty rule set sends every accepted connection DIRECT,
#  which is exactly what an exit node wants, and needs no geo databases.
# =============================================================================
mode: rule
log-level: warning
ipv6: true
allow-lan: false
bind-address: '*'
find-process-mode: off
unified-delay: true
tcp-concurrent: true
profile:
  store-selected: false
  store-fake-ip: false
EOF
    if [[ -n $API_LISTEN ]]; then
      printf 'external-controller: %s\n' "$API_LISTEN"
      printf "secret: '%s'\n" "${API_SECRET//\'/\'\'}"
    fi
    cat <<'EOF'

# No outbound proxies and no rules: everything accepted here egresses DIRECT.
proxies: []
proxy-groups: []
rules: []

listeners:
EOF
    for key in $SELECTED; do lst_of "$key"; done
  } >"$MH_CONF"

  chown "root:${MH_USER}" "$MH_CONF" 2>/dev/null || true
  chmod 0640 "$MH_CONF"

  # Validate with the installed binary before the service is ever restarted.
  # mktemp, not a fixed /tmp path: a local user could pre-create the latter and
  # have root truncate it, then see attacker-controlled text echoed into the log.
  local tlog; tlog="$(mktemp)"
  if "$MH_BIN" -t -d "$MH_HOME" >"$tlog" 2>&1; then
    rm -f "$tlog"; ok "Config accepted by \`mihomo -t\` ($(selected_count) listeners)."
  else
    sed 's/^/    /' "$tlog" >&2; rm -f "$tlog"
    die "mihomo rejected the generated config (see above)."
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 11. Kernel tuning (TCP + QUIC)
# -----------------------------------------------------------------------------
kernel_tuning() {
  [[ $KERNEL_TUNING == yes ]] || { log "Kernel tuning skipped."; return 0; }
  head1 "Kernel / sysctl tuning"

  local bbr_block=""
  modprobe tcp_bbr >/dev/null 2>&1 || true
  if grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    bbr_block=$'\n# --- congestion control (BBR + fair-queue pacing) ---\nnet.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr'
    echo "tcp_bbr" >/etc/modules-load.d/mihomo-bbr.conf
    ok "BBR available and enabled."
  else
    warn "BBR unavailable on this kernel; leaving congestion control unchanged."
  fi

  # A sysctl.d drop-in silently skips keys the running kernel does not know, so
  # obsolete keys from old guides (tcp_tw_recycle, tcp_low_latency, ...) are
  # simply absent here rather than being force-set.
  cat >/etc/sysctl.d/99-mihomo.conf <<EOF
# ---------------------------------------------------------------------------
# mihomo proxy tuning (Mihomo_Deployment.sh) — TCP + QUIC
# ---------------------------------------------------------------------------

# rmem_max/wmem_max are CEILINGS on what a socket may request, not allocations:
# TCP autotuning uses tcp_rmem/tcp_wmem and ignores these entirely. Raising them
# is what lets this node run WITHOUT CAP_NET_ADMIN: quic-go asks for an 8 MB
# SO_RCVBUF and, when the kernel clamps it, retries with SO_RCVBUFFORCE — a
# NET_ADMIN-only syscall. Give it the headroom and the force path is never taken.
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

  # mihomo never calls setrlimit itself, so the unit is the only thing raising
  # the descriptor ceiling — and a full catalogue is a lot of sockets.
  install -d -m 0755 /etc/systemd/system/mihomo.service.d
  cat >/etc/systemd/system/mihomo.service.d/10-limits.conf <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
  systemctl daemon-reload
  ok "Applied sysctl drop-in and confirmed LimitNOFILE for mihomo."
  return 0
}

# -----------------------------------------------------------------------------
# 12. Firewall (userspace proxy: INPUT only — no forwarding or NAT needed)
# -----------------------------------------------------------------------------
_tcp_ports() {
  local key out=()
  for key in $SELECTED; do
    case "$(proto_l4 "$key")" in tcp|both) out+=("${PORT[$key]}") ;; esac
  done
  [[ $CERT_MODE == letsencrypt ]] && needs_any_cert && out+=("80")
  [[ $SUB_HOST == yes ]] && out+=("$SUB_PORT")
  printf '%s\n' "${out[@]}" | sort -un
}
_udp_ports() {
  local key out=()
  for key in $SELECTED; do
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
  iptables -N MIHOMO_IN 2>/dev/null || iptables -F MIHOMO_IN || true
  iptables -C INPUT -j MIHOMO_IN >/dev/null 2>&1 || iptables -I INPUT 1 -j MIHOMO_IN || true
  iptables -A MIHOMO_IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || warn "conntrack rule not added (module missing?)."
  iptables -A MIHOMO_IN -p tcp --dport "$(ssh_port)" -j ACCEPT || true
  # One rule per port would be 80+ rules; multiport batches them 15 at a time.
  local batch=() n=0
  for p in $(_tcp_ports); do
    batch+=("$p"); n=$((n+1))
    if (( n == 15 )); then
      iptables -A MIHOMO_IN -p tcp -m multiport --dports "$(IFS=,; echo "${batch[*]}")" -j ACCEPT || true
      batch=(); n=0
    fi
  done
  (( n > 0 )) && { iptables -A MIHOMO_IN -p tcp -m multiport --dports "$(IFS=,; echo "${batch[*]}")" -j ACCEPT || true; }
  batch=(); n=0
  for p in $(_udp_ports); do
    batch+=("$p"); n=$((n+1))
    if (( n == 15 )); then
      iptables -A MIHOMO_IN -p udp -m multiport --dports "$(IFS=,; echo "${batch[*]}")" -j ACCEPT || true
      batch=(); n=0
    fi
  done
  (( n > 0 )) && { iptables -A MIHOMO_IN -p udp -m multiport --dports "$(IFS=,; echo "${batch[*]}")" -j ACCEPT || true; }
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
  log "Backend: ${backend}   tcp: $(_tcp_ports | wc -l) port(s)   udp: $(_udp_ports | wc -l) port(s)"
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
  systemctl enable mihomo >/dev/null 2>&1 || true
  # `|| true` so the is-active check below owns the failure path and can print
  # the journal, instead of the ERR trap aborting with no diagnostics.
  systemctl restart mihomo || true
  sleep 3
  if systemctl is-active --quiet mihomo; then
    ok "mihomo is running."
  else
    bad "mihomo failed to start:"
    journalctl -u mihomo -n 25 --no-pager 2>/dev/null | sed 's/^/    /' >&2
    die "Fix the config and re-run."
  fi
  # A listener that cannot bind is NOT fatal to mihomo: PatchInboundListeners
  # logs "Listener <name> listen err: ..." and carries on, leaving the service
  # active with a dead listener. Surface those lines now.
  local errs
  errs="$(journalctl -u mihomo --since '-1 min' --no-pager 2>/dev/null | grep -i 'listen err' || true)"
  if [[ -n $errs ]]; then
    bad "Some listeners failed to bind:"
    printf '%s\n' "$errs" | sed 's/^/    /' >&2
  fi
  return 0
}

# -----------------------------------------------------------------------------
# 14. Client artefacts
#
# The mihomo YAML is the primary artefact: it is the only format that can carry
# ShadowQUIC, Sudoku, Mieru, TrustTunnel, Snell and every ShadowTLS / RestLS /
# JLS / TLS-mirror wrapper. Share links are emitted only for the schemes the
# wider client ecosystem actually parses; everything else is YAML-only and says
# so in README.txt rather than emitting a link no client can import.
# -----------------------------------------------------------------------------
# ALPN a given transport should advertise. WebSocket speaks HTTP/1.1 only, so
# advertising h2 there invites a client or CDN to break the Upgrade handshake.
_alpn_of() {
  case "${K_XPORT[$1]}" in
    ws)          echo "http/1.1" ;;
    grpc|xhttp)  echo "h2" ;;
    *)           echo "h2,http/1.1" ;;
  esac
}

# The SNI a client must present: the decoy for the borrowed-identity layers,
# your own domain for a real certificate.
_cli_sni() {
  case "${K_SEC[$1]}" in
    reality)                     printf '%s' "$REALITY_SNI" ;;
    shadowtls|restls|jls|tlsmirror) printf '%s' "$STEAL_SNI" ;;
    *)                           printf '%s' "$VPN_DOMAIN" ;;
  esac
}

# Does this key have a share link the mainstream GUI clients can import?
has_link() {
  local key=$1
  case "${K_BASE[$key]}" in
    hysteria2|tuic) return 0 ;;
    anytls)  [[ ${K_SEC[$key]} == tls ]] && return 0 || return 1 ;;
    ss)      case "${K_XPORT[$key]}" in plain|obfs-http|obfs-tls) [[ ${K_SEC[$key]} == none ]] && return 0 ;; esac; return 1 ;;
    vless|vmess|trojan)
      case "${K_XPORT[$key]}" in tcp|ws|grpc|xhttp) : ;; *) return 1 ;; esac
      case "${K_SEC[$key]}" in tls|reality) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}

# --- mihomo / Clash.Meta client YAML -----------------------------------------
# The security layer, client side. `tls: true` is what actually switches on
# reality / shadow-tls / res-tls / jls in the vless & vmess outbounds — without
# it the opts blocks are parsed and then ignored.
_cli_sec() {
  local key=$1 sni sci
  sni="$(_cli_sni "$key")"; sci="$(insec_bool)"
  case "${K_SEC[$key]}" in
    tls)
      printf '    tls: true\n    servername: %s\n    skip-cert-verify: %s\n' "$sni" "$sci"
      [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
    reality)
      cat <<EOF
    tls: true
    servername: ${sni}
    reality-opts:
      public-key: ${REALITY_PUBLIC}
      short-id: ${REALITY_SHORTID}
EOF
      ;;
    shadowtls)
      cat <<EOF
    tls: true
    servername: ${sni}
    shadow-tls-opts:
      version: 3
      password: "${SHADOWTLS_PASSWORD}"
EOF
      ;;
    restls)
      cat <<EOF
    tls: true
    servername: ${sni}
    restls-opts:
      password: "${RESTLS_PASSWORD}"
      version-hint: tls13
EOF
      ;;
    jls)
      cat <<EOF
    tls: true
    servername: ${sni}
    jls-opts:
      username: ${JLS_USER}
      password: "${JLS_PASSWORD}"
EOF
      ;;
    tlsmirror)
      cat <<EOF
    tls: true
    servername: ${sni}
    tlsmirror-opts:
      primary-key: "${TLSMIRROR_KEY}"
      transport-layer-padding:
        enabled: true
      sequence-watermarking-enabled: true
EOF
      ;;
  esac
  return 0
}

# The transport layer, client side.
_cli_xport() {
  local key=$1
  case "${K_XPORT[$key]}" in
    tcp)  printf '    network: tcp\n' ;;
    ws)
      cat <<EOF
    network: ws
    ws-opts:
      path: ${WS_PATH}
      headers:
        Host: $(_cli_sni "$key")
EOF
      ;;
    grpc)
      cat <<EOF
    network: grpc
    grpc-opts:
      grpc-service-name: ${GRPC_SVC}
EOF
      ;;
    xhttp)
      cat <<EOF
    network: xhttp
    xhttp-opts:
      path: "${XHTTP_PATH}"
      host: ${VPN_DOMAIN}
      mode: auto
EOF
      ;;
    mkcp)
      cat <<EOF
    network: mkcp
    mkcp-opts:
      seed: ${MKCP_SEED}
      header: srtp
      mtu: 1350
      tti: 50
      uplink-capacity: 12
      downlink-capacity: 100
      congestion: false
EOF
      ;;
    mekya)
      cat <<EOF
    network: mekya
    mekya-opts:
      url: https://${VPN_DOMAIN}/mekya
      max-write-size: 10485760
      max-write-duration-ms: 500
      max-simultaneous-write-connection: 128
      packet-writing-buffer: 65536
      kcp:
        mtu: 1350
        tti: 15
        uplink-capacity: 40
        downlink-capacity: 2000
        write-buffer: 67108864
        read-buffer: 67108864
EOF
      ;;
  esac
  return 0
}

# One complete `proxies:` entry for the mihomo client config.
mihomo_of() {
  local key=$1 a p n sci
  a="$(addr)"; p="${PORT[$key]}"; n="$(node_name "$key")"; sci="$(insec_bool)"
  # A realm server is a rendezvous endpoint, not a proxy: no client entry.
  [[ ${K_BASE[$key]} == realm ]] && return 1

  printf '  - name: "%s"\n    type: %s\n    server: %s\n    port: %s\n' \
    "$n" "$(mh_type "$key" | sed 's/^shadowsocks$/ss/')" "$a" "$p"

  case "${K_BASE[$key]}" in
    vless)
      printf '    uuid: %s\n    udp: true\n    packet-encoding: xudp\n    client-fingerprint: chrome\n' "$UUID"
      if [[ ${K_XPORT[$key]} == tcp && ( ${K_SEC[$key]} == tls || ${K_SEC[$key]} == reality ) ]]; then
        printf '    flow: xtls-rprx-vision\n'
      fi
      _cli_xport "$key"; _cli_sec "$key" ;;
    vmess)
      printf '    uuid: %s\n    alterId: 0\n    cipher: auto\n    udp: true\n    packet-encoding: xudp\n    client-fingerprint: chrome\n' "$UUID"
      _cli_xport "$key"; _cli_sec "$key" ;;
    trojan)
      # The trojan outbound has no `tls:` key — it is always TLS — and names its
      # SNI `sni:` rather than `servername:`.
      printf '    password: "%s"\n    udp: true\n    client-fingerprint: chrome\n    sni: %s\n    skip-cert-verify: %s\n' \
        "$PASSWORD" "$(_cli_sni "$key")" "$sci"
      _cli_xport "$key"
      case "${K_SEC[$key]}" in
        reality)   printf '    reality-opts:\n      public-key: %s\n      short-id: %s\n' "$REALITY_PUBLIC" "$REALITY_SHORTID" ;;
        shadowtls) printf '    shadow-tls-opts:\n      version: 3\n      password: "%s"\n' "$SHADOWTLS_PASSWORD" ;;
        restls)    printf '    restls-opts:\n      password: "%s"\n      version-hint: tls13\n' "$RESTLS_PASSWORD" ;;
        jls)       printf '    jls-opts:\n      username: %s\n      password: "%s"\n' "$JLS_USER" "$JLS_PASSWORD" ;;
        tls)       [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
      esac ;;
    anytls)
      printf '    password: "%s"\n    udp: true\n    client-fingerprint: chrome\n    sni: %s\n    skip-cert-verify: %s\n' \
        "$PASSWORD" "$(_cli_sni "$key")" "$sci"
      case "${K_SEC[$key]}" in
        shadowtls) printf '    shadow-tls-opts:\n      version: 3\n      password: "%s"\n' "$SHADOWTLS_PASSWORD" ;;
        restls)    printf '    restls-opts:\n      password: "%s"\n      version-hint: tls13\n' "$RESTLS_PASSWORD" ;;
        jls)       printf '    jls-opts:\n      username: %s\n      password: "%s"\n' "$JLS_USER" "$JLS_PASSWORD" ;;
        tls)       [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
      esac ;;
    ss)
      printf '    cipher: %s\n    password: "%s"\n    udp: true\n    client-fingerprint: chrome\n' "$SS_METHOD" "$SS_PASSWORD"
      # Shadowsocks carries its extra layers as a SIP003-style plugin rather
      # than as top-level option blocks.
      case "${K_XPORT[$key]}:${K_SEC[$key]}" in
        obfs-http:*|obfs-tls:*)
          printf '    plugin: obfs\n    plugin-opts:\n      mode: %s\n      host: %s\n' "${K_XPORT[$key]#obfs-}" "$OBFS_HOST" ;;
        kcptun:*)
          printf '    plugin: kcptun\n    plugin-opts:\n      key: "%s"\n      crypt: aes-128\n      mode: fast\n      mtu: 1350\n      sndwnd: 1024\n      rcvwnd: 1024\n      datashard: 10\n      parityshard: 3\n' "$PASSWORD" ;;
        *:shadowtls)
          printf '    plugin: shadow-tls\n    plugin-opts:\n      host: %s\n      password: "%s"\n      version: 3\n      alpn: ["h2","http/1.1"]\n' "$STEAL_SNI" "$SHADOWTLS_PASSWORD" ;;
        *:restls)
          printf '    plugin: restls\n    plugin-opts:\n      host: %s\n      password: "%s"\n      version-hint: tls13\n' "$STEAL_SNI" "$RESTLS_PASSWORD" ;;
        *:jls)
          printf '    plugin: jls\n    plugin-opts:\n      host: %s\n      username: %s\n      password: "%s"\n' "$STEAL_SNI" "$JLS_USER" "$JLS_PASSWORD" ;;
      esac ;;
    snell)
      printf '    psk: "%s"\n    version: %s\n    udp: true\n    client-fingerprint: chrome\n' "$SNELL_PSK" "$SNELL_VERSION"
      # Snell packs obfuscation AND its security layers into one obfs-opts map.
      case "${K_XPORT[$key]}:${K_SEC[$key]}" in
        obfs-http:*|obfs-tls:*)
          printf '    obfs-opts:\n      mode: %s\n      host: %s\n' "${K_XPORT[$key]#obfs-}" "$OBFS_HOST" ;;
        *:shadowtls)
          printf '    obfs-opts:\n      mode: shadow-tls\n      host: %s\n      password: "%s"\n      version: 3\n      alpn: ["h2","http/1.1"]\n' "$STEAL_SNI" "$SHADOWTLS_PASSWORD" ;;
        *:restls)
          printf '    obfs-opts:\n      mode: restls\n      host: %s\n      password: "%s"\n      version-hint: tls13\n' "$STEAL_SNI" "$RESTLS_PASSWORD" ;;
        *:jls)
          printf '    obfs-opts:\n      mode: jls\n      host: %s\n      username: %s\n      password: "%s"\n' "$STEAL_SNI" "$JLS_USER" "$JLS_PASSWORD" ;;
      esac ;;
    hysteria2)
      printf '    password: "%s"\n    sni: %s\n    skip-cert-verify: %s\n' "$PASSWORD" "$VPN_DOMAIN" "$sci"
      [[ ${K_SEC[$key]} == obfs ]] && printf '    obfs: %s\n    obfs-password: "%s"\n' "$HY2_OBFS" "$HY2_OBFS_PASSWORD"
      printf '    alpn:\n      - h3\n'
      [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
    tuic)
      cat <<EOF
    uuid: ${TUIC_UUID}
    password: "${TUIC_PASSWORD}"
    sni: ${VPN_DOMAIN}
    skip-cert-verify: ${sci}
    udp-relay-mode: native
    congestion-controller: bbr
    alpn:
      - h3
EOF
      [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
    shadowquic)
      cat <<EOF
    username: ${SQ_USER}
    password: "${SQ_PASSWORD}"
    sni: ${STEAL_SNI}
    zero-rtt: true
    congestion-controller: bbr
    alpn:
      - h3
EOF
      ;;
    mieru)
      local mt="TCP"; [[ ${K_XPORT[$key]} == udp ]] && mt="UDP"
      printf '    transport: %s\n    username: %s\n    password: "%s"\n    udp: true\n    multiplexing: MULTIPLEXING_LOW\n' \
        "$mt" "$MIERU_USER" "$MIERU_PASSWORD" ;;
    sudoku)
      # The client presents the PRIVATE half of the keypair; the server holds
      # the public one.
      printf '    key: "%s"\n' "$SUDOKU_PRIV"
      if [[ ${K_XPORT[$key]} == httpmask ]]; then
        printf '    httpmask:\n      disable: false\n      mode: stream\n      path-root: "%s"\n' "${XHTTP_PATH#/}"
      else
        printf '    httpmask:\n      disable: true\n'
      fi ;;
    trusttunnel)
      printf '    username: %s\n    password: "%s"\n    sni: %s\n    skip-cert-verify: %s\n    udp: true\n    health-check: true\n' \
        "$TT_USER" "$TT_PASSWORD" "$VPN_DOMAIN" "$sci"
      [[ ${K_XPORT[$key]} == quic ]] && printf '    quic: true\n    congestion-controller: bbr\n'
      [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
    *) return 1 ;;
  esac
  return 0
}

# --- share links (only the schemes mainstream GUI clients import) ------------
link_of() {
  local key=$1 a p ins name alpn sni
  has_link "$key" || return 1
  a="$(addr)"; p="${PORT[$key]}"; ins="$(insec)"
  name="$(urlenc "$(node_name "$key")")"
  alpn="$(urlenc "$(_alpn_of "$key")")"
  sni="$(_cli_sni "$key")"

  local xtype="${K_XPORT[$key]}" q=""
  case "${K_BASE[$key]}" in
    vless)
      q="encryption=none&type=${xtype}&fp=chrome&sni=$(urlenc "$sni")&alpn=${alpn}"
      case "$xtype" in
        ws)    q+="&path=$(urlenc "$WS_PATH")&host=$(urlenc "$sni")" ;;
        grpc)  q+="&serviceName=$(urlenc "$GRPC_SVC")&mode=gun" ;;
        xhttp) q+="&path=$(urlenc "$XHTTP_PATH")&host=$(urlenc "$VPN_DOMAIN")&mode=auto" ;;
      esac
      if [[ ${K_SEC[$key]} == reality ]]; then
        q+="&security=reality&pbk=$(urlenc "$REALITY_PUBLIC")&sid=${REALITY_SHORTID}"
        [[ $xtype == tcp ]] && q+="&flow=xtls-rprx-vision"
      else
        q+="&security=tls&allowInsecure=${ins}"
        [[ $xtype == tcp ]] && q+="&flow=xtls-rprx-vision"
      fi
      printf 'vless://%s@%s:%s?%s#%s' "$UUID" "$a" "$p" "$q" "$name" ;;
    vmess)
      if [[ ${K_SEC[$key]} == reality ]]; then
        # The base64-JSON dialect has no REALITY fields; only the URL dialect does.
        q="encryption=auto&type=${xtype}&security=reality&pbk=$(urlenc "$REALITY_PUBLIC")&sid=${REALITY_SHORTID}&fp=chrome&sni=$(urlenc "$sni")"
        case "$xtype" in
          ws)   q+="&path=$(urlenc "$WS_PATH")&host=$(urlenc "$sni")" ;;
          grpc) q+="&serviceName=$(urlenc "$GRPC_SVC")" ;;
        esac
        printf 'vmess://%s@%s:%s?%s#%s' "$UUID" "$a" "$p" "$q" "$name"
      else
        local net="$xtype" path="" host=""
        case "$xtype" in
          ws)   path="$WS_PATH"; host="$sni" ;;
          grpc) path="$GRPC_SVC"; host="$sni" ;;
        esac
        local j
        j="$(jq -cn --arg add "$a" --arg port "$p" --arg id "$UUID" --arg host "$host" \
              --arg path "$path" --arg net "$net" --arg sni "$sni" --arg ps "$(node_name "$key")" \
              --arg alpn "$(_alpn_of "$key")" \
              '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:$net,type:"none",
                host:$host,path:$path,tls:"tls",sni:$sni,alpn:$alpn,fp:"chrome"}')"
        printf 'vmess://%s' "$(printf '%s' "$j" | base64 -w0)"
      fi ;;
    trojan)
      q="type=${xtype}&security=tls&sni=$(urlenc "$sni")&fp=chrome&alpn=${alpn}&allowInsecure=${ins}"
      case "$xtype" in
        ws)   q+="&path=$(urlenc "$WS_PATH")&host=$(urlenc "$sni")" ;;
        grpc) q+="&serviceName=$(urlenc "$GRPC_SVC")" ;;
      esac
      [[ ${K_SEC[$key]} == reality ]] && q="type=${xtype}&security=reality&pbk=$(urlenc "$REALITY_PUBLIC")&sid=${REALITY_SHORTID}&fp=chrome&sni=$(urlenc "$sni")"
      printf 'trojan://%s@%s:%s?%s#%s' "$(urlenc "$PASSWORD")" "$a" "$p" "$q" "$name" ;;
    anytls)
      printf 'anytls://%s@%s:%s?sni=%s&insecure=%s#%s' \
        "$(urlenc "$PASSWORD")" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$ins" "$name" ;;
    hysteria2)
      q="sni=$(urlenc "$VPN_DOMAIN")&insecure=${ins}&alpn=h3"
      [[ ${K_SEC[$key]} == obfs ]] && q+="&obfs=${HY2_OBFS}&obfs-password=$(urlenc "$HY2_OBFS_PASSWORD")"
      printf 'hysteria2://%s@%s:%s/?%s#%s' "$(urlenc "$PASSWORD")" "$a" "$p" "$q" "$name" ;;
    tuic)
      printf 'tuic://%s:%s@%s:%s?sni=%s&alpn=h3&congestion_control=bbr&udp_relay_mode=native&allow_insecure=%s#%s' \
        "$TUIC_UUID" "$(urlenc "$TUIC_PASSWORD")" "$a" "$p" "$(urlenc "$VPN_DOMAIN")" "$ins" "$name" ;;
    ss)
      # SIP002: the userinfo is raw-URL base64 of "method:password" — mihomo's
      # own parser tries RawURLEncoding first.
      local ui plug=""
      ui="$(printf '%s:%s' "$SS_METHOD" "$SS_PASSWORD" | base64 -w0 | tr '+/' '-_' | tr -d '=')"
      case "$xtype" in
        obfs-http) plug="?plugin=$(urlenc "obfs-local;obfs=http;obfs-host=${OBFS_HOST}")" ;;
        obfs-tls)  plug="?plugin=$(urlenc "obfs-local;obfs=tls;obfs-host=${OBFS_HOST}")" ;;
      esac
      printf 'ss://%s@%s:%s/%s#%s' "$ui" "$a" "$p" "$plug" "$name" ;;
    *) return 1 ;;
  esac
}

# --- sing-box client outbound (only what upstream sing-box can actually do) ---
# sing-box has no XHTTP, no mKCP/Mekya, no TLS-mirror, no RestLS, no JLS, no
# Snell client, no ShadowQUIC / Sudoku / Mieru / TrustTunnel — those keys are
# simply skipped and README.txt says why.
singbox_capable() {
  local key=$1
  case "${K_BASE[$key]}" in
    hysteria2|tuic) return 0 ;;
    anytls) [[ ${K_SEC[$key]} == tls ]] && return 0 || return 1 ;;
    ss)     [[ ${K_XPORT[$key]} == plain && ${K_SEC[$key]} == none ]] && return 0 || return 1 ;;
    vless|vmess|trojan)
      case "${K_XPORT[$key]}" in tcp|ws|grpc) : ;; *) return 1 ;; esac
      case "${K_SEC[$key]}" in tls|reality) return 0 ;; *) return 1 ;; esac ;;
    *) return 1 ;;
  esac
}

_sb_tls() { # $1 = key, $2 = alpn json array
  local key=$1 alpn=$2
  if [[ ${K_SEC[$key]} == reality ]]; then
    jq -cn --arg sni "$REALITY_SNI" --arg pbk "$REALITY_PUBLIC" --arg sid "$REALITY_SHORTID" \
      '{enabled:true,server_name:$sni,utls:{enabled:true,fingerprint:"chrome"},
        reality:{enabled:true,public_key:$pbk,short_id:$sid}}'
  else
    jq -cn --arg sni "$VPN_DOMAIN" --argjson insec "$( [[ $CERT_MODE == self ]] && echo true || echo false )" \
      --argjson alpn "$alpn" \
      '{enabled:true,server_name:$sni,insecure:$insec,alpn:$alpn,utls:{enabled:true,fingerprint:"chrome"}}'
  fi
}

_sb_transport() { # $1 = key ; emits null for raw TCP
  local key=$1
  case "${K_XPORT[$key]}" in
    ws)   jq -cn --arg path "$WS_PATH" --arg host "$(_cli_sni "$key")" \
            '{type:"ws",path:$path,headers:{Host:$host}}' ;;
    grpc) jq -cn --arg svc "$GRPC_SVC" '{type:"grpc",service_name:$svc}' ;;
    *)    echo null ;;
  esac
}

singbox_ob_of() {
  local key=$1
  singbox_capable "$key" || return 1
  local a p tag tls tr alpn
  a="$(addr)"; p="${PORT[$key]}"; tag="$(node_name "$key")"
  alpn="$(jq -cn --arg s "$(_alpn_of "$key")" '$s | split(",")')"
  tls="$(_sb_tls "$key" "$alpn")"
  tr="$(_sb_transport "$key")"

  case "${K_BASE[$key]}" in
    vless)
      local flow=""
      [[ ${K_XPORT[$key]} == tcp ]] && flow="xtls-rprx-vision"
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg uuid "$UUID" \
             --arg flow "$flow" --argjson tls "$tls" --argjson tr "$tr" '
        {type:"vless",tag:$tag,server:$s,server_port:$p,uuid:$uuid,tls:$tls,packet_encoding:"xudp"}
        + (if $flow == "" then {} else {flow:$flow} end)
        + (if $tr == null then {} else {transport:$tr} end)' ;;
    vmess)
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg uuid "$UUID" \
             --argjson tls "$tls" --argjson tr "$tr" '
        {type:"vmess",tag:$tag,server:$s,server_port:$p,uuid:$uuid,security:"auto",alter_id:0,tls:$tls}
        + (if $tr == null then {} else {transport:$tr} end)' ;;
    trojan)
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" \
             --argjson tls "$tls" --argjson tr "$tr" '
        {type:"trojan",tag:$tag,server:$s,server_port:$p,password:$pw,tls:$tls}
        + (if $tr == null then {} else {transport:$tr} end)' ;;
    anytls)
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --argjson tls "$tls" \
        '{type:"anytls",tag:$tag,server:$s,server_port:$p,password:$pw,tls:$tls}' ;;
    ss)
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg m "$SS_METHOD" --arg pw "$SS_PASSWORD" \
        '{type:"shadowsocks",tag:$tag,server:$s,server_port:$p,method:$m,password:$pw}' ;;
    hysteria2)
      local obfs="null"
      [[ ${K_SEC[$key]} == obfs ]] && obfs="$(jq -cn --arg pw "$HY2_OBFS_PASSWORD" --arg t "$HY2_OBFS" '{type:$t,password:$pw}')"
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg pw "$PASSWORD" --arg sni "$VPN_DOMAIN" \
             --argjson insec "$( [[ $CERT_MODE == self ]] && echo true || echo false )" --argjson obfs "$obfs" '
        {type:"hysteria2",tag:$tag,server:$s,server_port:$p,password:$pw,
         tls:{enabled:true,server_name:$sni,insecure:$insec,alpn:["h3"]}}
        + (if $obfs == null then {} else {obfs:$obfs} end)' ;;
    tuic)
      jq -cn --arg tag "$tag" --arg s "$a" --argjson p "$p" --arg uuid "$TUIC_UUID" --arg pw "$TUIC_PASSWORD" \
             --arg sni "$VPN_DOMAIN" --argjson insec "$( [[ $CERT_MODE == self ]] && echo true || echo false )" '
        {type:"tuic",tag:$tag,server:$s,server_port:$p,uuid:$uuid,password:$pw,
         congestion_control:"bbr",udp_relay_mode:"native",
         tls:{enabled:true,server_name:$sni,insecure:$insec,alpn:["h3"]}}' ;;
    *) return 1 ;;
  esac
}

write_client_mihomo() {
  local key names=() f="${CLIENT_OUT_DIR}/client-mihomo.yaml" n
  {
    cat <<EOF
# mihomo / Clash.Meta client config generated by Mihomo_Deployment.sh v${SCRIPT_VERSION}
# node: ${NODE_LABEL} (${VPN_DOMAIN})   generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
#
# This file is the COMPLETE bundle: every listener on the server appears here,
# including the ones that have no share-link representation anywhere.
mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
ipv6: true
unified-delay: true
tcp-concurrent: true
find-process-mode: off
external-controller: 127.0.0.1:9090
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
proxies:
EOF
  } >"$f"
  for key in $SELECTED; do
    if mihomo_of "$key" >>"$f" 2>/dev/null; then names+=("$(node_name "$key")"); fi
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

write_client_singbox() {
  local frags=() key ob
  for key in $SELECTED; do
    ob="$(singbox_ob_of "$key" 2>/dev/null || true)"; [[ -n $ob ]] && frags+=("$ob")
  done
  (( ${#frags[@]} > 0 )) || return 0
  local outbounds; outbounds="$(printf '%s\n' "${frags[@]}" | jq -s '.')"
  jq -n --argjson obs "$outbounds" '
    {log:{level:"warn"},
     inbounds:[{type:"mixed",tag:"mixed-in",listen:"127.0.0.1",listen_port:2080}],
     outbounds:( $obs + [{type:"direct",tag:"direct"}] )}' \
    >"${CLIENT_OUT_DIR}/client-singbox.json"
  return 0
}

write_readme() {
  local f="${CLIENT_OUT_DIR}/README.txt" key
  {
    echo "mihomo node: ${NODE_LABEL}  (${VPN_DOMAIN} / ${VPN_IP})"
    echo "generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "mihomo: ${MH_VERSION:-unknown}  channel=${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}}  cert=${CERT_MODE}"
    echo "listeners: $(selected_count)"
    echo
    echo "Files:"
    echo "  client-mihomo.yaml  mihomo / Clash.Meta config — every PROXY node (see 'yaml' below)"
    echo "  links.txt           one share link per line (the portable subset only)"
    echo "  subscription.txt    base64 of links.txt (v2rayN, NekoBox, Streisand, Shadowrocket)"
    echo "  client-singbox.json sing-box client config (compatible subset — see below)"
    echo
    echo "Which artefact carries which node:"
    printf '  %-28s %-6s %-6s %-6s %-9s %s\n' "key" "l4" "yaml" "link" "sing-box" "port"
    local _y _n_yaml=0 _n_link=0 _n_sb=0
    for key in $SELECTED; do
      # mihomo_of returns non-zero for anything that is not a client-dialable
      # proxy — today that is only the hysteria2 realm rendezvous server.
      if mihomo_of "$key" >/dev/null 2>&1; then _y=yes; _n_yaml=$((_n_yaml+1)); else _y=no; fi
      has_link "$key" && _n_link=$((_n_link+1))
      singbox_capable "$key" && _n_sb=$((_n_sb+1))
      printf '  %-28s %-6s %-6s %-6s %-9s %s\n' "$key" "$(proto_l4 "$key")" "$_y" \
        "$(has_link "$key" && echo yes || echo no)" \
        "$(singbox_capable "$key" && echo yes || echo no)" \
        "${PORT[$key]}"
    done
    printf '  %-28s %-6s %-6s %-6s %-9s\n' "TOTAL $(selected_count)" "" "$_n_yaml" "$_n_link" "$_n_sb"
    echo
    echo "Client limitations (upstream implementations, verified Aug 2026):"
    echo "  * mihomo is the ONLY client that speaks every node here. Anything marked"
    echo "    'link: no' exists only in client-mihomo.yaml — there is no URI grammar"
    echo "    for it in any client, so emitting one would be a link nothing can import."
    echo "  * 'yaml: no' means the listener is not a client-dialable proxy at all."
    echo "    hysteria2-realm is the only such entry: it is the HTTPS rendezvous"
    echo "    endpoint that hysteria2 nodes register with through realm-opts, so it"
    echo "    has no proxies: entry of its own. It is deployed but nothing in the"
    echo "    generated config points at it — wire it up by hand if you want realm mode."
    echo "  * No share link exists for: Snell, ShadowQUIC, Sudoku, Mieru, TrustTunnel,"
    echo "    mKCP/Mekya/TLS-mirror transports, and every ShadowTLS / RestLS / JLS"
    echo "    wrapper. mihomo's own URI parser has no parameters for them."
    echo "  * sing-box has no XHTTP, mKCP, Mekya, TLS-mirror, RestLS, JLS, Snell,"
    echo "    ShadowQUIC, Sudoku, Mieru or TrustTunnel -> those nodes are omitted from"
    echo "    client-singbox.json."
    echo "  * Xray-core can consume the VLESS / VMess / Trojan / Shadowsocks nodes but"
    echo "    has neither ShadowQUIC nor AnyTLS nor Snell."
    if [[ $CERT_MODE == self ]]; then
      echo "  * Self-signed certificate. Clients use skip-cert-verify: true, or pin:"
      echo "      fingerprint: ${CERT_PIN}"
      echo "    Share links carry allowInsecure=1 / insecure=1, which GUI clients honour."
    fi
    echo
    echo "Camouflage targets — these must stay reachable FROM THE SERVER:"
    echo "  REALITY dest                 ${REALITY_SNI}:443"
    echo "  ShadowTLS/RestLS/JLS/mirror  ${STEAL_SNI}:443"
    echo "  Hysteria2 masquerade         https://${STEAL_SNI}"
    echo "  An unauthenticated prober is proxied to those sites verbatim; if the"
    echo "  server cannot reach them, the disguise fails open and looks anomalous."
    echo
    echo "Credentials:"
    echo "  vless/vmess uuid    : ${UUID}"
    echo "  trojan/anytls/hy2   : ${PASSWORD}"
    [[ -n $SS_PASSWORD ]]        && echo "  shadowsocks key     : ${SS_PASSWORD} (${SS_METHOD})"
    [[ -n $SNELL_PSK ]]          && echo "  snell psk           : ${SNELL_PSK} (v${SNELL_VERSION})"
    [[ -n $TUIC_UUID ]]          && echo "  tuic                : ${TUIC_UUID} / ${TUIC_PASSWORD}"
    [[ -n $HY2_OBFS_PASSWORD ]]  && echo "  hysteria2 obfs      : ${HY2_OBFS} / ${HY2_OBFS_PASSWORD}"
    [[ -n $REALITY_PUBLIC ]]     && echo "  reality public key  : ${REALITY_PUBLIC}   short-id: ${REALITY_SHORTID}"
    [[ -n $SHADOWTLS_PASSWORD ]] && echo "  shadow-tls (v3)     : ${SHADOWTLS_PASSWORD}"
    [[ -n $RESTLS_PASSWORD ]]    && echo "  res-tls             : ${RESTLS_PASSWORD}"
    [[ -n $JLS_PASSWORD ]]       && echo "  jls                 : ${JLS_USER} / ${JLS_PASSWORD}"
    [[ -n $TLSMIRROR_KEY ]]      && echo "  tls-mirror key      : ${TLSMIRROR_KEY}"
    [[ -n $SQ_PASSWORD ]]        && echo "  shadowquic          : ${SQ_USER} / ${SQ_PASSWORD}"
    [[ -n $MIERU_PASSWORD ]]     && echo "  mieru               : ${MIERU_USER} / ${MIERU_PASSWORD}"
    [[ -n $SUDOKU_PRIV ]]        && echo "  sudoku client key   : ${SUDOKU_PRIV}   (server holds ${SUDOKU_PUB})"
    [[ -n $TT_PASSWORD ]]        && echo "  trusttunnel         : ${TT_USER} / ${TT_PASSWORD}"
    [[ -n $REALM_TOKEN ]]        && echo "  hysteria2-realm tok : ${REALM_TOKEN}  (rendezvous server, not a proxy inbound)"
    [[ -n $API_SECRET ]]         && echo "  RESTful api secret  : ${API_SECRET}  (bound to ${API_LISTEN})"
    echo
    echo "Paths / names: ws=${WS_PATH}  grpc=${GRPC_SVC}  xhttp=${XHTTP_PATH}  mkcp-seed=${MKCP_SEED}  obfs-host=${OBFS_HOST}"
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
  if (( ${#links[@]} > 0 )); then
    printf '%s\n' "${links[@]}" >"${CLIENT_OUT_DIR}/links.txt"
    printf '%s\n' "${links[@]}" | base64 -w0 >"${CLIENT_OUT_DIR}/subscription.txt"
  else
    : >"${CLIENT_OUT_DIR}/links.txt"; : >"${CLIENT_OUT_DIR}/subscription.txt"
  fi
  write_client_mihomo
  write_client_singbox
  write_readme
  chmod 0600 "${CLIENT_OUT_DIR}"/*.txt "${CLIENT_OUT_DIR}"/*.json "${CLIENT_OUT_DIR}"/*.yaml 2>/dev/null || true
  ok "Bundles written to ${CLIENT_OUT_DIR}  (${#links[@]} share link(s), $(selected_count) YAML node(s))"
  setup_sub_server
  return 0
}

setup_sub_server() {
  [[ $SUB_HOST == yes ]] || return 0
  [[ -n $SUB_TOKEN ]] || SUB_TOKEN="$(gen_hex 12)"
  local root="/var/lib/mihomo-sub"
  install -d -m 0755 "$root"
  # The unit runs under DynamicUser=yes (a transient UID) which cannot traverse
  # /root (0700) nor read the 0600 bundles, so every request would 404. Serve a
  # world-readable staging copy instead; the secret token in the URL remains the
  # access control.
  install -d -m 0755 "${root}/pub"
  install -m 0644 "${CLIENT_OUT_DIR}/links.txt" "${CLIENT_OUT_DIR}/subscription.txt" "${root}/pub/" 2>/dev/null || true
  install -m 0644 "${CLIENT_OUT_DIR}/client-mihomo.yaml" "${root}/pub/" 2>/dev/null || true
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
        if "clash" in ua or "mihomo" in ua or "meta" in ua: fn,ct="client-mihomo.yaml","text/yaml; charset=utf-8"
        elif "sing-box" in ua or "sfa" in ua or "sfi" in ua: fn,ct="client-singbox.json","application/json"
        else: fn,ct="subscription.txt","text/plain; charset=utf-8"
        try: data=open(os.path.join(DIR,fn),"rb").read()
        except OSError: self.send_error(404); return
        self.send_response(200); self.send_header("Content-Type",ct)
        self.send_header("Profile-Update-Interval","24"); self.end_headers(); self.wfile.write(data)
    def log_message(self,*a): pass
socketserver.TCPServer.allow_reuse_address=True
with socketserver.TCPServer(("0.0.0.0",${SUB_PORT}),H) as s: s.serve_forever()
PYEOF
  cat >/etc/systemd/system/mihomo-sub.service <<EOF
[Unit]
Description=mihomo subscription server
After=network-online.target

[Service]
Environment=SUB_TOKEN=${SUB_TOKEN}
ExecStart=/usr/bin/python3 ${cgi}
Restart=on-failure
DynamicUser=yes
ReadOnlyPaths=${root}/pub

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now mihomo-sub.service >/dev/null 2>&1 || warn "Could not start mihomo-sub.service."
  ok "Subscription served at:  http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
  return 0
}

# -----------------------------------------------------------------------------
# 15. Verify / status / summary
# -----------------------------------------------------------------------------
verify_all() {
  head1 "Health checks"; local rc=0
  if have "$MH_BIN" || [[ -x $MH_BIN ]]; then
    ok "mihomo: ${MH_VERSION:-$("$MH_BIN" -v 2>/dev/null | awk 'NR==1{print $3}')}"
  else
    bad "mihomo binary missing at ${MH_BIN}"; rc=1
  fi
  if [[ -r $MH_CONF ]]; then
    "$MH_BIN" -t -d "$MH_HOME" >/dev/null 2>&1 && ok "config.yaml valid" || { bad "config.yaml fails \`mihomo -t\`"; rc=1; }
  else
    bad "${MH_CONF} missing"; rc=1
  fi
  systemctl is-active --quiet mihomo && ok "mihomo.service active" || { bad "mihomo.service not active"; rc=1; }

  # A listener that fails to bind leaves the service "active" — so every port is
  # probed individually rather than trusting the unit state.
  local key p l4 up=0 down=0
  for key in $SELECTED; do
    p="${PORT[$key]:-}"; l4="$(proto_l4 "$key")"
    if [[ -z $p ]]; then bad "no saved port for ${key} — re-run a deploy"; rc=1; continue; fi
    case "$l4" in
      tcp)  port_listening tcp "$p" && up=$((up+1)) || { bad "nothing on tcp/${p} (${key})"; down=$((down+1)); rc=1; } ;;
      udp)  port_listening udp "$p" && up=$((up+1)) || { bad "nothing on udp/${p} (${key})"; down=$((down+1)); rc=1; } ;;
      both) { port_listening tcp "$p" || port_listening udp "$p"; } && up=$((up+1)) || { bad "nothing on ${p} (${key})"; down=$((down+1)); rc=1; } ;;
    esac
  done
  (( down == 0 )) && ok "all ${up} listener(s) bound" || warn "${up} listener(s) up, ${down} down"
  return $rc
}

do_status() {
  head1 "Service"
  systemctl --no-pager status mihomo 2>/dev/null | head -8 || true
  head1 "Listening ports"
  ss -tulpnH 2>/dev/null | grep -E 'mihomo' || warn "No mihomo listeners found."
  return 0
}

summary() {
  echo
  printf '%s' "$C_G"
  cat <<'BANNER'
  +==========================================================+
  |           M I H O M O   N O D E   I S   R E A D Y        |
  +==========================================================+
BANNER
  printf '%s' "$C_RST"; echo; hr
  printf '  %-22s %s\n' "Server"   "${VPN_DOMAIN} (${VPN_IP})"
  printf '  %-22s %s\n' "mihomo"   "${MH_VERSION:-unknown} (${INSTALL_CHANNEL}${PIN_VERSION:+ ${PIN_VERSION}})"
  printf '  %-22s %s\n' "Listeners" "$(selected_count) of ${#ALL_KEYS[@]} possible combinations"
  needs_any_cert && printf '  %-22s %s\n' "TLS certificate" "$CERT_MODE"
  hr
  printf '  %sProtocols & ports%s\n' "$C_BOLD" "$C_RST"
  local key i=0 n; n="$(selected_count)"
  for key in $SELECTED; do
    if (( i < 24 )); then printf '    %-28s %s/%s\n' "$key" "$(proto_l4 "$key")" "${PORT[$key]}"; fi
    i=$((i+1))
  done
  (( n > 24 )) && printf '    %s... and %d more — full map in %s/README.txt%s\n' "$C_D" "$((n-24))" "$CLIENT_OUT_DIR" "$C_RST"
  hr
  printf '  %sClient bundles%s\n' "$C_BOLD" "$C_RST"
  # Count what actually landed in the YAML rather than assuming it equals the
  # listener count: a listener that is not a client-dialable proxy (the realm
  # rendezvous server) is deployed but has no proxies: entry.
  local _yaml=0
  for key in $SELECTED; do mihomo_of "$key" >/dev/null 2>&1 && _yaml=$((_yaml+1)); done
  printf '    %-38s %s\n' "${CLIENT_OUT_DIR}/client-mihomo.yaml" "<- all ${_yaml} proxy nodes"
  printf '    %s\n' "${CLIENT_OUT_DIR}/links.txt"
  printf '    %s\n' "${CLIENT_OUT_DIR}/subscription.txt"
  printf '    %s\n' "${CLIENT_OUT_DIR}/client-singbox.json"
  printf '    %s\n' "${CLIENT_OUT_DIR}/README.txt"
  [[ $SUB_HOST == yes ]] && printf '    %s\n' "sub URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"
  hr
  printf '  %sManage%s\n' "$C_BOLD" "$C_RST"
  printf '    %s\n' "mihomoctl info        # reprint links / credentials"
  printf '    %s\n' "mihomoctl status      # service + listening ports"
  printf '    %s\n' "mihomoctl check       # health checks"
  printf '    %s\n' "mihomoctl update      # upgrade mihomo"
  printf '    %s\n' "journalctl -u mihomo -f"
  hr
  printf '    %sscp -r root@%s:%s .%s\n' "$C_D" "${VPN_IP:-$VPN_DOMAIN}" "$CLIENT_OUT_DIR" "$C_RST"
  hr
  (( WARN_COUNT > 0 )) && { printf '  %s%d warning(s) above — scroll up.%s\n' "$C_Y" "$WARN_COUNT" "$C_RST"; hr; }
  echo
  return 0
}

do_info() {
  [[ -r ${CLIENT_OUT_DIR}/README.txt ]] || die "No bundles found — run a deploy first."
  if [[ -s ${CLIENT_OUT_DIR}/links.txt ]]; then
    head1 "Share links (portable subset)"; cat "${CLIENT_OUT_DIR}/links.txt"
    echo; head1 "Base64 subscription"; cat "${CLIENT_OUT_DIR}/subscription.txt"; echo
  else
    warn "No node in this deployment has a share-link form; use client-mihomo.yaml."
  fi
  [[ $SUB_HOST == yes ]] && { echo; ok "Subscription URL: http://$(addr):${SUB_PORT}/${SUB_TOKEN}"; }
  echo; head1 "Full details"; cat "${CLIENT_OUT_DIR}/README.txt"
  return 0
}

do_update() {
  head1 "Updating mihomo (${INSTALL_CHANNEL})"
  install_mihomo
  if [[ -r $MH_CONF ]] && "$MH_BIN" -t -d "$MH_HOME" >/dev/null 2>&1; then
    systemctl restart mihomo || true; sleep 2
    systemctl is-active --quiet mihomo && ok "mihomo updated and restarted." || bad "mihomo did not come back up."
  else
    warn "Existing config missing or invalid for the new version; not restarting."
  fi
  save_state
  return 0
}

do_uninstall() {
  local go; ask_yn go "Remove mihomo configuration, certificates and firewall rules" "no"
  [[ $go == yes ]] || die "Aborted."
  systemctl disable --now mihomo >/dev/null 2>&1 || true
  systemctl disable --now mihomo-sub >/dev/null 2>&1 || true
  rm -f "$MH_CONF"
  rm -rf "$MH_CERT_DIR"
  rm -rf /etc/systemd/system/mihomo.service.d
  rm -f /etc/systemd/system/mihomo.service /etc/systemd/system/mihomo-sub.service
  rm -f /etc/sysctl.d/99-mihomo.conf /etc/modules-load.d/mihomo-bbr.conf
  iptables -D INPUT -j MIHOMO_IN 2>/dev/null || true
  iptables -F MIHOMO_IN 2>/dev/null || true; iptables -X MIHOMO_IN 2>/dev/null || true
  have netfilter-persistent && netfilter-persistent save >/dev/null 2>&1 || true
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true
  ok "Removed. Kept: ${MH_BIN}, ${STATE_DIR} and ${CLIENT_OUT_DIR}."
  ok "Delete ${MH_BIN} yourself if you want the binary gone too."
  return 0
}

install_self() {
  local target="/usr/local/sbin/mihomoctl"
  local src; src="$(readlink -f "${BASH_SOURCE[0]}")"
  if [[ $src != "$target" ]]; then
    install -m 0700 "$src" "$target" && ok "Installed as ${target}"
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

  printf '\n%s mihomo (Clash.Meta) multi-protocol deployment for Ubuntu 22/24/26 — v%s %s\n' "$C_BOLD" "$SCRIPT_VERSION" "$C_RST"
  printf '%s %d protocol x transport x security combinations; every secret and subscription generated %s\n\n' "$C_D" "${#ALL_KEYS[@]}" "$C_RST"

  load_state
  resolve_selection
  collect_config

  start_logging
  [[ $SKIP_PREFLIGHT == yes ]] || preflight

  install_deps
  install_mihomo
  gen_credentials
  # gen_credentials can only ever DROP a key (e.g. sudoku-keypair unavailable).
  # Prune just those entries — re-running assign_ports here would reset PORT and
  # silently discard any ports the operator hand-picked in review_ports.
  for _k in "${!PORT[@]}"; do
    selected_has "$_k" || unset "PORT[$_k]"
  done
  unset _k
  setup_cert
  write_mihomo_config
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
