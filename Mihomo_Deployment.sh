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
#  The combination space (81 listeners with --protocols all):
#     vless    tcp | xhttp                  x  tls | reality | shadowtls
#                                              | restls | jls
#              ws     (no reality), grpc (no restls)                      (18)
#     vmess    tcp                          x  the above five             (5)
#              ws     (no reality), grpc (no restls)                      (8)
#              mkcp x {srtp, dtls, wechat-video, utp, srtp-no-congestion}   (5)
#              mekya (h2-over-kcp inside TLS)                               (1)
#     trojan   tcp                          x  the above five             (5)
#              ws     (no reality), grpc (no restls)                      (8)
#     anytls   tls | shadowtls | restls | jls                              (4)
#     ss       plain x (none|shadowtls|restls|jls), obfs-http, obfs-tls     (6)
#              kcptun x {rotate, static, fec, fast3}                        (4)
#     snell    plain x (none|shadowtls|restls|jls), obfs-http, obfs-tls     (6)
#     hysteria2, hysteria2-obfs, hysteria2-realm                           (3)
#     tuic, shadowquic                                                     (2)
#     mieru-tcp, mieru-udp                                                 (2)
#     sudoku, sudoku-httpmask                                              (2)
#     trusttunnel-tcp, trusttunnel-quic                                    (2)
#
#  Every combination emitted here is source-verified against MetaCubeX/mihomo
#  (listener/inbound/*.go struct tags, listener/parse.go, the *_interop_test.go
#  fixtures) and was booted end-to-end against mihomo v1.19.30 — all 81 bind and
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
#     ./Mihomo_Deployment.sh amplification  wire bytes vs payload bytes per port
#     ./Mihomo_Deployment.sh pmtu <host>    largest unfragmented UDP payload to <host>
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
readonly DECOY_SITE="/etc/nginx/sites-available/mihomo-decoy.conf"
readonly DECOY_ROOT="/var/www/mihomo-decoy"
readonly DECOY_UNIT_DROPIN="/etc/systemd/system/mihomo.service.d/20-decoy.conf"
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

# --- link profile ------------------------------------------------------------
# Window-based transports (mKCP, kcp-tun) size their in-flight window from
# numbers that describe THE LOCAL LINK OF THE SIDE THAT WRITES THEM.  A German
# VPS and an Iranian handset do not share a link, so the same numbers on both
# sides are wrong on at least one of them.  Everything window-shaped below is
# derived from these six values instead of being hard-coded; see _bdp_pkts.
SRV_UP_MBPS="1000"            # server uplink   (a 1 Gbps port)
SRV_DOWN_MBPS="1000"          # server downlink
# Deliberately the LOW end of a 60-100 Mbps cohort, and an uplink well under the
# 12 Mbps Iranian mobile median. Under-declaring costs a little throughput;
# over-declaring makes a rate-based sender burst into a policer, and on this path
# loss is usually a censorship signal rather than congestion — so a burst that
# would merely be inefficient elsewhere is what gets the flow, and eventually the
# IP, killed here.
CLI_DOWN_MBPS="60"            # client downlink — the number that sets download speed
CLI_UP_MBPS="15"              # client uplink   — the number that sets upload speed
PATH_RTT_MS="120"             # Iran -> Frankfurt: 75-85 ms DC, +access network
PATH_LOSS_PCT="2"             # healthy-path loss; drives the FEC ratio only

# KCP framing. 1200 is QUIC's own safe-datagram floor and survives every
# documented Iranian path including mobile. It is not a guess at the real PMTU:
# ICMP is suppressed on MCI/TCI after a couple of packets, so PMTU discovery
# black-holes silently and there is nothing to discover with. A KCP packet that
# fragments is lost outright when either fragment is dropped, so the safe value
# wins over the efficient one.
KCP_MTU="1200"
MKCP_TTI="25"                 # mKCP tick, ms. Must divide 1000 (see _mkcp_cap).

# Camouflage destination for the borrowed-identity layers.
#   steal — relay the handshake to ${STEAL_SNI}:443 (one extra RTT per connection,
#           and the client presents an SNI that does not match this IP)
#   local — relay it to a local TLS 1.3 site serving YOUR domain's real
#           certificate (no extra RTT, and SNI, certificate and IP all agree)
#   auto  — local when a real certificate is available, steal otherwise
DECOY_MODE="auto"
DECOY_PORT="8443"             # loopback port the local decoy listens on
DECOY_RESOLVED=""             # steal | local, decided in setup_decoy

# 0 = omit the key and let the server use its built-in 15. Raising it pads every
# short record to a uniform floor, which is itself a signature; it is only worth
# setting if you have measured genuinely short records on your own path.
RESTLS_MIN_RECORD_LEN="0"
PROBE_INTERVAL="60"           # client url-test interval, seconds
PROBE_TIMEOUT="3000"          # client health-check timeout, ms
# TCP Brutal is a FIXED-RATE congestion control: it ignores loss by design. On a
# path where loss is frequently the censor rather than the network, that turns
# every loss event into a sustained burst — and a sudden burst is one of the
# documented triggers for having the flow killed and the IP graylisted. Off by
# default here for that reason; --brutal turns it on with measured rates.
BRUTAL="no"

API_LISTEN="127.0.0.1:9090"   # RESTful controller; loopback only by default
API_SECRET=""

AUTO_PORTS="yes"
KERNEL_TUNING="yes"
METERING="yes"          # nftables byte counters behind `mihomoctl amplification`
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
METER_RESET="no"
PMTU_TARGET=""

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
KCPTUN_KEY=""                 # kcp-tun's own secret — NOT shared with trojan/hy2
RESTLS_SCRIPT_S=""            # server->client record-length programme
RESTLS_SCRIPT_C=""            # client->server programme (independent of the above)
RESTLS_VERSION_HINT="tls13"   # confirmed against the decoy in preflight
DECOY_ALPN="h2,http/1.1"      # what the decoy actually negotiates
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
declare -A K_BASE=() K_XPORT=() K_SEC=() K_PORTS=() K_VAR=()

# _cat_add <key> <base> <transport> <security> <candidate ports...>
_cat_add() {
  local key=$1 base=$2 xport=$3 sec=$4; shift 4
  ALL_KEYS+=("$key")
  K_BASE[$key]="$base"; K_XPORT[$key]="$xport"; K_SEC[$key]="$sec"
  K_PORTS[$key]="$*"; K_VAR[$key]=""
}

# _cat_var <key> <variant>
# A transport parameter whose right value is a judgement call rather than a fact
# — which packet header to wear, whether to run congestion control, how much FEC
# to pay for — becomes a variant here and gets its own listener, so the choice
# can be measured on the live path instead of argued about.  The variant tag is
# read back by _mkcp_* / _kcptun_* at emit time and by nothing else.
_cat_var() { K_VAR[$1]="$2"; }

# Candidate ports are drawn from a per-family band so that a full 81-listener
# deployment stays readable in `ss -tulpn`; three candidates each, then
# _pick_free falls back to a random high port.
_band() { local base=$1 n=$2; printf '%s %s %s' "$((base+n))" "$((base+300+n))" "$((base+600+n))"; }

build_catalogue() {
  ALL_KEYS=(); K_BASE=(); K_XPORT=(); K_SEC=(); K_PORTS=(); K_VAR=()
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
  # mKCP variants. `header` is the whole disguise — these packets carry no TLS at
  # all — and `congestion` is the throughput/retransmit trade, so each gets its
  # own listener and can be A/B-ed on the live path.
  #
  # The ports are deliberately unremarkable high ports rather than the "matching"
  # service ports the header names suggest. There is no evidence that Iranian
  # networks treat the RTP range (16384-32767) or STUN/3478 as privileged, and
  # UDP/443 is measurably the WORST choice because that is where the QUIC filter
  # lives. What is documented is that UDP drops are keyed on the full
  # (srcIP, srcPort, dstIP, dstPort) tuple, so a fresh port resurrects a
  # blackholed path — which makes the port a rotation knob, not a disguise.
  _cat_add vmess-mkcp        vmess mkcp none "27411 33507 41209"; _cat_var vmess-mkcp        srtp
  _cat_add vmess-mkcp-dtls   vmess mkcp none "24683 31097 44521"; _cat_var vmess-mkcp-dtls   dtls
  _cat_add vmess-mkcp-wechat vmess mkcp none "22157 36841 47309"; _cat_var vmess-mkcp-wechat wechat-video
  _cat_add vmess-mkcp-utp    vmess mkcp none "29063 38219 45707"; _cat_var vmess-mkcp-utp    utp
  _cat_add vmess-mkcp-nocong vmess mkcp none "26339 34751 42863"; _cat_var vmess-mkcp-nocong srtp-nocong
  n=$((n+1))
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
  # kcp-tun variants. It wears no header camouflage at all — the wire is
  # indistinguishable from random bytes — so nothing about it is plausible on any
  # port, and the ports below are chosen only to be unremarkable and spread out.
  #
  # Rotation is the DEFAULT here rather than a variant, because it is the one
  # mitigation the measurement literature supports directly: UDP blackholing is
  # keyed on the 4-tuple, so retiring each connection onto a fresh source port
  # before the middlebox acts is a structural fix rather than a tuning guess.
  # -static exists to measure what rotation is actually buying you.
  _cat_add ss-kcptun        ss kcptun none "23417 31861 43229"; _cat_var ss-kcptun        rotate
  _cat_add ss-kcptun-static ss kcptun none "25603 35129 46811"; _cat_var ss-kcptun-static static
  _cat_add ss-kcptun-fec    ss kcptun none "21739 32467 44093"; _cat_var ss-kcptun-fec    fec
  _cat_add ss-kcptun-fast3  ss kcptun none "28871 37253 48619"; _cat_var ss-kcptun-fast3  fast3

  # --- Snell: 4 security layers + 2 obfs modes = 6 --------------------------
  _cat_add snell-plain     snell plain     none      "$(_band 35000 0)"
  _cat_add snell-shadowtls snell plain     shadowtls "$(_band 35000 1)"
  _cat_add snell-restls    snell plain     restls    "$(_band 35000 2)"
  _cat_add snell-jls       snell plain     jls       "$(_band 35000 3)"
  _cat_add snell-obfs-http snell obfs-http none      "$(_band 35000 4)"
  _cat_add snell-obfs-tls  snell obfs-tls  none      "$(_band 35000 5)"

  # --- QUIC family (each carries its own TLS; no transport axis) ------------
  # 443/udp is kept as the first candidate. There is a real argument for moving
  # it — QUIC Initial packets from Iran are reported dropped at close to 100%,
  # and the filter is port-sensitive — but 443/udp is also the only UDP port
  # carrying plausible cover traffic, and the same flow on a random high port is
  # anomalous everywhere rather than just in Iran. Move it with --list-protocols
  # + manual port review if your own measurements say otherwise.
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
  local v="${K_VAR[$key]:-}"
  case "$x" in
    tcp)       xd="raw TCP" ;;
    ws)        xd="WebSocket" ;;
    grpc)      xd="gRPC" ;;
    xhttp)     xd="XHTTP" ;;
    mkcp)
      case "$v" in
        srtp-nocong)  xd="mKCP srtp, no cong." ;;
        wechat-video) xd="mKCP wechat-video" ;;
        "")           xd="mKCP (UDP)" ;;
        *)            xd="mKCP ${v} header" ;;
      esac ;;
    mekya)     xd="Mekya (h2 over KCP)" ;;
    plain)     xd="raw TCP" ;;
    obfs-http) xd="simple-obfs http" ;;
    obfs-tls)  xd="simple-obfs tls" ;;
    kcptun)
      case "$v" in
        rotate) xd="KCPTun, port rotation" ;;
        static) xd="KCPTun, no rotation" ;;
        fec)    xd="KCPTun, FEC 10/3" ;;
        fast3)  xd="KCPTun, mode fast3" ;;
        *)      xd="KCPTun (UDP)" ;;
      esac ;;
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

# A Restls record-length programme, generated per deployment, per direction.
#
# Restls is not "off" without one: both halves substitute the SAME built-in
# default — "250?100<1,350~100<1,600~100,300~200,300~100" — when the key is
# empty (restls_utils.go:248, restls_server.go:231-234). Every untouched Restls
# deployment therefore emits one identical record-length sequence, which is a
# stable public signature and a considerably easier one to match than the
# TLS-in-TLS pattern Restls exists to hide. Shipping the README's example string
# has the same problem for the same reason. The design's whole claim is that
# each deployment writes its own; this generates one.
#
# Grammar, from the parser (restls_utils.go:146-231), entries comma-separated:
#     <target>[ ('?'|'~') <range> ][ '<' <n> ]
#   ?  resolves ONCE at parse time and mihomo memoises the parse per process, so
#      a `?` line is a constant shared by every connection and every user on that
#      listener until restart — learnable from a handful of flows. It is only
#      honest on record 1, where a fixed-size preamble is genuinely plausible.
#   ~  re-rolls per record; this is what actually randomises anything.
#   <n asks the peer for n fake response records AND blocks the sender until one
#      comes back — one full round trip each, paid on every connection.
# Limits: target <= 32767, range <= 32767, target+range <= 32768, n < 255.
# Values above 16372 are silently clamped to the TLS record ceiling.
#
# The two directions are INDEPENDENT programmes: the server's script indexes
# server->client records, the client's indexes client->server, commands travel
# in-band, and neither side ever compares its script against the peer's. So they
# are shaped differently on purpose — responses are long, requests are short.
# Setting only one side leaves the other on the shared default.
#
#   gen_restls_script <server|client>
gen_restls_script() {
  local dir=$1 n i t r op out=() marks=() idx lo span nmark long1 long2 base spread
  # Everything structural is drawn, not fixed. A generator whose output always
  # has the same entry count, the same '?' position, the same marker placement
  # and the same two-mode length distribution replaces one exact-string
  # signature with one shape-family signature — better, but not by much.
  n=$(( 5 + RANDOM % 6 ))                       # 5..10 records

  # 0, 1 or 2 response markers, anywhere in the first two thirds. Zero is a
  # legitimate choice: each marker costs a full round trip on every connection.
  marks=()
  nmark=$(( RANDOM % 100 ))
  if   (( nmark < 25 )); then nmark=0
  elif (( nmark < 75 )); then nmark=1
  else                        nmark=2; fi
  for (( i = 0; i < nmark; i++ )); do
    idx=$(( RANDOM % ((n * 2 + 2) / 3) ))
    marks[$idx]=1
  done

  # Which records are the long ones is drawn too, rather than being every third.
  long1=$(( RANDOM % n )); long2=$(( RANDOM % n ))

  # Per-script base and spread, so two deployments differ in scale and not only
  # in the individual draws.
  if [[ $dir == client ]]; then
    base=$(( 60 + RANDOM % 140 )); spread=$(( 90 + RANDOM % 220 ))
  else
    base=$(( 900 + RANDOM % 700 )); spread=$(( 80 + RANDOM % 400 ))
  fi

  for (( i = 0; i < n; i++ )); do
    if (( i == long1 || i == long2 )); then
      # A long record: a body frame rather than a header frame.
      if [[ $dir == client ]]; then lo=$(( 700 + RANDOM % 900 )); span=$(( 200 + RANDOM % 900 ))
      else                          lo=$(( 1900 + RANDOM % 1800 )); span=$(( 300 + RANDOM % 1600 )); fi
    else
      lo=$base; span=$spread
    fi
    t=$(( lo + RANDOM % span ))
    r=$(( 20 + RANDOM % 400 ))
    # 16372 is the real ceiling: writeOneRestlsRecord clamps to maxPlaintext
    # minus the 12-byte auth header, so anything larger is silently truncated
    # and the script would not mean what it says.
    (( t > 16000 )) && t=$(( 12000 + RANDOM % 4000 ))
    (( t + r > 16372 )) && r=$(( 16372 - t ))
    (( r < 1 )) && r=1
    # '?' only ever on the first record, and only sometimes: it resolves once at
    # parse time and mihomo caches the parse per process, so a '?' line is a
    # constant shared by every user of that listener until restart. On record 1
    # that is plausible as a fixed-size preamble; anywhere else it is a gift.
    op='~'; (( i == 0 && RANDOM % 3 == 0 )) && op='?'
    out+=( "${t}${op}${r}${marks[$i]:+<1}" )
  done
  local IFS=','; printf '%s' "${out[*]}"
}

# Reject a script the parser would refuse, so a hand-edited --restls-script
# fails here rather than per-connection at runtime on the server.
valid_restls_script() {
  local sc="${1// /}" e t r n
  [[ -n $sc ]] || return 1
  # An empty entry (leading, trailing or doubled comma) is skipped by mihomo's Go
  # parser but becomes a zero-length target in the Rust reference server, which
  # then emits header-only records without consuming data. Caught here, before
  # word-splitting silently discards a trailing one.
  [[ $sc == ,* || $sc == *, || $sc == *,,* ]] && return 1
  IFS=',' read -r -a __rs <<<"$sc"
  (( ${#__rs[@]} > 0 )) || return 1
  for e in "${__rs[@]}"; do
    [[ $e =~ ^([0-9]+)([~?]([0-9]+))?(\<([0-9]+))?$ ]] || return 1
    t="${BASH_REMATCH[1]}"; r="${BASH_REMATCH[3]:-}"; n="${BASH_REMATCH[5]:-0}"
    # A zero target makes the writer emit header-only records without consuming
    # data, and `?0` is an empty random range that panics the Rust server — both
    # parse fine and break at runtime, so they are rejected here instead.
    (( 10#$t >= 1 )) || return 1
    [[ ${e:0:${#t}+1} == "${t}?" && ${r:-0} -eq 0 ]] && return 1
    (( 10#$t <= 32767 )) || return 1
    (( 10#${r:-0} <= 32767 )) || return 1
    (( 10#$t + 10#${r:-0} <= 32768 )) || return 1
    (( 10#$n < 255 )) || return 1
  done
  return 0
}

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
# 10000, not 100000: this gates the two CLIENT link prompts, and validate_tunables
# bounds those at 1..10000. A looser prompt validator just moves the rejection
# from "type it again" to a fatal error three lines later.
valid_mbps()    { [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 10000 )); }
valid_ms()      { [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= 1 && 10#$1 <= 2000 )); }
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
             AUTO_PORTS KERNEL_TUNING FIREWALL METERING SUB_HOST SUB_PORT SUB_TOKEN NIC \
             SRV_UP_MBPS SRV_DOWN_MBPS CLI_DOWN_MBPS CLI_UP_MBPS PATH_RTT_MS PATH_LOSS_PCT \
             KCP_MTU MKCP_TTI BRUTAL PROBE_INTERVAL PROBE_TIMEOUT \
             DECOY_MODE DECOY_PORT DECOY_RESOLVED DECOY_ALPN \
             RESTLS_MIN_RECORD_LEN RESTLS_VERSION_HINT RESTLS_SCRIPT_S RESTLS_SCRIPT_C KCPTUN_KEY \
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
  # The local decoy serves OUR certificate on loopback, so a selection made
  # entirely of certificate-less layers still needs one issued. Without this,
  # collect_config takes the "nothing wants a cert" branch, hard-sets
  # CERT_MODE=self, and --decoy local then silently downgrades to steal.
  [[ $DECOY_MODE == local ]] && uses_decoy && return 0
  return 1
}
# Does any selected key borrow a real EXTERNAL site's TLS identity? With the
# local decoy nothing reaches out, so nothing needs to be reachable.
uses_steal_site() {
  local k
  # These three reach STEAL_SNI directly and are NOT routed through the decoy:
  # hysteria2's masquerade URL, shadowquic's jls-upstream (which would need an
  # HTTP/3 peer, not a TCP nginx), and sudoku's http-mask fallback. They keep the
  # site reachable-from-the-server requirement even under --decoy local.
  for k in $SELECTED; do
    case "${K_BASE[$k]}" in
      hysteria2|shadowquic) return 0 ;;
      sudoku) [[ ${K_XPORT[$k]} == httpmask ]] && return 0 ;;
    esac
  done
  _decoy_local && return 1
  for k in $SELECTED; do
    case "${K_SEC[$k]}" in shadowtls|restls|jls|tlsmirror) return 0 ;; esac
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
  amplification          wire bytes vs payload bytes per listener; --reset zeroes it
  pmtu <host>            largest unfragmented UDP payload to <host>; sizes --kcp-mtu
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
      --no-metering            skip the nftables byte counters (see 'amplification')
      --serve-sub              also serve the subscription over plain HTTP
      --skip-preflight

  Camouflage destination (ShadowTLS / RestLS / JLS relay probers here):
      --decoy <auto|local|steal>
                               local = a TLS1.3 site on loopback serving YOUR
                               certificate: SNI, cert and IP agree, and RestLS
                               stops paying a round trip to a third party on
                               every connection. Needs --cert-mode letsencrypt
                               and installs nginx.
                               steal (and auto, the default) = relay to
                               --steal-sni. local is opt-in because it puts every
                               camouflage layer behind ONE name of yours, which a
                               single blocklist entry can then take out.
      --decoy-port <n>         loopback port for the local decoy (default: ${DECOY_PORT})
      --restls-script <s>      override the generated RestLS record programme.
                               Grammar: <len>[?|~<range>][<n], comma separated.
                               Do NOT ship a script anyone else has: the whole
                               point is that no two deployments share one.
      --restls-min-record-len <n>
                               0 (default) leaves the server's built-in 15. A
                               raised floor pads every short record to a uniform
                               size, which is itself a signature.

  Link profile — mKCP and kcp-tun derive every window and buffer from these.
  They describe each side's OWN link, so the two ends must not share numbers:
      --client-down-mbps <n>   default ${CLI_DOWN_MBPS}
      --client-up-mbps <n>     default ${CLI_UP_MBPS} — the expensive one to get wrong
      --server-up-mbps <n>     default ${SRV_UP_MBPS}
      --server-down-mbps <n>   default ${SRV_DOWN_MBPS}
      --rtt-ms <n>             default ${PATH_RTT_MS}
      --loss-pct <n>           default ${PATH_LOSS_PCT} (guides the FEC ratio only)
      --kcp-mtu <n>            default ${KCP_MTU}; QUIC's safe-datagram floor
      --mkcp-tti <n>           default ${MKCP_TTI} ms; must divide 1000 exactly
      --probe-interval <n>     client health-check interval, s (default ${PROBE_INTERVAL})
      --brutal | --no-brutal   TCP Brutal over smux. Off by default: it is a
                               fixed-rate sender that ignores loss, and on a path
                               where loss is often the censor rather than
                               congestion that turns into a burst that gets the
                               flow killed.

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
      deploy|info|status|check|update|regen-sub|uninstall|amplification|pmtu) CMD="$1"; shift ;;
      --reset)            METER_RESET="yes"; shift ;;
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
      --no-metering)      METERING="no"; shift ;;
      --decoy)            DECOY_MODE="$2"; shift 2 ;;
      --decoy-port)       DECOY_PORT="$2"; shift 2 ;;
      --client-down-mbps) CLI_DOWN_MBPS="$2"; shift 2 ;;
      --client-up-mbps)   CLI_UP_MBPS="$2"; shift 2 ;;
      --server-up-mbps)   SRV_UP_MBPS="$2"; shift 2 ;;
      --server-down-mbps) SRV_DOWN_MBPS="$2"; shift 2 ;;
      --rtt-ms)           PATH_RTT_MS="$2"; shift 2 ;;
      --loss-pct)         PATH_LOSS_PCT="$2"; shift 2 ;;
      --kcp-mtu)          KCP_MTU="$2"; shift 2 ;;
      --mkcp-tti)         MKCP_TTI="$2"; shift 2 ;;
      --restls-script)    RESTLS_SCRIPT_S="$2"; RESTLS_SCRIPT_C="$2"; shift 2 ;;
      --restls-min-record-len) RESTLS_MIN_RECORD_LEN="$2"; shift 2 ;;
      --probe-interval)   PROBE_INTERVAL="$2"; shift 2 ;;
      --brutal)           BRUTAL="yes"; shift ;;
      --no-brutal)        BRUTAL="no"; shift ;;
      --firewall)         FIREWALL="$2"; shift 2 ;;
      --serve-sub)        SUB_HOST="yes"; shift ;;
      --skip-preflight)   SKIP_PREFLIGHT="yes"; shift ;;
      --list-protocols)   list_protocols; exit 0 ;;
      -h|--help)          usage; exit 0 ;;
      -*) die "Unknown option: $1  (try --help)" ;;
      *)  # `pmtu` takes a bare target; every other subcommand takes none.
          if [[ $CMD == pmtu && -z $PMTU_TARGET ]]; then PMTU_TARGET="$1"; shift
          else die "Unexpected argument: $1  (try --help)"; fi ;;
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

# The link profile drives every window in the config, so a typo here is a
# silently mis-tuned deployment rather than an error. Bound it instead.
_valid_num() { [[ $1 =~ ^[0-9]+$ ]] && (( 10#$1 >= $2 && 10#$1 <= $3 )); }
# Strip leading zeros in place. _valid_num forces base 10 for its own comparison,
# but every consumer downstream does bare arithmetic — and bash reads a leading
# zero as octal, so "060" would silently become 48 Mbit/s and "08" would abort
# the emit with a syntax error halfway through writing the config.
_denorm_zeros() {
  local v n
  for v in "$@"; do
    n="${!v}"
    [[ $n =~ ^0[0-9]+$ ]] || continue
    n="${n#"${n%%[!0]*}"}"; [[ -z $n ]] && n=0
    printf -v "$v" '%s' "$n"
  done
}
validate_tunables() {
  _denorm_zeros CLI_DOWN_MBPS CLI_UP_MBPS SRV_UP_MBPS SRV_DOWN_MBPS PATH_RTT_MS \
                PATH_LOSS_PCT KCP_MTU MKCP_TTI DECOY_PORT PROBE_INTERVAL \
                PROBE_TIMEOUT RESTLS_MIN_RECORD_LEN
  _valid_num "$CLI_DOWN_MBPS" 1 10000  || die "--client-down-mbps must be 1..10000 (got '${CLI_DOWN_MBPS}')."
  _valid_num "$CLI_UP_MBPS"   1 10000  || die "--client-up-mbps must be 1..10000 (got '${CLI_UP_MBPS}')."
  _valid_num "$SRV_UP_MBPS"   1 100000 || die "--server-up-mbps must be 1..100000 (got '${SRV_UP_MBPS}')."
  _valid_num "$SRV_DOWN_MBPS" 1 100000 || die "--server-down-mbps must be 1..100000 (got '${SRV_DOWN_MBPS}')."
  _valid_num "$PATH_RTT_MS"   1 2000   || die "--rtt-ms must be 1..2000 (got '${PATH_RTT_MS}')."
  _valid_num "$PATH_LOSS_PCT" 0 100    || die "--loss-pct must be 0..100 (got '${PATH_LOSS_PCT}')."
  _valid_num "$KCP_MTU"       576 1500 || die "--kcp-mtu must be 576..1500 (got '${KCP_MTU}')."
  _valid_num "$DECOY_PORT"    1 65535  || die "--decoy-port must be 1..65535 (got '${DECOY_PORT}')."
  _valid_num "$PROBE_INTERVAL" 10 3600 || die "--probe-interval must be 10..3600 (got '${PROBE_INTERVAL}')."
  # 0 means "omit the key and let the server use its built-in 15"; 16384 is the
  # TLS record ceiling. Unvalidated, a non-numeric value reaches the `(( ... > 0 ))`
  # guard in _sec_block and aborts the deploy part-way through writing config.yaml.
  _valid_num "$RESTLS_MIN_RECORD_LEN" 0 16384 || die "--restls-min-record-len must be 0..16384 (0 = omit) — got '${RESTLS_MIN_RECORD_LEN}'."
  # mihomo computes ticks as the INTEGER 1000/tti, so a tti that does not divide
  # 1000 silently inflates every derived window by the truncation error.
  case "$MKCP_TTI" in
    10|20|25|40|50|100) : ;;
    *) die "--mkcp-tti must divide 1000 exactly (10, 20, 25, 40, 50 or 100) — got '${MKCP_TTI}'." ;;
  esac
  if [[ -n $RESTLS_SCRIPT_S ]]; then
    valid_restls_script "$RESTLS_SCRIPT_S" || die "--restls-script is not valid restls grammar: ${RESTLS_SCRIPT_S}"
  fi
  # Not fatal, but almost always a mistake worth saying out loud.
  (( 10#$CLI_UP_MBPS > 25 )) && warn "--client-up-mbps ${CLI_UP_MBPS} is above the Iranian mobile median (~12 Mbps); over-declaring the uplink is what turns a loss event into a burst."

  # Say once, here, what _mkcp_cap has to stay silent about: this profile asks
  # for a window mihomo's uint32 arithmetic cannot express, so it is clamped and
  # the link will not be filled at this RTT. A larger --mkcp-tti buys window for
  # the same capacity value, which is the way out.
  local _t
  for _t in "$(_pkts_down)" "$(_pkts_up)"; do
    if (( (_t * KCP_MTU * $(_mkcp_ticks) + 1048575) / 1048576 > MKCP_CAP_MAX )); then
      warn "This link profile needs a larger mKCP window than mihomo can express (capacity > ${MKCP_CAP_MAX})."
      warn "It is clamped, so mKCP will not fill the link at ${PATH_RTT_MS} ms RTT. Raise --mkcp-tti to widen it."
      break
    fi
  done
  return 0
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
  if uses_decoy; then
    echo
    echo "  ShadowTLS / RestLS / JLS forward every unauthenticated connection to a"
    echo "  real TLS server, so an active prober sees that server and nothing else."
    echo "  Which server is the choice:"
    echo
    echo "    ${C_BOLD}local${C_RST} – a TLS 1.3 site on loopback serving YOUR certificate."
    echo "            SNI, certificate and IP all agree, and RestLS stops paying a"
    echo "            round trip to a third party on every single connection."
    echo "            Needs --cert-mode letsencrypt. Installs nginx."
    echo "    ${C_BOLD}steal${C_RST} – relay to a third-party site. Their real certificate, but"
    echo "            your clients then claim their hostname from your IP, and that"
    echo "            disagreement is exactly what gets scored."
    ask_choice DECOY_MODE "Camouflage destination" "$DECOY_MODE" auto local steal
    resolve_decoy_mode
    if ! _decoy_local; then
      echo
      echo "  Pick a busy TLS 1.3 host that is NOT blocked where your clients are,"
      echo "  and ideally not the same one as the REALITY target."
      ask_valid STEAL_SNI "Decoy site for the certificate-less layers" "$STEAL_SNI" \
        valid_domain "must be a hostname, e.g. www.apple.com"
    fi
  fi

  # --- link profile ---
  # These are not cosmetic. mKCP and kcp-tun derive every window and buffer from
  # them, and because those windows describe the LOCAL side of an asymmetric
  # path, one set of numbers cannot be right for both ends. Getting the client
  # uplink wrong is the expensive one: too large and every upload sits in a
  # multi-second queue that DNS and ACKs then queue behind.
  if _xport_used mkcp || _xport_used kcptun || _xport_used mekya; then
    echo
    echo "  ${C_BOLD}Link profile${C_RST} — mKCP and kcp-tun size their windows from these."
    echo "  Give the CLIENT's real numbers, not the plan's headline figure, and"
    echo "  round DOWN. An over-declared uplink does not go faster; it queues."
    ask_valid CLI_DOWN_MBPS "Typical client DOWNLOAD, Mbit/s" "$CLI_DOWN_MBPS" \
      valid_mbps "a whole number of Mbit/s, 1..10000"
    ask_valid CLI_UP_MBPS   "Typical client UPLOAD, Mbit/s"   "$CLI_UP_MBPS" \
      valid_mbps "a whole number of Mbit/s, 1..10000"
    ask_valid PATH_RTT_MS   "Round-trip time to the clients, ms" "$PATH_RTT_MS" \
      valid_ms "a whole number of milliseconds, 1..2000"
    validate_tunables
    printf '    -> %s packets in flight downstream, %s upstream (at mtu %s, tti %s)\n' \
      "$(_pkts_down)" "$(_pkts_up)" "$KCP_MTU" "$MKCP_TTI"
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
  uses_decoy && printf '  %-24s %s\n' "Camouflage decoy" \
    "$(_decoy_local && echo "local nginx (${VPN_DOMAIN})" || echo "${STEAL_SNI}:443")"
  if _xport_used mkcp || _xport_used kcptun || _xport_used mekya; then
    printf '  %-24s %s\n' "Link profile" \
      "client ${CLI_DOWN_MBPS}/${CLI_UP_MBPS} Mbit/s down/up, ${PATH_RTT_MS} ms RTT"
    printf '  %-24s %s\n' "KCP windows" \
      "$(_pkts_down)/$(_pkts_up) pkt down/up, mtu ${KCP_MTU}, tti ${MKCP_TTI}"
  fi
  printf '  %-24s %s\n' "TCP Brutal"      "$BRUTAL"
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
  log "apt-get update ..."
  # A stalled mirror must not hang the whole deploy — bound it and retry once.
  if ! timeout 300 apt-get update -qq; then
    warn "apt-get update failed (slow mirrors?) — retrying once in 5s ..."
    sleep 5
    timeout 300 apt-get update -qq || warn "apt-get update reported errors."
  fi
  local base=(curl ca-certificates jq openssl gzip zip iproute2 dnsutils)
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
  # NOT the decoy: simple-obfs does not relay anywhere, so this string is the
  # entire disguise. As the Host: header of obfs-http and the SNI of obfs-tls it
  # has to name a plausible third party; your own domain would announce the node.
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

  # kcp-tun gets its OWN key. Sharing $PASSWORD across trojan, anytls, hysteria2
  # and kcp-tun means one leaked node config compromises four protocols at once.
  _xport_used kcptun && { [[ -n $KCPTUN_KEY ]] || KCPTUN_KEY="$(gen_pass)"; }

  _sec_used shadowtls && { [[ -n $SHADOWTLS_PASSWORD ]] || SHADOWTLS_PASSWORD="$(gen_pass)"; }
  if _sec_used restls; then
    [[ -n $RESTLS_PASSWORD ]] || RESTLS_PASSWORD="$(gen_pass)"
    # Two independent programmes: the server's shapes server->client records,
    # the client's shapes client->server. Generated once and kept in state so
    # they stay stable across regen-sub — a script that changed on every rebuild
    # would make each client bundle its own distinguishable variant.
    [[ -n $RESTLS_SCRIPT_S ]] || RESTLS_SCRIPT_S="$(gen_restls_script server)"
    [[ -n $RESTLS_SCRIPT_C ]] || RESTLS_SCRIPT_C="$(gen_restls_script client)"
    valid_restls_script "$RESTLS_SCRIPT_S" || die "Invalid server restls script: ${RESTLS_SCRIPT_S}"
    valid_restls_script "$RESTLS_SCRIPT_C" || die "Invalid client restls script: ${RESTLS_SCRIPT_C}"
  fi
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
# 9a. Camouflage destination
#
# ShadowTLS, RestLS and JLS all relay an unauthenticated peer to a real TLS
# server so that a prober sees that server rather than a proxy. WHICH server is
# the interesting choice.
#
#   steal — a third-party site (${STEAL_SNI}). The disguise is somebody else's
#           real certificate, but the client then presents that hostname to an
#           IP that demonstrably is not theirs, and the SNI/IP disagreement is
#           itself scored. RestLS additionally dials dest before reading a single
#           client byte and, in mihomo, holds that socket open for the whole
#           session — so every proxied connection is one live connection to the
#           decoy, your TLS handshake completes one decoy-RTT later than your TCP
#           handshake did, and that timing gap is visible to an active prober.
#
#   local — a TLS 1.3 site on loopback serving YOUR domain's real certificate.
#           SNI, certificate and IP all agree, the extra round trip disappears,
#           and the held-open sockets are loopback. The honest cost: you are no
#           longer impersonating a large site, you are a small site — so the
#           decoy has to be worth looking at, which is why a page is generated
#           rather than leaving nginx's default welcome screen in place.
#
# `local` needs a certificate a stranger can verify, so it requires
# --cert-mode letsencrypt; `auto` picks it when that is available.
# -----------------------------------------------------------------------------
_decoy_local() { [[ $DECOY_RESOLVED == local ]]; }

# Does anything selected actually relay to a decoy?
uses_decoy() {
  local k
  for k in $SELECTED; do
    case "${K_SEC[$k]}" in shadowtls|restls|jls|tlsmirror) return 0 ;; esac
  done
  return 1
}

# host:port the SERVER relays unauthenticated peers to.
_decoy_dest() {
  if _decoy_local; then printf '127.0.0.1:%s' "$DECOY_PORT"
  else printf '%s:443' "$STEAL_SNI"; fi
}
# The hostname the CLIENT presents, and that the decoy's certificate must cover.
_decoy_sni() {
  if _decoy_local; then printf '%s' "$VPN_DOMAIN"
  else printf '%s' "$STEAL_SNI"; fi
}

resolve_decoy_mode() {
  case "$DECOY_MODE" in
    local)
      if [[ $CERT_MODE != letsencrypt ]]; then
        warn "--decoy local needs a publicly verifiable certificate; falling back to the ${STEAL_SNI} decoy."
        DECOY_RESOLVED="steal"
      else
        DECOY_RESOLVED="local"
      fi ;;
    steal) DECOY_RESOLVED="steal" ;;
    auto|*)
      # `auto` deliberately resolves to STEAL, not local, even where local would
      # work. Local is better against SNI/IP-mismatch scoring, but it is a
      # different bet, not a strictly better one: every borrowed-identity layer
      # then presents YOUR domain, so one blocklist entry against a name that is
      # already public in the CT logs takes out ShadowTLS, RestLS and JLS
      # together — whereas a large third party's name is not realistically
      # blockable. Choosing that trade is the operator's call, so it is opt-in.
      DECOY_RESOLVED="steal" ;;
  esac
  return 0
}

# Probe what the decoy actually negotiates, and make the config say that rather
# than assume it. version-hint is a CLIENT-ONLY key with no default — an absent
# or wrong value is a hard error in NewRestlsConfig, not a fallback — and JLS's
# server-side alpn has to intersect what the client offers or the server sends
# alertNoApplicationProtocol, which counts as having written to the client and
# therefore disables the fallback path entirely.
probe_decoy() {
  local host=$1 port=$2 out=""
  have openssl || { warn "openssl missing; keeping version-hint=${RESTLS_VERSION_HINT}, alpn=${DECOY_ALPN}."; return 0; }
  out="$(printf '' | timeout 12 openssl s_client -connect "${host}:${port}" -servername "$(_decoy_sni)" \
          -alpn h2,http/1.1 -tls1_3 2>/dev/null || true)"
  if [[ $out == *"Protocol"*"TLSv1.3"* || $out == *"TLSv1.3"* ]]; then
    RESTLS_VERSION_HINT="tls13"
    ok "Decoy ${host}:${port} negotiates TLS 1.3."
  else
    out="$(printf '' | timeout 12 openssl s_client -connect "${host}:${port}" -servername "$(_decoy_sni)" \
            -alpn h2,http/1.1 2>/dev/null || true)"
    if [[ -z $out ]]; then
      bad "Decoy ${host}:${port} did not answer a TLS handshake at all."
      bad "RestLS and JLS relay every unauthenticated peer there; with it down the disguise fails open."
      return 1
    fi
    RESTLS_VERSION_HINT="tls12"
    warn "Decoy ${host}:${port} does NOT do TLS 1.3 — version-hint set to tls12."
    warn "A TLS 1.2 decoy is a weaker disguise; prefer --decoy local or a TLS 1.3 --steal-sni."
  fi
  local a; a="$(printf '%s' "$out" | sed -n 's/^ *ALPN protocol: *//p' | head -1 | tr -d "\r")"
  case "$a" in
    h2)         DECOY_ALPN="h2,http/1.1" ;;   # h2 chosen from our offer; both are served
    http/1.1)   DECOY_ALPN="http/1.1" ;;
    "")         warn "Decoy negotiated no ALPN; leaving jls-config alpn at ${DECOY_ALPN}." ;;
    *)          DECOY_ALPN="$a" ;;
  esac
  return 0
}

# A loopback TLS 1.3 site serving the real certificate for VPN_DOMAIN.
#
# The four non-obvious settings all come from how RestLS and JLS consume this:
#   ssl_session_tickets off  — NewSessionTicket records are counted as part of
#       the server flight and CONSUME RestLS script lines, so a dest that emits
#       a varying number of tickets shifts your script alignment per connection.
#   ssl_ecdh_curve X25519:...— both RestLS and JLS reject a HelloRetryRequest
#       outright, so the curve the browser fingerprint puts its first key_share
#       on has to be acceptable on the first try.
#   TLSv1.2 TLSv1.3          — 1.3 for the normal path, 1.2 kept so an old prober
#       gets a real answer rather than an alert no real site would send.
#   no listen on :80         — certbot renews standalone on port 80 and nginx
#       must not be holding it.
setup_decoy() {
  # mihomo.service and nginx.service share the same start gate
  # (After=network-online.target nss-lookup.target) and nothing orders them, so
  # on boot mihomo can bind and start relaying failed probes to a decoy that is
  # not listening yet. Written from here rather than install_unit because only
  # this function knows whether the local decoy actually came up.
  rm -f "$DECOY_UNIT_DROPIN"
  _decoy_local || { log "Camouflage decoy: ${STEAL_SNI}:443 (external)."; systemctl daemon-reload >/dev/null 2>&1 || true; return 0; }
  head1 "Local camouflage decoy (127.0.0.1:${DECOY_PORT})"

  apt-get install -y -qq nginx >/dev/null 2>&1 || {
    warn "Could not install nginx; falling back to the ${STEAL_SNI} decoy."
    DECOY_RESOLVED="steal"; rm -f "$DECOY_UNIT_DROPIN"; return 0
  }

  install -d -m 0755 "$DECOY_ROOT"
  # Every prober that fails authentication is relayed here, so this page IS the
  # disguise. A fixed template would be worse than useless: identical bytes on
  # every deployment of this script is a cross-deployment signature that
  # identifies the tool itself, and finding one node would then find the rest.
  # So the wording, the layout and the padding are all drawn per deployment.
  if [[ ! -s ${DECOY_ROOT}/index.html ]]; then
    local _h _p _f _pad _n
    local -a _heads=("Service status" "${VPN_DOMAIN}" "API endpoint" "Internal service"
                     "Status" "${VPN_DOMAIN%%.*}" "Host information")
    local -a _paras=(
      "This host exposes a small number of authenticated HTTP endpoints. There is no public index."
      "Access to this service requires credentials. Unrecognised paths return this page."
      "This endpoint is not intended for interactive use. Refer to the service documentation."
      "No public content is served from this address. Requests without a valid route land here."
      "Automated clients only. Human traffic is not expected on this host."
    )
    local -a _foots=("" "<p><code>${VPN_DOMAIN}</code></p>"
                     "<p><small>${VPN_DOMAIN}</small></p>" "<hr><p><small>${VPN_DOMAIN}</small></p>")
    _h="${_heads[RANDOM % ${#_heads[@]}]}"
    _p="${_paras[RANDOM % ${#_paras[@]}]}"
    _f="${_foots[RANDOM % ${#_foots[@]}]}"
    # An HTML comment of random length so the response body length varies too —
    # the page is delivered over TLS, where length is the observable.
    _pad=""; _n=$(( 40 + RANDOM % 700 ))
    _pad="$(head -c "$_n" /dev/urandom | base64 -w0 | tr -d '=+/' )"
    cat >"${DECOY_ROOT}/index.html" <<EOF
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${_h}</title>
<style>
body{margin:0;font:$(( 15 + RANDOM % 3 ))px/1.$(( 4 + RANDOM % 3 )) system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
     padding:$(( 2 + RANDOM % 3 ))rem;max-width:$(( 30 + RANDOM % 14 ))rem;margin:auto}
h1{font-size:1.$(( 2 + RANDOM % 5 ))rem;margin:0 0 .75rem}
p{margin:0 0 1rem;opacity:.$(( 7 + RANDOM % 2 ))}
</style></head>
<body>
<h1>${_h}</h1>
<p>${_p}</p>
${_f}
<!-- ${_pad} -->
</body></html>
EOF
  fi
  chmod 0644 "${DECOY_ROOT}/index.html"

  # `listen ... http2` was replaced by a standalone `http2 on;` in nginx 1.25.1;
  # emitting the wrong one is a config error, not a warning, so pick by version.
  local ngver h2line
  ngver="$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p')"
  if [[ -n $ngver ]] && [[ "$(printf '%s\n1.25.1\n' "$ngver" | sort -V | head -1)" == "1.25.1" ]]; then
    h2line="    listen 127.0.0.1:${DECOY_PORT} ssl;
    http2 on;"
  else
    h2line="    listen 127.0.0.1:${DECOY_PORT} ssl http2;"
  fi

  cat >"$DECOY_SITE" <<EOF
# Generated by Mihomo_Deployment.sh — camouflage decoy for RestLS / JLS / ShadowTLS.
# Loopback only: this is never reached from the internet directly, only relayed
# to by mihomo when a peer fails authentication.
server {
${h2line}
    server_name ${VPN_DOMAIN};

    ssl_certificate     ${MH_CERT_FULL};
    ssl_certificate_key ${MH_CERT_KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ecdh_curve      X25519:prime256v1;
    ssl_session_tickets off;
    ssl_prefer_server_ciphers off;

    root  ${DECOY_ROOT};
    index index.html;
    location / { try_files \$uri \$uri/ /index.html; }
    access_log off;
}
EOF
  rm -f /etc/nginx/sites-enabled/default
  ln -sf "$DECOY_SITE" "/etc/nginx/sites-enabled/$(basename "$DECOY_SITE")"

  if ! nginx -t >/dev/null 2>&1; then
    nginx -t 2>&1 | sed 's/^/    /' >&2
    warn "nginx rejected the decoy site; falling back to the ${STEAL_SNI} decoy."
    rm -f "/etc/nginx/sites-enabled/$(basename "$DECOY_SITE")" "$DECOY_UNIT_DROPIN"
    DECOY_RESOLVED="steal"; return 0
  fi
  systemctl enable --now nginx >/dev/null 2>&1 || true
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true

  # The certificate is renewed under mihomo's hook, which knows nothing about
  # nginx; without this the decoy would keep serving an expired chain to probers.
  if [[ -s $MH_RENEW_HOOK ]] && ! grep -q 'reload nginx' "$MH_RENEW_HOOK"; then
    printf 'systemctl reload nginx >/dev/null 2>&1 || true\n' >>"$MH_RENEW_HOOK"
  fi

  if port_listening tcp "$DECOY_PORT"; then
    install -d -m 0755 /etc/systemd/system/mihomo.service.d
    cat >"$DECOY_UNIT_DROPIN" <<'EOF'
[Unit]
# The camouflage decoy must be listening before mihomo starts relaying failed
# probes to it. Written by Mihomo_Deployment.sh only while --decoy local is in
# effect; removed again if the decoy is turned off.
After=nginx.service
Wants=nginx.service
EOF
    systemctl daemon-reload >/dev/null 2>&1 || true
    ok "Decoy serving ${VPN_DOMAIN} on 127.0.0.1:${DECOY_PORT}."
  else
    warn "Nothing is listening on 127.0.0.1:${DECOY_PORT}; falling back to the ${STEAL_SNI} decoy."
    rm -f "$DECOY_UNIT_DROPIN"
    DECOY_RESOLVED="steal"
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
# -----------------------------------------------------------------------------
# 10a. Window sizing for the two window-based transports
#
# mKCP and kcp-tun both size their in-flight window from a number that describes
# THE LINK OF THE SIDE THAT WRITES IT.  Copying one set of numbers onto both
# sides is therefore wrong on at least one of them, and the wrong side is always
# the client: a window meant for a 1 Gbps VPS, applied to a home or mobile
# uplink, is seconds of standing queue that every DNS lookup and TCP ACK then
# has to wait behind.
#
# Both sides are derived from the same bandwidth-delay product instead:
#
#   _bdp_pkts <mbps>   packets that fit in one RTT at that rate, x1.5 headroom
#   _mkcp_cap <pkts>   the uplink/downlink-capacity value that yields that many
#   _kcp_buf  <pkts>   a write-buffer that holds two windows and no more
#
# _mkcp_cap inverts mihomo's own formula (transport/mkcp/config.go:65-71):
#
#   sendingInFlightSize = capacity * 1048576 / mtu / (1000 / tti)
#
# so `uplink-capacity` is NOT a link speed — it is a window dial whose product
# with `tti` sets bytes in flight.  Naming it after a bandwidth is upstream's
# choice, not a description of what it does, which is exactly why copying a
# plausible-looking megabyte figure onto both sides goes unnoticed.
# -----------------------------------------------------------------------------
# The largest capacity that does not wrap mihomo's uint32 `capacity * 1048576`.
readonly MKCP_CAP_MAX=4095

_mkcp_ticks() { printf '%s' "$(( 1000 / MKCP_TTI ))"; }

# Packets in flight to keep a link of <mbps> busy over PATH_RTT_MS, x1.5.
_bdp_pkts() {
  local mbps=$1 bytes pkts
  bytes=$(( mbps * 125 * PATH_RTT_MS ))          # mbps*125000 B/s * rtt/1000 s
  pkts=$(( (bytes * 3 / 2 + KCP_MTU - 1) / KCP_MTU ))
  (( pkts < 8 )) && pkts=8                       # mihomo's own floor
  # Sanity ceiling. A 10 Gbit/s profile at 2 s RTT derives ~6.5 million packets,
  # which becomes a multi-gigabyte write-buffer (overflowing mihomo's uint32
  # field) and a kcp-go window it would try to allocate up front. Nothing on this
  # path is that fat; a runaway --rtt-ms or --client-down-mbps is.
  (( pkts > 65535 )) && pkts=65535
  printf '%s' "$pkts"
}

# The uplink-/downlink-capacity value that produces <pkts> in flight.
_mkcp_cap() {
  local pkts=$1 ticks cap
  ticks="$(_mkcp_ticks)"
  cap=$(( (pkts * KCP_MTU * ticks + 1048575) / 1048576 ))
  (( cap < 1 )) && cap=1
  # HARD CEILING, not a style choice. mihomo computes the window as
  #   size := c.uplinkCapacity() * 1024 * 1024 / c.mtu() / (1000/c.tti())
  # in uint32 arithmetic, and 4096 * 1048576 is exactly 2^32 — so a capacity of
  # 4096 wraps the product to 0 and the window collapses to the 8-packet floor,
  # i.e. the config would look aggressive and run at a crawl. 4095 is the last
  # value that does not wrap.
  #
  # This function is SILENT by design: it is called from inside $( ) in a
  # heredoc, so anything it writes to stdout is captured straight into the YAML
  # value. The operator-facing warning lives in validate_tunables, where it also
  # fires once instead of once per listener per direction.
  (( cap > MKCP_CAP_MAX )) && cap=$MKCP_CAP_MAX
  printf '%s' "$cap"
}

# write-buffer for a <pkts> window.  sendingBufferSize = write-buffer / mtu is
# the Conn.Write backpressure bound, i.e. how much may queue BEHIND the window;
# two windows is enough to keep the window full and little enough that the queue
# cannot dominate latency.  mihomo's 2 MB default is 1553 segments no matter how
# small the link, which is where the multi-second queue comes from.
_kcp_buf() {
  local pkts=$1 b
  b=$(( pkts * 2 * KCP_MTU ))
  (( b < 262144 )) && b=262144
  # Both write-buffer and read-buffer are uint32 in mihomo. 64 MiB is already
  # four times what upstream's own mekya interop fixture uses, and well clear of
  # the wrap; beyond it the number is a queue nobody wants anyway.
  (( b > 67108864 )) && b=67108864
  printf '%s' "$b"
}

# kcp-tun window, in packets. Separate from _bdp_pkts because kcp-go sizes real
# buffers from this: a six-figure window is not an aggressive setting, it is an
# allocation. 8192 packets is ~9.8 MB in flight at the default MTU, which covers
# any link this script is plausibly deployed on.
_kcp_wnd() {
  local w=$1
  (( w < 16 ))   && w=16
  (( w > 8192 )) && w=8192
  printf '%s' "$w"
}

# The four windows this deployment actually needs.  A path is only as wide as
# its narrower end, so each direction is sized from the min of the two links.
_pkts_down() { _bdp_pkts "$(( SRV_UP_MBPS   < CLI_DOWN_MBPS ? SRV_UP_MBPS   : CLI_DOWN_MBPS ))"; }
_pkts_up()   { _bdp_pkts "$(( SRV_DOWN_MBPS < CLI_UP_MBPS   ? SRV_DOWN_MBPS : CLI_UP_MBPS   ))"; }

# --- per-variant transport parameters ----------------------------------------
# mihomo accepts exactly these header names (transport/mkcp/header.go:16-30);
# anything else silently becomes the no-op header on BOTH sides, which produces
# a hang rather than an error, so the mapping is closed rather than pass-through.
# `wireguard` is implemented and deliberately not offered: WireGuard's handshake
# is itself DPI-classified and throttled on Iranian carriers, so wearing it as a
# disguise attracts exactly the attention the disguise is meant to avoid.
_mkcp_header_of() {
  case "${K_VAR[$1]:-srtp}" in
    dtls)         printf 'dtls' ;;
    wechat-video) printf 'wechat-video' ;;
    utp)          printf 'utp' ;;
    *)            printf 'srtp' ;;
  esac
}

# With congestion on, the configured capacity becomes a CEILING that KCP backs
# off from under loss.  With it off the window stays wide open and KCP
# retransmits into the loss, which is where 2-3x wire amplification comes from —
# see `mihomoctl amplification`.
_mkcp_cong_of() {
  case "${K_VAR[$1]:-}" in *nocong*) printf 'false' ;; *) printf 'true' ;; esac
}

# mode maps to a fixed nodelay/interval/resend/nc tuple and OVERWRITES any
# explicit values (transport/kcptun/common.go:101-110), so those are never
# emitted.  `fast` — the upstream default — leaves nodelay at 0; on a lossy path
# fast2 (nodelay 1, 20 ms) and fast3 (nodelay 1, 10 ms) are what actually cut
# retransmit latency, at the cost of a higher packet rate.
_kcptun_mode_of() {
  case "${K_VAR[$1]:-}" in fast3) printf 'fast3' ;; *) printf 'fast2' ;; esac
}

# FEC CANNOT BE TURNED OFF in mihomo: FillDefaults rewrites datashard 0 -> 10 and
# parityshard 0 -> 3 (transport/kcptun/common.go:79-84), so `0/0` does not mean
# "no FEC", it means "30% overhead". The only real knob is the ratio, and the
# right ratio is a function of the path's loss rate, not a constant:
#
#   loss    ratio    wire overhead   why
#   <1%     10/1     10%             lowest reachable; ARQ handles the rest
#   1-3%    10/2     20%             one parity recovers a single loss per block
#   4-9%    10/3     30%             upstream's default; 10/2 is not enough here
#   >=10%   20/10    50%             a longer group averages bursts out better
#                                    than 10/5 at the same overhead
#
# Every parity packet is charged against the volume budget that decides how long
# the IP survives, so over-provisioning FEC is not free insurance — check the
# real cost with `mihomoctl amplification`.
_fec_tier() {       # <tier 0..3> -> "<datashard> <parityshard>"
  case "$1" in
    0) printf '10 1'  ;;
    1) printf '10 2'  ;;
    2) printf '10 3'  ;;
    *) printf '20 10' ;;
  esac
}
_tier_for_loss() {
  local l=$1
  if   (( l >= 10 )); then printf '3'
  elif (( l >= 4  )); then printf '2'
  elif (( l >= 1  )); then printf '1'
  else                     printf '0'; fi
}
# The -fec variant sits exactly one tier above the baseline, so the pair is
# always a meaningful A/B rather than two arbitrary constants. At the top tier
# there is nothing stronger worth offering, so the two converge.
_kcptun_fec_of() {
  local t
  t="$(_tier_for_loss "$PATH_LOSS_PCT")"
  [[ ${K_VAR[$1]:-} == fec ]] && t=$(( t + 1 ))
  (( t > 3 )) && t=3
  _fec_tier "$t"
}
# Split with parameter expansion rather than `read`: _kcptun_fec_of emits no
# trailing newline, so `read` would hit EOF, return non-zero and trip `set -e`.
_kcptun_ds_of() { local f; f="$(_kcptun_fec_of "$1")"; printf '%s' "${f%% *}"; }
_kcptun_ps_of() { local f; f="$(_kcptun_fec_of "$1")"; printf '%s' "${f##* }"; }

# Connection rotation, client side only. A middlebox that kills a flow after
# 7-35 s costs 100% of throughput when one connection carries everything; with
# `conn` connections retired every `autoexpire` seconds onto fresh source ports,
# it costs 1/conn — and because UDP blackholing is keyed on the 4-tuple, the
# fresh source port is what actually resurrects the path. scavengettl is the
# drain window for a retired connection and is kept BELOW autoexpire; above it,
# kcptun warns and retired sessions accumulate.
_kcptun_rotates()  { [[ ${K_VAR[$1]:-} == rotate ]]; }
_kcptun_conn_of()  { _kcptun_rotates "$1" && printf '4' || printf '1'; }

# The client opens `conn` INDEPENDENT KCP sessions, each with its own window, so
# the aggregate in flight is conn x window. Divide the client's windows by conn
# or rotation quietly multiplies the queue it was supposed to shorten. The
# server cannot see conn, so its own windows stay whole and the client's smaller
# advertised window is what clamps the pair.
_per_conn() {
  # Split across statements deliberately: under `set -u` bash declares every
  # name in one `local` as an unset local BEFORE running the assignments, so an
  # arithmetic expansion in the same statement reads the unset local and aborts.
  local v=$1 n=$2 r
  r=$(( (v + n - 1) / n ))
  (( r < 16 )) && r=16
  printf '%s' "$r"
}

# kcptun's own rate limiter, bytes/sec of OUTGOING packets, FEC included.
# PER KCP SESSION on both sides — the server calls SetRateLimit inside its
# AcceptKCP loop and the client calls it once per `conn` — so both halves must
# divide by the connection count or the rotate variant runs at conn x the cap.
# (kcp-go sess.go: the limiter is consulted in postProcess before tx, and there
# is no matching check on the input path). Every kcptun mode sets nc=1, i.e. no
# congestion control at all, so this is the only thing that bounds the send
# rate — and because it counts FEC and retransmits, it is also the only direct
# cap on how much wire traffic a byte of payload can turn into.
_kcp_rate() { local mbps=$1; printf '%s' "$(( mbps * 1000000 / 8 * 9 / 10 ))"; }
_rate_down() { _kcp_rate "$(( SRV_UP_MBPS   < CLI_DOWN_MBPS ? SRV_UP_MBPS   : CLI_DOWN_MBPS ))"; }
_rate_up()   { _kcp_rate "$(( SRV_DOWN_MBPS < CLI_UP_MBPS   ? SRV_DOWN_MBPS : CLI_UP_MBPS   ))"; }

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
        dest: $(_decoy_dest)
      strict-mode: true
EOF
      ;;
    restls)
      # restls-script is the whole protocol: without it BOTH halves fall back to
      # the same public default string, and "every deployment emits an identical
      # record-length sequence" is the fingerprint RestLS exists to remove.
      # This one is generated per deployment and shaped for THIS direction.
      #
      # rate-limit is deliberately left unset (0 = unlimited). It throttles only
      # the relay a failed prober gets, so any value makes your server serve the
      # decoy at a capped, unnaturally smooth bitrate the real site does not —
      # converting a byte-perfect impersonation into a measurable one.
      cat <<EOF
    res-tls:
      enable: true
      dest: $(_decoy_dest)
      password: ${RESTLS_PASSWORD}
      restls-script: "${RESTLS_SCRIPT_S}"
EOF
      # 0 means "omit and let the server use its built-in 15": a raised floor
      # pads every short record to a uniform size, which is its own signature.
      (( RESTLS_MIN_RECORD_LEN > 0 )) && printf '      min-record-len: %s\n' "$RESTLS_MIN_RECORD_LEN"
      ;;
    jls)
      # alpn has to intersect what the client's browser fingerprint offers.
      # ALPN is negotiated AFTER the JLS authentication check, so a mismatch is
      # not a soft failure: the server sends alertNoApplicationProtocol, which
      # counts as having written to the client, which disables the relay-to-dest
      # fallback — an authenticated user gets a dead connection and a prober gets
      # an alert no real site would send. Probed from the decoy, not assumed.
      #
      # rate-limit is left unset for the same reason as res-tls above.
      cat <<EOF
    jls-config:
      enable: true
      dest: $(_decoy_dest)
      sni: $(_decoy_sni)
      users:
        - username: ${JLS_USER}
          password: ${JLS_PASSWORD}
      alpn:
EOF
      local _a; local IFS=','
      for _a in $DECOY_ALPN; do printf '        - %s\n' "$_a"; done
      ;;
    # Retained for hand-editing /etc/mihomo/config.yaml; no catalogue key
    # selects it (see build_catalogue for why).
    tlsmirror)
      cat <<EOF
    tlsmirror-config:
      primary-key: ${TLSMIRROR_KEY}
      dest: $(_decoy_dest)
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
      # obfuscation secret and `header` disguises the packets.
      #
      # seed / header / mtu / tti MUST match the client.  The four capacity and
      # buffer values MUST NOT: uplink-capacity sizes what THIS side may have in
      # flight, downlink-capacity is the receive window it advertises to the
      # peer, and the two ends of this path are a 1 Gbps VPS and a handset.
      # Hence: uplink here is the download direction, downlink here is upload.
      local dp up
      dp="$(_pkts_down)"; up="$(_pkts_up)"
      cat <<EOF
    mkcp-config:
      enable: true
      seed: ${MKCP_SEED}
      header: $(_mkcp_header_of "$key")
      mtu: ${KCP_MTU}
      tti: ${MKCP_TTI}
      uplink-capacity: $(_mkcp_cap "$dp")
      downlink-capacity: $(_mkcp_cap "$up")
      congestion: $(_mkcp_cong_of "$key")
      write-buffer: $(_kcp_buf "$dp")
      read-buffer: $(_kcp_buf "$up")
EOF
      ;;
    mekya)
      # h2-over-KCP inside real TLS. The nested kcp block is the same struct as
      # mkcp-config, so it is sized the same asymmetric way; the surrounding h2
      # parameters follow the upstream interop test.
      local dp up
      dp="$(_pkts_down)"; up="$(_pkts_up)"
      cat <<EOF
    mekya-config:
      enable: true
      max-write-size: 10485760
      max-write-duration-ms: 500
      max-simultaneous-write-connection: 128
      packet-writing-buffer: 65536
      kcp:
        mtu: ${KCP_MTU}
        tti: ${MKCP_TTI}
        uplink-capacity: $(_mkcp_cap "$dp")
        downlink-capacity: $(_mkcp_cap "$up")
        congestion: true
        write-buffer: $(_kcp_buf "$dp")
        read-buffer: $(_kcp_buf "$up")
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
      #
      # key / crypt / mode / mtu / datashard / parityshard / nocomp must be
      # IDENTICAL on both sides — a nocomp mismatch in particular corrupts the
      # stream silently rather than failing.  sndwnd / rcvwnd must not be:
      # sndwnd is what this side may have in flight, rcvwnd is the window it
      # advertises, and the effective window is min(sndwnd, peer rcvwnd).
      #
      # conn / autoexpire / scavengettl are deliberately absent here.  They
      # exist in the listener struct but transport/kcptun/server.go never reads
      # them; only the client half acts on them, so they live in plugin-opts.
      local dp up
      dp="$(_pkts_down)"; up="$(_pkts_up)"
      cat <<EOF
    kcp-tun:
      enable: true
      key: ${KCPTUN_KEY}
      crypt: aes-128
      mode: $(_kcptun_mode_of "$key")
      mtu: ${KCP_MTU}
      sndwnd: $(_kcp_wnd "$dp")
      rcvwnd: $(_kcp_wnd "$up")
      datashard: $(_kcptun_ds_of "$key")
      parityshard: $(_kcptun_ps_of "$key")
      nocomp: true
      ratelimit: $(( $(_rate_down) / $(_kcptun_conn_of "$key") ))
      sockbuf: 16777216
      smuxver: 2
      smuxbuf: 8388608
      streambuf: 2097152
      keepalive: 10
      dscp: 0
EOF
      ;;
    *) : ;;
  esac
  return 0
}

# Does this key carry sing-mux?
#
# The LISTENER side accepts `mux-option` on exactly eight inbound types — vmess,
# vless, trojan, shadowsocks, hysteria2, tuic, shadowquic, sudoku. anytls and
# snell are NOT among them (anytls has its own native session multiplexing and
# its listener never routes through the sing handler, so a client `smux` on it
# is silently never demultiplexed).
#
# Of the eight, only the four stream-oriented ones are worth muxing: the QUIC
# family already multiplexes natively, kcp-tun runs its own smux inside the
# tunnel, and mkcp/mekya are left alone rather than stacked.
#
# The payoff is not throughput — it is connection count. Iranian ISP QoS is
# reported to bite past roughly 4-8 concurrent connections to one IP, and each
# new connection is another first-two-packets event for the protocol whitelister
# to score. Folding many streams onto four connections cuts both.
_muxable_any() { local k; for k in $SELECTED; do _muxable "$k" && return 0; done; return 1; }

_muxable() {
  case "${K_BASE[$1]}" in vless|vmess|trojan|ss) : ;; *) return 1 ;; esac
  case "${K_XPORT[$1]}" in
    tcp|ws|grpc|xhttp|plain|obfs-http|obfs-tls) return 0 ;;
    *) return 1 ;;
  esac
}

# Listener half. The struct has exactly two fields — `padding` and `brutal` —
# there is no `enabled`, no protocol, no stream counts; the client picks the
# protocol and announces it, and the server obeys.
#
# The mux SERVICE is always active on the eight supported inbound types — there
# is no on/off switch — so this block is emitted only when it has something to
# say, i.e. when brutal is enabled.
#
# `padding: true` is deliberately NOT set here, even though padding is wanted.
# On the listener it is an ENFORCEMENT: sing-mux rejects every unpadded mux
# connection once the server sets it ("non-padded connection rejected"). The
# generated mihomo YAML pads, but a share link has no field that can express
# sing-mux padding and neither does the generated sing-box config, so enforcing
# it server-side turns "this client enabled mux" into a hard, silent failure for
# everyone outside this script's own YAML. Setting it CLIENT-side instead gets
# the padding onto the wire anyway — the server honours a padded connection
# whether or not it demands one — with no way to lock anybody out.
_mux_listener_block() {
  _muxable "$1" || return 0
  [[ $BRUTAL == yes ]] || return 0
  printf '    mux-option:\n      brutal:\n        enabled: true\n        up: "%s Mbps"\n        down: "%s Mbps"\n' \
    "$SRV_UP_MBPS" "$SRV_DOWN_MBPS"
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
      _xport_block "$key"; _sec_block "$key"; _mux_listener_block "$key" ;;
    vmess)
      printf '    users:\n      - username: %s\n        uuid: %s\n        alterId: 0\n' "$NODE_LABEL" "$UUID"
      _xport_block "$key"; _sec_block "$key"; _mux_listener_block "$key" ;;
    trojan)
      printf '    users:\n      - username: %s\n        password: %s\n' "$NODE_LABEL" "$PASSWORD"
      _xport_block "$key"; _sec_block "$key"; _mux_listener_block "$key" ;;
    anytls)
      printf '    users:\n      %s: %s\n    padding-scheme: ""\n' "$NODE_LABEL" "$PASSWORD"
      _sec_block "$key" ;;
    ss)
      printf '    password: %s\n    cipher: %s\n    udp: true\n' "$SS_PASSWORD" "$SS_METHOD"
      _xport_block "$key"; _sec_block "$key"; _mux_listener_block "$key" ;;
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

  # udp_mem is in PAGES and is meaningless as an absolute number: the kernel's
  # own default is derived from nr_free_buffer_pages, so a fixed triple either
  # starves a big host or over-commits a small one. 1/16, 1/8, 1/4 of RAM keeps
  # the same shape as the kernel's default with headroom for our own listeners,
  # floored so a tiny VPS still gets a workable budget.
  local _pages _um_min _um_pres _um_max udp_mem
  _pages="$(getconf _PHYS_PAGES 2>/dev/null || echo 0)"
  if [[ $_pages =~ ^[0-9]+$ ]] && (( _pages > 0 )); then
    _um_min=$(( _pages / 16 )); _um_pres=$(( _pages / 8 )); _um_max=$(( _pages / 4 ))
  else
    _um_min=0; _um_pres=0; _um_max=0
  fi
  (( _um_min  < 24576 )) && _um_min=24576      # 96 MiB
  (( _um_pres < 32768 )) && _um_pres=32768     # 128 MiB
  (( _um_max  < 49152 )) && _um_max=49152      # 192 MiB
  udp_mem="${_um_min} ${_um_pres} ${_um_max}"

  # TCP Brutal is not a mainline module. sing-mux asks for it per connection and
  # logs at debug when the setsockopt fails, so its absence is harmless — but
  # silently harmless, which is worth saying out loud when --brutal was asked for.
  if [[ $BRUTAL == yes ]]; then
    modprobe brutal >/dev/null 2>&1 || true
    if grep -qw brutal /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
      ok "TCP Brutal congestion control available."
    else
      warn "--brutal is set but the tcp_brutal kernel module is not present."
      warn "sing-mux will negotiate brutal and then silently fall back to the system CC."
    fi
  fi

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

# UDP memory accounting. rmem_max/wmem_max above are only per-socket CEILINGS;
# udp_mem is the SYSTEM-WIDE budget, in 4 KiB PAGES, shared by every UDP socket
# on the box. With mKCP, kcp-tun and three QUIC listeners each asking for
# multi-megabyte buffers — and the kernel charging double what a socket requests
# — the global pages are what runs out first, and the symptom is silent drops
# with nothing in any log. Derived from RAM rather than hard-coded so a 1 GB VPS
# is not handed a 4 GB ceiling it can never honour.
net.ipv4.udp_mem = ${udp_mem}
# Per-socket floors that survive a pressure event. The usual 16384 is about a
# millisecond of a 100 Mbps flow — far too little to keep a flow alive once the
# system-wide accounting tightens.
net.ipv4.udp_rmem_min = 262144
net.ipv4.udp_wmem_min = 262144

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
# 12a. Wire-amplification metering
#
# `check` answers "is the port bound", which is the wrong question for this
# deployment. The number that decides how many days an IP survives is
#
#     bytes actually put on the wire  /  bytes of payload delivered
#
# because the graylist that matters here is volume-driven — Iranian testers
# report blocks after roughly 40 GB in two hours, and under 100 GB cumulative on
# a normally-loaded node. Every retransmit, every FEC parity packet and every
# padding record is charged against that budget, so a transport running at 2x
# amplification is spending a third of the budget on nothing.
#
# Nothing in mihomo reports this: its own counters are payload. So the wire side
# is counted by the kernel (nftables byte counters on each listener port) and
# divided by mihomo's payload totals from the RESTful API.
#
# Chain priority -300 puts these counters ahead of any filter/NAT rules, so they
# see traffic the firewall may later drop — which is what you want, since a
# dropped packet still crossed the wire and still counts.
# -----------------------------------------------------------------------------
readonly METER_TABLE="mihomo_meter"
readonly METER_BASE="${STATE_DIR}/meter.base"

_meter_available() { have nft; }

setup_metering() {
  [[ $METERING == yes ]] || { log "Wire-amplification metering skipped."; return 0; }
  if ! _meter_available; then
    apt-get install -y -qq nftables >/dev/null 2>&1 || true
  fi
  if ! _meter_available; then
    warn "nft not available; \`mihomoctl amplification\` will have no wire counters."
    return 0
  fi
  head1 "Wire-amplification counters"

  local key p l4 counters="" inrules="" outrules="" n=0
  for key in $SELECTED; do
    p="${PORT[$key]:-}"; [[ -n $p ]] || continue
    l4="$(proto_l4 "$key")"
    case "$l4" in
      udp|both)
        counters+="  counter u${p}_in { }"$'\n'"  counter u${p}_out { }"$'\n'
        inrules+="    udp dport ${p} counter name u${p}_in"$'\n'
        outrules+="    udp sport ${p} counter name u${p}_out"$'\n'
        n=$((n+1)) ;;
    esac
    case "$l4" in
      tcp|both)
        counters+="  counter t${p}_in { }"$'\n'"  counter t${p}_out { }"$'\n'
        inrules+="    tcp dport ${p} counter name t${p}_in"$'\n'
        outrules+="    tcp sport ${p} counter name t${p}_out"$'\n'
        n=$((n+1)) ;;
    esac
  done
  (( n > 0 )) || { log "No listener ports to meter."; return 0; }

  nft delete table inet "$METER_TABLE" >/dev/null 2>&1 || true
  if ! nft -f - <<EOF >/dev/null 2>&1
table inet ${METER_TABLE} {
${counters}  chain meter_in {
    type filter hook input priority -300; policy accept;
${inrules}  }
  chain meter_out {
    type filter hook output priority -300; policy accept;
${outrules}  }
}
EOF
  then
    warn "nftables rejected the counter table; metering disabled for this run."
    return 0
  fi
  ok "Metering ${n} counter pair(s); read them with \`mihomoctl amplification\`."
  return 0
}

# mihomo's totals are cumulative since the process started, and the nft counters
# are cumulative since they were created. A ratio between two differently-based
# running totals is meaningless, so the API totals are snapshotted whenever the
# counters are zeroed and the delta is what gets divided.
_api_totals() {   # -> "<up> <down>" or empty
  local host secret out
  [[ -n $API_LISTEN ]] || return 1
  host="$API_LISTEN"; [[ $host == :* ]] && host="127.0.0.1${host}"
  out="$(curl -fsS --max-time 4 -H "Authorization: Bearer ${API_SECRET}" \
        "http://${host}/connections" 2>/dev/null || true)"
  [[ -n $out ]] || return 1
  printf '%s' "$out" | jq -r '"\(.uploadTotal // 0) \(.downloadTotal // 0)"' 2>/dev/null
}

_meter_baseline() {
  local t; t="$(_api_totals || true)"
  install -d -m 0700 "$STATE_DIR"
  { printf '%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"; printf '%s\n' "${t:-0 0}"; } >"$METER_BASE"
  chmod 0600 "$METER_BASE"
  return 0
}

_human() {  # bytes -> human
  local b=$1
  if   (( b >= 1099511627776 )); then printf '%d.%02d TiB' $(( b / 1099511627776 )) $(( b % 1099511627776 * 100 / 1099511627776 ))
  elif (( b >= 1073741824 ));    then printf '%d.%02d GiB' $(( b / 1073741824 ))    $(( b % 1073741824 * 100 / 1073741824 ))
  elif (( b >= 1048576 ));       then printf '%d.%02d MiB' $(( b / 1048576 ))       $(( b % 1048576 * 100 / 1048576 ))
  elif (( b >= 1024 ));          then printf '%d.%02d KiB' $(( b / 1024 ))          $(( b % 1024 * 100 / 1024 ))
  else printf '%d B' "$b"; fi
}

do_amplification() {
  if [[ ${1:-} == --reset ]]; then
    _meter_available || die "nft is not installed; nothing to reset."
    nft reset counters table inet "$METER_TABLE" >/dev/null 2>&1 \
      || die "No counter table — run a deploy, or 'mihomoctl check' to confirm setup."
    _meter_baseline
    ok "Counters zeroed and the payload baseline re-snapshotted."
    return 0
  fi

  _meter_available || die "nft is not installed, so there are no wire counters to read."
  local js; js="$(nft -j list counters table inet "$METER_TABLE" 2>/dev/null || true)"
  [[ -n $js ]] || die "No counter table found. Re-run a deploy, or drop --no-metering."

  head1 "Wire bytes per listener port"
  printf '  %-30s %-6s %14s %14s\n' "key" "l4" "in" "out"
  local key p l4 cin cout wire_in=0 wire_out=0 v
  for key in $SELECTED; do
    p="${PORT[$key]:-}"; [[ -n $p ]] || continue
    l4="$(proto_l4 "$key")"
    local pfx; case "$l4" in udp) pfx=u ;; tcp) pfx=t ;; both) pfx=both ;; *) continue ;; esac
    if [[ $pfx == both ]]; then
      cin=$(( $(_ctr "$js" "t${p}_in")  + $(_ctr "$js" "u${p}_in")  ))
      cout=$(( $(_ctr "$js" "t${p}_out") + $(_ctr "$js" "u${p}_out") ))
    else
      cin="$(_ctr "$js" "${pfx}${p}_in")"; cout="$(_ctr "$js" "${pfx}${p}_out")"
    fi
    wire_in=$(( wire_in + cin )); wire_out=$(( wire_out + cout ))
    (( cin == 0 && cout == 0 )) && continue
    printf '  %-30s %-6s %14s %14s\n' "$key" "$l4" "$(_human "$cin")" "$(_human "$cout")"
  done
  hr
  local wire=$(( wire_in + wire_out ))
  printf '  %-30s %s\n' "wire total (in+out)" "$(_human "$wire")"

  # Payload delta against the baseline taken when the counters were last zeroed.
  local base_up=0 base_dn=0 since="unknown" now up=0 dn=0
  if [[ -r $METER_BASE ]]; then
    since="$(sed -n 1p "$METER_BASE")"
    # `|| ...` because `read` returns non-zero at EOF, so a truncated or empty
    # baseline would abort the whole command under `set -e` instead of just
    # losing the payload half of the report.
    read -r base_up base_dn < <(sed -n 2p "$METER_BASE") || { base_up=0; base_dn=0; }
    [[ -n $since ]] || since="unknown"
  fi
  now="$(_api_totals || true)"
  if [[ -n $now ]]; then
    read -r up dn <<<"$now"
    # mihomo restarting resets its own totals below the baseline; treat that as
    # "the baseline is stale" rather than printing a negative payload.
    local stale=no
    if (( up < base_up || dn < base_dn )); then
      # mihomo's totals are cumulative per PROCESS. If they have gone backwards
      # the process restarted, and the wire counters — which did not — now cover
      # a strictly longer window. Dividing the two would understate amplification
      # by an unknown factor, so the ratio is withheld rather than guessed at.
      stale=yes
    else
      up=$(( up - base_up )); dn=$(( dn - base_dn ))
    fi
    local payload=$(( up + dn ))
    if [[ $stale == yes ]]; then
      printf '  %-30s %s  (raw total — baseline is stale)\n' "payload delivered" "$(_human "$payload")"
    else
      printf '  %-30s %s\n' "payload delivered" "$(_human "$payload")"
    fi
    printf '  %-30s %s\n' "measuring since" "$since"
    if [[ $stale == yes ]]; then
      warn "mihomo's payload counters restarted since the baseline, so the two sides"
      warn "cover different windows and the ratio would be meaningless."
      warn "Re-base both with: mihomoctl amplification --reset"
    elif (( payload > 0 )); then
      hr
      printf '  %-30s %d.%02dx\n' "AMPLIFICATION" $(( wire / payload )) $(( wire % payload * 100 / payload ))
      echo
      echo "  Below ~1.15x is normal overhead. Above ~1.5x something is paying for"
      echo "  itself in retransmits or FEC — the usual causes are congestion: false"
      echo "  on a lossy mkcp node and a parityshard ratio larger than the path"
      echo "  needs. Compare the per-port rows above against their variants:"
      echo "  vmess-mkcp vs vmess-mkcp-nocong, ss-kcptun vs ss-kcptun-fec."
    else
      warn "mihomo reports no payload since the baseline; ratio not computed."
    fi
  else
    warn "Could not read mihomo's API (${API_LISTEN:-disabled}); wire bytes only."
  fi

  # The budget that actually decides how long the IP lives.
  hr
  local hrs=0
  if [[ $since != unknown ]] && have date; then
    local t0 t1; t0="$(date -u -d "$since" +%s 2>/dev/null || echo 0)"; t1="$(date -u +%s)"
    (( t0 > 0 )) && hrs=$(( (t1 - t0 + 1799) / 3600 ))
  fi
  if (( hrs > 0 )); then
    # Integer division on GiB rounds a 900 MiB/h node to "0 GiB/h", which reads
    # as "nothing is happening" — divide first, humanise second.
    local gbh
    gbh=$(( wire / hrs ))
    printf '  %-30s ~%s/h over %d h\n' "wire rate" "$(_human "$gbh")" "$hrs"
    gbh=$(( gbh / 1073741824 ))
    if (( gbh >= 15 )); then
      warn "At/above the ~15-20 GiB/h band where volume graylisting has been reported."
      warn "Shard users across more IPs rather than tuning — this is a detection limit, not a capacity one."
    fi
  fi
  return 0
}

# Measure the largest UDP datagram that survives to a target, by binary search
# on the don't-fragment bit.
#
# This exists because the sysctl drop-in sets net.ipv4.tcp_mtu_probing=1 and
# nothing at all measures the UDP path — and a KCP packet that fragments is lost
# outright when either fragment is dropped, so an over-large --kcp-mtu is a
# latency and loss problem, not an efficiency one.
#
# Two honest limitations, stated up front rather than buried:
#   * It measures THIS server's path to the target. Run it against a real client
#     address to learn something about a real client's path; run it against
#     anything else and you have measured a different path.
#   * It probes with ICMP, and ICMP is heavily filtered on exactly the networks
#     this matters for. A failure at every size means "no answer", not "MTU is
#     tiny" — which is also why PMTU discovery cannot be relied on there and why
#     the default is a conservative constant instead of a discovered value.
#
# ICMP payload P puts P+28 bytes on the wire (8 ICMP + 20 IP). A UDP datagram
# carrying a KCP packet of `mtu` bytes puts mtu+28 on the wire (8 UDP + 20 IP).
# The overheads match, so the largest working P is directly the largest safe
# --kcp-mtu.
do_pmtu() {
  local target=${1:-}
  [[ -n $target ]] || die "usage: mihomoctl pmtu <client-ip-or-host>"
  have ping || die "ping is not installed."
  head1 "UDP path MTU probe -> ${target}"

  local lo=500 hi=1472 mid best=0
  # Confirm the target answers at all before reading silence as a small MTU.
  if ! ping -c 2 -W 2 -n "$target" >/dev/null 2>&1; then
    bad "${target} does not answer ICMP at all — this probe cannot tell you anything."
    bad "That is itself common on Iranian carriers; keep the conservative --kcp-mtu default."
    return 1
  fi
  while (( lo <= hi )); do
    mid=$(( (lo + hi) / 2 ))
    if ping -c 1 -W 2 -n -M do -s "$mid" "$target" >/dev/null 2>&1; then
      best=$mid; lo=$(( mid + 1 ))
    else
      hi=$(( mid - 1 ))
    fi
  done

  if (( best == 0 )); then
    bad "No DF-bit probe got through at any size; the path drops them or filters the reply."
    return 1
  fi
  ok "Largest unfragmented payload: ${best} bytes  (path MTU $(( best + 28 )))"
  printf '  %-30s %s\n' "safe --kcp-mtu" "$best"
  printf '  %-30s %s\n' "currently configured"  "$KCP_MTU"
  if (( KCP_MTU > best )); then
    warn "--kcp-mtu ${KCP_MTU} exceeds this path's ${best}: every KCP packet fragments,"
    warn "and losing either fragment loses the whole packet. Re-deploy with --kcp-mtu ${best}."
  else
    ok "The configured --kcp-mtu fits this path with $(( best - KCP_MTU )) bytes to spare."
  fi
  return 0
}

# Pull one counter's byte total out of `nft -j list counters` output.
_ctr() {
  local js=$1 name=$2 v
  v="$(printf '%s' "$js" | jq -r --arg n "$name" \
        '[.nftables[]?.counter? | select(.name == $n) | .bytes] | first // 0' 2>/dev/null || echo 0)"
  [[ $v =~ ^[0-9]+$ ]] || v=0
  printf '%s' "$v"
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
# ALPN a given transport should advertise, for the share links and the sing-box
# config. WebSocket speaks HTTP/1.1 only, so advertising h2 there invites a
# client or CDN to break the Upgrade handshake.
#
# Everything else gets the BROWSER'S list rather than the transport-minimal one.
# gRPC and XHTTP need h2 and used to say so alone, but a lone `h2` is a list no
# browser sends, and the server still selects h2 from ["h2","http/1.1"] by
# preference order — so the minimal form bought nothing and cost a distinguisher.
# Keeping this in step with _cli_alpn also means one node no longer advertises
# three different ALPN lists depending on which artefact the user imported.
_alpn_of() {
  case "${K_XPORT[$1]}" in
    ws) echo "http/1.1" ;;
    *)  echo "h2,http/1.1" ;;
  esac
}

# The SNI a client must present: the decoy for the borrowed-identity layers,
# your own domain for a real certificate.
# The decoy's negotiated ALPN as an inline YAML flow list: ["h2","http/1.1"].
# Used by the shadowsocks and snell plugin paths, whose alpn key sits inside a
# flow mapping rather than a block one.
_alpn_yaml_inline() {
  local a out=() IFS=','
  for a in $DECOY_ALPN; do out+=("\"$a\""); done
  IFS=','; printf '%s' "${out[*]}"
}

# ALPN for a client proxy entry.
#
# The review this implements asked for `alpn:` on every node, on the grounds that
# the YAML advertises none while the share links do. Reading the source says the
# premise is wrong, and the correction matters more than the fix:
#
#   EVERY node here sets `client-fingerprint: chrome`, so the ClientHello is
#   built by uTLS from the Chrome parrot template — and that template's ALPN
#   extension is what goes on the wire. mihomo proves this itself: the only way
#   it can force http/1.1 for WebSocket is BuildWebsocketHandshakeState, which
#   walks conn.Extensions and rewrites the ALPNExtension by hand after the
#   handshake state is built. If NextProtos were enough, that function would not
#   need to exist. So these nodes were never advertising "no ALPN" — they were
#   advertising Chrome's, which is what you want.
#
# What `alpn:` actually reaches, per transport/vmess/tls.go:
#   REALITY    — nothing. GetRealityConn is called without the tls.Config at all.
#   ShadowTLS  — already defaults to exactly ["h2","http/1.1"] when unset.
#   JLS        — the proxy-level alpn IS passed to jls.NewClient, and a non-nil
#                value calls overrideUTLSALPN, which rewrites the ALPN extension
#                inside an otherwise pristine Chrome ClientHello AND drops the
#                ApplicationSettings extension when h2 is absent. Setting it can
#                only make the fingerprint worse; leaving it unset keeps
#                Chrome's own list. JLS nodes therefore get nothing.
#   tls/restls — reaches NextProtos, which the non-uTLS path and RestLS's own
#                config do consume.
#
# So the value emitted is the BROWSER'S list, not `_alpn_of`'s transport-minimal
# one: `h2` alone would be a novel fingerprint if it ever did reach the wire,
# while ["h2","http/1.1"] is what the template sends anyway and the server still
# selects h2 for grpc/xhttp by preference order. WebSocket is the one exception —
# an h2 selection there breaks the Upgrade, and http/1.1 alone is what mihomo
# forces on that path regardless.
#
# Net effect: on a client-fingerprint node this is a no-op that documents intent;
# on a node with the fingerprint disabled it is the correct value. It is never a
# new signature, which is the only property that mattered.
_cli_alpn() {
  case "${K_SEC[$1]}" in
    tls|restls) : ;;
    *) return 0 ;;
  esac
  case "${K_XPORT[$1]}" in
    mkcp|mekya) return 0 ;;   # no TLS layer / mekya forces its own
    ws)         printf '    alpn:\n      - http/1.1\n' ;;
    *)          printf '    alpn:\n      - h2\n      - http/1.1\n' ;;
  esac
  return 0
}

_cli_sni() {
  case "${K_SEC[$1]}" in
    reality)                        printf '%s' "$REALITY_SNI" ;;
    shadowtls|restls|jls|tlsmirror) _decoy_sni ;;
    *)                              printf '%s' "$VPN_DOMAIN" ;;
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
      _cli_alpn "$key"
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
      # version-hint is CLIENT-ONLY and has NO default: NewRestlsConfig rejects
      # anything but tls12/tls13, so an absent value is a hard error rather than
      # a fallback. It must describe what `dest` really negotiates, which is why
      # probe_decoy measures it instead of hard-coding tls13.
      printf '    tls: true\n    servername: %s\n' "$sni"
      # Called outside the heredoc: command substitution strips trailing
      # newlines, so $(...) inside one silently joins the next key onto the
      # last emitted line and produces YAML that parses as something else.
      _cli_alpn "$key"
      cat <<EOF
    restls-opts:
      password: "${RESTLS_PASSWORD}"
      version-hint: ${RESTLS_VERSION_HINT}
      restls-script: "${RESTLS_SCRIPT_C}"
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
      # The mirror image of the server block: seed / header / mtu / tti are
      # copied verbatim because they must match, and the capacities and buffers
      # are SWAPPED because they describe this side's link, not the server's.
      # `uplink-capacity: 12` on a handset — the value both sides used to carry —
      # is roughly 630 KB in flight upward, which on a real Iranian uplink is
      # several seconds of queue that every DNS lookup then waits behind.
      local dp up
      dp="$(_pkts_down)"; up="$(_pkts_up)"
      cat <<EOF
    network: mkcp
    mkcp-opts:
      seed: ${MKCP_SEED}
      header: $(_mkcp_header_of "$key")
      mtu: ${KCP_MTU}
      tti: ${MKCP_TTI}
      uplink-capacity: $(_mkcp_cap "$up")
      downlink-capacity: $(_mkcp_cap "$dp")
      congestion: $(_mkcp_cong_of "$key")
      write-buffer: $(_kcp_buf "$up")
      read-buffer: $(_kcp_buf "$dp")
EOF
      ;;
    mekya)
      local dp up
      dp="$(_pkts_down)"; up="$(_pkts_up)"
      cat <<EOF
    network: mekya
    mekya-opts:
      url: https://${VPN_DOMAIN}/mekya
      max-write-size: 10485760
      max-write-duration-ms: 500
      max-simultaneous-write-connection: 128
      packet-writing-buffer: 65536
      kcp:
        mtu: ${KCP_MTU}
        tti: ${MKCP_TTI}
        uplink-capacity: $(_mkcp_cap "$up")
        downlink-capacity: $(_mkcp_cap "$dp")
        congestion: true
        write-buffer: $(_kcp_buf "$up")
        read-buffer: $(_kcp_buf "$dp")
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
      _cli_alpn "$key"
      case "${K_SEC[$key]}" in
        reality)   printf '    reality-opts:\n      public-key: %s\n      short-id: %s\n' "$REALITY_PUBLIC" "$REALITY_SHORTID" ;;
        shadowtls) printf '    shadow-tls-opts:\n      version: 3\n      password: "%s"\n' "$SHADOWTLS_PASSWORD" ;;
        restls)    printf '    restls-opts:\n      password: "%s"\n      version-hint: %s\n      restls-script: "%s"\n' \
                     "$RESTLS_PASSWORD" "$RESTLS_VERSION_HINT" "$RESTLS_SCRIPT_C" ;;
        jls)       printf '    jls-opts:\n      username: %s\n      password: "%s"\n' "$JLS_USER" "$JLS_PASSWORD" ;;
        tls)       [[ $CERT_MODE == self && -n $CERT_PIN ]] && printf '    fingerprint: %s\n' "$CERT_PIN" ;;
      esac ;;
    anytls)
      printf '    password: "%s"\n    udp: true\n    client-fingerprint: chrome\n    sni: %s\n    skip-cert-verify: %s\n' \
        "$PASSWORD" "$(_cli_sni "$key")" "$sci"
      _cli_alpn "$key"
      case "${K_SEC[$key]}" in
        shadowtls) printf '    shadow-tls-opts:\n      version: 3\n      password: "%s"\n' "$SHADOWTLS_PASSWORD" ;;
        restls)    printf '    restls-opts:\n      password: "%s"\n      version-hint: %s\n      restls-script: "%s"\n' \
                     "$RESTLS_PASSWORD" "$RESTLS_VERSION_HINT" "$RESTLS_SCRIPT_C" ;;
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
          # Windows are the inverse of the listener's, and conn/autoexpire/
          # scavengettl appear ONLY here because only the client half acts on
          # them.  Enabling kcptun also forces udp-over-tcp on this outbound and
          # makes the listener UDP-only, both by construction upstream.
          local _dp _up _n
          _n="$(_kcptun_conn_of "$key")"
          _dp="$(_kcp_wnd "$(_per_conn "$(_pkts_down)" "$_n")")"
          _up="$(_kcp_wnd "$(_per_conn "$(_pkts_up)" "$_n")")"
          printf '    plugin: kcptun\n    plugin-opts:\n'
          printf '      key: "%s"\n      crypt: aes-128\n      mode: %s\n      mtu: %s\n' \
            "$KCPTUN_KEY" "$(_kcptun_mode_of "$key")" "$KCP_MTU"
          printf '      sndwnd: %s\n      rcvwnd: %s\n' "$_up" "$_dp"
          printf '      datashard: %s\n      parityshard: %s\n      nocomp: true\n' \
            "$(_kcptun_ds_of "$key")" "$(_kcptun_ps_of "$key")"
          printf '      ratelimit: %s\n' "$(( $(_rate_up) / _n ))"
          printf '      sockbuf: 8388608\n      smuxver: 2\n      smuxbuf: 8388608\n      streambuf: 2097152\n'
          # keepalive under the 60 s idle window Iran's protocol whitelister
          # keeps per flow — a flow that goes quiet for longer is re-evaluated.
          printf '      keepalive: 10\n      dscp: 0\n'
          if _kcptun_rotates "$key"; then
            printf '      conn: %s\n      autoexpire: 25\n      scavengettl: 20\n' "$_n"
          fi ;;
        *:shadowtls)
          printf '    plugin: shadow-tls\n    plugin-opts:\n      host: %s\n      password: "%s"\n      version: 3\n      alpn: [%s]\n' \
            "$(_decoy_sni)" "$SHADOWTLS_PASSWORD" "$(_alpn_yaml_inline)" ;;
        *:restls)
          printf '    plugin: restls\n    plugin-opts:\n      host: %s\n      password: "%s"\n      version-hint: %s\n      restls-script: "%s"\n' \
            "$(_decoy_sni)" "$RESTLS_PASSWORD" "$RESTLS_VERSION_HINT" "$RESTLS_SCRIPT_C" ;;
        *:jls)
          # Unlike jls-opts on vless/vmess/trojan, the shadowsocks jls plugin
          # DOES take alpn, and it is the only ALPN this outbound has.
          printf '    plugin: jls\n    plugin-opts:\n      host: %s\n      username: %s\n      password: "%s"\n      alpn: [%s]\n' \
            "$(_decoy_sni)" "$JLS_USER" "$JLS_PASSWORD" "$(_alpn_yaml_inline)" ;;
      esac ;;
    snell)
      printf '    psk: "%s"\n    version: %s\n    udp: true\n    client-fingerprint: chrome\n' "$SNELL_PSK" "$SNELL_VERSION"
      # Snell packs obfuscation AND its security layers into one obfs-opts map.
      case "${K_XPORT[$key]}:${K_SEC[$key]}" in
        obfs-http:*|obfs-tls:*)
          printf '    obfs-opts:\n      mode: %s\n      host: %s\n' "${K_XPORT[$key]#obfs-}" "$OBFS_HOST" ;;
        *:shadowtls)
          printf '    obfs-opts:\n      mode: shadow-tls\n      host: %s\n      password: "%s"\n      version: 3\n      alpn: [%s]\n' \
            "$(_decoy_sni)" "$SHADOWTLS_PASSWORD" "$(_alpn_yaml_inline)" ;;
        *:restls)
          printf '    obfs-opts:\n      mode: restls\n      host: %s\n      password: "%s"\n      version-hint: %s\n      restls-script: "%s"\n' \
            "$(_decoy_sni)" "$RESTLS_PASSWORD" "$RESTLS_VERSION_HINT" "$RESTLS_SCRIPT_C" ;;
        *:jls)
          printf '    obfs-opts:\n      mode: jls\n      host: %s\n      username: %s\n      password: "%s"\n      alpn: [%s]\n' \
            "$(_decoy_sni)" "$JLS_USER" "$JLS_PASSWORD" "$(_alpn_yaml_inline)" ;;
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
  _cli_mux "$key"
  return 0
}

# Client half of sing-mux. `smux` is not part of any proxy's option struct — the
# parser reads mapping["smux"] separately and wraps whatever adapter it just
# built — so it is a top-level key on the proxy entry and valid on every type.
# That also means a typo in here is silently ignored rather than rejected.
#
# protocol must be one of "", h2mux, smux, yamux; anything else is a hard error
# at config load. It is negotiated, not agreed in advance: the client announces
# its choice in the mux request and the server follows, which is why the
# listener block has no protocol key.
_cli_mux() {
  _muxable "$1" || return 0
  cat <<EOF
    smux:
      enabled: true
      protocol: h2mux
      padding: true
      max-connections: 4
      min-streams: 4
      statistic: false
EOF
  # Brutal is a fixed-rate sender that ignores loss by design. The rates below
  # are negotiated down to min(peer's receive rate, own send rate), so they must
  # be MEASURED — an inflated number does not go faster, it retransmits into a
  # policer and produces exactly the burst that gets a flow killed here.
  if [[ $BRUTAL == yes ]]; then
    printf '      brutal-opts:\n        enabled: true\n        up: "%s Mbps"\n        down: "%s Mbps"\n' \
      "$CLI_UP_MBPS" "$CLI_DOWN_MBPS"
  fi
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
# silent: mihomo keeps no log ring buffer and does no per-connection formatting.
# This is the single biggest cut to a client's steady-state memory use.
log-level: silent
# The networks this deployment targets are IPv4-only; advertising IPv6 makes
# every dual-stack dial wait out a dead AAAA path before falling back.
ipv6: false
unified-delay: true
# tcp-concurrent races one dial per resolved address and keeps them all alive
# until the first wins. On mobile clients that multiplies sockets and FDs for
# no gain when the node is a single pinned IPv4 address.
tcp-concurrent: false
find-process-mode: off
external-controller: 127.0.0.1:9090
EOF
    # DNS is the one part of a client config that can break EVERY node at once,
    # and it does so on exactly the networks this deployment exists for.
    #
    #  * `hosts:` pins this node's name to its address, so opening the tunnel
    #    needs no DNS at all. Without it the client must resolve the domain
    #    before it can dial anything, and if that lookup is blocked then all
    #    ${#ALL_KEYS[@]} nodes fail identically — which reads like a dead server.
    #  * The resolvers are plain UDP :53 and carry NO '#PROXY' fragment. A
    #    '#PROXY' resolver makes mihomo route every lookup through the tunnel,
    #    which means the proxy group must already be up before DNS can answer —
    #    on a slow or flapping node that stalls, queues queries and has been the
    #    source of client hangs and OOM kills. Plain resolvers answer locally.
    #  * DoH/DoT are deliberately not used: they add a TLS session per resolver
    #    and fail closed on networks that block :443 to public resolvers.
    #  * `proxy-server-nameserver` resolves proxy hostnames only, for the case
    #    where someone strips the hosts: entry.
    if valid_ipv4 "$VPN_IP"; then
      printf 'hosts:\n  %s: %s\n' "$VPN_DOMAIN" "$VPN_IP"
    fi
    cat <<'EOF'
dns:
  enable: true
  ipv6: false
  prefer-h3: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '+.lan'
    - '+.local'
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 9.9.9.9
  proxy-server-nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 9.9.9.9
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 9.9.9.9
proxies:
EOF
  } >"$f"
  for key in $SELECTED; do
    if mihomo_of "$key" >>"$f" 2>/dev/null; then names+=("$(node_name "$key")"); fi
  done
  {
    # Two automatic groups, because they fail over on different principles and
    # this network kills flows on a timescale neither one alone covers.
    #
    #   AUTO     url-test — picks the lowest latency of everything alive. Best
    #            steady-state choice, but it memoises its pick in a singleflight
    #            with a 10-SECOND result TTL, so it can keep handing out a node
    #            the health checker has already buried for up to 10 s.
    #   FAILOVER fallback — takes the first node in list order that is alive and
    #            moves on the moment it is not. No latency optimisation, no
    #            10 s cache. This is the one to select when nodes are dying.
    #
    # interval is SECONDS (default 300 — five minutes of a dead node selected,
    # against measured flow kills at 7-35 s), tolerance is MILLISECONDS, and
    # timeout is MILLISECONDS. Note that timeout does double duty: it is both
    # the per-probe deadline AND the window in which max-failed-times failures
    # have to occur, so shortening it also shortens that window — hence the
    # matching drop in max-failed-times.
    #
    # lazy defaults to TRUE, which skips a tick whenever the group has not been
    # dialled through within the last interval. Note what that does and does not
    # mean: the group you have SELECTED is being dialled through, so it probes on
    # every tick regardless. lazy only decides whether the group you are NOT
    # using stays warm.
    #
    # So lazy:false is set on FAILOVER alone. That keeps the escape hatch warm
    # for the moment a node dies, and costs one probe per node per interval —
    # setting it on both groups would double the probe traffic to buy nothing,
    # because the two groups have separate health checkers and do not share
    # results. With the full catalogue that difference is ~80 extra dials a
    # minute to one IP across ~80 ports, which is a port-scan-shaped pattern and
    # the opposite of what the multiplexing above is for.
    #
    # The test URL is Cloudflare's rather than gstatic's: ten clients probing
    # the same Google endpoint on the same schedule is both rate-limited and a
    # pattern. expected-status pins it to 204 so a captive portal's 200 does not
    # read as success.
    local _url="http://cp.cloudflare.com/generate_204"
    echo "proxy-groups:"
    echo "  - name: PROXY"
    echo "    type: select"
    echo "    proxies:"
    echo "      - AUTO"
    echo "      - FAILOVER"
    for n in "${names[@]}"; do echo "      - \"$n\""; done
    echo "      - DIRECT"
    echo "  - name: AUTO"
    echo "    type: url-test"
    echo "    url: ${_url}"
    echo "    interval: ${PROBE_INTERVAL}"
    echo "    timeout: ${PROBE_TIMEOUT}"
    echo "    tolerance: 30"
    echo "    max-failed-times: 2"
    echo "    expected-status: '204'"
    echo "    proxies:"
    for n in "${names[@]}"; do echo "      - \"$n\""; done
    echo "  - name: FAILOVER"
    echo "    type: fallback"
    echo "    url: ${_url}"
    echo "    interval: ${PROBE_INTERVAL}"
    echo "    timeout: ${PROBE_TIMEOUT}"
    echo "    lazy: false"
    echo "    max-failed-times: 2"
    echo "    expected-status: '204'"
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
    if _decoy_local; then
      echo "  ShadowTLS/RestLS/JLS         127.0.0.1:${DECOY_PORT}  (local nginx, serving ${VPN_DOMAIN})"
      echo "    Clients present servername ${VPN_DOMAIN}, which is this IP's real"
      echo "    certificate — no SNI/IP disagreement to score, and RestLS no longer"
      echo "    pays a round trip to a third party on every connection."
      echo "    Nothing external is required for the disguise to hold."
    else
      echo "  ShadowTLS/RestLS/JLS/mirror  ${STEAL_SNI}:443"
      echo "    Clients present servername ${STEAL_SNI} to an IP that is not theirs."
      echo "    --decoy local removes both that disagreement and the per-connection"
      echo "    round trip RestLS pays to reach this host — at the cost of putting"
      echo "    every camouflage layer behind ONE name of yours, which a single"
      echo "    blocklist entry can take out. It is a different bet, not a free win."
    fi
    echo "  Hysteria2 masquerade         https://${STEAL_SNI}"
    echo "  An unauthenticated prober is proxied to those targets verbatim; if the"
    echo "  server cannot reach them, the disguise fails open and looks anomalous."
    echo
    echo "TRANSPORT TUNING (the numbers every window in these files derives from)"
    echo "  client link          ${CLI_DOWN_MBPS} Mbit/s down, ${CLI_UP_MBPS} Mbit/s up"
    echo "  server link          ${SRV_UP_MBPS} Mbit/s up, ${SRV_DOWN_MBPS} Mbit/s down"
    echo "  path                 ${PATH_RTT_MS} ms RTT, ~${PATH_LOSS_PCT}% loss assumed"
    echo "  KCP framing          mtu ${KCP_MTU}, tti ${MKCP_TTI} ms"
    echo "  windows              $(_pkts_down) packets in flight down, $(_pkts_up) up"
    echo
    echo "  mKCP and kcp-tun size their windows from the link of the side that"
    echo "  writes the number, so the two ends carry DIFFERENT values on purpose:"
    echo "  the server's uplink-capacity governs your download, the client's"
    echo "  governs your upload. Only seed/header/mtu/tti (mKCP) and"
    echo "  key/crypt/mode/mtu/datashard/parityshard/nocomp (kcp-tun) must match."
    echo "  If your real link differs from the numbers above, re-run with"
    echo "  --client-down-mbps / --client-up-mbps / --rtt-ms rather than editing"
    echo "  the YAML — every buffer is derived and they have to stay consistent."
    echo
    echo "  Variants exist so you can measure instead of guess. Same protocol,"
    echo "  one parameter changed, its own port:"
    echo "    vmess-mkcp / -dtls / -wechat / -utp    packet header disguise"
    echo "    vmess-mkcp-nocong                      congestion control off"
    echo "    ss-kcptun / -static                    source-port rotation on/off"
    echo "    ss-kcptun-fec                          FEC 10/3 instead of 10/1"
    echo "    ss-kcptun-fast3                        lower latency, higher packet rate"
    echo "  Note FEC cannot be switched off: mihomo rewrites datashard/parityshard"
    echo "  0 to 10/3, so 10/1 is the lowest overhead reachable."
    echo
    echo "  \`mihomoctl amplification\` reports wire bytes over payload bytes per"
    echo "  port. That ratio, not throughput, is what decides how long this IP"
    echo "  survives — volume graylisting has been reported at roughly 40 GB in"
    echo "  two hours. Compare a variant against its baseline there."
    echo
    if _sec_used restls; then
      echo "RESTLS RECORD PROGRAMME (per deployment — do not share it between nodes)"
      echo "  server->client  ${RESTLS_SCRIPT_S}"
      echo "  client->server  ${RESTLS_SCRIPT_C}"
      echo "  Both halves fall back to one built-in default string when unset, so"
      echo "  every untouched RestLS deployment emits the same record-length"
      echo "  sequence. These two were generated for this node; if you deploy a"
      echo "  second node, let it generate its own."
      echo
    fi
    if _muxable_any; then
      echo "MULTIPLEXING"
      echo "  vless / vmess / trojan / shadowsocks nodes carry sing-mux. The point is"
      echo "  connection COUNT, not throughput: ISP QoS bites past roughly 4-8"
      echo "  concurrent connections to one IP, and each new connection is another"
      echo "  first-two-packets event for a protocol whitelister to score."
      echo "  Padding is set client-side only. On a listener it is an ENFORCEMENT"
      echo "  that rejects any unpadded mux connection, which would lock out every"
      echo "  client that cannot express it — share links and sing-box configs have"
      echo "  no field for it. Client-side padding puts the same bytes on the wire."
      if [[ $BRUTAL == yes ]]; then
        echo "  TCP Brutal is ON at ${CLI_UP_MBPS}/${CLI_DOWN_MBPS} Mbit/s up/down. It is a fixed-rate"
        echo "  sender that ignores loss by design; if flows start dying under load,"
        echo "  turn it off first."
      fi
      echo
    fi
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
    [[ -n $KCPTUN_KEY ]]         && echo "  kcp-tun key         : ${KCPTUN_KEY}  (its own secret, not shared)"
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
  # Count what actually landed in the YAML, not the listener count: a listener
  # that is not a client-dialable proxy (the realm rendezvous server) is deployed
  # but has no proxies: entry, so selected_count would overstate this by one.
  local _y=0
  for key in $SELECTED; do mihomo_of "$key" >/dev/null 2>&1 && _y=$((_y+1)); done
  ok "Bundles written to ${CLIENT_OUT_DIR}  (${#links[@]} share link(s), ${_y} YAML node(s))"
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
  printf '    %s\n' "mihomoctl amplification  # wire bytes vs payload, per port"
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
    if systemctl is-active --quiet mihomo; then
      ok "mihomo updated and restarted."
      # The restart zeroed mihomo's payload counters but not the kernel's wire
      # counters, so the two sides would cover different windows from here on and
      # every later amplification ratio would read low. Re-base both.
      if [[ $METERING == yes ]] && _meter_available && nft list table inet "$METER_TABLE" >/dev/null 2>&1; then
        nft reset counters table inet "$METER_TABLE" >/dev/null 2>&1 || true
        _meter_baseline
        log "Wire-amplification counters re-based after the restart."
      fi
    else
      bad "mihomo did not come back up."
    fi
  else
    warn "Existing config missing or invalid for the new version; not restarting."
  fi
  save_state
  return 0
}

_uninstall_extras() {
  if have nft; then nft delete table inet "$METER_TABLE" >/dev/null 2>&1 || true; fi
  rm -f "$METER_BASE" "$DECOY_UNIT_DROPIN"
  if [[ -e /etc/nginx/sites-enabled/$(basename "$DECOY_SITE") || -e $DECOY_SITE ]]; then
    rm -f "/etc/nginx/sites-enabled/$(basename "$DECOY_SITE")" "$DECOY_SITE"
    rm -rf "$DECOY_ROOT"
    # nginx is left installed — it may predate this script or serve something
    # else — but the decoy site is removed and the config reloaded.
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    ok "Removed the camouflage decoy site (nginx itself left installed)."
  fi
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
  _uninstall_extras
  systemctl daemon-reload; sysctl --system >/dev/null 2>&1 || true
  ok "Removed. Kept: ${MH_BIN}, ${STATE_DIR} and ${CLIENT_OUT_DIR}."
  ok "Delete ${MH_BIN} yourself if you want the binary gone too."
  return 0
}

install_self() {
  local target="/usr/local/sbin/mihomoctl"
  local src; src="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || true)"
  # Piping the script in (`bash <(curl ...)`, `curl ... | bash`) leaves
  # BASH_SOURCE pointing at a /dev/fd entry or a name that no longer exists, and
  # `install` then fails with "cannot stat". That must not look like a deploy
  # error — everything else has already succeeded by this point.
  if [[ -z $src || ! -f $src ]]; then
    warn "This script is not on disk as a regular file (piped in?), so ${target} was not installed."
    warn "Save it to the server and re-run to get the mihomoctl helper, or call the file directly."
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
  # Keep argv: save_state writes a file of UNCONDITIONAL assignments, so sourcing
  # it in load_state silently undoes everything parse_args just set. Before the
  # link profile and --decoy existed that was invisible — the saved values were
  # the same ones the flags would have set. Now a redeploy with
  # `--decoy local --client-up-mbps 30` would quietly keep last run's values and
  # report success. The command line has to win, so it is replayed afterwards.
  local -a _argv=("$@")
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
    # `|| _rc=$?` rather than a bare call: do_pmtu returns 1 by design when the
    # target does not answer, and under `set -e` that fires the ERR trap and
    # prints a spurious "failed at line N" over the real diagnosis.
    pmtu)      load_state; _rc=0; do_pmtu "$PMTU_TARGET" || _rc=$?; exit "$_rc" ;;
    amplification)
      load_state
      [[ $METER_RESET == yes ]] && { do_amplification --reset; exit 0; }
      do_amplification; exit 0 ;;
    deploy)    : ;;
  esac

  printf '\n%s mihomo (Clash.Meta) multi-protocol deployment for Ubuntu 22/24/26 — v%s %s\n' "$C_BOLD" "$SCRIPT_VERSION" "$C_RST"
  printf '%s %d protocol x transport x security combinations; every secret and subscription generated %s\n\n' "$C_D" "${#ALL_KEYS[@]}" "$C_RST"

  load_state
  parse_args "${_argv[@]}"
  validate_tunables
  resolve_selection
  collect_config
  # collect_config can still change CERT_MODE, and `auto` depends on it.
  resolve_decoy_mode

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
  # setup_cert may fall back to self-signed, which disqualifies the local decoy.
  resolve_decoy_mode
  setup_decoy
  # The config has to describe what the decoy really does, not what we hoped:
  # version-hint has no default and is a hard error if wrong, and a JLS alpn that
  # does not intersect the client's kills the connection instead of falling back.
  if uses_decoy; then
    if _decoy_local; then probe_decoy 127.0.0.1 "$DECOY_PORT" || true
    else                  probe_decoy "$STEAL_SNI" 443 || true; fi
  fi
  write_mihomo_config
  kernel_tuning
  firewall_setup
  setup_metering
  start_services
  # After start_services, not before: start_services restarts mihomo, which
  # zeroes its own payload counters. A baseline taken before the restart would
  # be larger than every later reading and make the delta negative.
  [[ $METERING == yes ]] && _meter_baseline
  gen_artifacts

  save_state
  install_self
  verify_all || warn "Some health checks failed — review the output above."
  summary
}

main "$@"
