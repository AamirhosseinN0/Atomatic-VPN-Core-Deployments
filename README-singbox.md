# Singbox_Deployment.sh

One self-contained Bash script that turns a fresh **Ubuntu 22.04 / 24.04 / 26.04**
server into a multi-protocol [**sing-box**](https://sing-box.sagernet.org) proxy
node. You pick **all** protocols or a **subset**; the script finds free ports,
generates every secret, writes a schema-correct config for the current sing-box,
tunes the kernel for TCP **and** QUIC, opens the firewall, and emits ready-to-import
client bundles (share links, a base64 subscription, a sing-box `config.json`, and a
mihomo / Clash.Meta YAML).

```bash
sudo bash Singbox_Deployment.sh
```

Fully unattended:

```bash
sudo bash Singbox_Deployment.sh -y --domain vpn.example.com --protocols all --cert-mode letsencrypt --le-email you@example.com
```

---

## What it installs

- The **latest sing-box** via the official installer (`https://sing-box.app/install.sh`),
  stable channel by default or **`--channel beta`** for the newest fixes
  (e.g. `1.14.x` prereleases). Falls back to the GitHub `.deb`/tarball if the
  installer is unreachable.
- **Snell** (`snell-server`) as a separate service when selected — **v5** (stable)
  or **v6** (release candidate) — because sing-box only ships a snell inbound on the
  1.14 beta line, whereas the standalone binary works everywhere.

## Protocols

Choose `all` or any comma-separated subset (keys; menu numbers work at the interactive prompt only):

| Key | Protocol | Cert | Share link | Clash YAML | sing-box JSON |
|---|---|:---:|:---:|:---:|:---:|
| `vless-reality` | VLESS + Reality (xtls-rprx-vision) | — | ✅ | ✅ | ✅ |
| `vless-ws` | VLESS + WebSocket + TLS | ✔ | ✅ | ✅ | ✅ |
| `vmess-ws` | VMess + WebSocket + TLS | ✔ | ✅ | ✅ | ✅ |
| `trojan` | Trojan + TLS | ✔ | ✅ | ✅ | ✅ |
| `hysteria2` | Hysteria2 (QUIC/UDP) | ✔ | ✅ | ✅ | ✅ |
| `tuic` | TUIC v5 (QUIC/UDP) | ✔ | ✅ | ✅ | ✅ |
| `shadowtls` | ShadowTLS v3 + Shadowsocks-2022 | — | — | ✅ | ✅ |
| `ss2022` | Shadowsocks 2022 | — | ✅ | ✅ | ✅ |
| `anytls` | AnyTLS | ✔ | ✅ | ✅ | ✅ |
| `naive` | NaiveProxy (HTTP/2 + TLS) | ✔ | ✅ | — | — |
| `snell` | Snell v5 / v6 (standalone) | — | — | v≤5 | — |

**Reality** and **ShadowTLS** need no certificate — they borrow the TLS handshake of a
real external site (`--reality-sni`, default `www.microsoft.com`). ShadowTLS and Snell
have no portable share-link form, so import them from the generated Clash YAML or
sing-box JSON (Snell also gets a Surge line in the bundle's `README.txt`).

## Certificates

Only requested when a TLS-cert protocol is selected:

- **`letsencrypt`** — a real certificate via `certbot --standalone` (needs the domain's
  A record pointing at the server and port 80 reachable). A renewal deploy-hook copies
  the renewed cert to a location the `sing-box` user can read and reloads the service.
- **`self`** — a self-signed ECDSA P-256 certificate; clients must allow insecure /
  skip-cert-verify (the generated links and configs set this for you).

If Let's Encrypt issuance fails, the script falls back to self-signed automatically.

## Ports

Each protocol has a curated candidate list (e.g. `443 8443 2087 2053` for Reality); the
script picks the first port that is actually free (`ss`-checked) and tracks TCP and UDP
separately, so `vless-reality` on TCP/443 and `hysteria2` on UDP/443 coexist. Answer
**n** to *auto-assign* to set every port by hand.

## Kernel tuning

`--no-kernel-tuning` to skip. Otherwise it writes `/etc/sysctl.d/99-singbox.conf`
(a drop-in, so unknown keys are skipped rather than aborting):

- **QUIC UDP buffers** `net.core.rmem_max = wmem_max = 16777216` — satisfies the
  hysteria2 (16 MiB) and quic-go (~7.5 MiB) recommendations and silences quic-go's
  *"failed to sufficiently increase receive buffer size"* warning.
- **BBR + `fq`** congestion control (module autoloaded when available).
- TCP autotuning ceilings, `somaxconn`, backlogs, TCP Fast Open, MTU probing,
  conntrack sizing, and a raised `LimitNOFILE` for the sing-box unit.

Obsolete keys that break old guides (`tcp_tw_recycle`, `tcp_low_latency`, …) are
deliberately **not** set. IP forwarding is **not** enabled — a userspace proxy
terminates connections and needs no NAT, unlike the IKEv2 gateway in this repo.

## Client bundles

Written to `/root/singbox-clients/`:

| File | For |
|---|---|
| `links.txt` | One share link per line |
| `subscription.txt` | Base64 subscription (v2rayN, NekoBox, Streisand, Shadowrocket) |
| `client-singbox.json` | sing-box client (SFA/SFI/SFM, NekoBox, Hiddify, Karing) |
| `client-clash.yaml` | mihomo / Clash.Meta |
| `README.txt` | All ports, credentials, and the Snell Surge line |

`--serve-sub` also serves the three flavours over plain HTTP at a secret path,
content-negotiated by client User-Agent (Clash → YAML, sing-box → JSON, else base64).

Copy the bundle to your machine:

```bash
scp -r root@SERVER_IP:/root/singbox-clients .
```

## Managing the node

After deployment the script installs itself as `singboxctl` (when run from a saved file — a piped `wget -O- … | bash` run skips this and says so):

```bash
singboxctl info        # reprint links / subscription / credentials
singboxctl status      # sing-box + snell services and listening ports
singboxctl check       # re-run every health check
singboxctl update      # upgrade sing-box to the latest build in the channel
singboxctl regen-sub   # rebuild the client bundles from saved state
singboxctl uninstall   # remove config (keeps the binaries)
```

Running `singboxctl` with no subcommand (or `singboxctl deploy`) re-runs the interactive deployment.

## Options

| Option | Default | Notes |
|---|---|---|
| `--domain <fqdn>` | *required* | Cert CN / server address in links |
| `--ip <ipv4>` | auto-detected | Public address |
| `--channel <stable\|beta>` | `stable` | `beta` = newest prerelease fixes |
| `--protocols <all\|list>` | `all` | e.g. `vless-reality,hysteria2,tuic,snell` |
| `--cert-mode <letsencrypt\|self>` | `letsencrypt` | Only if a TLS protocol is chosen |
| `--le-email <email>` | — | Let's Encrypt contact |
| `--reality-sni <host>` | `www.microsoft.com` | Reality/ShadowTLS steal target |
| `--snell-version <v5\|v6>` | `v5` | Snell protocol version |
| `--dns <local\|host>` | `local` | Server-side resolver |
| `--firewall <auto\|ufw\|iptables\|none>` | `auto` | |
| `--no-kernel-tuning` | tuning on | |
| `--serve-sub` | off | Host the subscription over HTTP |
| `-y, --yes` | off | Unattended; requires `--domain` |
| `--skip-preflight` | off | Skip the OS/arch/DNS pre-flight checks |

## Requirements

- Ubuntu 22.04 / 24.04 / 26.04, root access. A userspace proxy works on any VPS,
  including OpenVZ/LXC containers (no kernel IPsec stack required).
- For `--cert-mode letsencrypt`: a domain A record pointing at the server and port 80
  reachable during issuance.

## License

MIT — see [LICENSE](LICENSE).
