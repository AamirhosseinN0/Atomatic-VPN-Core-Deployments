# Atomatic VPN Core Deployments

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Ubuntu](https://img.shields.io/badge/Ubuntu-22.04%2B-E95420?logo=ubuntu&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-one--file%20deployers-4EAA25?logo=gnu-bash&logoColor=white)

Four self-contained Bash scripts, each of which turns a fresh **Ubuntu** server into a
working VPN or proxy node in one run. You pick the protocols; the script generates every
secret, requests the certificate, validates the config, tunes the kernel, opens the
firewall, and hands you ready-to-import client bundles.

No Ansible, no Docker, no clone needed — `wget` one file and run it.

---

## One-step run

On a fresh Ubuntu server — each command downloads one deployer and runs it. The
script stays on disk, so you keep it for re-runs and get the management CLI:

```bash
# IKEv2/IPsec VPN gateway for Windows + Android (strongSwan)
wget -qO iKev2_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/iKev2_Deployment.sh && sudo bash iKev2_Deployment.sh

# sing-box proxy node
wget -qO Singbox_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/Singbox_Deployment.sh && sudo bash Singbox_Deployment.sh

# Xray-core proxy node
wget -qO Xray_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/Xray_Deployment.sh && sudo bash Xray_Deployment.sh

# mihomo (Clash.Meta) proxy node
wget -qO Mihomo_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/Mihomo_Deployment.sh && sudo bash Mihomo_Deployment.sh
```

Piping works too (`wget -qO- … | sudo bash`) with one difference: a script arriving
on a pipe cannot install the management CLI, so the deployer skips that step and
says so. All questions are asked on the terminal either way.

Flags pass straight through for unattended runs:

```bash
wget -qO Singbox_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/Singbox_Deployment.sh
sudo bash Singbox_Deployment.sh -y --domain vpn.example.com
```

---

## The four deployers

| Script | Turns a fresh Ubuntu server into… | Docs |
|---|---|---|
| [`iKev2_Deployment.sh`](iKev2_Deployment.sh) | an **IKEv2/IPsec VPN gateway** (strongSwan) for Windows 10/11 and Android, with username/password **and** certificate auth | [README-ikev2.md](README-ikev2.md) |
| [`Singbox_Deployment.sh`](Singbox_Deployment.sh) | a **[sing-box](https://sing-box.sagernet.org)** proxy node — VLESS-Reality, VLESS-WS, Hysteria2, TUIC, Trojan, AnyTLS, ShadowTLS, Shadowsocks-2022, NaiveProxy, VMess, Snell v5/v6 | [README-singbox.md](README-singbox.md) |
| [`Xray_Deployment.sh`](Xray_Deployment.sh) | an **[Xray-core](https://xtls.github.io)** proxy node — VLESS-Reality/Vision, XHTTP, post-quantum VLESS Encryption, Trojan, VMess, Hysteria2, SS-2022, and a fallbacks mode hiding several protocols behind one HTTPS port | [README-xray.md](README-xray.md) |
| [`Mihomo_Deployment.sh`](Mihomo_Deployment.sh) | a **[mihomo](https://github.com/MetaCubeX/mihomo) (Clash.Meta)** node — 81 protocol × transport × camouflage combinations, including ShadowQUIC, Mieru, Sudoku, TrustTunnel, JLS/RestLS, mKCP/Mekya and Snell v1–v4 | [README-mihomo.md](README-mihomo.md) |

### Which one do I want?

- **A VPN your devices connect to natively** (built-in Windows / Android clients) →
  `iKev2_Deployment.sh`
- **A proxy node for v2rayN / Clash / sing-box clients** → `Singbox_Deployment.sh` for
  the mainstream set, `Xray_Deployment.sh` for XHTTP / post-quantum VLESS / fallbacks,
  `Mihomo_Deployment.sh` for every protocol the other two cores cannot do

---

## At a glance

| | iKev2 | Singbox | Xray | Mihomo |
|---|---|---|---|---|
| Ubuntu | 22.04 | 22.04 / 24.04 / 26.04 | 22.04 / 24.04 / 26.04 | 22.04 / 24.04 / 26.04 |
| Runs on a container VPS (OpenVZ/LXC) | no — needs the kernel IPsec stack | yes | yes | yes |
| Client bundles | `.p12`, `.sswan`, `.ps1` installers | links, subscription, sing-box + Clash configs | links, subscription, Xray + sing-box + Clash configs | links, subscription, mihomo + sing-box configs |
| Management CLI | `ikev2ctl` | `singboxctl` | `xrayctl` | `mihomoctl` |

---

## Quick start

```bash
git clone https://github.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments.git
cd Atomatic-VPN-Core-Deployments
sudo bash Singbox_Deployment.sh        # or any of the four
```

Or standalone — every script is a single file with no dependencies on the rest:

```bash
wget https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-Deployments/main/Singbox_Deployment.sh
sudo bash Singbox_Deployment.sh
```

Interactive by default — nearly every question has a sensible default you can accept
with ENTER (the IKEv2 deployer also requires a domain and public IP) — or fully
unattended:

```bash
sudo bash Singbox_Deployment.sh -y --domain vpn.example.com --protocols all --cert-mode letsencrypt
sudo bash iKev2_Deployment.sh  -y --domain vpn.example.com --ip 203.0.113.10
```

Each README lists that script's full option set and unattended examples.

---

## What every deployer does

- **One self-contained file** — nothing to install beyond a stock Ubuntu system
- **Secrets generated** — keys, UUIDs and passwords are created, never reused
- **Certificates handled** — Let's Encrypt when a protocol wants TLS, automatic
  self-signed fallback if issuance fails (the three proxy deployers; the IKEv2
  deployer stops instead); REALITY / ShadowTLS / JLS-style camouflage needs no
  certificate at all
- **Ports found, not asked for** (proxy deployers) — every protocol gets a port that is
  verified free, TCP and UDP tracked separately
- **Config validated before the service restarts**, and a `check` command re-runs every
  health check afterwards
- **Kernel tuned** — BBR + `fq`, QUIC UDP buffers, conntrack sizing, written as a sysctl
  drop-in (`--no-kernel-tuning` to skip); the IKEv2 script adds IP forwarding and MSS
  clamping
- **Firewall opened** for exactly the ports in use (`--firewall auto|ufw|iptables|none`)
- **Client bundles written to `/root/*-clients/`** — share links, a base64 subscription
  and per-core client configs; `--serve-sub` (proxy deployers) also serves them over HTTP
- **A management CLI stays behind** — `ikev2ctl`, `singboxctl`, `xrayctl`, `mihomoctl` —
  for status, health checks and node management, plus updates on the three proxy
  deployers

---

## Requirements

- An Ubuntu server and root access
- A **KVM/Xen** VPS for `iKev2_Deployment.sh` — containers usually lack the XFRM/IPsec
  kernel stack. The three proxy deployers are userspace and run anywhere, containers
  included
- A domain whose **A record points at the server** whenever certificates are involved;
  REALITY-based protocols work with no domain and no certificate
- The scripts open their own firewall ports — nothing else to prepare

---

## Security notes

- Generated client bundles under `/root/*-clients/` contain **private keys and cleartext
  passwords**. Copy them over `scp`, then delete what you no longer need.
- Nothing server-specific is committed: the `.gitignore` is **deny-by-default**, so keys,
  bundles and deployment state can never be committed by accident.
- Each deployer's README carries its own security notes — service hardening, certificate
  revocation, `--serve-sub` caveats.

---

## License

MIT — see [LICENSE](LICENSE).
