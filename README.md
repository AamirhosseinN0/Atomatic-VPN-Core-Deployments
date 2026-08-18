# iKev2_Deployment

One self-contained Bash script that turns a fresh **Ubuntu 22.04** server into a working
**IKEv2/IPsec VPN** for **Windows 10/11** and **Android**, with both
**username + password (EAP-MSCHAPv2)** and **certificate** authentication.

It also generates ready-to-use client bundles: an importable `.p12`, an Android
`.sswan` profile, and a PowerShell installer that configures Windows for you.

```bash
sudo bash iKev2_Deployment.sh
```

> **Also in this repo:** [`Singbox_Deployment.sh`](Singbox_Deployment.sh) — a
> multi-protocol [**sing-box**](https://sing-box.sagernet.org) proxy deployer for
> Ubuntu 22/24/26 (VLESS-Reality, Hysteria2, TUIC, Trojan, ShadowTLS, Shadowsocks-2022,
> AnyTLS, NaiveProxy, VMess, and Snell v5/v6), with generated share links,
> subscription, sing-box and Clash configs. See [README-singbox.md](README-singbox.md).

---

## Why another IKEv2 script

Most IKEv2 setups fail on Windows for reasons that are easy to get wrong and hard to
diagnose from the client's generic error codes. This script encodes the fixes:

| Constraint | What breaks without it | Handled by |
|---|---|---|
| Stock Windows ESP offers **SHA-1 only** (`aes256/aes128/3des/des/null`) | Tunnel negotiates then dies | `aes256-sha1` kept in `esp_proposals` |
| Stock Windows IKE DH is **modp1024**; a server-initiated rekey needs modp2048 listed first | Drops after ~4 h | `modp2048` heads the proposal list |
| An ESP proposal carrying a DH group the client never configured | Error **13816** | Non-PFS proposals ordered first |
| Server cert needs EKU `serverAuth` **+** `1.3.6.1.5.5.8.2.2`, and the IP must be a **`DNS:`** SAN | Error **13801** | SAN = `DNS:<domain>, DNS:<ip>, IP:<ip>` |
| Windows **cannot import PBES2/AES-256 PKCS#12** — OpenSSL 3's default | `.p12` import silently rejected | Built with `PBE-SHA1-3DES` + SHA-1 MAC, then verified |
| OpenSSL 3 on Jammy moved **MD4** to the legacy provider | EAP-MSCHAPv2 fails; password login impossible | Legacy provider scoped to strongSwan via a systemd drop-in |
| NATed Windows rejects a gateway-initiated CHILD_SA rekey | Error **12345** | `rekey_time = 0` on the children |
| `strongswan.service` is an **alias for the legacy starter** on Jammy | Wrong daemon restarted; drop-in lands in the wrong directory | Unit chosen by which one runs `charon-systemd` |

---

## Requirements

- Ubuntu 22.04 LTS, root access
- A **KVM/Xen** VPS — containers (OpenVZ/LXC) usually lack the XFRM/IPsec kernel stack
- A domain whose **A record points at the server**
- UDP **500** and **4500** reachable

> **Cloudflare users:** the A record must be **DNS only** (grey cloud). IKEv2 is UDP;
> Cloudflare's proxy cannot carry it. The script detects proxied records and stops.

---

## Quick start

```bash
wget https://raw.githubusercontent.com/<you>/iKev2_Deployment/main/iKev2_Deployment.sh
sudo bash iKev2_Deployment.sh
```

The script asks for everything it needs — domain and public IP are required, the rest
have sensible defaults you can accept with ENTER. Afterwards it installs itself as
`/usr/local/sbin/ikev2ctl`.

Fully unattended:

```bash
sudo bash iKev2_Deployment.sh -y --domain vpn.example.com --ip 203.0.113.10
```

---

## Managing clients

```bash
ikev2ctl add-client                 # interactive
ikev2ctl add-client laptop --platform windows --auth both
ikev2ctl list-clients               # users, certificates, bundles
ikev2ctl revoke-client --name bob   # revokes the cert, regenerates the CRL
ikev2ctl status                     # live IKE/CHILD SAs
ikev2ctl check                      # re-run every health check
ikev2ctl repair-md4                 # re-apply the EAP-MSCHAPv2 / MD4 fix
```

Each client bundle lands in `/root/ikev2-clients/<name>/` (plus a `.zip`) and contains:

| File | For |
|---|---|
| `ca.crt` | Root CA to trust (self-signed mode only) |
| `<name>-windows.p12` | Windows certificate login |
| `<name>-windows-cert.ps1` | Installs CA + cert + VPN profile |
| `<name>-windows-userpass.ps1` | Installs CA + username/password VPN profile |
| `<name>-android-cert.sswan` | strongSwan app, certificate |
| `<name>-android-userpass.sswan` | strongSwan app, username/password |
| `README.txt` | Per-client instructions and credentials |

---

## Options

| Option | Default | Notes |
|---|---|---|
| `--domain <fqdn>` | *required* | What clients type; goes into the cert SAN |
| `--ip <ipv4>` | *required* | Public address; also added as a `DNS:` SAN |
| `--cert-mode self\|letsencrypt` | `self` | Let's Encrypt means no CA to install on clients |
| `--key-type rsa\|ecdsa` | `rsa` | Windows accepts RSA, P-256, P-384 only |
| `--profile compat\|balanced\|strict` | `compat` | See below |
| `--pool-eap <cidr>` | `10.20.10.0/24` | Username/password clients |
| `--pool-cert-win <cidr>` | `10.20.11.0/24` | Windows certificate clients |
| `--pool-cert-android <cidr>` | `10.20.12.0/24` | Android certificate clients |
| `--dns <a,b>` | `1.1.1.1,8.8.8.8` | Pushed to clients |
| `--ipv6 yes\|no` | `no` | Adds an IPv6 ULA pool |
| `--firewall auto\|ufw\|iptables\|none` | `auto` | |
| `--no-kernel-tuning` | tuning on | sysctl, BBR, conntrack, MSS clamp |

### Crypto profiles

| Profile | IKE | ESP | Windows setup |
|---|---|---|---|
| `compat` | includes modp1024 / 3DES for stock Windows | includes `aes256-sha1` | nothing to configure |
| `balanced` | AES-256 + SHA-256, modp2048 / ECP384 | AES-256 + SHA-256 | run the generated `.ps1` |
| `strict` | AES-256-GCM + ECP384 only | AES-256-GCM + ECP384 | **must** run the generated `.ps1` |

`compat` is the default so the built-in Windows dialog works with zero client-side
configuration. Choose `balanced` or `strict` if every client will run the `.ps1`.

---

## Separate address pools

Clients are placed in different pools by how they authenticate, which strongSwan can
distinguish reliably:

- **EAP** (username/password, Windows + Android) → `pool-eap`
- **Certificate, Android** → `pool-cert-android` (matched on `*@android.<domain>`, which
  the `.sswan` pins via `local.id`)
- **Certificate, anything else** → `pool-cert-win`

This makes per-group firewall and routing rules straightforward.

---

## Windows error codes

| Code | Cause |
|---|---|
| **809** | NAT-T. Reboot after the `.ps1` sets `AssumeUDPEncapsulationContextOnSendRule = 2` |
| **13801** | Server name typed doesn't match the certificate SAN, or the CA isn't in **Local Machine → Trusted Root** |
| **13806** | CA certificate not imported at all |
| **13868** / **789** | Crypto policy mismatch — re-run the `.ps1` for your profile |
| **812** | Wrong username/password, or charon has no MD4 (`ikev2ctl repair-md4`) |

---

## Security notes

- Client bundles under `/root/ikev2-clients/` contain **private keys and cleartext
  passwords**. Copy them over `scp`, then delete what you no longer need.
- The `.sswan` profiles embed the PKCS#12 and, for the password profiles, the password
  itself — treat them as secrets.
- `compat` deliberately keeps 3DES and modp1024 reachable so the stock Windows dialog
  works. If that is unacceptable for your threat model, use `balanced` or `strict`.
- The OpenSSL legacy provider is enabled **only for the strongSwan unit** via a systemd
  drop-in; system-wide TLS is untouched.
- Revocation is real: `revoke-client` marks the certificate in the CA database,
  regenerates the CRL and reloads it into charon.
- Nothing in this repository contains server-specific values — the `.gitignore` also
  blocks keys, bundles and state files from ever being committed.

---

## Troubleshooting

```bash
ikev2ctl check                                  # every health check, with fixes
journalctl -u strongswan-swanctl.service -f     # daemon log
tail -f /var/log/strongswan.log                 # charon log
swanctl --list-sas                              # live sessions
ss -lunp | grep -E ':500|:4500'                 # is charon actually bound?
```

---

## License

MIT — see [LICENSE](LICENSE).
