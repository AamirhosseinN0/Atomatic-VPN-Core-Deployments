# singbox (ubuntu-24.04) — run 32295263509

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu24 / 6.17.0-1022-azure x86_64
- deploy command: `wget -qO- https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>_Deployment.sh | sudo bash -s -- -y --domain vpn.example.com --protocols all --cert-mode self`
- deploy status: FAILED

## Verification
```
FAIL: singboxctl is installed at /usr/local/sbin/singboxctl
FAIL: singboxctl check exits 0
    sudo: /usr/local/sbin/singboxctl: command not found
FAIL: singboxctl status exits 0
    sudo: /usr/local/sbin/singboxctl: command not found
FAIL: service 'sing-box' is active
FAIL: sysctl drop-in /etc/sysctl.d/99-singbox.conf exists and is non-empty
FAIL: bundle file /root/singbox-clients/links.txt exists and is non-empty
FAIL: bundle file /root/singbox-clients/subscription.txt exists and is non-empty
FAIL: bundle file /root/singbox-clients/client-singbox.json exists and is non-empty
FAIL: bundle file /root/singbox-clients/client-clash.yaml exists and is non-empty
FAIL: bundle file /root/singbox-clients/README.txt exists and is non-empty
```

## Deploy log (last 120 lines)
```

 sing-box multi-protocol deployment for Ubuntu 22/24/26 — v1.0.0 
 pick all protocols or a subset; every secret=<redacted> sub is generated for you 


==> Configuration
Press ENTER to accept the value in brackets.


  Available protocols:
     1) vless-reality  VLESS + Reality (TCP, xtls-rprx-vision) — no cert, strongest against DPI
     2) vless-ws       VLESS + WebSocket + TLS — CDN/nginx friendly
     3) vmess-ws       VMess + WebSocket + TLS — legacy client compatibility
     4) trojan         Trojan + TLS (TCP)
     5) hysteria2      Hysteria2 (QUIC/UDP) — fast on lossy / high-latency links
     6) tuic           TUIC v5 (QUIC/UDP)
     7) shadowtls      ShadowTLS v3 wrapping Shadowsocks-2022 — mimics a real TLS site
     8) ss2022         Shadowsocks 2022 (TCP+UDP)
     9) anytls         AnyTLS (TCP) — TLS-in-TLS fingerprint resistant
    10) naive          NaiveProxy (HTTP/2 + TLS)
    11) snell          Snell v5/v6 (standalone snell-server) — Surge / Clash.Meta

  Enter 'all', or a comma list of keys/numbers (e.g. vless-reality,hysteria2,tuic,snell).
  Selected: vless-reality vless-ws vmess-ws trojan hysteria2 tuic shadowtls ss2022 anytls naive snell

  letsencrypt – real cert via certbot (needs the domain's A record pointing here + port 80 free).
  self        – self-signed cert; clients must allow insecure / skip-cert-verify.

  Ports selected (free on this host):
    vless-reality    tcp/443
    vless-ws         tcp/8443
    vmess-ws         tcp/2087
    trojan           tcp/2083
    hysteria2        udp/443
    tuic             udp/2083
    shadowtls        tcp/9443
    ss2022           both/8388
    anytls           tcp/2096
    naive            tcp/40236
    snell            tcp/6160

----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 57.154.232.213
  sing-box channel         stable
  Protocols                vless-reality vless-ws vmess-ws trojan hysteria2 tuic shadowtls ss2022 anytls naive snell
  TLS certificate          self
  Reality/STLS SNI         www.microsoft.com
  Snell version            v5.0.1 (obfs=off)
  Firewall                 auto
  Kernel tuning            yes
  Serve sub                no
----------------------------------------------------------------------
[*] Logging this run to /var/log/singbox-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 24.04.4 LTS
[+] Architecture: x86_64
[+] Virtualisation: microsoft   (a userspace proxy works fine in containers, unlike IPsec)
[+] Outbound interface: eth0
[+] Detected public IPv4: 57.154.232.213

==> Installing dependencies
[*] apt-get update ...
```

## Service status
```
Unit sing-box.service could not be found.
```

## Service journal (last 60 lines)
```
-- No entries --
```

## Client bundle listing
```
ls: cannot access '/root/singbox-clients': No such file or directory
```

## sysctl drop-in (first 20 lines)
```
head: cannot open '/etc/sysctl.d/99-singbox.conf' for reading: No such file or directory
```
