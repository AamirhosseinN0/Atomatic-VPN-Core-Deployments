# singbox-pipe (ubuntu-22.04) — run 32503173693

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu22 / 6.8.0-1064-azure x86_64
- deploy command: `wget -qO- https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>_Deployment.sh | sudo bash -s -- -y --domain vpn.example.com --protocols vless-reality,ss2022`
- deploy status: OK

## Verification
```
PASS: service 'sing-box' is active
PASS: sysctl drop-in /etc/sysctl.d/99-singbox.conf exists and is non-empty
PASS: bundle file /root/singbox-clients/links.txt exists and is non-empty
PASS: bundle file /root/singbox-clients/subscription.txt exists and is non-empty
PASS: bundle file /root/singbox-clients/client-singbox.json exists and is non-empty
PASS: bundle file /root/singbox-clients/README.txt exists and is non-empty
PASS: piped run skips singboxctl by design and says so
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
  Selected: vless-reality ss2022

  Ports selected (free on this host):
    vless-reality    tcp/443
    ss2022           both/8388

----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 52.161.178.102
  sing-box channel         stable
  Protocols                vless-reality ss2022
  Reality/STLS SNI         www.microsoft.com
  Firewall                 auto
  Kernel tuning            yes
  Serve sub                no
----------------------------------------------------------------------
[*] Logging this run to /var/log/singbox-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 22.04.5 LTS
[+] Architecture: x86_64
[+] Virtualisation: microsoft   (a userspace proxy works fine in containers, unlike IPsec)
[+] Outbound interface: eth0
[+] Detected public IPv4: 52.161.178.102

==> Installing dependencies
[*] apt-get update ...

==> Installing sing-box (stable)
[+] sing-box installed via the official script.
[+] sing-box version: 1.13.19   (runs as: sing-box)

==> Generating credentials
[+] Secrets ready (UUID, passwords, Reality keypair, SS-2022 key).
[*] No TLS-certificate protocol selected; skipping certificates.

==> Writing /etc/sing-box/config.json
[+] Config validated by sing-box check.

==> Kernel / sysctl tuning
[+] BBR available and enabled.
[+] Applied sysctl drop-in and raised LimitNOFILE for sing-box.

==> Firewall
[+] iptables rules applied for 443 8388 (tcp) 8388 (udp).

==> Starting services
[+] sing-box is running.

==> Generating client bundles
[+] Bundles written to /root/singbox-clients (links.txt, subscription.txt, client-singbox.json, client-clash.yaml).
[!] This script is not on disk as a regular file (piped in?), so /usr/local/sbin/singboxctl was not installed.
[!] Save it to the server and re-run to get the singboxctl helper, or call the file directly.

==> Health checks
[+] sing-box: 1.13.19
[+] config.json valid
[+] sing-box.service active
[+] listening tcp/443 (vless-reality)
[+] listening 8388 (ss2022)

  <redacted-blob>
  |          S I N G - B O X   N O D E   I S   R E A D Y      |
  <redacted-blob>

----------------------------------------------------------------------
  Server                 vpn.example.com (52.161.178.102)
  sing-box               1.13.19 (stable)
----------------------------------------------------------------------
  Protocols & ports
    vless-reality    tcp/443
    ss2022           both/8388
----------------------------------------------------------------------
  Client bundles
    /root/singbox-clients/links.txt          (individual share links)
    /root/singbox-clients/subscription.txt   (base64 subscription)
    /root/singbox-clients/client-singbox.json
    /root/singbox-clients/client-clash.yaml
----------------------------------------------------------------------
  Manage
    singboxctl info        # reprint links / credentials
    singboxctl status      # services + listening ports
    singboxctl check       # health checks
    singboxctl update      # upgrade sing-box
    journalctl -u sing-box -f
----------------------------------------------------------------------
  Copy the bundle to your PC
    scp -r root@52.161.178.102:/root/singbox-clients .
----------------------------------------------------------------------
  2 warning(s) above — scroll up.
----------------------------------------------------------------------

```

## Service status
```
● sing-box.service - sing-box service
     Loaded: loaded (/lib/systemd/system/sing-box.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/sing-box.service.d
             └─10-limits.conf
     Active: active (running) since Fri 2026-08-21 16:29:54 UTC; 2s ago
       Docs: https://sing-box.sagernet.org
   Main PID: 2944 (sing-box)
      Tasks: 9 (limit: 19154)
     Memory: 4.9M
        CPU: 19ms
     CGroup: /system.slice/sing-box.service
             └─2944 /usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run

Aug 21 16:29:54 runnervmec1zy systemd[1]: Started sing-box service.
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO network: updated default interface eth0, index 2
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/vless[vless-reality-in]: tcp server started at [::]:443
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/shadowsocks[ss2022-in]: tcp server started at [::]:8388
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/shadowsocks[ss2022-in]: udp server started at [::]:8388
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO sing-box started (0.00s)
```

## Service journal (last 60 lines)
```
Aug 21 16:29:54 runnervmec1zy systemd[1]: Started sing-box service.
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO network: updated default interface eth0, index 2
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/vless[vless-reality-in]: tcp server started at [::]:443
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/shadowsocks[ss2022-in]: tcp server started at [::]:8388
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO inbound/shadowsocks[ss2022-in]: udp server started at [::]:8388
Aug 21 16:29:54 runnervmec1zy sing-box[2944]: +0000 2026-08-21 16:29:54 INFO sing-box started (0.00s)
```

## Client bundle listing
```
/root/singbox-clients:
total 28
drwx------  2 root root 4096 Aug 21 16:29 .
drwx------ 25 root root 4096 Aug 21 16:29 ..
-rw-------  1 root root  788 Aug 21 16:29 README.txt
-rw-------  1 root root 1571 Aug 21 16:29 client-clash.yaml
-rw-------  1 root root 2350 Aug 21 16:29 client-singbox.json
-rw-------  1 root root  336 Aug 21 16:29 links.txt
-rw-------  1 root root  448 Aug 21 16:29 subscription.txt
```

## sysctl drop-in (first 20 lines)
```
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
```
