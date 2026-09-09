# singbox (ubuntu-24.04) — run 34405191591

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu24 / 6.17.0-1022-azure x86_64
- deploy command: `wget -qO Singbox_Deployment.sh https://raw.githubusercontent.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>_Deployment.sh && sudo bash Singbox_Deployment.sh -y --domain vpn.example.com --protocols all --cert-mode self`
- deploy status: OK

## Verification
```
PASS: singboxctl is installed at /usr/local/sbin/singboxctl
PASS: singboxctl check exits 0
PASS: singboxctl status exits 0
PASS: service 'sing-box' is active
PASS: sysctl drop-in /etc/sysctl.d/99-singbox.conf exists and is non-empty
PASS: bundle file /root/singbox-clients/links.txt exists and is non-empty
PASS: bundle file /root/singbox-clients/subscription.txt exists and is non-empty
PASS: bundle file /root/singbox-clients/client-singbox.json exists and is non-empty
PASS: bundle file /root/singbox-clients/client-clash.yaml exists and is non-empty
PASS: bundle file /root/singbox-clients/README.txt exists and is non-empty
```

## Deploy log (last 120 lines)
```
    shadowtls        tcp/9443
    ss2022           both/8388
    anytls           tcp/2096
    naive            tcp/29060
    snell            tcp/6160

----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 52.241.147.103
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
[+] Detected public IPv4: 52.241.147.103

==> Installing dependencies
[*] apt-get update ...

==> Installing sing-box (stable)
[+] sing-box installed via the official script.
[+] sing-box version: 1.14.0   (runs as: sing-box)

==> Installing snell-server (v5.0.1)
[*] Downloading https://dl.nssurge.com/snell/snell-server-v5.0.1-linux-amd64.zip
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0 43 1185k   43  511k    0     0  4620k      0 --:--:-- --:--:-- --:--:-- 4610k100 1185k  100 1185k    0     0  9068k      0 --:--:-- --:--:-- --:--:-- 9051k
[+] snell-server: 

==> Generating credentials
[+] Secrets ready (UUID, passwords, Reality keypair, SS-2022 key, Snell PSK).

==> TLS certificate (self)
[+] Self-signed certificate written to /etc/sing-box/cert (clients must allow insecure).

==> Writing /etc/sing-box/config.json
[+] Config validated by sing-box check.

==> Kernel / sysctl tuning
[+] BBR available and enabled.
[+] Applied sysctl drop-in and raised LimitNOFILE for sing-box.

==> Firewall
[+] iptables rules applied for 443 2083 2087 2096 6160 8388 8443 9443 29060 (tcp) 443 2083 8388 (udp).

==> Starting services
[+] sing-box is running.
[+] snell is running.

==> Generating client bundles
[+] Bundles written to /root/singbox-clients (links.txt, subscription.txt, client-singbox.json, client-clash.yaml).
[+] Installed as /usr/local/sbin/singboxctl

==> Health checks
[+] sing-box: 1.14.0
[+] config.json valid
[+] sing-box.service active
[+] snell.service active
[+] listening tcp/443 (vless-reality)
[+] listening tcp/8443 (vless-ws)
[+] listening tcp/2087 (vmess-ws)
[+] listening tcp/2083 (trojan)
[+] listening udp/443 (hysteria2)
[+] listening udp/2083 (tuic)
[+] listening tcp/9443 (shadowtls)
[+] listening 8388 (ss2022)
[+] listening tcp/2096 (anytls)
[+] listening tcp/29060 (naive)
[+] listening tcp/6160 (snell)

  <redacted-blob>
  |          S I N G - B O X   N O D E   I S   R E A D Y      |
  <redacted-blob>

----------------------------------------------------------------------
  Server                 vpn.example.com (52.241.147.103)
  sing-box               1.14.0 (stable)
  TLS certificate        self
----------------------------------------------------------------------
  Protocols & ports
    vless-reality    tcp/443
    vless-ws         tcp/8443
    vmess-ws         tcp/2087
    trojan           tcp/2083
    hysteria2        udp/443
    tuic             udp/2083
    shadowtls        tcp/9443
    ss2022           both/8388
    anytls           tcp/2096
    naive            tcp/29060
    snell            tcp/6160
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
    scp -r root@52.241.147.103:/root/singbox-clients .
----------------------------------------------------------------------

```

## Service status
```
● sing-box.service - sing-box service
     Loaded: loaded (/usr/lib/systemd/system/sing-box.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/sing-box.service.d
             └─10-limits.conf
     Active: active (running) since Wed 2026-09-09 21:08:40 UTC; 2s ago
       Docs: https://sing-box.sagernet.org
   Main PID: 3758 (sing-box)
      Tasks: 9 (limit: 19151)
     Memory: 15.6M (peak: 15.6M)
        CPU: 55ms
     CGroup: /system.slice/sing-box.service
             └─3758 /usr/bin/sing-box -D /var/lib/sing-box -C /etc/sing-box run

Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/tuic[tuic-in]: udp server started at [::]:2083
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowtls[shadowtls-in]: tcp server started at [::]:9443
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[shadowtls-ss-in]: tcp server started at 127.0.0.1:30000
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[shadowtls-ss-in]: udp server started at 127.0.0.1:30000
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[ss2022-in]: tcp server started at [::]:8388
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[ss2022-in]: udp server started at [::]:8388
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/anytls[anytls-in]: tcp server started at [::]:2096
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/naive[naive-in]: tcp server started at [::]:29060
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/naive[naive-in]: udp server started at [::]:29060
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO sing-box started (0.00s)
```

## Service journal (last 60 lines)
```
Sep 09 21:08:40 runnervmejwal systemd[1]: Started sing-box.service - sing-box service.
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO network: updated default interface eth0, index 2
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO network: updated network environment: gateway 10.1.0.1, gateway_mac 12:34:56:78:9a:bc
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/vless[vless-reality-in]: tcp server started at [::]:443
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/vless[vless-ws-in]: tcp server started at [::]:8443
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/vmess[vmess-ws-in]: tcp server started at [::]:2087
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/trojan[trojan-in]: tcp server started at [::]:2083
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/hysteria2[hysteria2-in]: udp server started at [::]:443
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/tuic[tuic-in]: udp server started at [::]:2083
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowtls[shadowtls-in]: tcp server started at [::]:9443
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[shadowtls-ss-in]: tcp server started at 127.0.0.1:30000
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[shadowtls-ss-in]: udp server started at 127.0.0.1:30000
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[ss2022-in]: tcp server started at [::]:8388
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/shadowsocks[ss2022-in]: udp server started at [::]:8388
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/anytls[anytls-in]: tcp server started at [::]:2096
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/naive[naive-in]: tcp server started at [::]:29060
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO inbound/naive[naive-in]: udp server started at [::]:29060
Sep 09 21:08:40 runnervmejwal sing-box[3758]: +0000 2026-09-09 21:08:40 INFO sing-box started (0.00s)
```

## Client bundle listing
```
/root/singbox-clients:
total 32
drwx------  2 root root 4096 Sep  9 21:08 .
drwx------ 20 root root 4096 Sep  9 21:08 ..
-rw-------  1 root root 1502 Sep  9 21:08 README.txt
-rw-------  1 root root 4074 Sep  9 21:08 client-clash.yaml
-rw-------  1 root root 5618 Sep  9 21:08 client-singbox.json
-rw-------  1 root root 1524 Sep  9 21:08 links.txt
-rw-------  1 root root 2032 Sep  9 21:08 subscription.txt
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
