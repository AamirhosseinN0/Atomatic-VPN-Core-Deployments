# xray (ubuntu-24.04) — run 34404316496

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu24 / 6.17.0-1022-azure x86_64
- deploy command: `sudo bash Xray_Deployment.sh -y --domain vpn.example.com --protocols vless-reality,hysteria2,ss2022`
- deploy status: OK

## Verification
```
PASS: xrayctl is installed at /usr/local/sbin/xrayctl
PASS: xrayctl check exits 0
PASS: xrayctl status exits 0
PASS: service 'xray' is active
PASS: sysctl drop-in /etc/sysctl.d/99-xray.conf exists and is non-empty
PASS: bundle file /root/xray-clients/links.txt exists and is non-empty
PASS: bundle file /root/xray-clients/subscription.txt exists and is non-empty
PASS: bundle file /root/xray-clients/client-xray.json exists and is non-empty
PASS: bundle file /root/xray-clients/client-singbox.json exists and is non-empty
PASS: bundle file /root/xray-clients/client-clash.yaml exists and is non-empty
```

## Deploy log (last 120 lines)
```
  stable – GitHub's latest non-prerelease (currently months old).
  pinned – an exact tag you name.

  Available protocols:
     1) vless-reality        VLESS + Vision + REALITY (RAW/TCP) — no cert, strongest against DPI
     2) vless-xhttp-reality  VLESS + XHTTP + REALITY — no cert, the transport XTLS now promotes
     3) vless-encryption     VLESS post-quantum Encryption (ML-KEM-768) + Vision — no cert at all
     4) vless-ws             VLESS + WebSocket + TLS — CDN/nginx friendly
     5) vless-xhttp          VLESS + XHTTP + TLS — HTTP/2-shaped, CDN friendly
     6) vmess-ws             VMess + WebSocket + TLS — legacy client compatibility
     7) trojan               Trojan + TLS
     8) hysteria2            Hysteria2 (QUIC/UDP) — native in Xray since v26.3.27
     9) ss2022               Shadowsocks 2022 (TCP+UDP)

  Enter 'all', or a comma list of keys/numbers (e.g. vless-reality,hysteria2,ss2022).
  Selected: vless-reality hysteria2 ss2022

  letsencrypt – real cert via certbot (needs the A record pointing here + port 80 free).
  self        – self-signed; clients must pin the certificate or allow insecure.

  Ports selected (free on this host):
    vless-reality          tcp/443
    hysteria2              udp/443
    ss2022                 both/8388

----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 20.57.47.235
  Xray channel             latest
  Protocols                vless-reality hysteria2 ss2022
  Port mode                dedicated
  TLS certificate          letsencrypt
  REALITY SNI              www.microsoft.com
  Firewall                 auto
  Kernel tuning            yes
----------------------------------------------------------------------
[*] Logging this run to /var/log/xray-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 24.04.5 LTS
[+] Architecture: x86_64
[+] Virtualisation: microsoft
[+] Outbound interface: eth0
[+] Detected public IPv4: 20.57.47.235
[!] DNS: vpn.example.com -> <none> (expected 20.57.47.235); Let's Encrypt HTTP-01 may fail.

==> Installing dependencies
[*] apt-get update ...

==> Installing Xray-core (latest)
[+] Xray version: 26.9.9   (service runs as: nobody)

==> Generating credentials
[+] Secrets ready.

==> TLS certificate (letsencrypt)
[!] Let's Encrypt issuance failed (DNS not pointing here, or :80 blocked).
[!] Falling back to a self-signed certificate.
[+] Self-signed certificate written to /usr/local/etc/xray/cert.
[!] Clients must pin this certificate (pcs) or enable 'allow insecure'.

==> Writing /usr/local/etc/xray/config.json
[+] Config validated by `xray run -test`.

==> Kernel / sysctl tuning
[+] BBR available and enabled.
[+] Applied sysctl drop-in and confirmed LimitNOFILE for Xray.

==> Firewall
[*] Backend: iptables   tcp: 443 8388   udp: 443 8388 
[+] iptables rules applied.

==> Starting services
[+] Xray is running.

==> Generating client bundles
[+] Bundles written to /root/xray-clients
[+] Installed as /usr/local/sbin/xrayctl

==> Health checks
[+] xray: 26.9.9
[+] config.json valid
[+] xray.service active
[+] listening tcp/443 (vless-reality)
[+] listening udp/443 (hysteria2)
[+] listening 8388 (ss2022)

  <redacted-blob>
  |             X R A Y   N O D E   I S   R E A D Y          |
  <redacted-blob>

----------------------------------------------------------------------
  Server                 vpn.example.com (20.57.47.235)
  Xray                   26.9.9 (latest)
  Port mode              dedicated
  TLS certificate        self
----------------------------------------------------------------------
  Protocols & ports
    vless-reality          tcp/443
    hysteria2              udp/443
    ss2022                 both/8388
----------------------------------------------------------------------
  Client bundles
    /root/xray-clients/links.txt
    /root/xray-clients/subscription.txt
    /root/xray-clients/client-xray.json
    /root/xray-clients/client-singbox.json
    /root/xray-clients/client-clash.yaml
----------------------------------------------------------------------
  Manage
    xrayctl info        # reprint links / credentials
    xrayctl status      # service + listening ports
    xrayctl check       # health checks
    xrayctl update      # upgrade Xray
    journalctl -u xray -f
----------------------------------------------------------------------
    scp -r root@20.57.47.235:/root/xray-clients .
----------------------------------------------------------------------
  4 warning(s) above — scroll up.
----------------------------------------------------------------------

```

## Service status
```
● xray.service - Xray Service
     Loaded: loaded (/etc/systemd/system/xray.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/xray.service.d
             └─10-donot_touch_single_conf.conf, 10-limits.conf
     Active: active (running) since Wed 2026-09-09 21:00:02 UTC; 2s ago
       Docs: https://github.com/xtls
   Main PID: 3906 (xray)
      Tasks: 9 (limit: 19151)
     Memory: 17.5M (peak: 17.7M)
        CPU: 66ms
     CGroup: /system.slice/xray.service
             └─3906 /usr/local/bin/xray run -config /usr/local/etc/xray/config.json

Sep 09 21:00:02 runnervmlun5p systemd[1]: Started xray.service - Xray Service.
Sep 09 21:00:02 runnervmlun5p xray[3906]: Xray 26.9.9 (Xray, Penetrates Everything.) 52a412d (go1.27.1 linux/amd64)
Sep 09 21:00:02 runnervmlun5p xray[3906]: A unified platform for anti-censorship.
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.755226 [Info] infra/conf/serial: Reading config: &{Name:/usr/local/etc/xray/config.json Format:json}
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.756006 [Warning] infra/conf: REALITY: Choosing "www.microsoft.com" as the target will increase the likelihood of your server's IP being blocked by the GFW
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.756880 [Warning] common/errors: The feature Shadowsocks (with no Forward Secrecy, etc.) is deprecated, not recommended for using and might be removed. Please migrate to VLESS Encryption as soon as possible.
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.772985 [Warning] core: Xray 26.9.9 started
```

## Service journal (last 60 lines)
```
Sep 09 20:59:54 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 20:59:54 runnervmlun5p systemd[1]: Started xray.service - Xray Service.
Sep 09 20:59:54 runnervmlun5p xray[3095]: Xray 26.9.9 (Xray, Penetrates Everything.) 52a412d (go1.27.1 linux/amd64)
Sep 09 20:59:54 runnervmlun5p xray[3095]: A unified platform for anti-censorship.
Sep 09 20:59:54 runnervmlun5p xray[3095]: 2026/09/09 20:59:54.132848 [Info] infra/conf/serial: Reading config: &{Name:/usr/local/etc/xray/config.json Format:json}
Sep 09 20:59:54 runnervmlun5p xray[3095]: 2026/09/09 20:59:54.133955 [Warning] core: Xray 26.9.9 started
Sep 09 20:59:54 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 20:59:55 runnervmlun5p systemd[1]: Stopping xray.service - Xray Service...
Sep 09 20:59:55 runnervmlun5p systemd[1]: xray.service: Deactivated successfully.
Sep 09 20:59:55 runnervmlun5p systemd[1]: Stopped xray.service - Xray Service.
Sep 09 20:59:57 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 20:59:59 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 20:59:59 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 21:00:00 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 21:00:00 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 21:00:00 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 21:00:02 runnervmlun5p systemd[1]: /etc/systemd/system/xray.service:7: Special user nobody configured, this is not safe!
Sep 09 21:00:02 runnervmlun5p systemd[1]: Started xray.service - Xray Service.
Sep 09 21:00:02 runnervmlun5p xray[3906]: Xray 26.9.9 (Xray, Penetrates Everything.) 52a412d (go1.27.1 linux/amd64)
Sep 09 21:00:02 runnervmlun5p xray[3906]: A unified platform for anti-censorship.
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.755226 [Info] infra/conf/serial: Reading config: &{Name:/usr/local/etc/xray/config.json Format:json}
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.756006 [Warning] infra/conf: REALITY: Choosing "www.microsoft.com" as the target will increase the likelihood of your server's IP being blocked by the GFW
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.756880 [Warning] common/errors: The feature Shadowsocks (with no Forward Secrecy, etc.) is deprecated, not recommended for using and might be removed. Please migrate to VLESS Encryption as soon as possible.
Sep 09 21:00:02 runnervmlun5p xray[3906]: 2026/09/09 21:00:02.772985 [Warning] core: Xray 26.9.9 started
```

## Client bundle listing
```
/root/xray-clients:
total 32
drwx------  2 root root 4096 Sep  9 21:00 .
drwx------ 20 root root 4096 Sep  9 21:00 ..
-rw-------  1 root root 1654 Sep  9 21:00 README.txt
-rw-------  1 root root 1826 Sep  9 21:00 client-clash.yaml
-rw-------  1 root root 2739 Sep  9 21:00 client-singbox.json
-rw-------  1 root root 2339 Sep  9 21:00 client-xray.json
-rw-------  1 root root  437 Sep  9 21:00 links.txt
-rw-------  1 root root  584 Sep  9 21:00 subscription.txt
```

## sysctl drop-in (first 20 lines)
```
# ---------------------------------------------------------------------------
# Xray-core proxy tuning (Xray_Deployment.sh) — TCP + QUIC (Hysteria2, XHTTP/3)
# ---------------------------------------------------------------------------

# rmem_max/wmem_max are CEILINGS on what a socket may request, not allocations:
# TCP autotuning uses tcp_rmem/tcp_wmem and ignores these entirely. Raising them
# costs nothing and is required by QUIC (quic-go asks for a large SO_RCVBUF and
# logs "failed to sufficiently increase receive buffer size" when capped).
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
```
