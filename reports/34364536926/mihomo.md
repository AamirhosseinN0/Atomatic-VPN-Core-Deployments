# mihomo (ubuntu-24.04) — run 34364536926

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu24 / 6.17.0-1022-azure x86_64
- deploy command: `sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols recommended`
- deploy status: OK

## Verification
```
PASS: mihomoctl is installed at /usr/local/sbin/mihomoctl
PASS: mihomoctl check exits 0
PASS: mihomoctl status exits 0
PASS: service 'mihomo' is active
PASS: sysctl drop-in /etc/sysctl.d/99-mihomo.conf exists and is non-empty
PASS: bundle file /root/mihomo-clients/links.txt exists and is non-empty
PASS: bundle file /root/mihomo-clients/subscription.txt exists and is non-empty
PASS: bundle file /root/mihomo-clients/client-mihomo.yaml exists and is non-empty
PASS: bundle file /root/mihomo-clients/client-singbox.json exists and is non-empty
PASS: bundle file /root/mihomo-clients/README.txt exists and is non-empty
```

## Deploy log (last 120 lines)
```
----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 172.208.13.55
  mihomo channel           stable
  Listeners                14
  Bind address             ::
  Client TUN MTU           1280
  TLS certificate          letsencrypt
  REALITY SNI              www.microsoft.com
  Camouflage decoy         www.apple.com:443
  TCP Brutal               no
  Firewall                 auto
  Kernel tuning            yes
----------------------------------------------------------------------
[*] Logging this run to /var/log/mihomo-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 24.04.4 LTS
[+] Architecture: x86_64 (GOAMD64 level: v2)
[+] Virtualisation: microsoft
[+] Outbound interface: eth0
[+] Detected public IPv4: 172.208.13.55
[!] DNS: vpn.example.com -> <none> (expected 172.208.13.55); Let's Encrypt HTTP-01 may fail.
[+] Decoy reachable: https://www.apple.com
[+] Decoy reachable: https://www.microsoft.com

==> Installing dependencies
[*] apt-get update ...

==> Installing mihomo (stable)
[*] Downloading https://github.<redacted-blob>.19.30/mihomo-linux-amd64-v2-v1.19.30.gz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 18.0M  100 18.0M    0     0  74.7M      0 --:--:-- --:--:-- --:--:-- 74.7M
[+] mihomo v1.19.30 installed to /usr/local/bin/mihomo (asset: linux-amd64-v2, service user: mihomo).

==> Generating credentials
[+] Secrets ready.

==> TLS certificate (letsencrypt)
[!] Let's Encrypt issuance failed (DNS not pointing here, or :80 blocked).
[!] Falling back to a self-signed certificate.
[+] Self-signed certificate written to /etc/mihomo/cert.
[!] Clients must set skip-cert-verify: true, or pin fingerprint: <redacted-blob>
[*] Camouflage decoy: www.apple.com:443 (external).
[+] Decoy www.apple.com:443 negotiates TLS 1.3.

==> Writing /etc/mihomo/config.yaml
[+] Config accepted by `mihomo -t` (14 listeners).

==> Kernel / sysctl tuning
[+] BBR available and enabled.
[+] Applied sysctl drop-in and confirmed LimitNOFILE for mihomo.

==> Firewall
[*] Backend: iptables   tcp: 10 port(s)   udp: 6 port(s)
[+] iptables rules applied.

==> Wire-amplification counters
[+] Metering 16 counter pair(s); read them with `mihomoctl amplification`.

==> Starting services
[+] mihomo is running.

==> Generating client bundles
[+] Bundles written to /root/mihomo-clients  (11 share link(s), 14 YAML node(s))
[+] Installed as /usr/local/sbin/mihomoctl

==> Health checks
[+] mihomo: v1.19.30
[+] config.yaml valid
[+] mihomo.service active
[+] all 14 listener(s) bound

  <redacted-blob>
  |           M I H O M O   N O D E   I S   R E A D Y        |
  <redacted-blob>

----------------------------------------------------------------------
  Server                 vpn.example.com (172.208.13.55)
  mihomo                 v1.19.30 (stable)
  Listeners              14 of 81 possible combinations
  TLS certificate        self
----------------------------------------------------------------------
  Protocols & ports
    vless-tcp-reality            tcp/30001
    vless-ws-tls                 tcp/30005
    vless-grpc-reality           tcp/30010
    vless-xhttp-reality          tcp/30014
    vmess-ws-tls                 tcp/31005
    trojan-tcp-tls               tcp/32000
    anytls-tls                   tcp/33000
    ss-plain                     both/34000
    snell-plain                  both/35000
    hysteria2                    udp/443
    hysteria2-obfs               udp/36001
    tuic                         udp/8443
    shadowquic                   udp/36004
    sudoku                       tcp/37002
----------------------------------------------------------------------
  Client bundles
    /root/mihomo-clients/client-mihomo.yaml <- all 14 proxy nodes
    /root/mihomo-clients/links.txt
    /root/mihomo-clients/subscription.txt
    /root/mihomo-clients/client-singbox.json
    /root/mihomo-clients/README.txt
----------------------------------------------------------------------
  Manage
    mihomoctl info        # reprint links / credentials
    mihomoctl status      # service + listening ports
    mihomoctl check       # health checks
    mihomoctl amplification  # wire bytes vs payload, per port
    mihomoctl update      # upgrade mihomo
    journalctl -u mihomo -f
----------------------------------------------------------------------
    scp -r root@172.208.13.55:/root/mihomo-clients .
----------------------------------------------------------------------
  4 warning(s) above — scroll up.
----------------------------------------------------------------------

```

## Service status
```
● mihomo.service - mihomo Daemon (server node)
     Loaded: loaded (/etc/systemd/system/mihomo.service; enabled; preset: enabled)
    Drop-In: /etc/systemd/system/mihomo.service.d
             └─10-limits.conf
     Active: active (running) since Wed 2026-09-09 14:35:15 UTC; 4s ago
       Docs: https://wiki.metacubex.one
   Main PID: 4137 (mihomo)
      Tasks: 8 (limit: 19151)
     Memory: 17.6M (peak: 17.8M)
        CPU: 212ms
     CGroup: /system.slice/mihomo.service
             └─4137 /usr/local/bin/mihomo -d /etc/mihomo

Sep 09 14:35:15 runnervmejwal systemd[1]: Started mihomo.service - mihomo Daemon (server node).
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.114341973Z" level=info msg="Start initial configuration in progress"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115082951Z" level=info msg="Geodata Loader mode: memconservative"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115117945Z" level=info msg="Geosite Matcher implementation: succinct"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115257193Z" level=info msg="Initial configuration complete, total time: 0ms"
```

## Service journal (last 60 lines)
```
Sep 09 14:35:15 runnervmejwal systemd[1]: Started mihomo.service - mihomo Daemon (server node).
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.114341973Z" level=info msg="Start initial configuration in progress"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115082951Z" level=info msg="Geodata Loader mode: memconservative"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115117945Z" level=info msg="Geosite Matcher implementation: succinct"
Sep 09 14:35:15 runnervmejwal mihomo[4137]: time="2026-09-09T14:35:15.115257193Z" level=info msg="Initial configuration complete, total time: 0ms"
```

## Client bundle listing
```
/root/mihomo-clients:
total 48
drwx------  2 root root  4096 Sep  9 14:35 .
drwx------ 20 root root  4096 Sep  9 14:35 ..
-rw-------  1 root root  8445 Sep  9 14:35 README.txt
-rw-------  1 root root 11039 Sep  9 14:35 client-mihomo.yaml
-rw-------  1 root root  5152 Sep  9 14:35 client-singbox.json
-rw-------  1 root root  2326 Sep  9 14:35 links.txt
-rw-------  1 root root  3104 Sep  9 14:35 subscription.txt
```

## sysctl drop-in (first 20 lines)
```
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

```
