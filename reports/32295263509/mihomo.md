# mihomo (ubuntu-24.04) — run 32295263509

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu24 / 6.17.0-1022-azure x86_64
- deploy command: `sudo bash Mihomo_Deployment.sh -y --domain vpn.example.com --protocols recommended`
- deploy status: FAILED

## Verification
```
FAIL: mihomoctl is installed at /usr/local/sbin/mihomoctl
FAIL: mihomoctl check exits 0
    sudo: /usr/local/sbin/mihomoctl: command not found
FAIL: mihomoctl status exits 0
    sudo: /usr/local/sbin/mihomoctl: command not found
FAIL: service 'mihomo' is active
FAIL: sysctl drop-in /etc/sysctl.d/99-mihomo.conf exists and is non-empty
FAIL: bundle file /root/mihomo-clients/links.txt exists and is non-empty
FAIL: bundle file /root/mihomo-clients/subscription.txt exists and is non-empty
FAIL: bundle file /root/mihomo-clients/client-mihomo.yaml exists and is non-empty
FAIL: bundle file /root/mihomo-clients/client-singbox.json exists and is non-empty
FAIL: bundle file /root/mihomo-clients/README.txt exists and is non-empty
```

## Deploy log (last 120 lines)
```

 mihomo (Clash.Meta) multi-protocol deployment for Ubuntu 22/24/26 — v1.0.0 
 74 protocol x transport x security combinations; every secret=<redacted> subscription generated 


==> Configuration
Press ENTER to accept the value in brackets.


  stable – the newest tagged release (currently v1.19.30). Recommended.
  alpha  – the rolling Prerelease-Alpha build of the Alpha branch.
           Its listener set is identical to stable today; it moves faster.
  pinned – an exact tag you name.

  Protocol selection. The catalogue holds 74 valid combinations of
  base protocol x transport x security layer.

    all          every combination (74 listeners, 74 ports)
    recommended  a curated 14 that cover every distinct technique
    core         the 8 classics also offered by the sing-box / Xray scripts

  Or a comma list of families and keys, e.g.:
    reality,jls,hysteria2,shadowquic     vless,quic     vless-tcp-reality,tuic
  Families: vless vmess trojan anytls ss snell quic exotic
            reality shadowtls restls jls tls ws grpc xhttp mkcp mekya kcptun
  (run 'Mihomo_Deployment.sh --list-protocols' for every key)
  Selected: 14 listener(s).

  letsencrypt – real cert via certbot (needs the A record pointing here + port 80 free).
  self        – self-signed; clients must allow insecure or pin the fingerprint.

  ShadowTLS / RestLS / JLS / TLS-mirror / ShadowQUIC forward every
  unauthenticated connection to a real site, so an active prober sees
  that site and nothing else. Pick a busy host that is NOT blocked where
  your clients are, and ideally not the same one as the REALITY target.

  Ports selected (free on this host) — 14 listener(s):
    vless-tcp-reality          tcp/30001
    vless-ws-tls               tcp/30005
    vless-grpc-reality         tcp/30010
    vless-xhttp-reality        tcp/30014
    vmess-ws-tls               tcp/31005
    trojan-tcp-tls             tcp/32000
    anytls-tls                 tcp/33000
    ss-plain                   both/34000
    snell-plain                both/35000
    hysteria2                  udp/443
    hysteria2-obfs             udp/36001
    tuic                       udp/8443
    shadowquic                 udp/36004
    sudoku                     tcp/37002

----------------------------------------------------------------------
  Domain / IP              vpn.example.com / 74.235.102.245
  mihomo channel           stable
  Listeners                14
  Bind address             ::
  TLS certificate          letsencrypt
  REALITY SNI              www.microsoft.com
  Decoy site               www.apple.com
  Firewall                 auto
  Kernel tuning            yes
----------------------------------------------------------------------
[*] Logging this run to /var/log/mihomo-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 24.04.4 LTS
[+] Architecture: x86_64 (GOAMD64 level: v2)
[+] Virtualisation: microsoft
[+] Outbound interface: eth0
[+] Detected public IPv4: 74.235.102.245
[!] DNS: vpn.example.com -> <none> (expected 74.235.102.245); Let's Encrypt HTTP-01 may fail.
[+] Decoy reachable: https://www.apple.com
[+] Decoy reachable: https://www.microsoft.com

==> Installing dependencies
[*] apt-get update ...
```

## Service status
```
Unit mihomo.service could not be found.
```

## Service journal (last 60 lines)
```
-- No entries --
```

## Client bundle listing
```
ls: cannot access '/root/mihomo-clients': No such file or directory
```

## sysctl drop-in (first 20 lines)
```
head: cannot open '/etc/sysctl.d/99-mihomo.conf' for reading: No such file or directory
```
