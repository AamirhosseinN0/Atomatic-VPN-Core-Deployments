# ikev2 (ubuntu-22.04) — run 32295263509

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu22 / 6.8.0-1064-azure x86_64
- deploy command: `sudo bash iKev2_Deployment.sh -y --domain vpn.example.com --ip 20.161.70.181`
- deploy status: FAILED

## Verification
```
FAIL: ikev2ctl is installed at /usr/local/sbin/ikev2ctl
FAIL: ikev2ctl check exits 0
    sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
    sudo: a password=<redacted> required
FAIL: ikev2ctl status exits 0
    sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
    sudo: a password=<redacted> required
FAIL: service 'strongswan-swanctl' is active
FAIL: sysctl drop-in /etc/sysctl.d/99-ikev2-vpn.conf exists and is non-empty
FAIL: bundle file /root/ikev2-clients/client1/client1-windows.p12 exists and is non-empty
FAIL: bundle file /root/ikev2-clients/client1/client1-android-cert.sswan exists and is non-empty
FAIL: bundle file /root/ikev2-clients/client1/client1-windows-userpass.ps1 exists and is non-empty
FAIL: bundle file /root/ikev2-clients/client1/README.txt exists and is non-empty
FAIL: bundle file /root/ikev2-clients/client1.zip exists and is non-empty
FAIL: charon binds UDP 500 and 4500 (README troubleshooting section)
```

## Deploy log (last 120 lines)
```

 strongSwan IKEv2 deployment for Ubuntu 22.04 — v1.0.0 
 Windows 10/11 + Android, certificate and username/password 


==> Configuration
Press ENTER to accept the value in brackets.


  compat   – accepts stock Windows defaults (incl. modp1024/3DES). Nothing to configure on the PC.
  balanced – AES-256 + SHA-256 + modp2048/ECP384. Windows needs the generated .ps1 (it applies it for you).
  strict   – AES-256-GCM + ECP384 only. Windows MUST use the generated .ps1.

  Three separate virtual-IP pools are created so you can tell traffic apart:



----------------------------------------------------------------------
  Domain                     vpn.example.com
  Public IP                  20.161.70.181
  Server cert                self
  Key                        RSA-3072
  Crypto profile             compat
  Pool EAP                   10.20.10.0/24
  Pool cert/Windows          10.20.11.0/24
  Pool cert/Android          10.20.12.0/24
  DNS                        1.1.1.1, 8.8.8.8
  IPv6                       no
  Firewall                   auto
  Kernel tuning              yes
----------------------------------------------------------------------
[*] Logging this run to /var/log/ikev2-deploy.log

==> Pre-flight checks
[+] OS: Ubuntu 22.04.5 LTS
[+] Virtualisation: microsoft
[+] Kernel XFRM (IPsec) stack present.
[+] Outbound interface: eth0
[+] Local IPv4 address(es): 10.1.0.216 172.17.0.1 
[+] Public IP confirmed: 20.161.70.181
[!] 20.161.70.181 is not bound to a local interface — assuming NAT / floating IP.
[!] DNS @1.1.1.1: vpn.example.com has no A record.
[!] DNS @8.8.8.8: vpn.example.com has no A record.
[!] DNS @9.9.9.9: vpn.example.com has no A record.
[!] DNS is not fully consistent. Certificate clients can still connect by IP,
[!] but Let's Encrypt issuance will fail until DNS is correct.
[+] UDP/500 is free.
[+] UDP/4500 is free.
[!] Clock is NOT NTP-synchronised. Certificate validation is time sensitive.
[!] chrony will be installed to fix this.
[+] Free disk space on /: 88605 MB


==> Installing packages
[*] apt-get update ...
```

## Service status
```
Unit strongswan-swanctl.service could not be found.
```

## Service journal (last 60 lines)
```
-- No entries --
```

## Client bundle listing
```
ls: cannot access '/root/ikev2-clients': No such file or directory
```

## sysctl drop-in (first 20 lines)
```
head: cannot open '/etc/sysctl.d/99-ikev2-vpn.conf' for reading: No such file or directory
```
