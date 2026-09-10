# ikev2 (ubuntu-22.04) — run 34534610173

- commit: [`<redacted-blob>`](https://github.com/AamirhosseinN0/Atomatic-VPN-Core-<redacted-blob>)
- image: ubuntu22 / 6.8.0-1064-azure x86_64
- deploy command: `sudo bash iKev2_Deployment.sh -y --domain vpn.example.com --ip 172.210.149.50`
- deploy status: OK

## Verification
```
PASS: ikev2ctl is installed at /usr/local/sbin/ikev2ctl
PASS: ikev2ctl check exits 0
PASS: ikev2ctl status exits 0
PASS: service 'strongswan-swanctl' is active
PASS: sysctl drop-in /etc/sysctl.d/99-ikev2-vpn.conf exists and is non-empty
PASS: bundle file /root/ikev2-clients/client1/client1-windows.p12 exists and is non-empty
PASS: bundle file /root/ikev2-clients/client1/client1-android-cert.sswan exists and is non-empty
PASS: bundle file /root/ikev2-clients/client1/client1-windows-userpass.ps1 exists and is non-empty
PASS: bundle file /root/ikev2-clients/client1/README.txt exists and is non-empty
PASS: bundle file /root/ikev2-clients/client1.zip exists and is non-empty
PASS: charon binds UDP 500 and 4500 (README troubleshooting section)
```

## Deploy log (last 120 lines)
```
            organizationName          = vpn.example.com VPN
            commonName                = vpn.example.com
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                DE:86:BE:59:A5:F2:FB:14:F6:67:C8:97:E6:08:7A:EF:CB:67:50:B9
            X509v3 Authority Key Identifier: 
                54:14:26:49:87:A4:69:81:55:46:57:02:9B:0F:BB:42:E8:26:7B:0A
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, 1.3.6.1.5.5.8.2.2
            X509v3 Subject Alternative Name: 
                DNS:vpn.example.com, DNS:172.210.149.50, IP Address:172.210.149.50
Certificate is to be certified until Sep  9 21:54:14 2031 GMT (1825 days)

Write out database with 1 new entries
Data Base Updated
[+] Server certificate issued (1825 days).

==> charon daemon settings
[+] Wrote /etc/strongswan.d/99-ikev2-vpn.conf

==> swanctl configuration
[+] Wrote /etc/swanctl/conf.d/10-pools.conf, 20-connections.conf, 30-secrets.conf

==> Kernel / sysctl tuning
[+] BBR available and enabled.
[+] ip_forward=1  rp_filter=0  cc=bbr

==> Firewall
[*] Backend: iptables
[+] Rules saved (netfilter-persistent).
[+] iptables rules installed on eth0 (SSH port 22 explicitly allowed).

==> Starting strongSwan
[+] Disabled legacy strongswan-starter.service (swanctl/charon-systemd is used).
[*] Using unit: strongswan-swanctl.service
[+] strongswan-swanctl.service is active.
[+] Installed as /usr/local/sbin/ikev2ctl

==> Creating client 'client1'  (platform=both, auth=both)
[+] EAP-MSCHAPv2 user created: client1
[+] Windows PKCS#12 written (encryption: PBE-SHA1-3DES).
[+] Bundle: /root/ikev2-clients/client1.zip

----------------------------------------------------------------------
  Client "client1" is ready
  Files: /root/ikev2-clients/client1
  EAP username / password=<redacted> client1 / FwVJtGM9F9DkFx3NsZlh
  Windows .p12 password   : 9Yo5qZNRGvb7lHYCJsWa
  Android .p12 password   : risMQ2NAdH8BkLZHWrfq
----------------------------------------------------------------------
  Copy the bundle to your PC with, e.g.:
    scp root@172.210.149.50:/root/ikev2-clients/client1.zip .


==> Verification
[+] strongswan-swanctl.service running
[+] listening on UDP/500 (charon-systemd)
[+] listening on UDP/4500 (charon-systemd)
[+] plugin eap-mschapv2 loaded
[+] MD4 via the OpenSSL legacy provider, active on strongswan-swanctl.service
[+] 3 connections loaded: ikev2-eap ikev2-cert-android ikev2-cert-win 
[+] virtual IP pools loaded
[+] server cert SAN contains DNS:vpn.example.com
[+] server cert SAN contains DNS:172.210.149.50 (lets Windows connect by IP)
[+] server cert EKU includes serverAuth
[+] server cert EKU includes ikeIntermediate
[+] server cert valid until Sep  9 21:54:14 2031 GMT
[+] server key matches the server certificate
[+] CA certificate loaded into charon (vpn.example.com VPN Root CA)
[+] net.ipv4.ip_forward = 1
[+] NAT/MASQUERADE rule present
[+] firewall allows UDP/500
[!] DNS: vpn.example.com has no A record
[+] clock synchronised

[+] All critical checks passed.

  <redacted-blob>
  |            I K E v 2   V P N   I S   R E A D Y           |
  <redacted-blob>

----------------------------------------------------------------------
  Server                   vpn.example.com (172.210.149.50)
  Protocol                 IKEv2/IPsec — UDP 500 + UDP 4500, ESP
  Server cert              private=<redacted> (import ca.crt on clients)
  Key                      RSA-3072
  Crypto profile           compat
  IKE proposals            aes256-sha256-modp2048,aes256-sha384-modp2048,aes256-sha1-mo...
  ESP proposals            aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1,aes256gc...
----------------------------------------------------------------------
  Pools
    username/password=<redacted>        10.20.10.0/24
    certificate / Windows          10.20.11.0/24
    certificate / Android          10.20.12.0/24
    DNS pushed to clients          1.1.1.1, 8.8.8.8
----------------------------------------------------------------------
  First client "client1"
    bundle directory               /root/ikev2-clients/client1
    zip archive                    /root/ikev2-clients/client1.zip
    EAP username                   client1
    EAP password                   FwVJtGM9F9DkFx3NsZlh
----------------------------------------------------------------------
  Manage the server
    ikev2ctl add-client            # new Windows / Android client
    ikev2ctl list-clients          # users, certs, bundles
    ikev2ctl revoke-client --name X
    ikev2ctl status                # live sessions
    ikev2ctl check                 # re-run every health check
    journalctl -u strongswan-swanctl.service -f   /   tail -f /var/log/strongswan.log
----------------------------------------------------------------------
  Get the bundle onto your PC
    scp root@172.210.149.50:/root/ikev2-clients/client1.zip .
----------------------------------------------------------------------
  8 warning(s) were printed above — scroll up and read them.
----------------------------------------------------------------------

```

## Service status
```
● strongswan.service - strongSwan IPsec IKEv1/IKEv2 daemon using swanctl
     Loaded: loaded (/lib/systemd/system/strongswan.service; enabled; vendor preset: enabled)
    Drop-In: /etc/systemd/system/strongswan.service.d
             └─10-openssl-legacy.conf
     Active: active (running) since Thu 2026-09-10 21:54:16 UTC; 6s ago
    Process: 4024 ExecStartPost=/usr/sbin/swanctl --load-all --noprompt (code=exited, status=0/SUCCESS)
   Main PID: 4007 (charon-systemd)
     Status: "charon-systemd running, strongSwan 5.9.5, Linux 6.8.0-1064-azure, x86_64"
      Tasks: 17 (limit: 19154)
     Memory: 5.2M
        CPU: 638ms
     CGroup: /system.slice/strongswan.service
             └─4007 /usr/sbin/charon-systemd

Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: 11[CFG] loaded certificate 'C=XX, O=vpn.example.com VPN, CN=vpn.example.com VPN Root CA'
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: loaded certificate 'C=XX, O=vpn.example.com VPN, CN=vpn.example.com VPN Root CA'
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: 01[CFG] loaded certificate 'C=XX, O=vpn.example.com VPN, CN=vpn.example.com VPN Root CA'
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: 01[LIB]   crl #02 is newer - existing crl #01 replaced
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: loaded certificate 'C=XX, O=vpn.example.com VPN, CN=vpn.example.com VPN Root CA'
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]:   crl #02 is newer - existing crl #01 replaced
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: 09[CFG] loaded RSA private=<redacted>
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: loaded RSA private=<redacted>
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: 11[CFG] loaded EAP shared key with id 'eap-client1' for: 'client1'
Sep 10 21:54:21 runnervm7g52i charon-systemd[4007]: loaded EAP shared key with id 'eap-client1' for: 'client1'
```

## Service journal (last 60 lines)
```
-- No entries --
```

## Client bundle listing
```
/root/ikev2-clients:
total 36
drwx------  3 root root  4096 Sep 10 21:54 .
drwx------ 25 root root  4096 Sep 10 21:54 ..
drwx------  2 root root  4096 Sep 10 21:54 client1
-rw-r--r--  1 root root 24496 Sep 10 21:54 client1.zip

/root/ikev2-clients/client1:
total 60
drwx------ 2 root root 4096 Sep 10 21:54 .
drwx------ 3 root root 4096 Sep 10 21:54 ..
-rw------- 1 root root 4014 Sep 10 21:54 README.txt
-rw-r--r-- 1 root root 1651 Sep 10 21:54 ca.crt
-rw------- 1 root root 8549 Sep 10 21:54 client1-android-cert.sswan
-rw------- 1 root root   21 Sep 10 21:54 client1-android-p12-password.txt
-rw------- 1 root root 2082 Sep 10 21:54 client1-android-userpass.sswan
-rw------- 1 root root 4856 Sep 10 21:54 client1-android.p12
-rw-r--r-- 1 root root 3065 Sep 10 21:54 client1-windows-cert.ps1
-rw-r--r-- 1 root root 2982 Sep 10 21:54 client1-windows-userpass.ps1
-rw------- 1 root root 4848 Sep 10 21:54 client1-windows.p12
```

## sysctl drop-in (first 20 lines)
```
# <redacted-blob>
# Kernel tuning for the strongSwan IKEv2 gateway (iKev2_Deployment.sh)
# <redacted-blob>

# --- routing: mandatory for a VPN gateway ---
net.ipv4.ip_forward = 1

# --- IPv6 forwarding disabled ---
net.ipv6.conf.all.forwarding = 0

# --- IPsec + policy routing needs loose/off reverse-path filtering, otherwise
#     decapsulated packets arriving on the wrong interface get dropped ---
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# --- do not act as a router for ICMP redirects (hardening) ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
```
