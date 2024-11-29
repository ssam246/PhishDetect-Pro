# **PhishDetect Pro**

PhishDetect Pro is a powerful Python-based tool designed to detect and analyze phishing emails. It examines email headers and bodies for potential phishing indicators, including suspicious URLs, redirection, and spelling errors. This tool provides detailed insights to help identify and mitigate phishing attempts.

---

## **Features**

- **Header Analysis**:  
  Extracts and displays key email header fields such as `From`, `To`, `Date`, `Subject`, `SPF`, `DKIM`, and more.

- **URL Analysis**:  
  Detects URLs in the email body, checks for redirection, analyzes protocols, and flags shortened URLs.

- **Spelling Error Detection**:  
  Identifies spelling mistakes in the email body content and suggests corrections.

- **Security Indicator Analysis**:  
  Highlights authentication results (SPF, DKIM signatures) and message integrity headers.

- **User-Friendly CLI**:  
  Simple and intuitive command-line arguments for analyzing headers and email bodies.

---

## **Prerequisites**

- **Python 3.8 or higher** installed on your system.
- Required libraries: Install dependencies using:
  ```bash
  pip install -r requirements.txt
  ```

---

## **Installation**

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ssam246/PhishDetect-Pro
   cd phishdetect-pro
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## **Usage**

### **Analyze Email Header and Body**:
Run the tool with an email header and body file:
```bash
python3 phishdetect.py -H header.txt -E email.txt
```

### **Command-Line Options**:
| Option          | Description                                           |
|------------------|-------------------------------------------------------|
| `-H, --header`  | Path to the email header file.                        |
| `-E, --email`   | Path to the email body file.                          |

---

## **Output Example**

### **Header Analysis**:
```
PhishDetect Pro - Email Phishing Analyzer
        By Stephen Sam

[[:]] Analyzing Email Header...

[+] From: sender@example.com
[+] To: recipient@example.com
[+] Date: Mon, 26 Sep 2024 10:00:00 +0000
[+] Subject: Important Account Update
[+] Message-ID: <12345@example.com>
[+] Received-SPF: pass
[+] DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=default;

```

### **Body Analysis**:
```
[[:]] Analyzing Email Body...

[!] URL Identified: http://example.com/login
[!] Redirection detected: http://phishing.com/fake-login
[!] URL Shortening Identified! Domain: bit.ly
[!] Spelling Error: acount -> account
```

---

## **Error Handling**

- **Invalid File**:  
  If the header or email file is missing or invalid:
  ```
  Error: Invalid file type or path.
  ```

- **Python Version**:  
  If Python version is below 3.8:
  ```
  Python 3.8 or higher is required.
  ```

---

## **Contributing**

Contributions are welcome!  
To contribute:
1. Fork the repository.
2. Implement your changes or fix issues.
3. Submit a pull request with a detailed description of your improvements.

---

## **License**

This project is licensed under the **MIT License**.  

---

## **Disclaimer**

This tool is intended for **educational and ethical purposes only**.  
The author does not condone the use of this tool for illegal or malicious activities.  
Always ensure you have proper authorization before analyzing email content.

---

### **Made with 💻 and 🛡️ by Stephen Sam**
