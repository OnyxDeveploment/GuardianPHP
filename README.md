# GuardianPHP - PHP Security Scanner 🔍🛡️

**GuardianPHP** is an advanced **PHP vulnerability scanner** that helps developers identify security weaknesses in PHP applications. It uses **static analysis** and **regex-based detection** to uncover common vulnerabilities such as **SQL Injection, XSS, Remote Code Execution (RCE), and more.**  

---

## ⚡ **Features**
✔ **Static Code Analysis** – Detects security flaws in PHP code by analyzing its structure, variable usage, and function calls.  
✔ **Comprehensive Vulnerability Detection** – Identifies various security risks, including **SQL Injection, XSS, RCE, LFI, OS Command Injection, and more.**  
✔ **Web-Based Interface** – Upload and analyze PHP files through a **user-friendly web UI** at `http://127.0.0.1:5000`.  
✔ **Detailed Severity Reporting** – Classifies vulnerabilities as **Critical, High, Medium, or Low**, making it easy to prioritize fixes.  
✔ **Real-Time Scanning** – Provides instant results with affected **code snippets and recommended fixes.**  
✔ **Customizable & Extensible** – Developers can extend detection rules to include new security threats.  

---

## 🔍 **Detected Vulnerabilities**
The scanner detects a wide range of PHP security flaws, including:

### 🛑 **Critical**
- Remote Code Execution (RCE)
- OS Command Injection

### ⚠️ **High**
- SQL Injection
- Cross-Site Scripting (XSS)
- Local File Inclusion (LFI)
- Remote File Inclusion (RFI)
- Server-Side Request Forgery (SSRF)

### 🟡 **Medium**
- Hardcoded Credentials
- Weak Cryptography
- Session Fixation
- Broken Authentication

### 🟢 **Low**
- Security Misconfiguration
- Clickjacking
- Directory Traversal
- Deprecated PHP Functions

---

## 🛠️ **Requirements**
- Python **>= 3.0**
- Flask **(For Web UI)**

---


## Installation

1.  Clone the repository:
    
     ```bash
       git clone https://github.com/OnyxDeveploment/GuardianPHP.git
     ```    
     
2.  Change to the project directory:
        
     ```bash
      cd GuardianPHP/ 
     ```
    
3.  Install the dependencies using Composer:
    
    ```bash
    pip install Flask
    ```
    

## Usage

1.  Navigate to the project directory.
    
2.  Run the vulnerability scanner command, providing the path to the PHP application you want to scan:
    
    
    ```bash
    python GuardianPHP.py
    ```
    

    
3.  Open your browser and go to: http://127.0.0.1:5000

4. Upload your PHP file, and the tool will display vulnerabilities along with recommended fixes.

5.  Once the scanning process is complete, the tool will generate a report file containing information about the identified vulnerabilities.

---

## 🤝 Contributing

Contributions to this project are welcome! If you encounter any issues or have ideas for improvements, please **open an issue** or submit a **pull request** on the GitHub repository.

When contributing:
- Follow the existing coding style.
- Include appropriate tests for any new features or bug fixes.
- Document any major changes in the codebase.

---

## 📜 License

This project is licensed under the **MIT License**. Feel free to use, modify, and distribute this code for both commercial and non-commercial purposes.

---

### 🔗 Connect with Us
For support or feature requests, open an issue on **GitHub** or contact the developers.

🚀 **Happy Secure Coding with GuardianPHP!**
