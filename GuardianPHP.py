import re
from flask import Flask, render_template, request
from vulnerability_fixes import vulnerability_fixes

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        php_code = request.files['php_file'].read().decode('utf-8')
        vulnerabilities = analyze_code(php_code)
        return render_template('dashboard.html', vulnerabilities=vulnerabilities)

    return render_template('index.html')


def analyze_code(code):
    """Analyze PHP code for security vulnerabilities"""
    vulnerabilities = []

    vulnerability_checks = {
        "XSS": detect_xss,
        "SQL Injection": detect_sql_injection,
        "Local File Inclusion (LFI)": detect_lfi,
        "Remote File Inclusion (RFI)": detect_rfi,
        "Unrestricted File Upload": detect_unrestricted_file_upload,
        "OS Command Injection": detect_os_command_injection,
        "SSRF": detect_ssrf,
        "IDOR": detect_idor,
        "RCE": detect_rce,
        "Session Fixation": detect_session_fixation,
        "Broken Authentication": detect_broken_authentication,
        "Hardcoded Credentials": detect_hardcoded_credentials,
        "Weak Cryptography": detect_weak_crypto,
        "Security Misconfiguration": detect_security_misconfiguration,
        "Using Components with Known Vulnerabilities": detect_known_vulnerabilities,
        "CSRF": detect_csrf,
        "Insecure Deserialization": detect_insecure_deserialization,
        "Logging & Monitoring Issues": detect_logging_monitoring_issues,
        "Directory Traversal": detect_directory_traversal,
        "XML External Entity (XXE)": detect_xxe,
        "Clickjacking": detect_clickjacking,
        "Unvalidated Redirects": detect_unvalidated_redirects,
        "PHP Object Injection": detect_php_object_injection,
        "PHP Code Injection": detect_php_code_injection,
        "Register Globals Usage": detect_register_globals_usage,
        "Use of Deprecated PHP Functions": detect_deprecated_php_functions,
        "HTTP Header Injection": detect_http_header_injection,
        "Unsafe ini_set() Usage": detect_unsafe_ini_set,
        "Weak Randomness": detect_weak_randomness,
        "Insecure Cookie Handling": detect_insecure_cookie_handling,
        "Exposed Error Messages": detect_exposed_error_messages

    }

    for vuln_name, detection_func in vulnerability_checks.items():
        results = detection_func(code)
        if results:
            vulnerabilities.append({
                "name": vuln_name,
                "issues": results,
                "description": vulnerability_fixes.get(vuln_name, {}).get("description", "No description available."),
                "fix": vulnerability_fixes.get(vuln_name, {}).get("fix", "No fix available.")
            })

    return vulnerabilities


### 🔍 Vulnerability Detection Functions

def detect_xss(code):
    """Detect Cross-Site Scripting (XSS) vulnerabilities."""
    pattern = r'echo\s*\$\w+|print\s*\$\w+|htmlspecialchars\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)


def detect_sql_injection(code):
    """Detect SQL Injection vulnerabilities."""
    pattern = r'\$.*\b(query|exec|prepare|mysql_query|mysqli_query)\b.*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_lfi(code):
    """Detect Local File Inclusion (LFI) vulnerabilities."""
    pattern = r'(?:include|require)(_once)?\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)


def detect_rfi(code):
    """Detect Remote File Inclusion (RFI) vulnerabilities."""
    pattern = r'(?:include|require)(_once)?\s*\(\s*["\']https?:\/\/'
    return detect_vulnerability(code, pattern)


def detect_unrestricted_file_upload(code):
    """Detect Unrestricted File Upload vulnerabilities."""
    pattern = r'\b(move_uploaded_file|copy)\s*\(\s*\$\w+'
    return detect_vulnerability(code, pattern)


def detect_os_command_injection(code):
    """Detect OS Command Injection vulnerabilities."""
    pattern = r'(exec|shell_exec|system|passthru|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_ssrf(code):
    """Detect Server-Side Request Forgery (SSRF) vulnerabilities."""
    pattern = r'(curl_exec|file_get_contents|fopen|fsockopen|readfile)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_idor(code):
    """Detect Insecure Direct Object References (IDOR) vulnerabilities."""
    pattern = r'\$_(GET|POST)\s*\[\s*[\'"]id[\'"]\s*\]'
    return detect_vulnerability(code, pattern)


def detect_rce(code):
    """Detect Remote Code Execution (RCE) vulnerabilities."""
    pattern = r'eval\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)


def detect_session_fixation(code):
    """Detect Session Fixation vulnerabilities."""
    pattern = r'session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_broken_authentication(code):
    """Detect Broken Authentication vulnerabilities."""
    pattern = r'password_verify\s*\(\s*\$\w+'
    return detect_vulnerability(code, pattern)


def detect_hardcoded_credentials(code):
    """Detect Hardcoded Credentials."""
    pattern = r'\b(password|passwd|pwd|api_key|secret)\b\s*=\s*[\'"].*[\'"]'
    return detect_vulnerability(code, pattern)


def detect_weak_crypto(code):
    """Detect Weak Cryptography Usage."""
    pattern = r'(md5|sha1)\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)


def detect_security_misconfiguration(code):
    """Detect Security Misconfiguration vulnerabilities."""
    pattern = r'(error_reporting|display_errors)\s*=\s*["\']?on["\']?'
    return detect_vulnerability(code, pattern)


def detect_known_vulnerabilities(code):
    """Detect use of known vulnerable components."""
    pattern = r'(include|require)(_once)?\s*\(\s*["\'].*\.php["\']\s*\)'
    return detect_vulnerability(code, pattern)


def detect_csrf(code):
    """Detect Cross-Site Request Forgery (CSRF) vulnerabilities."""
    pattern = r'\$_(GET|POST)\s*\[\s*[\'"](csrf_token|token)[\'"]\s*\]'
    return detect_vulnerability(code, pattern)


def detect_insecure_deserialization(code):
    """Detect Insecure Deserialization vulnerabilities."""
    pattern = r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_logging_monitoring_issues(code):
    """Detect Insufficient Logging and Monitoring vulnerabilities."""
    pattern = r'error_log\s*\(\s*\$\w+'
    return detect_vulnerability(code, pattern)


def detect_directory_traversal(code):
    """Detect Directory Traversal vulnerabilities."""
    pattern = r'\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]file[\'"]\s*\]'
    return detect_vulnerability(code, pattern)


def detect_xxe(code):
    """Detect XML External Entity (XXE) vulnerabilities."""
    pattern = r'simplexml_load_string\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)


def detect_clickjacking(code):
    """Detect Clickjacking vulnerabilities."""
    pattern = r'header\s*\(\s*["\']X-Frame-Options:'
    return detect_vulnerability(code, pattern)


def detect_unvalidated_redirects(code):
    """Detect Unvalidated Redirects vulnerabilities."""
    pattern = r'header\s*\(\s*["\']Location:\s*\$\w+'
    return detect_vulnerability(code, pattern)


def detect_php_object_injection(code):
    """Detect PHP Object Injection vulnerabilities."""
    pattern = r'unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    return detect_vulnerability(code, pattern)

def detect_php_code_injection(code):
    """Detect PHP Code Injection vulnerabilities."""
    pattern = r'eval\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)

def detect_register_globals_usage(code):
    """Detect usage of register_globals."""
    pattern = r'ini_set\s*\(\s*[\'"]register_globals[\'"]\s*,\s*[\'"]on[\'"]\s*\)'
    return detect_vulnerability(code, pattern)

def detect_race_condition(code):
    """Detect Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities."""
    pattern = r'file_exists\s*\(\s*\$\w+\s*\)|is_writable\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)

def detect_deprecated_php_functions(code):
    """Detect use of deprecated PHP functions."""
    pattern = r'mysql_\w+\s*\('
    return detect_vulnerability(code, pattern)

def detect_http_header_injection(code):
    """Detect HTTP Header Injection vulnerabilities."""
    pattern = r'header\s*\(\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)

def detect_unsafe_ini_set(code):
    """Detect insecure usage of ini_set()."""
    pattern = r'ini_set\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)

def detect_weak_randomness(code):
    """Detect weak randomness usage."""
    pattern = r'(rand|mt_rand)\s*\(\s*\)'
    return detect_vulnerability(code, pattern)

def detect_insecure_cookie_handling(code):
    """Detect insecure cookie handling."""
    pattern = r'setcookie\s*\(\s*\$\w+\s*,\s*\$\w+\s*\)'
    return detect_vulnerability(code, pattern)

def detect_exposed_error_messages(code):
    """Detect exposed error messages."""
    pattern = r'ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']on["\']\s*\)'
    return detect_vulnerability(code, pattern)



### 🛠️ Helper Functions
def detect_vulnerability(code, pattern):
    """Generalized function for detecting vulnerabilities"""
    matches = re.finditer(pattern, code)
    return [(get_line_number(code, match.start()), get_line_content(code, match.start())) for match in matches]


def get_line_number(code, index):
    """Get line number from index position"""
    return code[:index].count("\n") + 1


def get_line_content(code, index):
    """Get full line content from index position"""
    start = code.rfind("\n", 0, index) + 1
    end = code.find("\n", index)
    return code[start:end]


if __name__ == '__main__':
    app.run(debug=True)
