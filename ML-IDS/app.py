from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import os
import time
from datetime import datetime
import ssl
import socket
import whois as pythonwhois
import re
import selenium.webdriver as webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from urllib.parse import urlparse, urljoin
import psutil
import subprocess
import platform
from collections import defaultdict
import warnings
from urllib3.exceptions import InsecureRequestWarning
import requests
from bs4 import BeautifulSoup
import html

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

app = Flask(__name__)
app.secret_key = 'your-secret-key-here-123'  # Change this for production

# Configure Chrome options to suppress errors
chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('--no-sandbox')
chrome_options.add_argument('--disable-dev-shm-usage')
chrome_options.add_argument('--disable-software-rasterizer')
chrome_options.add_argument('--log-level=3')
chrome_options.add_argument('--disable-extensions')
chrome_options.add_argument('--disable-infobars')
chrome_options.add_argument('--disable-notifications')
chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])

# Disable SSL verification warnings
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'wikipedia.org', 'github.com', 'reddit.com'
]

# Payloads for testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "1' ORDER BY 1--",
    "1' UNION SELECT null, table_name FROM information_schema.tables--"
]

# Vulnerability patterns
VULN_PATTERNS = {
    'xss': re.compile(r'(<script.*?>.*?</script>|onerror=|onload=|javascript:)', re.IGNORECASE),
    'sqli': re.compile(r'(union.*select|select.*from|insert into|update.*set|delete from|drop table|'
                       r'or\s+\'\d\'=\'\d\'|or\s+\d=\d|--|\/\*|\*\/)', re.IGNORECASE),
    'lfi': re.compile(r'(\.\.\/|\.\.\\|etc\/passwd|boot\.ini|win\.ini)', re.IGNORECASE),
    'rfi': re.compile(r'(http:\/\/|https:\/\/|ftp:\/\/|file:\/\/)', re.IGNORECASE),
    'command_injection': re.compile(r'(;|\||&|\$\(|\`|\$\{)', re.IGNORECASE)
}

# More conservative severity levels
SEVERITY_LEVELS = {
    'critical': 3,
    'high': 2,
    'medium': 1,
    'low': 0.5,
    'info': 0
}

# Scan history in memory
scan_history = defaultdict(list)


def is_trusted_domain(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    for trusted in TRUSTED_DOMAINS:
        if domain.endswith(trusted):
            return True
    return False


def get_network_info():
    try:
        interfaces = psutil.net_if_addrs()
        interface_stats = psutil.net_if_stats()

        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr:
                try:
                    process = psutil.Process(conn.pid) if conn.pid else None
                    connections.append({
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                        'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                        'status': conn.status,
                        'pid': conn.pid,
                        'process': process.name() if process else 'N/A'
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        arp_table = []
        if platform.system() == 'Windows':
            output = subprocess.check_output(
                ['arp', '-a'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            for line in output.split('\n'):
                if 'dynamic' in line.lower():
                    parts = line.split()
                    if len(parts) >= 3:
                        arp_table.append({
                            'ip': parts[0],
                            'mac': parts[1],
                            'type': parts[2]
                        })
        else:
            output = subprocess.check_output(
                ['arp', '-n'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
            for line in output.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        arp_table.append({
                            'ip': parts[0],
                            'mac': parts[2],
                            'type': parts[1] if len(parts) > 3 else 'unknown'
                        })

        io_counters = psutil.net_io_counters(pernic=True)

        return {
            'interfaces': interfaces,
            'interface_stats': interface_stats,
            'connections': connections,
            'arp_table': arp_table,
            'io_counters': io_counters,
            'success': True
        }
    except Exception as e:
        return {
            'error': str(e),
            'success': False
        }


def crawl_forms_and_inputs(url):
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        forms = []
        for form in soup.find_all('form'):
            form_details = {
                'action': urljoin(url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }

            for input_tag in form.find_all('input'):
                input_details = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', '')
                }
                form_details['inputs'].append(input_details)

            forms.append(form_details)

        return forms

    except Exception as e:
        return {'error': str(e)}


def test_xss(url, forms):
    vulnerabilities = []
    for form in forms:
        for input_field in form['inputs']:
            if input_field['type'] in ('text', 'search', 'textarea', 'password'):
                for payload in XSS_PAYLOADS:
                    try:
                        data = {i['name']: i['value'] for i in form['inputs']}
                        data[input_field['name']] = payload

                        if form['method'] == 'GET':
                            response = requests.get(
                                form['action'], params=data, timeout=10, verify=False)
                        else:
                            response = requests.post(
                                form['action'], data=data, timeout=10, verify=False)

                        # More precise XSS detection
                        if (payload in response.text and
                                not any(escape in response.text for escape in ['&lt;', '&gt;', '&amp;'])):
                            vulnerabilities.append({
                                'type': 'XSS',
                                'severity': 'high',
                                'form_action': form['action'],
                                'input_name': input_field['name'],
                                'payload': html.escape(payload),
                                'evidence': html.escape(response.text[:200] + '...') if len(response.text) > 200 else html.escape(response.text)
                            })

                    except Exception as e:
                        continue

    return vulnerabilities


def test_sqli(url, forms):
    vulnerabilities = []
    for form in forms:
        for input_field in form['inputs']:
            if input_field['type'] in ('text', 'search', 'textarea', 'password'):
                for payload in SQLI_PAYLOADS:
                    try:
                        data = {i['name']: i['value'] for i in form['inputs']}
                        data[input_field['name']] = payload

                        if form['method'] == 'GET':
                            response = requests.get(
                                form['action'], params=data, timeout=10, verify=False)
                        else:
                            response = requests.post(
                                form['action'], data=data, timeout=10, verify=False)

                        error_patterns = [
                            'SQL syntax',
                            'mysql_fetch',
                            'syntax error',
                            'unclosed quotation mark',
                            'ORA-',
                            'Microsoft OLE DB Provider'
                        ]

                        if any(error in response.text for error in error_patterns):
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'severity': 'critical',
                                'form_action': form['action'],
                                'input_name': input_field['name'],
                                'payload': html.escape(payload),
                                'evidence': html.escape(response.text[:200] + '...') if len(response.text) > 200 else html.escape(response.text)
                            })

                    except Exception as e:
                        continue

    return vulnerabilities


def scan_for_vulnerabilities(url, page_source):
    vulnerabilities = []

    # Check for reflected XSS in URLs
    parsed_url = urlparse(url)
    query_params = parsed_url.query
    if query_params:
        for param in query_params.split('&'):
            if '=' in param:
                name, value = param.split('=', 1)
                for payload in XSS_PAYLOADS:
                    if payload in value:
                        vulnerabilities.append({
                            'type': 'Reflected XSS',
                            'severity': 'high',
                            'location': 'URL parameter',
                            'param_name': name,
                            'payload': html.escape(payload),
                            'evidence': f"Found in URL parameter: {name}={html.escape(value)}"
                        })

    # Pattern matching in page source
    for vuln_type, pattern in VULN_PATTERNS.items():
        matches = pattern.findall(page_source)
        if matches:
            # Only report if we find multiple matches to reduce false positives
            if len(matches) > 3:
                unique_matches = list(set(matches))[:5]
                vulnerabilities.append({
                    'type': vuln_type.upper(),
                    'severity': 'medium' if vuln_type in ['xss', 'sqli'] else 'low',
                    'location': 'Page source',
                    'evidence': f"Found {len(matches)} instances of {vuln_type} patterns. Examples: {', '.join(html.escape(m) for m in unique_matches)}"
                })

    return vulnerabilities


def scan_url(url):
    scan_time = datetime.now().strftime('%B %d, %Y at %H:%M:%S')
    scan_id = str(int(time.time()))

    if is_trusted_domain(url):
        result = {
            'result': 'safe',
            'message': ['Trusted domain detected'],
            'scan_time': scan_time,
            'scan_id': scan_id,
            'vulnerabilities': []
        }
        scan_history[scan_id] = result
        return result

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.set_page_load_timeout(30)
        driver.get(url)
        time.sleep(3)

        page_source = driver.page_source.lower()
        current_url = driver.current_url.lower()

        security_checks = {
            'ssl_issues': False,
            'new_domain': False,
            'ip_address': False,
            'hidden_elements': False,
            'obfuscated_code': False,
            'suspicious_scripts': False,
            'phishing_keywords': False,
            'insecure_forms': False,
            'foreign_iframes': False
        }
        messages = []
        red_flags = 0
        vulnerabilities = []

        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # SSL Certificate Check
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        # Only raise if it's an ecommerce/payment site
                        if any(kw in url.lower() for kw in ['checkout', 'payment', 'login', 'signin']):
                            security_checks['ssl_issues'] = True
                            messages.append(
                                "Missing SSL certificate on sensitive page")
                            red_flags += 3
                            vulnerabilities.append({
                                'type': 'SSL Issue',
                                'severity': 'critical',
                                'evidence': 'Missing SSL certificate on sensitive page'
                            })

                    not_after = datetime.strptime(
                        cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        security_checks['ssl_issues'] = True
                        messages.append("Expired SSL certificate")
                        red_flags += 3
                        vulnerabilities.append({
                            'type': 'SSL Issue',
                            'severity': 'critical',
                            'evidence': 'Expired SSL certificate'
                        })

                    cert_domains = []
                    for name in cert.get('subjectAltName', []):
                        cert_domains.append(name[1].lower())
                    if domain.lower() not in cert_domains:
                        security_checks['ssl_issues'] = True
                        messages.append("SSL domain mismatch")
                        red_flags += 3
                        vulnerabilities.append({
                            'type': 'SSL Issue',
                            'severity': 'critical',
                            'evidence': 'SSL domain mismatch'
                        })
        except Exception as e:
            security_checks['ssl_issues'] = True
            messages.append(f"SSL error: {str(e)}")
            red_flags += 3
            vulnerabilities.append({
                'type': 'SSL Issue',
                'severity': 'critical',
                'evidence': f"SSL error: {str(e)}"
            })

        # Domain Age Check
        try:
            domain_info = pythonwhois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 7:  # Only flag very new domains
                    security_checks['new_domain'] = True
                    messages.append(
                        f"Very new domain ({domain_age} days) detected")
                    red_flags += 1
                    vulnerabilities.append({
                        'type': 'New Domain',
                        'severity': 'low',
                        'evidence': f"Domain is only {domain_age} days old"
                    })
        except Exception:
            pass

        # IP Address in URL
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            security_checks['ip_address'] = True
            messages.append("IP address in URL")
            red_flags += 1
            vulnerabilities.append({
                'type': 'IP Address in URL',
                'severity': 'medium',
                'evidence': 'URL contains IP address instead of domain name'
            })

        # Hidden Elements
        hidden_count = driver.execute_script(
            "return document.querySelectorAll('input[type=hidden], div[style*=\"display:none\"], "
            "div[style*=\"visibility:hidden\"], *[hidden]').length"
        )
        if hidden_count > 5:  # Only flag if excessive hidden elements
            security_checks['hidden_elements'] = True
            messages.append(f"Many hidden elements ({hidden_count}) detected")
            red_flags += 1
            vulnerabilities.append({
                'type': 'Hidden Elements',
                'severity': 'low',
                'evidence': f'Found {hidden_count} hidden elements on the page'
            })

        # Obfuscated Code
        obfuscation_patterns = [
            r'eval\s*\(', r'unescape\s*\(', r'escape\s*\(',
            r'fromCharCode\s*\(', r'exec\s*\(', r'constructor\s*\(',
            r'document\.write\s*\(', r'window\.location\s*='
        ]
        obfuscation_count = sum(1 for pattern in obfuscation_patterns
                                if re.search(pattern, page_source))
        if obfuscation_count > 3:  # Only flag if multiple patterns found
            security_checks['obfuscated_code'] = True
            messages.append(
                f"Multiple obfuscation patterns detected ({obfuscation_count})")
            red_flags += 2
            vulnerabilities.append({
                'type': 'Obfuscated Code',
                'severity': 'medium',
                'evidence': f'Found {obfuscation_count} instances of obfuscated code patterns'
            })

        # Suspicious Scripts
        suspicious_scripts = driver.execute_script(
            "return Array.from(document.scripts).filter(s => { "
            "const src = s.src || 'inline'; "
            "return src !== 'inline' && !src.startsWith('http') && !src.startsWith('https'); "
            "}).length"
        )
        if suspicious_scripts > 0:
            security_checks['suspicious_scripts'] = True
            messages.append("Suspicious scripts detected")
            red_flags += 2
            vulnerabilities.append({
                'type': 'Suspicious Scripts',
                'severity': 'high',
                'evidence': 'Found scripts with suspicious sources'
            })

        # Phishing Keywords
        phishing_terms = [
            'login', 'secure', 'verify', 'account', 'password',
            'update', 'banking', 'confirm', 'validate', 'credentials',
            'sign in', 'authentication', 'security question', 'ssn', 'credit card'
        ]
        keyword_matches = sum(1 for term in phishing_terms
                              if re.search(rf'\b{re.escape(term)}\b', page_source))
        if keyword_matches >= 5:  # Only flag if many keywords found
            security_checks['phishing_keywords'] = True
            messages.append(
                f"Multiple phishing terms detected ({keyword_matches})")
            red_flags += 1
            vulnerabilities.append({
                'type': 'Phishing Keywords',
                'severity': 'medium',
                'evidence': f'Found {keyword_matches} phishing-related keywords'
            })

        # Insecure Forms
        insecure_forms = driver.execute_script(
            "return Array.from(document.forms).filter(f => { "
            "const hasPassword = f.querySelector('input[type=password]') !== null; "
            "const isSecure = f.action.startsWith('https://') || "
            "f.action === '' || f.action.startsWith('//'); "
            "return hasPassword && !isSecure; "
            "}).length"
        )
        if insecure_forms > 0:
            security_checks['insecure_forms'] = True
            messages.append(f"Insecure forms detected ({insecure_forms})")
            red_flags += 2
            vulnerabilities.append({
                'type': 'Insecure Forms',
                'severity': 'high',
                'evidence': 'Found forms with password fields submitted over insecure HTTP'
            })

        # Foreign Iframes
        foreign_iframes = driver.execute_script(
            "return Array.from(document.querySelectorAll('iframe')).filter(i => { "
            "const src = i.src || ''; "
            "return src && !src.startsWith('http') && !src.startsWith('https'); "
            "}).length"
        )
        if foreign_iframes > 0:
            security_checks['foreign_iframes'] = True
            messages.append(f"Foreign iframes detected ({foreign_iframes})")
            red_flags += 1
            vulnerabilities.append({
                'type': 'Foreign Iframes',
                'severity': 'medium',
                'evidence': 'Found iframes with suspicious sources'
            })

        # Additional vulnerability scanning
        forms = crawl_forms_and_inputs(url)
        if isinstance(forms, dict) and 'error' in forms:
            messages.append(f"Form crawling error: {forms['error']}")
        else:
            # Test for XSS vulnerabilities
            xss_vulns = test_xss(url, forms)
            vulnerabilities.extend(xss_vulns)

            # Test for SQL injection vulnerabilities
            sqli_vulns = test_sqli(url, forms)
            vulnerabilities.extend(sqli_vulns)

            # Scan page source for vulnerabilities
            source_vulns = scan_for_vulnerabilities(url, page_source)
            vulnerabilities.extend(source_vulns)

            # Update red flags based on found vulnerabilities
            for vuln in vulnerabilities:
                red_flags += SEVERITY_LEVELS.get(vuln['severity'], 0)

        driver.quit()

        # More conservative classification
        if red_flags >= 4:  # Only mark as unsafe if we have strong evidence
            result = 'unsafe'
        elif red_flags > 0:
            result = 'suspicious'
        else:
            result = 'safe'
            messages.append('No security issues detected')

        scan_result = {
            'result': result,
            'message': messages,
            'scan_time': scan_time,
            'scan_id': scan_id,
            'security_checks': security_checks,
            'vulnerabilities': vulnerabilities,
            'url': url,
            'red_flags': red_flags  # For debugging purposes
        }

        scan_history[scan_id] = scan_result
        return scan_result

    except WebDriverException as e:
        error_result = {
            'result': 'error',
            'message': [f"WebDriver error: {e}"],
            'scan_time': scan_time,
            'scan_id': scan_id
        }
        scan_history[scan_id] = error_result
        return error_result
    except Exception as e:
        error_result = {
            'result': 'error',
            'message': [f"An error occurred: {e}"],
            'scan_time': scan_time,
            'scan_id': scan_id
        }
        scan_history[scan_id] = error_result
        return error_result


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan_history')
def show_scan_history():
    return render_template('scan_history.html', scans=scan_history)


@app.route('/scan_details/<scan_id>')
def scan_details(scan_id):
    scan = scan_history.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template('scan_details.html', scan=scan)


@app.route('/choose_scan', methods=['POST'])
def choose_scan():
    scan_type = request.form.get('type')

    if scan_type == 'file':
        return render_template('upload_file.html')
    elif scan_type == 'url':
        return render_template('scan_url.html')
    elif scan_type == 'network':
        network_info = get_network_info()
        if not network_info['success']:
            return render_template('network_scan_results.html',
                                   error=network_info['error'],
                                   has_data=False)
        return render_template('network_scan_results.html',
                               interfaces=network_info['interfaces'],
                               interface_stats=network_info['interface_stats'],
                               connections=network_info['connections'],
                               arp_table=network_info['arp_table'],
                               io_counters=network_info['io_counters'],
                               has_data=True)
    else:
        return render_template('index.html', error="Invalid scan type selected")


@app.route('/scan_url', methods=['POST'])
def handle_url_scan():
    url = request.form.get('url')
    if not url:
        return render_template('scan_url.html', error="URL is required")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    scan_result = scan_url(url)
    return render_template('result.html', result=scan_result)


@app.route('/get_network_data')
def get_network_data():
    network_info = get_network_info()
    if not network_info['success']:
        return jsonify({'error': network_info['error']}), 500
    return jsonify({
        'interfaces': network_info['interfaces'],
        'connections': network_info['connections'],
        'arp_table': network_info['arp_table'],
        'io_counters': network_info['io_counters']
    })


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
