from flask import Flask, render_template, request, jsonify
import os
import ipaddress
import http.client
import secrets
from datetime import datetime
import ssl
import socket
try:
    import whois as pythonwhois
except ImportError:
    pythonwhois = None
import re
from urllib.parse import urlparse, urljoin
try:
    import psutil
except ImportError:
    psutil = None
import subprocess
import platform
from html.parser import HTMLParser
import html

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '').lower() == 'true',
)

MAX_SCAN_HISTORY = 100
MAX_PAGE_SIZE = 2 * 1024 * 1024


@app.after_request
def add_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    return response

# Trusted domains
TRUSTED_DOMAINS = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'wikipedia.org', 'github.com', 'reddit.com'
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
scan_history = {}


def is_trusted_domain(url):
    parsed_url = urlparse(url)
    domain = (parsed_url.hostname or '').lower().rstrip('.')
    for trusted in TRUSTED_DOMAINS:
        trusted = trusted.lower()
        if domain == trusted or domain.endswith('.' + trusted):
            return True
    return False


def normalize_scan_url(raw_url):
    raw_url = (raw_url or '').strip()
    if not raw_url:
        raise ValueError('URL is required')
    if len(raw_url) > 2048:
        raise ValueError('URL is too long')
    if not raw_url.lower().startswith(('http://', 'https://')):
        raw_url = 'http://' + raw_url

    parsed = urlparse(raw_url)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname:
        raise ValueError('Enter a valid HTTP or HTTPS URL')
    if parsed.username is not None or parsed.password is not None:
        raise ValueError('URLs with embedded credentials are not allowed')
    if parsed.port == 0:
        raise ValueError('Enter a valid HTTP or HTTPS URL')

    hostname = parsed.hostname.lower().rstrip('.')
    _resolve_public_addresses(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))

    return raw_url


def _resolve_public_addresses(hostname, port):
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, ValueError) as exc:
        raise ValueError('The hostname could not be resolved') from exc

    addresses = []
    for record in records:
        sockaddr = record[4]
        if not sockaddr:
            continue
        address_text = sockaddr[0]
        if not isinstance(address_text, str):
            continue
        try:
            address = ipaddress.ip_address(address_text.split('%', 1)[0])
        except ValueError:
            continue
        if not address.is_global:
            raise ValueError('Private and local network targets are not allowed')
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise ValueError('The hostname could not be resolved')
    return addresses


def _open_pinned_connection(parsed_url):
    hostname = parsed_url.hostname
    port = parsed_url.port
    if port == 0:
        raise ValueError('Invalid target port')
    port = port or (443 if parsed_url.scheme == 'https' else 80)
    addresses = _resolve_public_addresses(hostname, port)
    last_error = None

    for address in addresses:
        raw_socket = None
        try:
            raw_socket = socket.create_connection((str(address), port), timeout=10)
            if parsed_url.scheme == 'https':
                context = ssl.create_default_context()
                return context.wrap_socket(raw_socket, server_hostname=hostname)
            return raw_socket
        except OSError as exc:
            last_error = exc
            if raw_socket is not None:
                raw_socket.close()

    raise OSError('Unable to connect to the target') from last_error


def _fetch_public_page(url):
    parsed_url = urlparse(url)
    connection_socket = _open_pinned_connection(parsed_url)
    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
    host_header = f'[{parsed_url.hostname}]' if ':' in parsed_url.hostname else parsed_url.hostname
    if parsed_url.port:
        host_header = f'{host_header}:{port}'
    path = parsed_url.path or '/'
    if parsed_url.query:
        path += '?' + parsed_url.query

    connection = None
    try:
        connection = http.client.HTTPConnection(parsed_url.hostname, port, timeout=10)
        connection.sock = connection_socket
        connection.request('GET', path, headers={
            'Host': host_header,
            'Connection': 'close',
            'Accept-Encoding': 'identity',
            'User-Agent': 'SecureShield/1.0',
        })
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError('Redirects are not followed')
        body = response.read(MAX_PAGE_SIZE + 1)
        if len(body) > MAX_PAGE_SIZE:
            raise ValueError('The target page is too large to scan')
        charset = response.headers.get_content_charset() or 'utf-8'
        certificate = None
        if isinstance(connection.sock, ssl.SSLSocket):
            certificate = connection.sock.getpeercert()
        return body.decode(charset, errors='replace'), certificate
    finally:
        if connection is not None:
            connection.close()
        else:
            connection_socket.close()


def remember_scan(scan_id, result):
    scan_history[scan_id] = result
    if len(scan_history) > MAX_SCAN_HISTORY:
        oldest_id = next(iter(scan_history))
        scan_history.pop(oldest_id, None)


def get_network_info():
    if psutil is None:
        return {
            'error': 'Network scanning is unavailable: psutil is not installed',
            'success': False
        }
    try:
        interfaces = psutil.net_if_addrs()
        interface_stats = psutil.net_if_stats()

        connections = []
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED' and conn.raddr and conn.laddr:
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


class PageMarkupParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.hidden_count = 0
        self.script_sources = []
        self.iframe_sources = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        style = (attrs.get('style') or '').replace(' ', '').lower()
        if 'hidden' in attrs or 'display:none' in style or 'visibility:hidden' in style:
            self.hidden_count += 1

        if tag == 'form':
            form = {
                'action': attrs.get('action', ''),
                'method': (attrs.get('method') or 'get').upper(),
                'has_password': False,
            }
            self.forms.append(form)
            self.current_form = form
        elif tag == 'input' and self.current_form is not None:
            if (attrs.get('type') or '').lower() == 'password':
                self.current_form['has_password'] = True
        elif tag == 'script' and attrs.get('src'):
            self.script_sources.append(attrs['src'])
        elif tag == 'iframe' and attrs.get('src'):
            self.iframe_sources.append(attrs['src'])

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == 'form':
            self.current_form = None

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current_form = None


def analyze_page_markup(page_source, base_url):
    parser = PageMarkupParser()
    parser.feed(page_source)
    return {
        'forms': [
            {**form, 'action': urljoin(base_url, form['action'])}
            for form in parser.forms
        ],
        'hidden_count': parser.hidden_count,
        'script_sources': [urljoin(base_url, src) for src in parser.script_sources],
        'iframe_sources': [urljoin(base_url, src) for src in parser.iframe_sources],
    }


def scan_for_vulnerabilities(page_source):
    vulnerabilities = []

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
    scan_id = secrets.token_urlsafe(12)

    try:
        url = normalize_scan_url(url)
    except ValueError as exc:
        result = {
            'result': 'error',
            'message': [str(exc)],
            'scan_time': scan_time,
            'scan_id': scan_id,
            'url': url
        }
        remember_scan(scan_id, result)
        return result

    try:
        page_source, certificate = _fetch_public_page(url)
        security_checks = {
            'ssl_issues': False,
            'ip_address': False,
            'hidden_elements': False,
            'obfuscated_code': False,
            'suspicious_scripts': False,
            'phishing_keywords': False,
            'insecure_forms': False,
            'foreign_iframes': False
        }
        messages = []
        vulnerabilities = []
        parsed_url = urlparse(url)
        domain = parsed_url.hostname

        if domain is not None and pythonwhois is not None:
            try:
                creation_date = pythonwhois.whois(domain).creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.now()
                    domain_age = (now - creation_date).days
                    security_checks['new_domain'] = domain_age < 7
                    if domain_age < 7:
                        vulnerabilities.append({
                            'type': 'New Domain',
                            'severity': 'low',
                            'evidence': f'Domain is only {domain_age} days old'
                        })
            except Exception as exc:
                app.logger.warning('Domain age check failed (%s)', type(exc).__name__)

        if certificate:
            not_after = certificate.get('notAfter')
            if isinstance(not_after, str) and (
                    ssl.cert_time_to_seconds(not_after) < datetime.now().timestamp()):
                security_checks['ssl_issues'] = True
                messages.append('Expired SSL certificate')
                vulnerabilities.append({
                    'type': 'SSL Issue',
                    'severity': 'critical',
                    'evidence': 'Expired SSL certificate'
                })

        if domain is not None:
            try:
                ipaddress.ip_address(domain)
            except ValueError:
                pass
            else:
                security_checks['ip_address'] = True
                messages.append("IP address in URL")
                vulnerabilities.append({
                    'type': 'IP Address in URL',
                    'severity': 'medium',
                    'evidence': 'URL contains IP address instead of domain name'
                })

        page_lower = page_source.lower()
        markup = analyze_page_markup(page_source, url)
        hidden_count = markup['hidden_count']
        if hidden_count > 5:
            security_checks['hidden_elements'] = True
            vulnerabilities.append({
                'type': 'Hidden Elements',
                'severity': 'low',
                'evidence': f'Found {hidden_count} hidden elements on the page'
            })

        obfuscation_patterns = [
            r'eval\s*\(', r'unescape\s*\(', r'escape\s*\(',
            r'fromCharCode\s*\(', r'exec\s*\(', r'constructor\s*\(',
            r'document\.write\s*\(', r'window\.location\s*='
        ]
        obfuscation_count = sum(1 for pattern in obfuscation_patterns
                                if re.search(pattern, page_lower))
        if obfuscation_count > 3:
            security_checks['obfuscated_code'] = True
            vulnerabilities.append({
                'type': 'Obfuscated Code',
                'severity': 'medium',
                'evidence': f'Found {obfuscation_count} instances of obfuscated code patterns'
            })

        suspicious_scripts = sum(
            urlparse(src).scheme not in ('http', 'https')
            for src in markup['script_sources']
        )
        if suspicious_scripts:
            security_checks['suspicious_scripts'] = True
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
                              if re.search(rf'\b{re.escape(term)}\b', page_lower))
        if keyword_matches >= 5:
            security_checks['phishing_keywords'] = True
            vulnerabilities.append({
                'type': 'Phishing Keywords',
                'severity': 'medium',
                'evidence': f'Found {keyword_matches} phishing-related keywords'
            })

        insecure_forms = sum(
            form['has_password'] and urlparse(form['action']).scheme != 'https'
            for form in markup['forms']
        )
        if insecure_forms:
            security_checks['insecure_forms'] = True
            vulnerabilities.append({
                'type': 'Insecure Forms',
                'severity': 'high',
                'evidence': 'Found forms with password fields submitted over insecure HTTP'
            })

        foreign_iframes = 0
        for src in markup['iframe_sources']:
            iframe_url = urlparse(src)
            if iframe_url.scheme not in ('http', 'https') or iframe_url.hostname != domain:
                foreign_iframes += 1
        if foreign_iframes > 0:
            security_checks['foreign_iframes'] = True
            vulnerabilities.append({
                'type': 'Foreign Iframes',
                'severity': 'medium',
                'evidence': 'Found iframes with suspicious sources'
            })

        vulnerabilities.extend(scan_for_vulnerabilities(page_lower))
        red_flags = sum(
            SEVERITY_LEVELS.get(vuln['severity'], 0) for vuln in vulnerabilities
        )

        if red_flags >= 4:
            result = 'unsafe'
        elif red_flags > 0:
            result = 'suspicious'
        else:
            result = 'safe'
            messages.append('No issues detected by passive checks')

        scan_result = {
            'result': result,
            'message': messages,
            'scan_time': scan_time,
            'scan_id': scan_id,
            'security_checks': security_checks,
            'vulnerabilities': vulnerabilities,
            'url': url,
            'red_flags': red_flags
        }

        remember_scan(scan_id, scan_result)
        return scan_result

    except Exception as exc:
        app.logger.error('URL scan failed (%s)', type(exc).__name__)
        error_result = {
            'result': 'error',
            'message': ['The target could not be scanned safely'],
            'scan_time': scan_time,
            'scan_id': scan_id,
            'url': url
        }
        remember_scan(scan_id, error_result)
        return error_result


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan_history')
def show_scan_history():
    return jsonify(dict(scan_history))


@app.route('/scan_details/<scan_id>')
def scan_details(scan_id):
    scan = scan_history.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return jsonify(scan)


@app.route('/choose_scan', methods=['POST'])
def choose_scan():
    scan_type = request.form.get('type')

    if scan_type == 'file':
        return "File scanning is not available", 400
    elif scan_type == 'url':
        return render_template('index.html')
    elif scan_type == 'network':
        network_info = get_network_info()
        if not network_info['success']:
            return jsonify({'error': network_info['error']}), 500
        return jsonify({
            'interfaces': network_info['interfaces'],
            'connections': network_info['connections'],
            'arp_table': network_info['arp_table'],
            'io_counters': network_info['io_counters']
        })
    else:
        return render_template('index.html', error="Invalid scan type selected")


@app.route('/scan_url', methods=['POST'])
def handle_url_scan():
    try:
        url = normalize_scan_url(request.form.get('url'))
    except ValueError as exc:
        return render_template('index.html', error=str(exc)), 400

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
    app.run(debug=os.environ.get('FLASK_DEBUG', '').lower() == 'true',
            host=os.environ.get('HOST', '127.0.0.1'), port=int(os.environ.get('PORT', '5000')))
