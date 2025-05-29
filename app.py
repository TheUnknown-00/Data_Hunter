from flask import Flask, request, jsonify, render_template
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from queue import Queue
import ssl
import socket
from datetime import datetime
import OpenSSL
import re
import whois
import subprocess
import dns.resolver
import dns.exception
import concurrent.futures
import asyncio
import requests
import socket
import threading

app = Flask(__name__)

# Number of threads for concurrent scanning
NUM_THREADS = 100

# Thread-safe queue for port numbers
port_queue = Queue()

# List to store open ports
open_ports = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/info', methods=['GET'])
def get_info():
    input_value = request.args.get('input')
    info_type = request.args.get('type')
    result = {}

    if info_type == 'whois':
        result = get_whois_info(input_value)
    elif info_type == 'openports':
        result = get_open_ports(input_value)
    elif info_type == 'subdomains':
        result = get_subdomains(input_value)
    elif info_type == 'technology':
        result = get_technology(input_value)
    elif info_type == 'dnslookup':
        result = get_dns_info(input_value)
    elif info_type == 'emailhunting':
        result = get_email_hunting(input_value)
    elif info_type == 'robots_sitemap':
        result = check_robots_and_sitemap(input_value)
    elif info_type == 'sslcheck':
        result = ssl_tls_checker(input_value)

    return jsonify(result)

def get_whois_info(query):
    try:
        w = whois.whois(query)
        if not w:
            return {"error": f"No WHOIS information found for {query}."}

        whois_info = {}
        for key, value in w.items():
            if value:
                whois_info[key.capitalize()] = value

        return whois_info

    except whois.WhoisException as e:
        return {"error": f"WHOIS exception occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

def scan_port(host, port):
    """Scans a single port and adds it to open_ports if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Set timeout for faster scans
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
    except Exception:
        pass  # Handle exceptions silently

def worker(host):
    """Thread worker function to scan ports from the queue."""
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(host, port)
        port_queue.task_done()

def get_open_ports(ip):
    global open_ports
    open_ports = []  # Reset the open_ports list for each scan
    try:
        # Resolve domain to IP if necessary
        host = socket.gethostbyname(ip)
    except socket.gaierror:
        return {"error": f"Unable to resolve domain {ip}"}

    # Populate the port queue with the first 1000 ports
    for port in range(1, 1001):
        port_queue.put(port)

    # Create and start threads
    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=worker, args=(host,))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    port_queue.join()

    for thread in threads:
        thread.join()

    # Return the open ports
    return {"open_ports": sorted(open_ports)}

def find_subdomains(domain, api_key):

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"

    headers = {

        "APIKEY": api_key

    }


    try:

        response = requests.get(url, headers=headers)


        if response.status_code == 200:

            data = response.json()


            if 'subdomains' in data:

                return data['subdomains']

            else:

                return None  # No subdomains found

        else:

            return {"error": f"Failed to fetch subdomains: {response.status_code} - {response.text}"}


    except requests.exceptions.RequestException as e:

        return {"error": f"An error occurred: {str(e)}"}


def check_subdomain_exists(full_domain, results):

    try:

        ip_address = socket.gethostbyname(full_domain)


        for protocol in ['http', 'https']:

            try:

                response = requests.get(f"{protocol}://{full_domain}", timeout=5)


                if response.status_code in [200, 301, 302]:

                    # Instead of printing, format the result

                    results.append(f"{full_domain} - {ip_address}")  # Store found subdomain and IP address

                    return


            except requests.exceptions.RequestException:

                continue


    except socket.gaierror:

        return
def get_subdomains(domain):
    api_key = "7-c4hueTRv3g11_eiL2okUhMAcnL4VPL"  # Your SecurityTrails API key
    subdomains = find_subdomains(domain, api_key)

    if subdomains is None:
        return {"error": "No subdomains found."}

    results = []
    threads = []

    for subdomain in subdomains:
        full_domain = f"{subdomain}.{domain}"
        thread = threading.Thread(target=check_subdomain_exists, args=(full_domain, results))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Format results as a single string with each entry on a new line
    formatted_results = " ".join(results)
    return {"subdomains \n": formatted_results}


def get_technology(domain):
    try:
        print(f"Analyzing technologies for: {domain}")
        response = requests.get(f"http://{domain}", timeout=10)
        if response.status_code != 200:
            return {"error": f"Unable to fetch data from {domain}. Status Code: {response.status_code}"}

        soup = BeautifulSoup(response.text, 'html.parser')
        tech_info = {
            "CMS": "Unknown",
            "Web Server": response.headers.get('Server', 'Unknown'),
            "Powered By": response.headers.get('X-Powered-By', 'Unknown'),
            "JavaScript Frameworks": [],
        }

        # Check CMS via meta tags
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and generator_meta.get('content'):
            tech_info["CMS"] = generator_meta.get('content')

        # Check common CMS patterns
        html_text = response.text.lower()
        if 'wp-content' in html_text or 'wp-includes' in html_text:
            tech_info["CMS"] = "WordPress"
        elif 'drupal' in html_text:
            tech_info["CMS"] = "Drupal"
        elif 'joomla' in html_text:
            tech_info["CMS"] = "Joomla"

        # Detect JavaScript libraries
        for script in soup.find_all('script'):
            if script.get('src'):
                src = script['src']
                if 'react' in src:
                    tech_info["JavaScript Frameworks"].append('React')
                elif 'angular' in src:
                    tech_info["JavaScript Frameworks"].append('Angular')
                elif 'vue' in src:
                    tech_info["JavaScript Frameworks"].append('Vue.js')
                elif 'jquery' in src:
                    tech_info["JavaScript Frameworks"].append('jQuery')

        return tech_info

    except requests.exceptions.RequestException as e:
        return {"error": f"An error occurred: {str(e)}"}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

def get_dns_info(domain):
    dns_info = {}

    try:
        # Get A records
        a_records = dns.resolver.resolve(domain, 'A')
        dns_info['A Records'] = [str(record) for record in a_records]

    except dns.resolver.NoAnswer:
        dns_info['A Records'] = "No A records found."
    except dns.resolver.NXDOMAIN:
        return {"error": f"The domain {domain} does not exist."}
    except Exception as e:
        return {"error": f"An unexpected error occurred while fetching A records: {str(e)}"}

    try:
        # Get MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        dns_info['MX Records'] = [(str(record.exchange), record.preference) for record in mx_records]

    except dns.resolver.NoAnswer:
        dns_info['MX Records'] = "No MX records found."
    except Exception as e:
        dns_info['MX Records'] = f"Error fetching MX records: {str(e)}"

    try:
        # Get NS records
        ns_records = dns.resolver.resolve(domain, 'NS')
        dns_info['NS Records'] = [str(record) for record in ns_records]

    except dns.resolver.NoAnswer:
        dns_info['NS Records'] = "No NS records found."
    except Exception as e:
        dns_info['NS Records'] = f"Error fetching NS records: {str(e)}"

    try:
        # Get TXT records
        txt_records = dns.resolver.resolve(domain, 'TXT')
        dns_info['TXT Records'] = [str(record) for record in txt_records]

    except dns.resolver.NoAnswer:
        dns_info['TXT Records'] = "No TXT records found."
    except Exception as e:
        dns_info['TXT Records'] = f"Error fetching TXT records: {str(e)}"

    try:
        # Get CNAME records
        cname_records = dns.resolver.resolve(domain, 'CNAME')
        dns_info['CNAME Records'] = [str(record) for record in cname_records]

    except dns.resolver.NoAnswer:
        dns_info['CNAME Records'] = "No CNAME records found."
    except Exception as e:
        dns_info['CNAME Records'] = f"Error fetching CNAME records: {str(e)}"

    return dns_info

def get_emails_from_domain(domain, api_key):

    url = "https://api.hunter.io/v2/domain-search"

    params = {

        'domain': domain,

        'api_key': api_key

    }


    try:

        response = requests.get(url, params=params)

        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx, 5xx)


        data = response.json()

        emails = []

        if data.get('data') and data['data'].get('emails'):

            emails = [email['value'] for email in data['data']['emails']]

        return emails if emails else ["No emails found for this domain."]

    except requests.exceptions.HTTPError as http_err:

        return [f"HTTP error occurred: {http_err}"]

    except requests.exceptions.RequestException as req_err:

        return [f"Request error occurred: {req_err}"]

    except Exception as err:

        return [f"An error occurred: {err}"]


def get_email_hunting(domain):

    api_key = "1bc01d801e364f1fdac819ff83ff1d5dd70e32ff" 

    emails = get_emails_from_domain(domain, api_key)


    # Format emails as a single string with each email on a new line

    formatted_emails = "  ".join(emails)

    return {"emails": formatted_emails}

# Function for Robots.txt and Sitemap.xml Checker
def check_robots_and_sitemap(domain):
    if not domain.startswith("http://") and not domain.startswith("https://"):
        domain = "http://" + domain

    robots_url = urljoin(domain, "/robots.txt")
    sitemap_url = urljoin(domain, "/sitemap.xml")

    results = {
        "robots.txt": {"allow": [], "disallow": []},
        "sitemap.xml": []
    }

    # Fetch Robots.txt
    try:
        response = requests.get(robots_url, timeout=5)
        if response.status_code == 200:
            allow, disallow = parse_robots_txt(response.text)
            results["robots.txt"]["allow"] = allow
            results["robots.txt"]["disallow"] = disallow
    except:
        pass  # Handle errors silently

    # Fetch Sitemap.xml
    try:
        response = requests.get(sitemap_url, timeout=5)
        if response.status_code == 200:
            urls = fetch_sitemap_urls(response.text)
            results["sitemap.xml"] = urls
    except:
        pass  # Handle errors silently

    return results

# Helper functions for parsing
def parse_robots_txt(content):
    allow_paths = []
    disallow_paths = []

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("Allow:"):
            allow_paths.append(line.replace("Allow:", "").strip())
        elif line.startswith("Disallow:"):
            disallow_paths.append(line.replace("Disallow:", "").strip())

    return allow_paths, disallow_paths

def fetch_sitemap_urls(content):
    urls = []
    for line in content.splitlines():
        if "<loc>" in line:
            start = line.find("<loc>") + 5
            end = line.find("</loc>")
            urls.append(line[start:end].strip())
    return urls


def ssl_tls_checker(domain):
    """
    Check SSL/TLS configuration of the given domain.
    """
    result = {}
    try:
        # Ensure domain uses HTTPS
        if not domain.startswith("https://") and not domain.startswith("http://"):
            domain = "https://" + domain

        # Extract hostname from URL
        hostname = domain.replace("https://", "").replace("http://", "").split("/")[0]

        # Establish an SSL connection
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the certificate in DER format
                cert = ssock.getpeercert()
                cert_der = ssock.getpeercert(binary_form=True)
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_der)

                # Extract certificate details
                result["Domain"] = hostname
                result["Valid From"] = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").isoformat()
                result["Valid To"] = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").isoformat()
                result["Issuer"] = dict(x[0] for x in cert["issuer"])["organizationName"]
                result["Protocol Version"] = ssock.version()
                result["Cipher Suite"] = ssock.cipher()[0]
                result["Serial Number"] = x509.get_serial_number()
                result["Signature Algorithm"] = x509.get_signature_algorithm().decode("utf-8")
                result["Key Size"] = x509.get_pubkey().bits()
    except ssl.SSLError as e:
        result["Error"] = f"SSL error: {str(e)}"
    except socket.gaierror:
        result["Error"] = "Invalid domain or cannot resolve host."
    except Exception as e:
        result["Error"] = f"An error occurred: {str(e)}"

    return result

if __name__ == '__main__':
    app.run(debug=True)