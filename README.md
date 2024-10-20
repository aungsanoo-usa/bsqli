# bsqli
Blind SQL Injection Scanner with Selenium An automated vulnerability scanner for detecting Time-Based Blind SQL Injection (SQLi) attacks. Uses Selenium WebDriver to perform safe and reliable multi-trial detection of potential vulnerabilities. Includes advanced error handling to avoid false positives and generate detailed HTML reports

# Blind SQL Injection Scanner with Selenium

This is a Python-based vulnerability scanner designed to detect Time-Based Blind SQL Injection vulnerabilities using Selenium. The scanner checks if the target URLs are vulnerable by performing automated tests using specific SQL injection payloads and analyzing the time taken by the server to respond.

## Features

- **Automated Testing**: Uses Selenium WebDriver to interact with target URLs.
- **Time-Based SQL Injection Detection**: Identifies potential vulnerabilities by introducing deliberate time delays in SQL queries.
- **Multi-Trial Validation**: Runs multiple trials to reduce false positives.
- **Error Handling**: Ignores server-side errors (HTTP 500) to avoid false detections.

## Prerequisites

- Python 3.6+
- Google Chrome browser (for Selenium WebDriver)
- ChromeDriver (automatically managed by `webdriver-manager`)

## Installation

1. Clone this repository:

    ```bash
    git clone https://github.com/aungsanoo-usa/bsqli.git
    cd bsqli
    ```

2. Create and activate a virtual environment (optional but recommended):

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Prepare a file containing URLs to be scanned (one URL per line).
2. Prepare a file containing SQL injection payloads (one payload per line).

3. Run the scanner:

    ```bash
    python your_script_name.py -u path_to_url_file.txt -p path_to_payload_file.txt -t 5
    ```

    - `-u` or `--url-file` : Path to the file containing URLs to scan.
    - `-p` or `--payload-file` : Path to the file containing SQL injection payloads.
    - `-t` or `--threads` : Number of concurrent threads (default is 5).

4. (Optional) If a cookie needs to be included in the request:

    ```bash
    python your_script_name.py -u path_to_url_file.txt -p path_to_payload_file.txt -c "session_id=abcdef123456"
    ```

## Example

```bash
python your_script_name.py -u urls.txt -p payloads.txt -t 10
