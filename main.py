"""
PhishDetect Pro - A Python tool for detecting phishing emails.
Features:
- Analyzes email headers for security information.
- Checks URL redirection and protocol.
- Identifies spelling mistakes in the email body.
- Detects potential phishing indicators.

Author: Stephen Sam
"""

import os
import sys
import argparse
import urllib.parse
import requests
import re
from bs4 import BeautifulSoup
from textblob import TextBlob
from email.parser import BytesParser
from email.policy import default

# Color codes for terminal output
RED = "\033[0;31m"
WHITE = "\033[0m"
YELLOW = "\033[1;33m"
GREEN = "\033[1;92m"
BLUE = "\033[0;34m"
BOLD = '\033[1m'

# User-Agent for HTTP requests
HEADER = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0'
}


class EmailHeaderAnalyzer:
    """Class to analyze email headers."""

    @staticmethod
    def analyze(file):
        try:
            with open(file, "rb") as fh:
                msg = BytesParser(policy=default).parse(fh)

            # Display basic information
            print(f"{BLUE}[+]{WHITE} {GREEN}From:{WHITE} {BOLD}{msg['From']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}To:{WHITE} {BOLD}{msg['To']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}Date:{WHITE} {BOLD}{msg['Date']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}Subject:{WHITE} {BOLD}{msg['Subject']}{WHITE}\n")

            # Security-related headers
            print(f"{BLUE}[+]{WHITE} {GREEN}Message-ID:{WHITE} {BOLD}{msg['Message-ID']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}Received-SPF:{WHITE} {BOLD}{msg['Received-SPF']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}DKIM-Signature:{WHITE} {BOLD}{msg['DKIM-Signature']}{WHITE}")
            print(f"{BLUE}[+]{WHITE} {GREEN}Authentication-Results:{WHITE} {BOLD}{msg['Authentication-Results']}{WHITE}\n")
        except Exception as e:
            print(f"{RED}[!]{WHITE} Error analyzing header: {e}", file=sys.stderr)


def analyze_email_body(file):
    """Analyze email body for URLs and phishing indicators."""
    try:
        with open(file) as fh:
            content = fh.read()

        # Find URLs in the email body
        url_pattern = re.compile(r'https?://\S+')
        urls = url_pattern.findall(content)
        if urls:
            for url in urls:
                print(f"{RED}[!]{WHITE} URL Identified: {BOLD}{url}{WHITE}")
                analyze_url(url)
        else:
            print(f"{GREEN}[✔]{WHITE} No URLs found in the email body.")
    except Exception as e:
        print(f"{RED}[!]{WHITE} Error analyzing email body: {e}", file=sys.stderr)


def analyze_url(url):
    """Analyze the given URL for protocol, redirection, and shortening services."""
    try:
        # Check protocol
        protocol_match = re.match(r'^([a-zA-Z]+)://', url)
        if protocol_match:
            print(f"{BLUE}[+]{WHITE} Protocol: {BOLD}{protocol_match.group(1)}{WHITE}")

        # Check redirection
        response = requests.get(f'http://urlxray.com/display.php?url={url}', headers=HEADER)
        soup = BeautifulSoup(response.content, 'html.parser')
        destination_url = soup.find('div', class_='resultURL2').find_all('a')[0].get('href')

        if url == destination_url:
            print(f"{GREEN}[✔]{WHITE} No redirection detected. URL: {destination_url}")
        else:
            print(f"{RED}[!]{WHITE} Redirection detected: {destination_url}")
            check_shortened_url(destination_url)

    except Exception as e:
        print(f"{RED}[!]{WHITE} Error analyzing URL: {e}", file=sys.stderr)


def check_shortened_url(url):
    """Check if the URL is from a shortening service."""
    domain = urllib.parse.urlparse(url).netloc
    if 'tinyurl' in domain or 'bit.ly' in domain or 'rb' in domain:
        print(f"{RED}[!]{WHITE} URL Shortening Identified! Domain: {domain}")


def check_spelling(file):
    """Check for spelling errors in the email body."""
    try:
        with open(file) as fh:
            content = fh.read()

        words = content.split()
        for word in words:
            corrected = TextBlob(word).correct()
            if word != corrected:
                print(f"{RED}[!]{WHITE} Spelling Error: {word} -> {BOLD}{corrected}{WHITE}")
    except Exception as e:
        print(f"{RED}[!]{WHITE} Error checking spelling: {e}", file=sys.stderr)


def main():
    """Main function to parse arguments and initiate email analysis."""
    parser = argparse.ArgumentParser(description="PhishDetect Pro - Email Phishing Analyzer")
    parser.add_argument("-H", "--header", help="Path to the email header file.", required=True)
    parser.add_argument("-E", "--email", help="Path to the email body file.", required=True)
    args = parser.parse_args()

    # Display banner
    print(f"\n{GREEN} PhishDetect Pro - Email Phishing Analyzer{WHITE}")
    print(f"{BOLD}         By Stephen Sam{WHITE}\n")

    # Analyze header
    print(f"{YELLOW}[[:]] Analyzing Email Header...{WHITE}\n")
    EmailHeaderAnalyzer.analyze(args.header)

    # Analyze email body
    print(f"\n{YELLOW}[[:]] Analyzing Email Body...{WHITE}\n")
    analyze_email_body(args.email)


if __name__ == "__main__":
    if sys.version_info >= (3, 8):
        main()
    else:
        print(f"{RED}[!]{WHITE} Python 3.8 or higher is required.", file=sys.stderr)

