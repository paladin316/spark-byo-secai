import os
import re
import requests
from datetime import datetime
from bs4 import BeautifulSoup

# Where to save raw and parsed intel
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
EVIDENCE_RAW = os.path.join(BASE_DIR, '..', 'evidence', 'raw')
EVIDENCE_PARSED = os.path.join(BASE_DIR, '..', 'evidence', 'parsed')

# IOC regex patterns by type
types = {
    'ip':   r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    'url':  r'https?://[^\s"<>]+' ,
    'hash': r"\b[a-fA-F0-9]{64}\b",
}

# Ensure directory structure
os.makedirs(EVIDENCE_RAW, exist_ok=True)
os.makedirs(EVIDENCE_PARSED, exist_ok=True)


def fetch_and_parse(url: str):
    """
    Fetch a remote HTML page (with browser-like UA), save a local copy,
    extract visible text, then parse IOCs and write CSV + .ioc.txt.
    Returns tuple of (html_path, csv_path, txt_path).
    """
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe = re.sub(r'[^a-zA-Z0-9]', '_', url)

    # Browser-like headers to avoid simple blocks
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/115.0 Safari/537.36'
        )
    }
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()

    # Save raw HTML
    html_path = os.path.join(EVIDENCE_RAW, f"{safe}_{ts}.html")
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(resp.text)

    # Extract visible text
    soup = BeautifulSoup(resp.text, 'html.parser')
    visible_text = soup.get_text(separator='\n')

    # Extract IOCs from visible text only
    found = {key: set(re.findall(pattern, visible_text)) for key, pattern in types.items()}

    # Write CSV
    csv_path = os.path.join(EVIDENCE_PARSED, f"{safe}_{ts}.csv")
    with open(csv_path, 'w', encoding='utf-8') as f:
        f.write('ioc,ioc_type\n')
        for key, vals in found.items():
            for ioc in sorted(vals):
                f.write(f"{ioc},{key}\n")

    # Write plain-text IOC list
    txt_path = os.path.join(EVIDENCE_PARSED, f"{safe}_{ts}.ioc.txt")
    with open(txt_path, 'w', encoding='utf-8') as f:
        for key, vals in found.items():
            f.write(f"# {key.upper()}s\n")
            for ioc in sorted(vals):
                f.write(ioc + '\n')
            f.write('\n')

    return html_path, csv_path, txt_path
