# hibp.py
import hashlib
import requests
import os

USER_AGENT = "AI-Cyber-Vault/1.0"  # polite user agent
HIBP_API_KEY = os.environ.get("HIBP_API_KEY")  # optional for email checks

def sha1_hex(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()

def pwned_password_count(password: str) -> int:
    """
    Uses k-anonymity API for passwords:
    - compute SHA1(password)
    - send first 5 chars to HIBP /range API
    - parse response for matching suffix and return count (0 if not found)
    """
    h = sha1_hex(password)
    prefix, suffix = h[:5], h[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": USER_AGENT}
    # No API key needed, safe k-anonymity usage
    resp = requests.get(url, headers=headers, timeout=10)
    resp.raise_for_status()
    # Response lines: SUFFIX:COUNT
    for line in resp.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix.strip().upper() == suffix:
            return int(count)
    return 0

def pwned_email_breaches(email: str):
    """
    Check breaches for an email address (requires HIBP API key).
    Returns list of breach names or empty list.
    If no API key, raises RuntimeError.
    """
    if not HIBP_API_KEY:
        raise RuntimeError("HIBP_API_KEY not set. Set environment variable HIBP_API_KEY to use email checks.")
    base = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    url = base + requests.utils.quote(email)
    headers = {
        "User-Agent": USER_AGENT,
        "hibp-api-key": HIBP_API_KEY
    }
    # We can use truncateResponse=true to get lightweight response if desired
    params = {"truncateResponse": "true"}
    resp = requests.get(url, headers=headers, params=params, timeout=10)
    if resp.status_code == 404:
        # Not found => no breaches
        return []
    resp.raise_for_status()
    # If truncateResponse true then resp.json() returns array of breach objects (short)
    return resp.json()
