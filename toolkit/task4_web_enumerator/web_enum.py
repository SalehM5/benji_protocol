"""
================================================================================
COM5413 — The Benji Protocol
Task 4: The Web Enumerator
File:   web_enum.py
================================================================================

MISSION BRIEF
-------------
The web layer talks too much. Server versions buried in HTTP headers. Developer
notes left in HTML comments. Sensitive paths left exposed because nobody
thought to check. Benji listens. A well-configured web server tells you almost
nothing; most servers are not well-configured.

Your job is to build an HTTP reconnaissance tool that extracts intelligence
from HTTP response headers and HTML source. This is passive reconnaissance —
you are reading what the server is already broadcasting, not probing for
weaknesses directly.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target URL as a command-line argument.
2. Send an HTTP GET request and analyse the response headers for:
   - Server (e.g., Apache/2.2.8)
   - X-Powered-By (e.g., PHP/5.2.4)
   - Any other headers that reveal technology or version information.
3. Parse the HTML response using BeautifulSoup to extract:
   - All HTML comments (<!-- --> blocks) — flags are often hidden here.
4. Check for the existence of sensitive paths:
   - /robots.txt
   - /admin
   - /phpmyadmin
   - /login
   - /.git
   (Report found/not found for each — do not enumerate further.)
5. Output a structured summary (JSON or formatted plaintext).

CONSTRAINTS
-----------
- Python 3.10+ only.
- Must use requests and beautifulsoup4 (bs4).
- Set a request timeout (default 5s) — never hang.
- Handle redirects gracefully (requests does this by default — be aware of it).
- NO use of the input built-in — all input via argparse.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
Print a summary containing at minimum:
    [HEADERS]
    Server: <value or "Not present">
    X-Powered-By: <value or "Not present">

    [COMMENTS]
    Found <n> HTML comment(s):
    1. <comment text>
    2. <comment text>

    [SENSITIVE PATHS]
    /robots.txt       → FOUND (200)
    /admin            → NOT FOUND (404)
    ...

EXAMPLE USAGE
-------------
    python web_enum.py http://192.168.56.101
    python web_enum.py http://192.168.56.101/dvwa --timeout 10

BUILD LOG
---------
Use docs/build.md to record what you find when running against Metasploitable.
HTML comments in particular — document what you find and what it implies.
This intelligence feeds directly into the Vulnerability Hunt diagnosis phase.
================================================================================
"""

# Your imports go here
import argparse        #import libraries 
import sys
from urllib.parse import urljoin, urlparse

try:
    import requests
    from bs4 import BeautifulSoup          #try module from library beautiful soup
except ImportError as e:
    print(
        f"[-] Missing dependency: {e}. Run: pip install requests beautifulsoup4",   #if not existing, install 
        file=sys.stderr,
    )
    sys.exit(1)


# Sensitive paths to probe — this list can be extended
SENSITIVE_PATHS = [
    "/robots.txt",
    "/admin",
    "/phpmyadmin",
    "/login",
    "/.git",
]


def parse_arguments():
    parser = argparse.ArgumentParser(description="Web Enumerator")

    parser.add_argument("url", help="Target URL")      #user input 
    parser.add_argument("--timeout", type=int, default=5)

    return parser.parse_args()


def analyse_headers(response: requests.Response) -> dict:
    headers = response.headers

    return {
        "Server": headers.get("Server", "Not present"),      #get service headers 
        "X-Powered-By": headers.get("X-Powered-By", "Not present"),
    }

from bs4 import Comment       #import specific 
from bs4 import BeautifulSoup


def extract_comments(html: str) -> list[str]:      #extract comments 
    soup = BeautifulSoup(html, "html.parser")

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    return [c.strip() for c in comments]


def check_sensitive_paths(base_url: str, timeout: int) -> dict:
    results = {}

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)

        try:
            r = requests.get(url, timeout=timeout)
            results[path] = r.status_code
        except Exception:
            results[path] = None

    return results


def main():
    args = parse_arguments()

    response = requests.get(args.url, timeout=args.timeout)

    headers = analyse_headers(response)
    comments = extract_comments(response.text)
    paths = check_sensitive_paths(args.url, args.timeout)

    print("[HEADERS]")
    print(f"Server: {headers['Server']}")
    print(f"X-Powered-By: {headers['X-Powered-By']}")          #print headers 
    print()

    print("[COMMENTS]")
    print(f"Found {len(comments)} HTML comment(s):")      #return comments 
    for i, c in enumerate(comments, 1):
        print(f"{i}. {c}")
    print()

    print("[SENSITIVE PATHS]")          #print sensitive paths 
    for path, status in paths.items():
        if status:
            if status == 200:
                print(f"{path} → FOUND ({status})")
            else:
                print(f"{path} → NOT FOUND ({status})")
        else:
            print(f"{path} → NOT FOUND (error)")


if __name__ == "__main__":        #run main 
    main()
