"""
================================================================================
COM5413 — The Benji Protocol
Task 1: The Evidence Collector
File:   log_parser.py
================================================================================

MISSION BRIEF
-------------
Before any operation, Benji pulls the logs. Something happened on that server.
The evidence is in the noise — if you know how to read it.

Your job is to parse a Linux auth.log file and extract Indicators of Compromise
(IoC). Specifically, you are looking for failed authentication attempts that
suggest a brute-force attack. Your output must be structured, consistent, and
machine-readable — sloppy evidence gets people killed in the field.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a log file path as a command-line argument (argparse — no input built-in).
2. Use regular expressions (re) to identify lines containing:
   - "Failed password"
   - "Invalid user"
3. Extract from each matching line:
   - Timestamp
   - IP Address
   - User Account
4. Write a CSV report to suspects.csv (or a path specified via --output).
   CSV headers must be exactly: Timestamp, IP_Address, User_Account
5. Handle errors gracefully:
   - File not found
   - Empty file
   - No matches found (report zero results, do not crash)

CONSTRAINTS
-----------
- Python 3.10+ only.
- Standard library only (re, csv, argparse, pathlib).
- NO use of the input built-in — all input via argparse.
- NO use of os.system() or subprocess.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
CSV file with headers: Timestamp, IP_Address, User_Account
Rows are comma-separated, one per matching log event.
Duplicate entries must be de-duplicated (same timestamp + IP + user = one row).

EXAMPLE USAGE
-------------
    python log_parser.py /var/log/auth.log
    python log_parser.py /var/log/auth.log --output /tmp/suspects.csv

BUILD LOG
---------
Use docs/build.md to record your development notes, decisions, and reflections
as you build this tool. Benji documents everything.
================================================================================
"""

import argparse
import csv
import re
import sys
from pathlib import Path


def parse_arguments():
    """
    Define and parse command-line arguments.
    Returns the parsed namespace object.
    """
    parser = argparse.ArgumentParser(description="Parse auth.log for failed login attempts")

    parser.add_argument("input_file", type=Path, help="Path to the log file")

    parser.add_argument("--output", type=Path, default="suspects.csv", help="Output CSV file")

    return parser.parse_args()


def parse_log(file_path: Path) -> list[dict]:
    """
    Read the log file and extract IoC records.

    Args:
        file_path: Path object pointing to the log file.

    Returns:
        A list of dicts, each containing:
        {'Timestamp': str, 'IP_Address': str, 'User_Account': str}

    Raises:
        FileNotFoundError: If the log file does not exist.
        ValueError: If the file is empty.
    """

    if not file_path.exists():
        raise FileNotFoundError("Log file not found")

    lines = file_path.read_text().splitlines()

    if not lines:
        raise ValueError("File is empty")

    pattern = re.compile(
        r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*?(Failed password|Invalid user).*?(?:user\s+)?(?P<user>\w+).*?from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    results = []
    seen = set()

    for line in lines:
        match = pattern.search(line)
        if match:
            record = {
                "Timestamp": match.group("timestamp"),
                "IP_Address": match.group("ip"),
                "User_Account": match.group("user"),
            }

            key = (record["Timestamp"], record["IP_Address"], record["User_Account"])

            if key not in seen:
                seen.add(key)
                results.append(record)

    return results


def write_csv(records: list[dict], output_path: Path) -> None:
    """
    Write extracted records to a CSV file.

    Args:
        records:     List of IoC record dicts.
        output_path: Path object for the output CSV file.
    """

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Timestamp", "IP_Address", "User_Account"])

        writer.writeheader()
        writer.writerows(records)


def main():
    args = parse_arguments()

    try:
        records = parse_log(args.input_file)

        if not records:
            print("No matches found.", file=sys.stderr)

        write_csv(records, args.output)

        print(f"Report written to {args.output}")

    except FileNotFoundError:
        print("Error: Log file not found", file=sys.stderr)

    except ValueError:
        print("Error: File is empty", file=sys.stderr)

    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()