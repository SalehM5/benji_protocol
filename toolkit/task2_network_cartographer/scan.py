"""
================================================================================
COM5413 — The Benji Protocol
Task 2: The Network Cartographer
File:   scan.py
================================================================================

MISSION BRIEF
-------------
Ethan cannot go in blind. Benji maps every door, every service, every version
number. The scan is not the attack — it is the intelligence that makes the
attack possible. A missed service or a wrong version assumption costs the
mission.

Your job is to build a threaded TCP port scanner that identifies open ports and
grabs the service banner from each one. The banner is the service telling you
exactly what it is and what version it is running. Listen carefully.

WHAT THIS SCRIPT MUST DO
-------------------------
1. Accept a target IP and port range/list as command-line arguments.
2. Attempt a TCP connection to each port using Python's socket library.
3. If the port is open, attempt to receive the service banner (the greeting
   text the service sends on connection).
4. Use threading (ThreadPoolExecutor) to scan multiple ports concurrently.
5. Implement a connection timeout (default 0.5s) — hanging the scanner is not
   an option in the field.
6. Output results as JSON: printed to stdout AND saved to recon_results.json.

CONSTRAINTS
-----------
- Python 3.10+ only.
- Use socket — do NOT wrap nmap or any external scanner.
- NO use of the input built-in — all input via argparse.
- Timeout must be configurable via --timeout argument.

OUTPUT CONTRACT (auto-grader depends on this)
---------------------------------------------
JSON structure:
{
    "target": "192.168.x.x",
    "scan_time": "YYYY-MM-DD HH:MM:SS",
    "open_ports": [
        {"port": 21, "banner": "220 (vsFTPd 2.3.4)"},
        {"port": 22, "banner": "SSH-2.0-OpenSSH_4.7p1"},
        {"port": 80, "banner": ""}
    ]
}
"banner" must always be present — use empty string if no banner received.

EXAMPLE USAGE
-------------
    python scan.py 192.168.56.101 --ports 1-1024
    python scan.py 192.168.56.101 --ports 21,22,80,443
    python scan.py 192.168.56.101 --ports 1-65535 --timeout 1.0 --threads 100

BUILD LOG
---------
Use docs/build.md to record your development notes, decisions, and reflections
as you build this tool. Pay particular attention to documenting what you observe
in the banner output when scanning Metasploitable — this feeds directly into
the Vulnerability Hunt.
================================================================================
"""

# Your imports go here
import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")   #target ip address 

    parser.add_argument("target", help="Target IP address")  #port input

    parser.add_argument("--ports", required=True, help="Ports (e.g. 1-1000 or 22,80,443)") 

    parser.add_argument("--timeout", type=float, default=0.5, help="Connection timeout")  #timeout for each connection attempt

    parser.add_argument("--threads", type=int, default=50, help="Number of threads")    #faster scanning

    parser.add_argument("--output", type=Path, default="recon_results.json", help="Output JSON file")   #output file with resuslts

    return parser.parse_args()


def parse_port_input(port_string: str) -> list[int]:
    ports = []

    if "-" in port_string:       #1-1000 range
        start, end = port_string.split("-")
        ports = list(range(int(start), int(end) + 1))
    else:        #If user gives list of numbers
        ports = [int(p.strip()) for p in port_string.split(",")]

    return sorted(set(ports))  #remove duplicates and sort


def grab_banner(sock: socket.socket, timeout: float = 0.5) -> str:   #read service banner 
    sock.settimeout(timeout)

    try:                      #receive data from service banner 
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()
    except:                          #if nothing return empty
        return ""


def check_port(target: str, port: int, timeout: float) -> dict | None:   #search open ports 
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:   #create tcp socket
            s.settimeout(timeout)       #set timeout for connection attempt 

            result = s.connect_ex((target, port))      #connect to target port 
            if result == 0:          #if port open
                banner = grab_banner(s, timeout)      #get service banner 
                return {"port": port, "banner": banner}#return results 

    except:              #else ignore and skip 
        return None

    return None


def main():
    args = parse_arguments()

    ports = parse_port_input(args.ports)     #get user arguments 

    results = []      #get scan results

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(check_port, args.target, port, args.timeout)
            for port in ports
        ]

        for f in as_completed(futures):       #get scan results 
            result = f.result()
            if result:
                results.append(result)

    output = {                             #build final JSON output 
        "target": args.target,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "open_ports": sorted(results, key=lambda x: x["port"])
    }

    print(json.dumps(output))           #print to terminal 

    with open(args.output, "w") as f:
        json.dump(output, f, indent=4)         #save 


if __name__ == "__main__":
    main()
