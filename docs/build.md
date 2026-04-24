# The Benji Protocol — Build Log

**Student Name: Saleh Moosa**
**Student ID: 2403662**
**GitHub Repository:https://github.com/SalehM5/benji_protocol.git**

---

> "Benji documents everything. Not because he is asked to. Because a tool with
> no history is a tool you cannot trust, and a mission with no record is a
> mission that never happened."

This is your running build log. Update it after every significant coding
session. It is not an essay — it is a technical journal. Short entries are
fine. No entry is not fine.

The build log serves three purposes:
1. It is evidence of your development process for the portfolio marker.
2. It is your own reference when something breaks at 23:00 the night before
   the Vulnerability Hunt.
3. It demonstrates that the code in your repository is yours.

---

## How to Use This Document

Add a new entry for each session using the template below. Commit this file
alongside your code — the build log and the code should tell the same story.

---

## Entry Template

### [DATE] — [TASK / SESSION]

**What I built / changed:**

**What broke and how I fixed it:**

**Decisions I made and why:**

**What the tool output when I ran it against Metasploitable:**

**Questions or things to revisit:**

---

## Week 1 — Task 1: Evidence Collector

### [4/3/26] — Installed Kali VM 



### [6/3/26] — Installed Metasploitable



---

## Week 2 — Task 2: Network Cartographer

### [11/3/26] — Session A

**Metasploitable scan output (paste key results):**
   "target": "172.16.19.101",
    "scan_time": "2026-04-24 10:18:06",
    "open_ports": []
}

```

no open ports 



### [13/3/26] — attempted to fix script and assign correct ip



---

## Week 3 — Task 3: Access Validator

### [17/3/26] — Attempted to build script 



### [19/3/26] — Worked on the script more, no changes made 



---

## Week 4 — Task 4: Web Enumerator

### [15/4/26] — Session A

**Metasploitable web recon output:**
python3 web_enum.py http://172.16.19.101 
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 204, in _new_conn                                                                     
    sock = connection.create_connection(
        (self._dns_host, self.port),
    ...<2 lines>...
        socket_options=self.socket_options,
    )
  File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 85, in create_connection
    raise err
  File "/usr/lib/python3/dist-packages/urllib3/util/connection.py", line 73, in create_connection
    sock.connect(sa)
    ~~~~~~~~~~~~^^^^
TimeoutError: timed out

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 787, in urlopen
    response = self._make_request(
        conn,
    ...<10 lines>...
        **response_kw,
    )
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 493, in _make_request
    conn.request(
    ~~~~~~~~~~~~^
        method,
        ^^^^^^^
    ...<6 lines>...
        enforce_content_length=enforce_content_length,
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    )
    ^
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 500, in request                                                                       
    self.endheaders()
    ~~~~~~~~~~~~~~~^^
  File "/usr/lib/python3.13/http/client.py", line 1353, in endheaders
    self._send_output(message_body, encode_chunked=encode_chunked)
    ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/http/client.py", line 1113, in _send_output
    self.send(msg)
    ~~~~~~~~~^^^^^
  File "/usr/lib/python3.13/http/client.py", line 1057, in send
    self.connect()
    ~~~~~~~~~~~~^^
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 331, in connect                                                                       
    self.sock = self._new_conn()
                ~~~~~~~~~~~~~~^^
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 213, in _new_conn                                                                     
    raise ConnectTimeoutError(
    ...<2 lines>...
    ) from e
urllib3.exceptions.ConnectTimeoutError: (<HTTPConnection(host='172.16.19.101', port=80) at 0x7f882a92f380>, 'Connection to 172.16.19.101 timed out. (connect timeout=5)')                                                              

The above exception was the direct cause of the following exception:

Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 644, in send                                                                           
    resp = conn.urlopen(
        method=request.method,
    ...<9 lines>...
        chunked=chunked,
    )
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 841, in urlopen
    retries = retries.increment(
        method, url, error=new_e, _pool=self, _stacktrace=sys.exc_info()[2]
    )
  File "/usr/lib/python3/dist-packages/urllib3/util/retry.py", line 535, in increment                                                                     
    raise MaxRetryError(_pool, url, reason) from reason  # type: ignore[arg-type]
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
urllib3.exceptions.MaxRetryError: HTTPConnectionPool(host='172.16.19.101', port=80): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPConnection(host='172.16.19.101', port=80) at 0x7f882a92f380>, 'Connection to 172.16.19.101 timed out. (connect timeout=5)'))                              

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "/home/kali/Downloads/benji_protocol-main/toolkit/task4_web_enumerator/web_enum.py", line 178, in <module>                                         
    main()
    ~~~~^^
  File "/home/kali/Downloads/benji_protocol-main/toolkit/task4_web_enumerator/web_enum.py", line 149, in main                                             
    response = requests.get(args.url, timeout=args.timeout)
  File "/usr/lib/python3/dist-packages/requests/api.py", line 73, in get
    return request("get", url, params=params, **kwargs)
  File "/usr/lib/python3/dist-packages/requests/api.py", line 59, in request
    return session.request(method=method, url=url, **kwargs)
           ~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/requests/sessions.py", line 589, in request                                                                        
    resp = self.send(prep, **send_kwargs)
  File "/usr/lib/python3/dist-packages/requests/sessions.py", line 703, in send                                                                           
    r = adapter.send(request, **kwargs)
  File "/usr/lib/python3/dist-packages/requests/adapters.py", line 665, in send                                                                           
    raise ConnectTimeout(e, request=request)
requests.exceptions.ConnectTimeout: HTTPConnectionPool(host='172.16.19.101', port=80): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPConnection(host='172.16.19.101', port=80) at 0x7f882a92f380>, 'Connection to 172.16.19.101 timed out. (connect timeout=5)')) 





### [17/4/26] — Session B

Bug fixes 

---

## Week 5 — Vulnerability Hunt

> This section is your mission log. Update it in real time during the session.
> Benji does not write the mission log after the mission. He writes it during.

### Pre-Hunt Checklist

- [ ] All four toolkit tools pass their field tests locally
- [ ] `requirements.txt` is up to date (`pip freeze > requirements.txt`)
- [ ] `AI_LOG.md` is current
- [ ] `vulnerability_hunt/exploit.py` — argument parsing in place
- [ ] `vulnerability_hunt/fix.py` — argument parsing in place
- [ ] `vulnerability_hunt/REPORT.md` — headings populated, ready to fill
- [ ] Git remote confirmed, can push
- [ ] Tags w1, w2, w3, w4 in place

### Hunt Log

**[TIME] — Diagnosis phase:**


**[TIME] — Vulnerability identified:**


**[TIME] — Exploit development:**


**[TIME] — Flag retrieved:**
```
FLAG:
```

**[TIME] — Remediation:**


**[TIME] — Final commit and push:**

