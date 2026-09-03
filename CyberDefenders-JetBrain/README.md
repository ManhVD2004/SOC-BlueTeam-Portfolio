# CyberDefenders Lab: JetBrains Writeup

**Category:** Network Forensics | **Difficulty:** Easy (Community rating: Medium) | **Tactics:** Initial Access, Execution, Command and Control | **Tools:** Wireshark, NetworkMiner, Brim

**Scenario:** During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation.

As part of the investigation, you are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

---

### Q1: What is the attacker's IP address?

*   **Approach:** Analyze traffic statistics by endpoint in Wireshark to identify any IP with anomalous traffic volume.
*   **Steps Taken:** Navigate to **Statistics → Conversations/Endpoints**, discovering that the IP `23.158.56.196` accounts for a massive amount of traffic. Applying the filter `ip.addr==23.158.56.196` and checking the **Protocol Hierarchy** reveals that the vast majority of the traffic is **HTTP**. Further filtering with `ip.addr==23.158.56.196 and http` shows this IP continuously sending a barrage of **GET/POST** requests to two internal IP ranges within a very short timeframe — a classic signature of a brute-force or automated exploitation tool.
*   **Evidence:**
    ![Q1 - Thống kê Endpoints trên Wireshark](images/q1_1.png)
    ![Q1 - Traffic GET/POST dồn dập từ attacker](images/q1_2.png)
    ![Q1 - Filter HTTP theo IP attacker](images/q1_3.png)
*   **Flag:** `23.158.56.196`

---

### Q2: What version of our web server service is running?

*   **Approach:** Follow the HTTP Stream to identify the service banner/version information.
*   **Steps Taken:** Using **Follow HTTP Stream** on the packets exchanged with the server, the running service is identified as **JetBrains TeamCity**, version `2023.11.3`.
*   **Evidence:**
    ![Q2 - Version TeamCity trong HTTP Stream](images/q2.png)
*   **Flag:** `2023.11.3`

---

### Q3: What CVE number corresponds to the vulnerability the attacker exploited?

*   **Approach:** Look up the CVE corresponding to the TeamCity version identified in Q2.
*   **Steps Taken:** Searching for CVEs related to TeamCity `2023.11.3` identifies **CVE-2024-27198** — whose behavior matches the traffic in the analyzed PCAP (related to Authentication Bypass).
    
    **Nature of the vulnerability:** It allows an attacker to bypass the authentication mechanism by injecting a fake `.jsp` file path (e.g., `/hax.jsp/...`) to directly call TeamCity's internal REST APIs without logging in. The attacker's goal is to immediately create a new Admin account (`SYSTEM_ADMIN`) to seize full control and maintain persistence.
*   **Evidence:**
    ![Q3 - CVE-2024-27198 khớp với hành vi tấn công](images/q3.png)
*   **Flag:** `CVE-2024-27198`

---

### Q4: What credentials did the attacker set up when creating a user account?

*   **Approach:** Inspect the CVE-2024-27198 exploitation request to view the payload used for user creation.
*   **Steps Taken:** Observe the URI at **Frame 24721**: `/hax?jsp=/app/rest/users;.jsp`. The attacker leveraged a **Path Manipulation** technique to deceive TeamCity's authentication filter — the server assumed this was a request for a public static `.jsp` file, but the backend forwarded the processing to the `/app/rest/users` REST API. This allowed the execution of administrative APIs (creating a user) completely **unauthenticated**.
    
    Using **Follow HTTP Stream**, the initialized username and password are identified.
*   **Evidence:**
    ![Q4 - Request khai thác Path Manipulation tạo user](images/q4_1.png)
    ![Q4 - Credentials trong HTTP Stream](images/q4_2.png)
*   **Flag:** `c91oyemw:CL5vzdwLuK`

---

### Q5: What is the name of the webshell file the attacker uploaded?

*   **Approach:** Inspect the plugin upload request to find the embedded webshell file.
*   **Steps Taken:** After creating the admin account (`c9loyemw`), the attacker moved to the **Persistence** phase by abusing TeamCity's plugin installation feature to upload a webshell to the server, evading standard file upload filters — executed via the `POST /admin/pluginUpload.html` endpoint.
    
    The uploaded file is `NSt8bHTg.zip`, which contains 3 signs of establishing solid persistence:
    *   **Permanent storage via Plugin loading mechanism:** When TeamCity receives a file via `/admin/pluginUpload.html`, the system automatically extracts and writes the data permanently to the `<TeamCity_Data>/plugins/` directory — meaning it is not lost upon service restart (reboot persistence).
    *   **Creating a fixed backdoor endpoint:** The archive structure contains the path `buildServerResources/NSt8bHTg.jsp`, prompting TeamCity to automatically map it to the public URL `/plugins/NSt8bHTg/NSt8bHTg.jsp` — allowing direct access without re-exploiting CVE-2024-27198.
    *   **On-demand remote control:** The JSP code inside the payload listens for the `cmd` parameter via HTTP requests, forwarding it to `ProcessBuilder` to execute system commands (RCE) — functioning as a permanent webshell.
*   **Evidence:**
    ![Q5 - Request upload plugin chứa webshell](images/q5.png)
*   **Flag:** `NSt8bHTg.zip`

---

### Q6: When did the attacker execute their first command via the web shell?

*   **Approach:** Monitor the traffic flow immediately after the plugin is activated to find the first command request sent to the webshell.
*   **Steps Taken:** Using **Follow HTTP Stream**, observe:
    *   The server responded with `<response>Plugin loaded successfully</response>` — confirming the malicious plugin was loaded.
    *   Immediately after, the attacker sent `POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1` with the payload `cmd=ls` — a directory listing command to verify execution privileges. The server responded with a list of files (starting with `append.bat...`), confirming successful execution.
    *   The response header recorded: `Date: Sun, 30 Jun 2024 08:03:57 GMT`. Converted to the requested format (`YYYY-MM-DD HH:MM`, rounded down to the minute): `2024-06-30 08:03`.
*   **Evidence:**
    ![Q6 - Plugin loaded successfully + lệnh cmd=ls đầu tiên](images/q6_1.png)
    ![Q6 - Timestamp trong response header](images/q6_2.png)
*   **Flag:** `2024-06-30 08:03`

---

### Q7: What new username and password did the attacker write into the tampered credentials file?

*   **Approach:** Locate the webshell request containing the command to overwrite the credentials file.
*   **Steps Taken:** At **TCP Stream 547**, the attacker used the `NSt8bHTg.jsp` webshell (`POST /plugins/NSt8bHTg/NSt8bHTg.jsp`) to send a data manipulation command. Decoding the URL-decoded command string yields:
    `bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'`
    This command overwrites the contents of the `/tmp/Creds.txt` file with fake credentials set by the attacker.
*   **Evidence:**
    ![Q7 - Lệnh ghi đè file Creds.txt qua webshell](images/q7.png)
*   **Flag:** `a1l4m:youarecompromised`

---

### Q8: What is the MITRE Technique ID for the attacker's action in Q7?

*   **Approach:** Map the file overwriting behavior from Q7 into the MITRE ATT&CK Tactic → Technique → Sub-technique structure.
*   **Steps Taken:**
    *   **Tactic:** The action `echo "..." > /tmp/Creds.txt` alters the content of a data file to compromise Integrity → falling under the **Impact** tactic (`TA0040`).
    *   **Technique:** The behavior of interfering with/modifying file content belongs to the **Data Manipulation** technique (`T1565`).
    *   **Sub-technique:** T1565 has 3 branches: `.001` Stored Data Manipulation (data on disk), `.002` Transmitted Data Manipulation (data in transit), `.003` Runtime Data Manipulation (data in RAM/processes). Because the attacker used a bash command to directly overwrite a file on the disk (`/tmp/Creds.txt`), the exact sub-technique is **T1565.001**.
*   **Evidence:**
    ![Q8 - Hành vi ghi đè file trên đĩa](images/q8.png)
*   **Flag:** `T1565.001`

---

### Q9: What command did the attacker use to try to escape from the container?

*   **Approach:** Find the subsequent webshell request containing the Docker-related command, and decode the URL-encoded payload.
*   **Steps Taken:** The command receiving endpoint remains `POST /plugins/NSt8bHTg/NSt8bHTg.jsp`. The raw payload (URL-encoded) is:
    `cmd=docker+run+--rm+-it+-v+%2F%3A%2Fhost+ubuntu+chroot+%2Fhost`
    Decoding the special characters (`+` → space, `%2F` → `/`, `%3A` → `:`), the full command is:
    `docker run --rm -it -v /:/host ubuntu chroot /host`
    
    **Attack Mechanism (Container Escape via Root Mount & chroot):**
    *   `docker run --rm -it`: Initializes a new container, cleans up after running, and opens an interactive session with a TTY.
    *   `-v /:/host`: **The core technique** — mounts the entire root directory (`/`) of the host into the `/host` directory inside the container.
    *   `chroot /host`: Changes the process's apparent root directory to `/host`, allowing direct interaction with the host's actual filesystem, bypassing sandbox restrictions — aimed at reading/writing sensitive files like `/etc/shadow`, `/root/.ssh/authorized_keys`.
    
    **Evidence of Failure:** The response has `Content-Length: 4` — with no output returned. Reason: the `-it` flag requires a valid TTY, but the Java webshell executes via `ProcessBuilder` (a non-interactive background process), causing Docker to report a missing input device error and terminate immediately.
*   **Evidence:**
    ![Q9 - Lệnh container escape thất bại](images/q9.png)
*   **Flag:** `docker run --rm -it -v /:/host ubuntu chroot /host`
