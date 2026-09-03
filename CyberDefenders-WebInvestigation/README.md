# CyberDefenders Lab: Web Investigation Writeup

**Category:** Network Forensics | **Difficulty:** Easy | **Tools:** Wireshark

**Scenario:** You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore. Recently, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to internal systems.

---

### Q1: By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

*   **Approach:** Analyze network traffic (Traffic Analysis) to detect bandwidth anomalies and identify suspicious IPs.
*   **Steps Taken:** Attackers typically generate a massive number of connections when scanning or exploiting a system. Navigating to `Wireshark -> Statistics -> Conversations`, an overwhelming traffic discrepancy is noticed between the external IP `111.224.250.131` and the destination server `73.124.22.98`. Using the filter `ip.src==111.224.250.131 and ip.dst==73.124.22.98`, it is easy to observe this IP continuously sending GET requests showing signs of SQL Injection vulnerability scanning.
*   **Evidence:**
    ![Q1 - Conversations statistics](images/q1_1.png)
    ![Q1 - Filtering Attacker IP](images/q1_2.png)
*   **Flag:** `111.224.250.131`

---

### Q2: If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

*   **Approach:** Apply Open Source Intelligence (OSINT) to look up the geographical location (Geolocation) to assess the risk of the source IP.
*   **Steps Taken:** Look up the IP `111.224.250.131` on the AbuseIPDB platform. The results return a location in Shijiazhuang city, China. For an online bookstore system (BookWorld) that has no customer base or branches in this region, this is a high-confidence Indicator of Compromise (IOC), confirming it as a targeted attack.
*   **Evidence:**
    ![Q2 - Geolocation lookup](images/q2.png)
*   **Flag:** `Shijiazhuang`

---

### Q3: Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?

*   **Approach:** Trace the target path of the malicious request streams to identify the weakness in the web application.
*   **Steps Taken:** Carefully analyzing the intercepted GET packets reveals the attacker continuously stuffing payloads containing SQL keywords (like `UNION`, `SELECT`) into queries sent to the `search.php` file. This indicates that `search.php` is the flawed script lacking Input Validation, creating a direct vulnerability for the SQL Injection to exploit.
*   **Evidence:**
    ![Q3 - Identifying the vulnerable script](images/q3.png)
*   **Flag:** `search.php`

---

### Q4: Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first SQLi attempt by the attacker?

*   **Approach:** Construct an incident timeline (Timeline Analysis) to determine the onset and the initial probing payload.
*   **Steps Taken:** Sorting the packets targeting `search.php` chronologically, the first request initiating the attack chain is found. Extracting the URI and performing a URL Decode yields the string `/search.php?search=book and 1=1; -- -`. This is a classic logic test (`1=1` is always true) for the hacker to confirm whether the server executes the injected queries.
*   **Evidence:**
    ![Q4 - First SQLi query](images/q4.png)
*   **Flag:** `/search.php?search=book and 1=1; -- -`

---

### Q5: Can you provide the complete request URI that was used to read the web server's available databases?

*   **Approach:** Analyze the escalation behavior (Database Enumeration) via the query merging technique (UNION SELECT).
*   **Steps Taken:** Once the vulnerability is confirmed, the hacker will attempt to map the database. Using the filter `ip.src==111.224.250.131 and http and frame contains "schema"`, a suspicious packet (frame 1520) is caught containing a call to `INFORMATION_SCHEMA.SCHEMATA`. Decoding this URL clearly shows the intent to use the `JSON_ARRAYAGG` function to force the server to aggregate and return a list of all existing Databases in a single query.
*   **Evidence:**
    ![Q5 - Schema query packet](images/q5_1.png)
    ![Q5 - URL Decode result](images/q5_2.png)
*   **Flag:** `/search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -`

---

### Q6: Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?

*   **Approach:** Analyze the HTTP Response packet to assess the extent of the Data Exfiltration.
*   **Steps Taken:** After obtaining the Database list, the attacker continues querying to find table names. Following the connection stream (Follow HTTP Stream) at frame 1548, the server's response to the attacker is read as a JSON array containing 3 tables: `["admin", "books", "customers"]`. Clearly, the `customers` table is the target containing sensitive user data.
*   **Evidence:**
    ![Q6 - Table containing user data](images/q6.png)
*   **Flag:** `customers`

---

### Q7: The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?

*   **Approach:** Analyze the change in communication method (from GET to POST) to detect deeper intrusion behavior.
*   **Steps Taken:** When changing the filter to `http.request.method == "POST"`, it is noticed that the hacker's target completely changes. Instead of exploiting SQLi on `search.php`, they are sending login form data to the `login.php` and `index.php` files. The paths of these files reveal that the attacker scanned and discovered the system's hidden administrative directory, which is `/admin/`.
*   **Evidence:**
    ![Q7 - Discovered administrative directory](images/q7.png)
*   **Flag:** `/admin/`

---

### Q8: Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?

*   **Approach:** Extract the compromised Credentials from the Body of the POST request stream.
*   **Steps Taken:** Locate the POST packet targeting `/admin/login.php` (at frame 88699) and use the Follow TCP Stream feature to analyze the entire connection session. At the end of the Request Body, the login credentials sent in cleartext are discovered: `username=admin&passwordfld=admin123%21`. The server responding with an HTTP 302 Found code confirms this account logged in successfully.
*   **Evidence:**
    ![Q8 - Login credentials](images/q8.png)
*   **Flag:** `admin:admin123!`

---

### Q9: We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?

*   **Approach:** Monitor Post-Exploitation behavior to detect any malicious payload (Web Shell/Backdoor) uploaded to the server.
*   **Steps Taken:** Continue analyzing the POST stream at frame 88757 targeting `/admin/index.php`. The appearance of the `Content-Type: multipart/form-data` header exposes file upload activity on the system. Following the HTTP Stream indicates that the attacker leveraged the newly acquired admin privileges to upload an executable file aimed at creating a Reverse Shell connection back to their server. The name of this malicious file is clearly declared as `NVri2vhp.php`.
*   **Evidence:**
    ![Q9 - Malicious file](images/q9_1.png)
    ![Q9 - Malicious file HTTP Stream](images/q9_2.png)
*   **Flag:** `NVri2vhp.php`
