# CyberDefenders Lab: DanaBot Writeup

**Category:** Network Forensics | **Difficulty:** Easy

**Scenario:** The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

---

### Q1: Which IP address was used by the attacker during the initial access?

*   **Approach:** Analyze DNS queries and verify on VirusTotal.
*   **Steps Taken:** Observe the DNS query and response to `portfolio.serveirc.com`, which has the IP address `62.173.142.148`. Searching for this domain on VirusTotal confirms it is a malicious domain.
*   **Evidence:**
    ![Q1 - Truy vấn DNS](images/q1_1.png)
    ![Q1 - VirusTotal](images/q1_2.png)
*   **Flag:** `62.173.142.148`

---

### Q2: What is the name of the malicious file used for initial access?

*   **Approach:** Analyze the HTTP GET request stream.
*   **Steps Taken:** Inspect the GET request querying the `login.php` file. By using Follow HTTP Stream on this GET frame, we can see an attachment with the filename `allegato_708.js`. This is the file used for initial access.
*   **Evidence:**
    ![Q2 - HTTP GET](images/q2_1.png)
    ![Q2 - Follow HTTP Stream](images/q2_2.png)
*   **Flag:** `allegato_708.js`

---

### Q3: What is the SHA-256 hash of the malicious file used for initial access?

*   **Approach:** Extract the file and calculate its SHA-256 hash.
*   **Steps Taken:** Essentially, when the victim clicks on `login.php`, the server forces the browser to download the malicious attachment `allegato_708.js`. Using the `sha256sum allegato_708.js` command in the Kali Linux Terminal, we obtain the hash of this file.
*   **Evidence:**
    ![Q3 - Lấy SHA-256](images/q3.png)
*   **Flag:** `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

---

### Q4: Which process was used to execute the malicious file?

*   **Approach:** Analyze the JavaScript source code to identify the execution process.
*   **Steps Taken:** Reviewing the obfuscated code, the malware makes calls to the `WScript` object. Furthermore, when deobfuscating the encrypted code, the appearance of `WScript` becomes even clearer, indicating that the execution process is `wscript.exe`.
*   **Evidence:**
    ![Q4 - Code bị làm rối](images/q4_1.png)
    ![Q4 - Code sau khi gỡ rối](images/q4_2.png)
*   **Flag:** `wscript.exe`

---

### Q5: What is the file extension of the second malicious file utilized by the attacker?

*   **Approach:** Identify the stage-two payload through the deobfuscated source code.
*   **Steps Taken:** From the deobfuscated code in Question 4, it is clearly visible that the second malicious file downloaded by the attacker is `resources.dll`. Therefore, the file extension is `.dll`.
*   **Evidence:**
    ![Q5 - Phát hiện payload thứ 2](images/q5.png)
*   **Flag:** `.dll`

---

### Q6: What is the MD5 hash of the second malicious file?

*   **Approach:** Extract the second payload file and calculate its MD5 hash.
*   **Steps Taken:** In Wireshark, navigate to **File -> Export Objects -> HTTP**, and proceed to export the second malicious file, `resources.dll`. Afterward, use the `md5sum resources.dll` command in the Terminal to check its MD5 hash.
*   **Evidence:**
    ![Q6 - Export Object](images/q6_1.png)
    ![Q6 - Lấy MD5](images/q6_2.png)
*   **Flag:** `e758e07113016aca55d9eda2b0ffeebe`
