# CyberDefenders Lab: Tusk Infostealer Writeup

**Category:** Threat Intel | **Difficulty:** Easy

**Scenario:** A blockchain development company detected unusual activity when an employee was redirected to an unfamiliar website while accessing a DAO management platform. Soon after, multiple cryptocurrency wallets linked to the organization were drained. Investigators suspect a malicious tool was used to steal credentials and exfiltrate funds. Your task is to analyze the provided intelligence to uncover the attack methods, identify indicators of compromise, and track the threat actor's infrastructure.

---

### Q1: In KB, what is the size of the malicious file?

*   **Approach:** Exploit the metadata of the sample file via its hash on VirusTotal.
*   **Steps Taken:** Calculate the MD5 hash of the downloaded malicious file (`E5B8B2CF5B244500B22B665C87C11767`). Search for this hash on VirusTotal, switch to the **Details** tab, and check the **Basic Properties** section to retrieve the File size.
*   **Evidence:**
    ![Checking the file size on VirusTotal](images/q1.png)
*   **Flag:** `921.36`

---

### Q2: What word do the threat actors use in log messages to describe their victims, based on the name of an ancient hunted creature?

*   **Approach:** Analyze the Threat Intel report from Kaspersky to understand the attacker group's slang.
*   **Steps Taken:** Search for information about the "Tusk" campaign in the report. The analysis specifies that the attacker uses the word "Mammoth" in log messages to refer to victims (implying gullible people, similar to mammoths hunted by prehistoric humans).
*   **Evidence:**
    ![The term Mammoth in the report](images/q2.png)
*   **Flag:** `Mammoth`

---

### Q3: The threat actor set up a malicious website to mimic a platform designed for creating and managing decentralized autonomous organizations (DAOs) on the MultiversX blockchain (peerme.io). What is the name of the malicious website the attacker created to simulate this platform?

*   **Approach:** Look for the typosquatting technique targeting the MultiversX DAO platform.
*   **Steps Taken:** Review the "First sub-campaign (TidyMe)" section in the report. The report notes that the attacker simulated the `peerme.io` platform by creating a malicious website with a similar interface and using the fraudulent domain `tidyme.io`.
*   **Evidence:**
    ![Spoofed website tidyme.io](images/q3.png)
*   **Flag:** `tidyme.io`

---

### Q4: Which cloud storage service did the campaign operators use to host malware samples for both macOS and Windows OS versions?

*   **Approach:** Identify the legitimate cloud storage service abused for payload hosting.
*   **Steps Taken:** Read the "Downloader routine" analysis section. The URLs decoded from the configuration file show that the malware hosts its payloads on the Dropbox service.
*   **Evidence:**
    ![Dropbox storage service](images/q4.png)
*   **Flag:** `dropbox`

---

### Q5: The malicious executable contains a configuration file that includes base64-encoded URLs and a password used for archived data decompression, enabling the download of second-stage payloads. What is the password for decompression found in this configuration file?

*   **Approach:** Analyze the content of the malware's configuration file (`config.json`) to extract the decryption/decompression key.
*   **Steps Taken:** In the "Downloader routine" section, check the content of the `config.json` file. This file contains Base64 URLs and a "password" field assigned the value `newfile2024`. This password is used to extract the RAR file containing the second-stage payload.
*   **Evidence:**
    ![Decompression password in the configuration file](images/q5.png)
*   **Flag:** `newfile2024`

---

### Q6: What is the name of the function responsible for retrieving the field archive from the configuration file?

*   **Approach:** Reverse engineer the execution logic of the executable file to find the download and extraction handling function.
*   **Steps Taken:** Read the source code analysis of the `preload.js` file. The function responsible for retrieving the `archive` field from the configuration file, downloading it from Dropbox, and extracting it is named `downloadAndExtractArchive`.
*   **Evidence:**
    ![downloadAndExtractArchive function](images/q6.png)
*   **Flag:** `downloadAndExtractArchive`

---

### Q7: In the third sub-campaign carried out by the operators, the attacker mimicked an AI translator project. What is the name of the legitimate translator, and what is the name of the malicious translator created by the attackers?

*   **Approach:** Extract the Indicators of Compromise (IoCs) from the third attack sub-campaign targeting the AI Translator project.
*   **Steps Taken:** Find the "Third sub-campaign (Voico)" section in the report. The attacker spoofed the legitimate project with the domain `yous.ai` by setting up the phishing website `voico.io`.
*   **Evidence:**
    ![AI translator spoofing campaign](images/q7.png)
*   **Flag:** `yous.ai,voico.io`

---

### Q8: The downloader is tasked with delivering additional malware samples to the victim’s machine, primarily infostealers like StealC and Danabot. What are the IP addresses of the StealC C2 servers used in the campaign?

*   **Approach:** Collect IoCs related to the Command and Control (C2) infrastructure of the StealC malware.
*   **Steps Taken:** Scroll down to the "Network IoCs" table at the end of the report, filter the IP addresses detailed as "StealC C2 Server". There are 2 matching addresses: `46.8.238.240` and `23.94.225.177`.
*   **Evidence:**
    ![StealC C2 Server IP addresses](images/q8.png)
*   **Flag:** `46.8.238.240,23.94.225.177`

---

### Q9: What is the address of the Ethereum cryptocurrency wallet used in this campaign?

*   **Approach:** Identify the attacker's cryptocurrency wallet embedded in the malware (typically used for Clipper techniques - replacing wallet addresses in the clipboard).
*   **Steps Taken:** Read the analysis section regarding the "clipper". The report provides the ETH wallet address as `0xaf0362e215Ff4e004F30e785e822F7E20b99723A`.
*   **Evidence:**
    ![Ethereum wallet address](images/q9.png)
*   **Flag:** `0xaf0362e215Ff4e004F30e785e822F7E20b99723A`
