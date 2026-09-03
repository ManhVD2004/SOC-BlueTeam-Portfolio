# CyberDefenders Lab: 3CX Supply Chain Writeup

**Category:** Threat Intel | **Difficulty:** Easy | **Tools:** VirusTotal, OSINT

**Scenario:** A large multinational corporation heavily relies on the 3CX software for phone communication. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations. As a threat intelligence analyst, your objective is to examine this supply chain attack, uncover how the attackers compromised the 3CX app, identify the potential threat actor, and assess the extent of the incident.

---

### Q1: How many versions of 3CX running on Windows have been flagged as malware?
*   **Approach:** Search OSINT reports on the 3CX supply chain attack to identify the list of affected versions.
*   **Steps Taken:** According to the analysis report by **Kudelski Security**, under the *Affected Application* section, the vendor confirmed **2 versions** of the Electron Windows App were flagged as malicious: `18.12.407` and `18.12.416`.
*   **Evidence:**
    ![Q1 - List of affected Windows versions](images/q1.png)
*   **Flag:** `2`

---

### Q2: What's the UTC creation time of the .msi malware?
*   **Approach:** Extract the hash of the `.msi` file and look up its Creation Time on VirusTotal.
*   **Steps Taken:** Hashed the provided file, obtaining SHA-256: `59e1edf4d82fae4978e97512b0331b7eb21dd4b838b850ba46794d9c7a2c0983`. Looked up this hash on **VirusTotal**, and under the **Details** tab, identified the file's Creation Time as `2023-03-13 06:33` (UTC).
*   **Evidence:**
    ![Q2 - Hash of the .msi file](images/q2_1.png)
    ![Q2 - Creation Time on VirusTotal](images/q2_2.png)
*   **Flag:** `2023-03-13 06:33`

---

### Q3: Which malicious DLLs were dropped by the .msi file?
*   **Approach:** Check the **Relations** tab on VirusTotal to identify the files dropped by the `.msi` file.
*   **Steps Taken:** On VirusTotal, switched to the **Relations** tab; the *Dropped Files* section lists 2 malicious DLLs: `ffmpeg.dll` and `d3dcompiler_47.dll`.
*   **Evidence:**
    ![Q3 - Dropped Files on VirusTotal](images/q3.png)
*   **Flag:** `ffmpeg.dll,d3dcompiler_47.dll`

---

### Q4: What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?
*   **Approach:** Check the **Behavior** tab on VirusTotal to identify the MITRE ATT&CK technique related to loading the DLL.
*   **Steps Taken:** In the **Behavior** tab, under *MITRE ATT&CK Tactics and Techniques*, the `.msi` file was recorded using technique `T1574.002` (**DLL Side-Loading**) to load the malicious DLL. Since the question only asks for the root Technique ID (not the sub-technique), the answer is `T1574`.
*   **Evidence:**
    ![Q4 - MITRE Technique on VirusTotal](images/q4.png)
*   **Flag:** `T1574`

---

### Q5: What is the threat category of the two malicious DLLs?
*   **Approach:** Check the Popular Threat Category field on the VirusTotal Summary page.
*   **Steps Taken:** On the Summary page of both DLL files on VirusTotal, the *Popular Threat Category* field labels both as `Trojan`.
*   **Evidence:**
    ![Q5 - Threat Category on VirusTotal](images/q5.png)
*   **Flag:** `Trojan`

---

### Q6: What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?
*   **Approach:** Check the **Behavior** tab on VirusTotal, looking for techniques belonging to the Defense Evasion category.
*   **Steps Taken:** In the **Behavior** tab, under MITRE ATT&CK, the Virtualization/Sandbox Evasion technique used by both DLL files has ID `T1497`.
*   **Evidence:**
    ![Q6 - Sandbox Evasion Technique](images/q6.png)
*   **Flag:** `T1497`

---

### Q7: Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?
*   **Approach:** Analyze the sandbox (Capa/Behavior) report of `ffmpeg.dll` to identify strings related to anti-VM techniques.
*   **Steps Taken:** In the sandbox report, under **Capabilities → Anti-Analysis**, a note reads *"Reference anti-VM strings targeting VMware"* — indicating the malware actively checks for and evades **VMware** virtualized environments.
*   **Evidence:**
    ![Q7 - Anti-Analysis Capability targeting VMware](images/q7.png)
*   **Flag:** `Vmware`

---

### Q8: What encryption algorithm is used by the ffmpeg.dll file?
*   **Approach:** Analyze the sandbox (Capa/Behavior) report, checking the Cryptography section to identify the encryption algorithm used.
*   **Steps Taken:** In the sandbox report, under **Capabilities → Cryptography → Encrypt Data**, the encryption algorithm used by `ffmpeg.dll` is recorded as `RC4`.
*   **Evidence:**
    ![Q8 - Cryptography Capability: RC4](images/q8.png)
*   **Flag:** `RC4`

---

### Q9: Which group is responsible for this attack?
*   **Approach:** Look up Threat Intelligence reports related to the 3CX Supply Chain campaign to identify the responsible APT group.
*   **Steps Taken:** According to the analysis report by **Black Kite**, the attack has been confirmed by the cybersecurity community as carried out by the **APT Lazarus** group (state-sponsored by North Korea), with the goal of deploying the Gopuram backdoor after exploiting the vulnerability in the 3CX DesktopApp.
*   **Evidence:**
    ![Q9 - Black Kite identifies the Lazarus group](images/q9.png)
*   **Flag:** `Lazarus`
