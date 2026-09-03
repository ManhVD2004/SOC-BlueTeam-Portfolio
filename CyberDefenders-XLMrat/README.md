# CyberDefenders Lab: XLMrat Writeup

**Scenario:** A compromised machine has been flagged due to suspicious network traffic. Your task is to analyze the PCAP file to determine the attack method, identify any malicious payloads, and trace the timeline of events. Focus on how the attacker gained access, what tools or techniques were used, and how the malware operated post-compromise.

---

### Q1: The attacker successfully executed a command to download the first stage of the malware. What is the URL from which the first malware stage was installed?

*   **Approach:** Open the pcap file in Wireshark, filter by HTTP protocol to find downloaded files.
*   **Steps Taken:**
    *   In the filter bar, typed `http` and found 2 downloaded files: `xlm.txt` and `mdm.jpg`.
    *   At frame 4, right-clicked → **Follow HTTP Stream**.
*   **Analysis of `xlm.txt`:**
    *   **Nature of the file:** This is a VBScript acting as a Stager/Dropper.
    *   **Obfuscation technique:** The attacker split the malicious code into an array of 88 string elements (`LZeWX(0)` to `LZeWX(87)`), then used a `For...Next` loop to concatenate them into the variable `OodjR`. This technique helps evade Antivirus/IDS systems that scan for static string signatures.
    *   **Execution & Defense Evasion technique:** The script instantiates a `WScript.Shell` object to silently execute a PowerShell process via `cmd.exe`, using a series of evasion flags:
        *   `-NOP` (NoProfile): Skips loading the user profile to speed up execution.
        *   `-WIND HIDDeN` (WindowStyle Hidden): Hides the command window so the victim doesn't notice.
        *   `-eXeC BYPASS` (ExecutionPolicy Bypass): Bypasses Windows PowerShell's script execution restriction policy.
        *   `-NONI` (NonInteractive): Runs in non-interactive mode.
*   **Relationship between `xlm.txt` and `mdm.jpg` (proving the infection chain):**
    Based on the list of packets filtered by HTTP, the timeline of the attack becomes clear:
    1.  **Step 1 (Frame 4):** The victim machine connects to `45.126.209.4:222` to download the `xlm.txt` script.
    2.  **Step 2 (Execution):** The `For...Next` loop in `xlm.txt` finishes decoding the `OodjR` string and silently triggers the PowerShell command. The decoded command string contains a request to connect to the payload download URL.
    3.  **Step 3 (Frame 12):** About 1 second later, a new HTTP GET request appears at Frame 12, downloading the `mdm.jpg` file from the same IP and port of the C2 server, `45.126.209.4:222`.
*   **Conclusion:** The file `mdm.jpg` is the first-stage payload fetched via the `xlm.txt` lure script. Therefore, the exact URL used to download the malware is: `http://45.126.209.4:222/mdm.jpg`.
*   **Evidence:**
    ![Filtering HTTP protocol reveals 2 downloaded files, xlm.txt and mdm.jpg](images/q1_1.png)
    ![Following the HTTP Stream of xlm.txt](images/q1_2.png)
    ![Details of the evasive and execution VBScript code](images/q1_3.png)
*   **Flag:** `http://45.126.209.4:222/mdm.jpg`

---

### Q2: Which hosting provider owns the associated IP address?

*   **Approach:** Use OSINT tools to look up identification information (ISP/ASN) for the malicious IP address `45.126.209.4` extracted in Q1.
*   **Steps Taken:** Accessed the `abuseipdb.com` database and entered the IP into the search bar to check the hosting provider information.
*   **Evidence:** The result shows the ISP managing this IP is **ReliableSite.Net LLC**.
    ![Looking up the malicious IP on AbuseIPDB](images/q2.png)
*   **Flag:** `ReliableSite.Net`

---

### Q3: By analyzing the malicious scripts, two payloads were identified: a loader and a secondary executable. What is the SHA256 of the malware executable?

*   **Approach:** While analyzing the HTTP Stream of the `mdm.jpg` file, it becomes clear this is not actually an image file but rather a PowerShell script acting as a second-stage Loader. Inside this script are 2 hexadecimal-encoded variables: `$hexString_bbb` and `$hexString_pe`.
    *   `$hexString_pe`: A .NET code-injection module.
    *   `$hexString_bbb`: Begins with the string `4D_5A_90...` (equivalent to the ASCII value MZ). This is the characteristic signature of a Windows PE (Portable Executable) file. The attacker split the malicious `.exe` file into a Hex string and hid it in this variable to perform code injection (Process Hollowing) into the legitimate process `RegSvcs.exe`.
    Therefore, to get the malware's hash, we need to extract and decode the `$hexString_bbb` variable.
*   **Steps Taken:**
    1.  On the Follow HTTP Stream view of `mdm.jpg`, copied the entire string inside the `$hexString_bbb` variable (excluding the quotation marks).
    2.  Used CyberChef to decode and compute the hash with the following recipe:
        *   **Find / Replace:** Find `_` (underscore), leave Replace empty to join the Hex string into one continuous string.
        *   **From Hex:** Converts the continuous Hex string back into the original binary format of the `.exe` file.
        *   **SHA2:** Set Size to 256 to compute the SHA256 hash directly from the restored binary file.
*   **Evidence:**
    ![Locating the Hex string hidden inside mdm.jpg](images/q3_1.png)
    ![Extracting the hexString_bbb variable](images/q3_2.png)
    ![Using CyberChef to restore the binary file and compute the SHA256 hash](images/q3_3.png)
*   **Flag:** `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798`

---

### Q4: What is the malware family label based on Alibaba?

*   **Approach:** Use the SHA256 hash found above to look up identification information on the VirusTotal malware analysis platform.
*   **Steps Taken:** Accessed VirusTotal, pasted the hash `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` into the search bar. On the Detection tab, checked the detection result of the Alibaba engine.
*   **Evidence:** The scan result shows Alibaba identifies this file as belonging to the family `Backdoor:MSIL/AsyncRat.a2786761`.
    ![Identifying the AsyncRat malware family on VirusTotal](images/q4.png)
*   **Flag:** `AsyncRat`

---

### Q5: What is the PE header compile (Creation Time) timestamp of the malware?

*   **Approach:** Examine the metadata of the PE file already analyzed by VirusTotal to find the compile/creation time of the malware.
*   **Steps Taken:** Still on the VirusTotal results page, switched to the Details tab. Scrolled down to the History section to view the Creation Time field.
*   **Evidence:** The recorded compile time is `2023-10-30 15:08:44 UTC`.
    ![Checking the Creation Time of the PE file](images/q5.png)
*   **Flag:** `2023-10-30 15:08`

---

### Q6: Which LOLBin is leveraged for stealthy process execution in this script? Provide the full path.

*   **Approach:** A LOLBin (Living-off-the-Land Binary) refers to legitimate executables/tools that already exist on Windows (such as `powershell.exe`, `certutil.exe`...) that attackers abuse to execute malicious code. The attacker's goal here is to inject the actual malicious file into a legitimate Windows process to remain stealthy. Attackers commonly use string obfuscation techniques to hide the path to this process.
*   **Steps Taken:** Returned to analyzing the PowerShell source code (located at the end of HTTP Stream 1 from the `mdm.jpg` file), and closely observed the variable assignment lines declaring the path. The script uses the `-replace '#', ''` function to strip out all the junk `#` characters. Manually reversing this obfuscation reveals the full path.
    *   **Deobfuscating variable `$NA`:** `'C:\W#######indow############s\Mi####cr'` — after stripping all `#`, we get the first part: `C:\Windows\Micr`
    *   **Deobfuscating variable `$AC`:** Takes the `$NA` variable above and concatenates it with `'osof#####t.NET\Fra###mework\v4.0.303###19\R##egSvc#####s.exe'` (also with all `#` stripped): concatenating gives the full path.
*   **Evidence:**
    ![Obfuscation technique used to hide the LOLBin path](images/q6.png)
*   **Flag:** `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

---

### Q7: The script is designed to drop several files. List the names of the files dropped by the script.

*   **Approach:** In attacks like this, malware commonly "drops" supporting files onto the victim's disk to establish a persistence mechanism or execute complex command chains. It's necessary to search for file-writing commands (e.g., `WriteAllText`, `Out-File`) within the source code to identify the names of these files.
*   **Steps Taken:** Continued analyzing the final portion of HTTP Stream 1 (from the `mdm.jpg` file), and discovered the malware uses the `[IO.File]::WriteAllText` method to sequentially create and write content into 3 files in the `C:\Users\Public\` directory. These files are:
    1.  `Conted.ps1`: Contains a command to launch PowerShell with hidden parameters.
    2.  `Conted.bat`: Contains a command to execute the VBScript script.
    3.  `Conted.vbs`: Contains VBScript code to run the batch file completely invisibly (visibility = 0).
*   **Evidence:**
    ![Commands creating the Conted.ps1 and Conted.bat files](images/q7_1.png)
    ![Command creating the Conted.vbs file and setting up Scheduled Task persistence](images/q7_2.png)
*   **Flag:** `Conted.ps1,Conted.bat,Conted.vbs`
