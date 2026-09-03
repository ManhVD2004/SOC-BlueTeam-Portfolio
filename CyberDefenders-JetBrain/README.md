# CyberDefenders Lab: JetBrains Writeup

**Category:** Network Forensics | **Difficulty:** Easy | **Tactics:** Initial Access, Execution, Command and Control | **Tools:** Wireshark, NetworkMiner, Brim

**Scenario:** During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation.

As part of the investigation, you are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

---

### Q1: What is the attacker's IP address?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q1 - ](images/q1.png)
*   **Flag:** ``

---

### Q2: What version of our web server service is running?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q2 - ](images/q2.png)
*   **Flag:** ``

---

### Q3: What CVE number corresponds to the vulnerability the attacker exploited?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q3 - ](images/q3.png)
*   **Flag:** ``

---

### Q4: What credentials did the attacker set up when creating a user account?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q4 - ](images/q4.png)
*   **Flag:** ``

---

### Q5: What is the name of the webshell file the attacker uploaded?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q5 - ](images/q5.png)
*   **Flag:** ``

---

### Q6: When did the attacker execute their first command via the web shell?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q6 - ](images/q6.png)
*   **Flag:** ``

---

### Q7: What new username and password did the attacker write into the tampered credentials file?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q7 - ](images/q7.png)
*   **Flag:** ``

---

### Q8: What is the MITRE Technique ID for the attacker's action in Q7 (tampering with the text file)?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q8 - ](images/q8.png)
*   **Flag:** ``

---

### Q9: What command did the attacker use to try to escape from the container?
*   **Cách làm:** 
*   **Thao tác thực hiện:** 
*   **Bằng chứng:**
    ![Q9 - ](images/q9.png)
*   **Flag:** ``
