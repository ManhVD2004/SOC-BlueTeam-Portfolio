# CyberDefenders Lab: PoisonedCredentials Writeup

**Category:** Network Forensics | **Difficulty:** Easy | **Tactics:** Credential Access, Collection | **Tool:** Wireshark

**Scenario:** Your organization's security team has detected a surge in suspicious network activity. There are concerns that LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning attacks may be occurring within your network. These attacks are known for exploiting these protocols to intercept network traffic and potentially compromise user credentials. Your task is to investigate the network logs and examine captured network traffic.

---

### Q1: Can you identify the specific mistyped query made by the machine with the IP address 192.168.232.162?

*   **Approach:** Filter LLMNR traffic by the victim's IP on Wireshark to find the mistyped hostname query.
*   **Steps Taken:** Apply the filter `ip.addr==192.168.232.162 and llmnr`. Right at the top of the results, at **Frame 52** (and 53), the machine `192.168.232.162` sends a **Standard Query** packet to the multicast address `224.0.0.252` — this is the specific multicast address designated for LLMNR, confirming that the victim machine is broadcasting to the entire network. Examining the details of Frame 52 reveals the query record: `fileshaare: type A, class IN`. The victim actually intended to type `fileshare` but accidentally added an extra `a`, making it `fileshaare`.
    
    Because LLMNR/NBT-NS **lacks an authentication mechanism**, whoever answers first is implicitly trusted by the victim's machine. The attacker (running a tool like **Responder**) only takes a few milliseconds to send a spoofed response ("I am `fileshaare`!"), causing the victim to immediately redirect their connection to the attacker's machine.
*   **Evidence:**
    ![Q1 - Mistyped LLMNR query "fileshaare"](images/q1.png)
*   **Flag:** `fileshaare`

---

### Q2: What is the IP address of the machine acting as the rogue entity?

*   **Approach:** Check the LLMNR Response packet corresponding to the `fileshaare` query in Q1 to identify the IP of the machine that sent the spoofed reply.
*   **Steps Taken:** Following the traffic flow after Frame 52/53, an **LLMNR Response** packet answering the `fileshaare` query is identified, originating from the IP `192.168.232.215` — this is the rogue (attacker) machine that spoofed the reply before anyone else could respond.
*   **Evidence:**
    ![Q2 - Spoofed LLMNR Response packet from the rogue machine](images/q2.png)
*   **Flag:** `192.168.232.215`

---

### Q3: What is the IP address of the second machine that received poisoned responses from the rogue machine?

*   **Approach:** Filter all LLMNR traffic originating from the rogue IP identified in Q2 to find other poisoned victims.
*   **Steps Taken:** Apply the filter `ip.addr==192.168.232.215 and llmnr`. The results show that the attacker also took advantage of a typo for a printer hostname, `prinetr` (which should have been `printer`), to send a spoofed response to another victim with the IP `192.168.232.176`.
*   **Evidence:**
    ![Q3 - Second victim poisoned via "prinetr" query](images/q3.png)
*   **Flag:** `192.168.232.176`

---

### Q4: What is the username of the account that the attacker compromised?

*   **Approach:** After the victim trusts the SMB connection to the rogue machine, inspect the NTLM Authentication packet to extract the username.
*   **Steps Taken:** After being poisoned via LLMNR/NBT-NS, the second victim (`192.168.232.176`) believes the attacker's machine (`192.168.232.215`) is the valid printer `prinetr`. Applying the filter `ip.addr==192.168.232.215 and smb2`, all captured SMB2 traffic occurs between the attacker and the second victim — confirming that the compromised account resulted from the printer query poisoning, not the `fileshaare` incident in Q1.
    
    When Windows attempts to connect to the spoofed printer via SMB, it triggers the **NTLM** authentication mechanism, sending an `NTLMSSP_AUTH` packet containing the identity `cybercactus.local\janesmith` straight to the attacker's machine (**Frame 242**).
*   **Evidence:**
    ![Q4 - NTLMSSP_AUTH packet containing the username janesmith](images/q4.png)
*   **Flag:** `janesmith`

---

### Q5: What is the hostname of the machine that the attacker accessed via SMB?

*   **Approach:** Examine the `Target Info` structure during the NTLM negotiation process to retrieve the hostname.
*   **Steps Taken:** At **Frame 241**, during the NTLM authentication negotiation via SMB2, the system exchanges the `Target Info` structure (which contains AV_PAIRS identity attributes). Expanding the branch **SMB2 → Security Blob → NTLM Secure Service Provider → Target Info**, the `NetBIOS computer name` field displays `ACCOUNTINGPC`, and the `DNS computer name` field displays `AccountingPC.cybercactus.local`.
*   **Evidence:**
    ![Q5 - Target Info containing the hostname ACCOUNTINGPC](images/q5.png)
*   **Flag:** `AccountingPC`
