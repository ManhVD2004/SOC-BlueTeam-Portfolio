# CyberDefenders Lab: FakeGPT Writeup

**Category:** Malware Analysis | **Difficulty:** Easy

**Scenario:** Analyze a malicious Chrome extension's code and behavior to identify data theft mechanisms, covert exfiltration via `<img>` tags, and anti-analysis techniques.

---

### Q1: Which encoding method does the browser extension use to obscure target URLs, making them more difficult to detect during analysis?

*   **Approach:** Search for obfuscated strings and the target URL decoding function in the source code.
*   **Steps Taken:** In the `app.js` file, at the declaration `const targets = [_0xabc1('d3d3LmZhY2Vib29rLmNvbQ==')];`, the string ending with `==` is a classic indicator of **Base64** encoding. Additionally, the code defines the `_0x5eaf` function which utilizes `btoa()` (JavaScript's built-in Base64 encoding function).
*   **Evidence:**
    ![Base64 Encoding](images/q1.png)
*   **Flag:** `base64`

---

### Q2: Which website does the extension monitor for data theft, targeting user accounts to steal sensitive information?

*   **Approach:** Decode the Base64 string found in Q1 to identify the target.
*   **Steps Taken:** By Base64-decoding the string `d3d3LmZhY2Vib29rLmNvbQ==`, we obtain the URL of the Facebook social network.
*   **Evidence:**
    ![Decode Base64](images/q2.png)
*   **Flag:** `www.facebook.com`

---

### Q3: Which type of HTML element is utilized by the extension to send stolen data?

*   **Approach:** Analyze the data exfiltration function to see which method the malware uses to send data to an external server.
*   **Steps Taken:** In the `app.js` file, the `sendToServer(encryptedData)` function creates an image object using the command `var img = new Image();`, appends the data to the URL, and injects an `<img>` tag into the DOM (`document.body.appendChild(img);`). This technique allows the malware to stealthily send outbound GET requests without being blocked by CORS policies.
*   **Evidence:**
    ![Sending data via img tag](images/q3.png)
*   **Flag:** `<img>`

---

### Q4: What is the first specific condition in the code that triggers the extension to deactivate itself?

*   **Approach:** Look for the malware's Anti-Analysis (sandbox evasion) techniques.
*   **Steps Taken:** In the `loader.js` file, right at the beginning, the malware uses an `if` statement to check the execution environment: `if (navigator.plugins.length === 0 || /HeadlessChrome/.test(navigator.userAgent))`. The first condition it checks is that the length of the browser's plugins array must not be zero (to avoid headless/virtual browsers).
*   **Evidence:**
    ![Anti-Analysis Technique](images/q4.png)
*   **Flag:** `navigator.plugins.length === 0`

---

### Q5: Which event does the extension capture to track user input submitted through forms?

*   **Approach:** Search for Event Listeners monitoring user interactions on the DOM.
*   **Steps Taken:** In `app.js`, the malware attaches a listener to the form to capture the event when a user submits data: `document.addEventListener('submit', ...)`. This event helps extract the username and password.
*   **Evidence:**
    ![Capturing submit event](images/q5.png)
*   **Flag:** `submit`

---

### Q6: Which API or method does the extension use to capture and monitor user keystrokes?

*   **Approach:** Look for Event Listeners specifically used to record keystrokes (acting as a Keylogger).
*   **Steps Taken:** Similar to Q5, the malware implants an additional keyboard monitoring event: `document.addEventListener('keydown', function(event) { ... }`.
*   **Evidence:**
    ![Keydown event keylogger](images/q6.png)
*   **Flag:** `keydown`

---

### Q7: What is the domain where the extension transmits the exfiltrated data?

*   **Approach:** Extract the IoC (C2 server Domain/IP) from the data exfiltration function.
*   **Steps Taken:** Returning to the `sendToServer` function in `app.js`, the URL string receiving the data explicitly specifies the domain `Mo.Elshaheedy.com`.
*   **Evidence:**
    ![C2 Server Domain](images/q7.png)
*   **Flag:** `Mo.Elshaheedy.com`

---

### Q8: Which function in the code is used to exfiltrate user credentials, including the username and password?

*   **Approach:** Identify the name of the function handling the theft of login credentials.
*   **Steps Taken:** Inside the `submit` event, if the `username` and `password` are successfully extracted, the malicious code calls the `exfiltrateCredentials(username, password)` function.
*   **Evidence:**
    ![Credentials extraction function](images/q8.png)
*   **Flag:** `exfiltrateCredentials(username, password);`

---

### Q9: Which encryption algorithm is applied to secure the data before sending?

*   **Approach:** Analyze the encryption algorithm used to hide the stolen data over the network transmission.
*   **Steps Taken:** In the `encryptPayload(data)` function of the `app.js` file (and also the `crypto.js` file), the source code uses the CryptoJS library with the `CryptoJS.AES.encrypt` method. The algorithm used is the Advanced Encryption Standard (AES).
*   **Evidence:**
    ![AES Encryption](images/q9.png)
*   **Flag:** `AES`

---

### Q10: What does the extension access to store or manipulate session-related data and authentication information?

*   **Approach:** Analyze the extension's permissions manifest to identify the target of the session data theft.
*   **Steps Taken:** Checking the `manifest.json` file, under the `"permissions"` array, the malware blatantly requests `"cookies"` permission. This is where the browser stores all user session data and authentication tokens. By gaining this permission, the malware can easily hijack the login session (Session Hijacking).
*   **Evidence:**
    ![Cookies permissions declaration](images/q10.png)
*   **Flag:** `cookies`
