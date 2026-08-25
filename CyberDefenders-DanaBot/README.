# CyberDefenders Lab: DanaBot Writeup

**Category:** Network Forensics | **Difficulty:** Easy

**Scenario:** The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

---

### Q1: Which IP address was used by the attacker during the initial access?

*   **Cách làm:** Phân tích truy vấn DNS và xác minh trên VirusTotal[cite: 4].
*   **Thao tác thực hiện:** Đầu tiên, chúng ta có thể thấy câu lệnh DNS query và response tới `portfolio.serveirc.com` có địa chỉ IP là `62.173.142.148`[cite: 4]. Khi tìm kiếm DNS này trên VirusTotal, kết quả trả về xác nhận đây là một malicious domain[cite: 4].
*   **Bằng chứng:**
    ![Q1 - Truy vấn DNS](images/q1_1.png)
    ![Q1 - VirusTotal](images/q1_2.png)
*   **Flag:** `62.173.142.148`[cite: 4]

---

### Q2: What is the name of the malicious file used for initial access?

*   **Cách làm:** Phân tích luồng HTTP GET request[cite: 4].
*   **Thao tác thực hiện:** Tiếp theo, kiểm tra lệnh truy vấn GET tới file `login.php`[cite: 4]. Khi Follow HTTP Stream của frame GET này, ta sẽ thấy một attachment (tệp đính kèm) với filename là `allegato_708.js`[cite: 4]. Đây chính là file dùng cho Initial access[cite: 4].
*   **Bằng chứng:**
    ![Q2 - HTTP GET](images/q2_1.png)
    ![Q2 - Follow HTTP Stream](images/q2_2.png)
*   **Flag:** `allegato_708.js`[cite: 4]

---

### Q3: What is the SHA-256 hash of the malicious file used for initial access?

*   **Cách làm:** Trích xuất file và tính toán mã băm SHA-256[cite: 4].
*   **Thao tác thực hiện:** Bản chất khi nạn nhân click vào `login.php`, máy chủ thực chất ép trình duyệt tải về file đính kèm độc hại `allegato_708.js`[cite: 4]. Sử dụng lệnh `sha256sum allegato_708.js` trong Terminal trên Kali Linux, ta lấy được mã hash của file này[cite: 4].
*   **Bằng chứng:**
    ![Q3 - Lấy SHA-256](images/q3.png)
*   **Flag:** `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`[cite: 4]

---

### Q4: Which process was used to execute the malicious file?

*   **Cách làm:** Phân tích mã nguồn JavaScript để tìm tiến trình thực thi[cite: 4].
*   **Thao tác thực hiện:** Khi xem đoạn mã đã bị làm rối, ta thấy mã độc đã gọi đến đối tượng `WScript`[cite: 4]. Ngoài ra, khi deobfuscate (gỡ rối) đoạn code bị mã hóa ở trên, sự xuất hiện của `WScript` càng rõ ràng hơn, chỉ định tiến trình thực thi là `wscript.exe`[cite: 4].
*   **Bằng chứng:**
    ![Q4 - Code bị làm rối](images/q4_1.png)
    ![Q4 - Code sau khi gỡ rối](images/q4_2.png)
*   **Flag:** `wscript.exe`[cite: 4]

---

### Q5: What is the file extension of the second malicious file utilized by the attacker?

*   **Cách làm:** Xác định payload giai đoạn 2 thông qua mã nguồn đã gỡ rối[cite: 4].
*   **Thao tác thực hiện:** Từ đoạn code đã được gỡ rối ở câu 4, ta có thể thấy rõ file mã độc thứ 2 được attacker tải về là `resources.dll`[cite: 4]. Do đó, file extension (phần mở rộng) là `.dll`[cite: 4].
*   **Bằng chứng:**
    ![Q5 - Phát hiện payload thứ 2](images/q5.png)
*   **Flag:** `.dll`[cite: 4]

---

### Q6: What is the MD5 hash of the second malicious file?

*   **Cách làm:** Trích xuất file payload thứ 2 và tính toán mã băm MD5[cite: 4].
*   **Thao tác thực hiện:** Vào Wireshark, chọn **File -> Export Objects -> HTTP**, tiến hành export (lưu) file mã độc thứ 2 là `resources.dll`[cite: 4]. Sau đó, sử dụng lệnh `md5sum resources.dll` trong Terminal để kiểm tra mã hash MD5[cite: 4].
*   **Bằng chứng:**
    ![Q6 - Export Object](images/q6_1.png)
    ![Q6 - Lấy MD5](images/q6_2.png)
*   **Flag:** `e758e07113016aca55d9eda2b0ffeebe`[cite: 4]
