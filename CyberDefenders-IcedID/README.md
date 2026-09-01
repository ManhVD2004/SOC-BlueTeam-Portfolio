# CyberDefenders Lab: IcedID Writeup

**Category:** Threat Intel | **Difficulty:** Easy | **Tools:** VirusTotal, Malpedia, X (Twitter), Tria.ge, ANY.RUN

**Scenario:** A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID. You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

**Hash mẫu được cung cấp:** `191eda0c539d284b29efe556abb05cd75a9077a0`

---

### Q1: What is the name of the file associated with the given hash?
*   **Cách làm:** Tra cứu mã hash mẫu trên VirusTotal để xác định tên file gốc.
*   **Thao tác thực hiện:** Tìm kiếm hash `191eda0c539d284b29efe556abb05cd75a9077a0` trên **VirusTotal**, tại phần thông tin chi tiết, xác định được file độc hại liên quan là `document-1982481273.xlsm`.
*   **Bằng chứng:**
    ![Q1 - Tên file trên VirusTotal](images/q1.png)
*   **Flag:** `document-1982481273.xlsm`

---

### Q2: Can you identify the filename of the GIF file that was deployed?
*   **Cách làm:** Kiểm tra tab **Relations** trên VirusTotal để xác định các file được liên kết/tải về bởi mẫu ban đầu.
*   **Thao tác thực hiện:** Tại tab **Relations** của file `.xlsm`, phát hiện file GIF độc hại được sử dụng trong chuỗi tấn công là `3003.gif`.
*   **Bằng chứng:**
    ![Q2 - File GIF trên tab Relations](images/q2.png)
*   **Flag:** `3003.gif`

---

### Q3: How many domains does the malware look to download the additional payload file in Q2?
*   **Cách làm:** Tiếp tục kiểm tra tab **Relations** trên VirusTotal, mục Contacted Domains liên quan đến file GIF ở Q2.
*   **Thao tác thực hiện:** Tại tab **Relations**, đếm số lượng domain mà mẫu độc hại cố gắng liên hệ để tải file `3003.gif`, xác định được tổng cộng **5 domain**.
*   **Bằng chứng:**
    ![Q3 - Danh sách domain tải file GIF](images/q3.png)
*   **Flag:** `5`

---

### Q4: From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?
*   **Cách làm:** Kiểm tra thông tin đăng ký (registrar) của các domain đã xác định ở Q3.
*   **Thao tác thực hiện:** Tại mục **Contacted Domains** trên VirusTotal, kiểm tra thông tin WHOIS/Registrar của từng domain, xác định registrar được sử dụng phổ biến nhất để lưu trữ nội dung độc hại là `NameCheap`.
*   **Bằng chứng:**
    ![Q4 - Registrar của các domain độc hại](images/q4.png)
*   **Flag:** `NameCheap`

---

### Q5: Could you specify the threat actor linked to the sample provided?
*   **Cách làm:** Tra cứu thông tin threat actor liên quan đến mẫu trên MITRE ATT&CK / VirusTotal Threat Intel.
*   **Thao tác thực hiện:** Trên **MITRE ATT&CK**, mẫu được xác định liên quan đến nhóm `TA551`. Kiểm tra thêm mục Associated Group của `TA551`, xác định được tên gọi khác (alias) của nhóm này là `Gold Cabin`.
*   **Bằng chứng:**
    ![Q5 - Group TA551 trên MITRE ATT&CK](images/q5_1.png)
    ![Q5 - Associated Group: Gold Cabin](images/q5_2.png)
*   **Flag:** `Gold Cabin`

---

### Q6: In the Execution phase, what function does the malware employ to fetch extra payloads onto the system?
*   **Cách làm:** Phân tích hành vi thực thi (Behavior/Execution) của mẫu bằng sandbox (Recorded Future Triage) để xác định API function được gọi.
*   **Thao tác thực hiện:** Trong báo cáo sandbox, tại phần API monitoring/Execution phase, ghi nhận mã độc gọi hàm Windows API `URLDownloadToFileA` để tải thêm payload từ các domain độc hại về máy nạn nhân. Hàm này cho phép tải file trực tiếp từ internet, giúp mã độc lấy và thực thi thêm các thành phần độc hại, mở rộng khả năng hoạt động và duy trì trên hệ thống bị nhiễm.

    Hậu tố `A` trong `URLDownloadToFileA` chỉ ra hàm sử dụng bảng mã **ANSI** để xử lý chuỗi ký tự (ngược lại, hậu tố `W` — ví dụ `URLDownloadToFileW` — sử dụng bảng mã **Unicode**). Sự khác biệt này liên quan đến khả năng tương thích: các hệ thống/ứng dụng cũ thường dùng ANSI, trong khi hệ thống hiện đại thường mặc định dùng Unicode. Trong trường hợp này, mẫu độc hại sử dụng cụ thể biến thể ANSI.
*   **Bằng chứng:**
    ![Q6 - API Call URLDownloadToFileA trong Execution phase](images/q6.png)
*   **Flag:** `URLDownloadToFileA`
