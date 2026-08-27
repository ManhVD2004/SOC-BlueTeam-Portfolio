# CyberDefenders Lab: Red Stealer Writeup

**Category:** Threat Intel | **Difficulty:** Easy | **Tools:** VirusTotal, MalwareBazaar, ThreatFox

**Scenario:** You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection. Your task is to investigate this executable by analyzing its hash.

*Note: The SHA-256 hash provided in the lab file is `248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B`.*

---

### Q1: Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

*   **Cách làm:** Sử dụng nền tảng phân tích tình báo VirusTotal (VT) để đối chiếu kết quả nhận diện từ các hệ thống bảo mật.
*   **Thao tác thực hiện:** Thực hiện truy vấn mã Hash trên VirusTotal. Tại thẻ **Detection**, kiểm tra danh sách kết quả phân tích từ các engine diệt virus. Trình nhận diện của Microsoft định danh tệp tin này là `Trojan:Win32/Redline!`. Theo định dạng chuẩn, tiền tố phân loại của tệp tin là Trojan.
*   **Bằng chứng:**
    ![Q1 - Phân loại trên VirusTotal](images/q1.png)
*   **Flag:** `Trojan`

---

### Q2: Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?

*   **Cách làm:** Phân tích siêu dữ liệu (Metadata) để trích xuất tên gốc của tệp tin.
*   **Thao tác thực hiện:** Điều hướng sang thẻ **Details** trên VirusTotal. Tại khu vực *Basic Properties* hoặc *Names*, hệ thống ghi nhận tệp tin mang tên `Wextract.exe`. Việc lạm dụng tên của một tiện ích giải nén hợp pháp thuộc hệ điều hành Windows (WEXTRACT) là một kỹ thuật ngụy trang (masquerading) phổ biến nhằm lẩn tránh sự phát hiện của các hệ thống giám sát. Theo yêu cầu của hệ thống, định dạng tệp (.exe) được lược bỏ.
*   **Bằng chứng:**
    ![Q2 - Tên tệp tin gốc](images/q2.png)
*   **Flag:** `Wextract`

---

### Q3: Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. What is the UTC timestamp of the malware's first submission to VirusTotal?

*   **Cách làm:** Trích xuất thông tin lịch sử hệ thống để xác định mốc thời gian phát hiện sớm nhất.
*   **Thao tác thực hiện:** Tại thẻ **Details**, định vị khu vực *History*. Chỉ số **First Submission** ghi nhận thời điểm tệp tin được hệ thống VirusTotal tiếp nhận phân tích lần đầu tiên là `2023-10-06 04:41:50`. Tiến hành định dạng lại chuỗi thời gian theo chuẩn `YYYY-MM-DD HH:MM`.
*   **Bằng chứng:**
    ![Q3 - Mốc thời gian First Submission](images/q3.png)
*   **Flag:** `2023-10-06 04:41`

---

### Q4: Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware collecting data from the local system prior to exfiltration?

*   **Cách làm:** Ánh xạ hành vi vi phạm vào khung tiêu chuẩn MITRE ATT&CK Framework.
*   **Thao tác thực hiện:** Chuyển sang thẻ **Behavior** trên VirusTotal và tham chiếu khu vực *MITRE ATT&CK Tactics and Techniques*. Dưới chiến thuật **Collection**, dữ liệu báo cáo chỉ ra rằng mã độc áp dụng kỹ thuật thu thập dữ liệu từ hệ thống cục bộ (Data from Local System) nhằm trích xuất thông tin trình duyệt và cấu hình trước khi tiến hành xuất dữ liệu. Mã kỹ thuật tương ứng là `T1005`.
*   **Bằng chứng:**
    ![Q4 - MITRE ATT&CK Technique](images/q4.png)
*   **Flag:** `T1005`

---

### Q5: Following execution, the malware performs a connectivity check by resolving a well-known social-media domain before contacting its C2. Which single domain does it resolve for this check?

*   **Cách làm:** Phân tích luồng phân giải tên miền (DNS Resolutions) trong môi trường phân tích động (Sandbox).
*   **Thao tác thực hiện:** Tại thẻ **Behavior**, kiểm tra khu vực *Network Communication* (hoặc *DNS Resolutions*). Báo cáo mạng ghi nhận mã độc tiến hành truy vấn phân giải một tên miền mạng xã hội hợp lệ. Đây là kỹ thuật kiểm tra trạng thái kết nối mạng (Connectivity Check) nhằm lẩn tránh các môi trường phân tích cô lập. Tên miền được sử dụng cho quá trình này là `facebook.com`.
*   **Bằng chứng:**
    ![Q5 - DNS Resolutions](images/q5.png)
*   **Flag:** `facebook.com`

---

### Q6: Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?

*   **Cách làm:** Phân tích lưu lượng mạng (IP Traffic) để xác định định danh của máy chủ Điều khiển & Ra lệnh (C2 Server).
*   **Thao tác thực hiện:** Tiến hành rà soát khu vực *IP Traffic* tại thẻ **Behavior**. Phần lớn các địa chỉ IP đều liên kết với các hostname hợp lệ. Điểm bất thường được ghi nhận tại kết nối hướng đến địa chỉ IP `77.91.124.55` thông qua cổng (port) `19071`. Việc sử dụng IP trực tiếp không thông qua DNS kết hợp cùng cổng giao tiếp phi tiêu chuẩn là đặc trưng cơ bản của cơ sở hạ tầng C2.
*   **Bằng chứng:**
    ![Q6 - Địa chỉ IP và Port máy chủ C2](images/q6.png)
*   **Flag:** `77.91.124.55:19071`

---

### Q7: YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?

*   **Cách làm:** Khai thác cơ sở dữ liệu MalwareBazaar để xác định các luật nhận diện (YARA Rules) từ cộng đồng tình báo mối đe dọa.
*   **Thao tác thực hiện:** Truy cập hệ thống `bazaar.abuse.ch` và thực hiện tìm kiếm bằng mã Hash. Trong phần chi tiết báo cáo, khu vực **YARA Signatures** ghi nhận một tập luật được xây dựng bởi chuyên gia nghiên cứu "Varp0s" nhằm nhận diện biến thể mã độc này. Tập luật mang tên `detect_Redline_Stealer`.
*   **Bằng chứng:**
    ![Q7 - YARA Rule trên MalwareBazaar](images/q7.png)
*   **Flag:** `detect_Redline_Stealer`

---

### Q8: Understanding which malware families are targeting the organization helps in strategic security planning for the future. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?

*   **Cách làm:** Tích hợp nền tảng ThreatFox để tra cứu chéo các định danh (Alias) thuộc họ mã độc liên kết với IP máy chủ C2.
*   **Thao tác thực hiện:** Truy cập `threatfox.abuse.ch` và thực hiện truy vấn với cú pháp `ioc:77.91.124.55` (địa chỉ IP C2 đã xác định tại Câu 6). Kết quả trả về tại trường **Malware Alias** xác nhận họ mã độc RedLine Stealer còn được phân loại dưới định danh thứ cấp là `RECORDSTEALER`.
*   **Bằng chứng:**
    ![Q8 - Malware Alias trên ThreatFox](images/q8.png)
*   **Flag:** `RECORDSTEALER`

---

### Q9: By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

*   **Cách làm:** Phân tích bảng Import Address Table (IAT) để xác định các thư viện liên kết động (DLL) hỗ trợ thao tác leo thang đặc quyền.
*   **Thao tác thực hiện:** Truy cập thẻ **Details** trên VirusTotal và định vị khu vực *Imports*. Kết quả phân tích tĩnh cho thấy mã độc tiến hành nạp nhiều thư viện hệ thống, trong đó có `ADVAPI32.dll`. Đây là thư viện cốt lõi chịu trách nhiệm xử lý các API liên quan đến quản lý bảo mật, registry và đặc quyền hệ thống, cung cấp cơ sở để mã độc thực thi các kỹ thuật Privilege Escalation.
*   **Bằng chứng:**
    ![Q9 - Imported DLLs leo quyền](images/q9.png)
*   **Flag:** `ADVAPI32.dll`
