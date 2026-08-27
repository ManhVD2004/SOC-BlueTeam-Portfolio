# CyberDefenders Lab: Red Stealer Writeup

**Category:** Threat Intel | **Difficulty:** Easy | **Tools:** VirusTotal, MalwareBazaar, ThreatFox

**Scenario:** You are part of the Threat Intelligence team in the SOC (Security Operations Center). An executable file has been discovered on a colleague's computer, and it's suspected to be linked to a Command and Control (C2) server, indicating a potential malware infection. Your task is to investigate this executable by analyzing its hash.

*Note: The SHA-256 hash provided in the lab file is `248FCC901AFF4E4B4C48C91E4D78A939BF681C9A1BC24ADDC3551B32768F907B`.*

---

### Q1: Categorizing malware enables a quicker and clearer understanding of its unique behaviors and attack vectors. What category has Microsoft identified for that malware in VirusTotal?

*   **Cách làm:** Sử dụng công cụ tình báo VirusTotal (VT) để kiểm tra định dạng phân loại của các hãng bảo mật.
*   **Thao tác thực hiện:** Dán mã Hash vào ô tìm kiếm của VirusTotal. Tại thẻ **Detection**, lướt xuống danh sách các trình diệt virus và tìm đến hàng của Microsoft. Hãng này nhận diện tệp tin là `Trojan:Win32/Redline!`. Tiền tố phân loại của nó chính là Trojan.
*   **Flag:** `Trojan`

---

### Q2: Clearly identifying the name of the malware file improves communication among the SOC team. What is the file name associated with this malware?

*   **Cách làm:** Khai thác siêu dữ liệu (Metadata) của tệp tin.
*   **Thao tác thực hiện:** Chuyển sang thẻ **Details** trên VirusTotal. Trong phần *Basic Properties* hoặc *Names*, ta thấy tệp tin được đặt tên là `Wextract.exe`. Việc sử dụng tên của một tiện ích giải nén hợp lệ của Windows (WEXTRACT) là thủ đoạn kinh điển để ngụy trang, qua mặt người dùng và các công cụ giám sát tự động. Đề bài yêu cầu không lấy phần mở rộng `.exe`.
*   **Flag:** `Wextract`

---

### Q3: Knowing the exact timestamp of when the malware was first observed can help prioritize response actions. What is the UTC timestamp of the malware's first submission to VirusTotal?

*   **Cách làm:** Phân tích lịch sử vòng đời tệp tin trên không gian mạng.
*   **Thao tác thực hiện:** Vẫn ở thẻ **Details**, cuộn xuống phần *History*. Tại đây sẽ ghi nhận mốc thời gian **First Submission** (Lần đầu tiên tệp này được tải lên VT để phân tích). Mốc thời gian được ghi nhận là `2023-10-06 04:41:50`. Đối chiếu với format của đề bài `YYYY-MM-DD HH:MM`, ta cắt bỏ phần giây đi.
*   **Flag:** `2023-10-06 04:41`

---

### Q4: Understanding the techniques used by malware helps in strategic security planning. What is the MITRE ATT&CK technique ID for the malware collecting data from the local system prior to exfiltration?

*   **Cách làm:** Ánh xạ hành vi của mã độc vào khung framework MITRE ATT&CK.
*   **Thao tác thực hiện:** Chuyển sang thẻ **Behavior** trên VirusTotal. Cuộn xuống phần *MITRE ATT&CK Tactics and Techniques*, tìm đến phần **Collection**. Ta sẽ thấy mã độc sử dụng kỹ thuật thu thập dữ liệu từ hệ thống nội bộ (Data from Local System) để gom nhặt thông tin trình duyệt, cấu hình trước khi gửi về máy chủ. Mã ID tương ứng của kỹ thuật này là `T1005`.
*   **Flag:** `T1005`

---

### Q5: Following execution, the malware performs a connectivity check by resolving a well-known social-media domain before contacting its C2. Which single domain does it resolve for this check?

*   **Cách làm:** Phân tích luồng DNS (DNS Resolutions) do mã độc kích hoạt trong môi trường Sandbox.
*   **Thao tác thực hiện:** Trong thẻ **Behavior**, phần *Network Communication* (hoặc DNS Resolutions), ta thấy mã độc đã thực hiện phân giải một số tên miền hợp lệ trước khi kết nối đến C2. Đây là thủ thuật "Connectivity Check" để kiểm tra xem máy tính có kết nối internet hay không, đồng thời giúp nó trà trộn vào luồng traffic sạch. Tên miền mạng xã hội nổi tiếng bị nó gọi tới chính là `facebook.com`.
*   **Flag:** `facebook.com`

---

### Q6: Once the malicious IP addresses are identified, network security devices such as firewalls can be configured to block traffic to and from these addresses. Can you provide the IP address and destination port the malware communicates with?

*   **Cách làm:** Rà soát danh sách kết nối mạng (IP Traffic) để tìm máy chủ Điều khiển & Ra lệnh (C2 Server).
*   **Thao tác thực hiện:** Kiểm tra phần *IP Traffic* trong thẻ **Behavior**. Hầu hết các IP đều có hostname rõ ràng (như Bing, Google). Tuy nhiên, có một kết nối vô danh nhắm đến IP `77.91.124.55` thông qua một cổng mạng (port) rất dị là `19071`. Sự kết hợp giữa một IP lạ không gắn với domain nào và sử dụng port cao phi tiêu chuẩn là dấu hiệu chắc chắn 100% của máy chủ C2.
*   **Flag:** `77.91.124.55:19071`

---

### Q7: YARA rules are designed to identify specific malware patterns and behaviors. Using MalwareBazaar, what's the name of the YARA rule created by "Varp0s" that detects the identified malware?

*   **Cách làm:** Tra cứu mã Hash trên kho lưu trữ mẫu mã độc MalwareBazaar để tìm các luật nhận diện (YARA Rules) do cộng đồng đóng góp.
*   **Thao tác thực hiện:** Truy cập trang web `bazaar.abuse.ch`, dán mã Hash vào tìm kiếm. Mở báo cáo chi tiết của tệp tin, cuộn xuống khu vực **YARA Signatures**. Ta sẽ thấy một luật nhận diện do tác giả "Varp0s" biên soạn nhằm tóm cổ con hàng này có tên là `detect_Redline_Stealer`.
*   **Flag:** `detect_Redline_Stealer`

---

### Q8: Understanding which malware families are targeting the organization helps in strategic security planning for the future. Can you provide the different malware alias associated with the malicious IP address according to ThreatFox?

*   **Cách làm:** Sử dụng nền tảng ThreatFox để tra cứu chéo các định danh (Alias) của họ mã độc liên quan đến địa chỉ IP máy chủ C2.
*   **Thao tác thực hiện:** Truy cập `threatfox.abuse.ch`, sử dụng cú pháp tìm kiếm `ioc:77.91.124.55` (IP tìm được ở Câu 6). Trong kết quả trả về, phần **Malware Alias** (Bí danh mã độc) sẽ cho biết RedLine Stealer còn được giới tình báo theo dõi dưới một cái tên khác là `RECORDSTEALER`.
*   **Flag:** `RECORDSTEALER`

---

### Q9: By identifying the malware's imported DLLs, we can configure security tools to monitor for the loading or unusual usage of these specific DLLs. Can you provide the DLL utilized by the malware for privilege escalation?

*   **Cách làm:** Phân tích các thư viện liên kết động (DLL) mà tệp thực thi import để đoán định hành vi leo thang đặc quyền.
*   **Thao tác thực hiện:** Quay lại VirusTotal, mở thẻ **Details**, tìm đến phần *Imports*. Mã độc này nạp rất nhiều DLL hệ thống, nhưng trong số đó, DLL chuyên chịu trách nhiệm thao tác quản lý bảo mật, registry, và quyền hạn quản trị (Privilege Escalation / Security APIs) trên môi trường Windows chính là `ADVAPI32.dll`. Việc load file này giúp nó thao túng và leo quyền hệ thống một cách mạnh mẽ.
*   **Flag:** `ADVAPI32.dll`
