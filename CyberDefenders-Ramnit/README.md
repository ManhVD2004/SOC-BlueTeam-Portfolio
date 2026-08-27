# CyberDefenders Lab: Ramnit Writeup

**Category:** Endpoint Forensics | **Difficulty:** Easy | **Tools:** Volatility 3, VirusTotal

**Scenario:** Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings.

---

### Q1: What is the name of the process responsible for the suspicious activity?

*   **Cách làm:** Phân tích cấu trúc cây tiến trình (Process Tree) để phát hiện các bất thường về tên gọi hoặc vị trí thực thi.
*   **Thao tác thực hiện:** Sử dụng plugin `windows.pstree` của nền tảng Volatility 3 để tái tạo hệ thống phân cấp tiến trình từ tệp tin dump (`Ramnit.dmp`). Rà soát danh sách trả về, đặc biệt lưu ý các tiến trình trực thuộc `explorer.exe` (PID 4568). Hệ thống ghi nhận một tiến trình đáng ngờ mang tên `ChromeSetup.exe` (PID 4628). Việc một tệp tin cài đặt duy trì trạng thái hoạt động ngầm (background service) là dấu hiệu điển hình của kỹ thuật giả mạo (Masquerading).
*   **Bằng chứng:**
    ![Q1 - Tiến trình đáng ngờ trên pstree](images/q1.png)
*   **Flag:** `ChromeSetup.exe`

---

### Q2: What is the exact path of the executable for the malicious process?

*   **Cách làm:** Khai thác dữ liệu đầu ra của quá trình phân tích cây tiến trình để định vị thư mục gốc.
*   **Thao tác thực hiện:** Từ bảng kết quả của lệnh `windows.pstree`, tiến hành kiểm tra cột *Path* tương ứng với tiến trình `ChromeSetup.exe` (PID 4628). Dữ liệu hệ thống chỉ ra rằng tệp thực thi này được khởi chạy từ thư mục Downloads của người dùng, củng cố thêm giả thuyết đây không phải là một tiến trình chuẩn của hệ điều hành.
*   **Bằng chứng:**
    ![Q2 - Đường dẫn thực thi của tiến trình](images/q2.png)
*   **Flag:** `C:\Users\alex\Downloads\ChromeSetup.exe`

---

### Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?

*   **Cách làm:** Rà soát không gian bộ nhớ (Pool Scanning) để trích xuất các kết nối mạng lịch sử hoặc đã bị đóng.
*   **Thao tác thực hiện:** Do tính chất ngắt kết nối liên tục của mã độc, việc sử dụng plugin `windows.netstat` có thể không đem lại kết quả. Tiến hành sử dụng plugin `windows.netscan` kết hợp với công cụ lọc (grep) nhằm tìm kiếm toàn bộ các artifact mạng liên quan đến PID 4628 hoặc từ khóa "Chrome":
    `python3 vol.py -f Ramnit.dmp windows.netscan | grep 4628`
    Từ kết quả trả về, xác định địa chỉ IP tại cột *Foreign Address* / *Dest IP*. Đây chính là máy chủ Điều khiển & Ra lệnh (C2) mà mã độc đã liên lạc.
*   **Bằng chứng:**
    ![Q3 - Artifact kết nối mạng qua lệnh netscan](images/q3.png)
*   **Flag:** `[Điền địa chỉ IP thu được từ terminal]`

---

### Q4: To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?

*   **Cách làm:** Ứng dụng tình báo nguồn mở (OSINT) để trích xuất thông tin định vị địa lý (Geolocation) của cơ sở hạ tầng tấn công.
*   **Thao tác thực hiện:** Sử dụng địa chỉ IP máy chủ C2 thu được từ Câu 3 để tiến hành truy vấn trên nền tảng cơ sở dữ liệu AbuseIPDB hoặc VirusTotal. Phân tích siêu dữ liệu (Metadata) trả về để xác minh khu vực/thành phố đăng ký của hệ thống mạng này.
*   **Bằng chứng:**
    ![Q4 - Thông tin định vị địa lý trên hệ thống OSINT](images/q4.png)
*   **Flag:** `[Điền tên thành phố]`

---

### Q5: Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?

*   **Cách làm:** Trích xuất tệp tin thực thi trực tiếp từ bộ nhớ RAM (Process Dumping) và tính toán mã băm định danh.
*   **Thao tác thực hiện:** Sử dụng plugin `windows.procdump` để cô lập và trích xuất tiến trình mã độc dựa trên PID:
    `python3 vol.py -f Ramnit.dmp windows.procdump --pid 4628 --dump-dir .`
    Sau khi tệp tin định dạng `.exe` được kết xuất thành công, sử dụng lệnh `sha1sum` trên hệ thống Linux để tính toán và thu thập chuỗi băm SHA-1 tương ứng.
*   **Bằng chứng:**
    ![Q5 - Kết quả tính toán mã băm SHA1](images/q5.png)
*   **Flag:** `[Điền chuỗi Hash SHA-1]`

---

### Q6: Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?

*   **Cách làm:** Khai thác nền tảng tình báo VirusTotal để phân tích cấu trúc Header của tệp tin PE (Portable Executable).
*   **Thao tác thực hiện:** Sử dụng mã Hash thu thập được tại Câu 5 để thực hiện truy vấn trên VirusTotal. Điều hướng sang thẻ **Details**, định vị khu vực thông tin lịch sử (History). Trích xuất giá trị thời gian tại trường **Compilation Time** (hoặc Creation Time) thể hiện thời điểm mã độc được lập trình viên biên dịch. Định dạng dữ liệu theo chuẩn `YYYY-MM-DD HH:MM`.
*   **Bằng chứng:**
    ![Q6 - Mốc thời gian biên dịch trên VirusTotal](images/q6.png)
*   **Flag:** `[Điền mốc thời gian biên dịch]`

---

### Q7: Identifying the domains associated with this malware is crucial for blocking future malicious communications. Can you provide the domain connected to the malware?

*   **Cách làm:** Phân tích đồ thị liên kết mạng (Network Graph/Relations) để lập bản đồ các tên miền liên quan đến hệ thống C2.
*   **Thao tác thực hiện:** Dựa trên báo cáo tổng hợp tại VirusTotal, truy cập thẻ **Relations**. Phân tích danh sách tại khu vực *Contacted Domains* hoặc *DNS Resolutions* để xác định tên miền độc hại mà tệp tin hoặc máy chủ C2 đã thực hiện kết nối tới.
*   **Bằng chứng:**
    ![Q7 - Tên miền độc hại trên thẻ Relations](images/q7.png)
*   **Flag:** `[Điền tên miền liên kết]`
