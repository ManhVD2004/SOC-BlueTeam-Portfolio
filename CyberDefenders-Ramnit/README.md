# CyberDefenders Lab: Ramnit Writeup

**Category:** Endpoint Forensics | **Difficulty:** Easy | **Tools:** Volatility 3, VirusTotal

**Scenario:** Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings.

---

### Q1: What is the name of the process responsible for the suspicious activity?

*   **Cách làm:** Phân tích cấu trúc cây tiến trình (Process Tree) để phát hiện các bất thường về tên gọi hoặc vị trí thực thi.
*   **Thao tác thực hiện:** Sử dụng plugin `windows.pstree` của nền tảng Volatility 3 để tái tạo hệ thống phân cấp tiến trình. Rà soát danh sách trả về, hệ thống xác định được một tiến trình ngoại lai mang tên `ChromeSetup.exe` (PID: 4628, PPID: 4568) đang chạy ngầm dưới trướng của tiến trình hệ thống `explorer.exe`. 
*   **Bằng chứng:**
    ![Q1 - Tiến trình đáng ngờ trên pstree](images/q1.png)
*   **Flag:** `ChromeSetup.exe`

---

### Q2: What is the exact path of the executable for the malicious process?

*   **Cách làm:** Khai thác dữ liệu đầu ra của quá trình phân tích cây tiến trình để định vị thư mục gốc.
*   **Thao tác thực hiện:** Từ bảng kết quả của lệnh `windows.pstree`, tiến hành kiểm tra cột dữ liệu tương ứng với tiến trình `ChromeSetup.exe` (PID 4628). Dữ liệu hệ thống chỉ ra rằng tệp thực thi này được khởi chạy trực tiếp từ thư mục Downloads của người dùng, xác nhận đây là một tệp tin độc hại ngụy trang.
*   **Bằng chứng:**
    ![Q2 - Đường dẫn thực thi của tiến trình](images/q2.png)
*   **Flag:** `C:\Users\alex\Downloads\ChromeSetup.exe`

---

### Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?

*   **Cách làm:** Rà soát không gian bộ nhớ để trích xuất các dấu vết kết nối mạng ngoại vi.
*   **Thao tác thực hiện:** Sử dụng plugin `windows.netscan` kết hợp với công cụ lọc (grep) nhằm tìm kiếm toàn bộ các artifact mạng liên quan đến mã PID 4628. Kết quả truy xuất cho thấy tiến trình độc hại đã thực hiện kết nối (ở các trạng thái CLOSED và SYN_SENT) tới một máy chủ có địa chỉ IP công cộng là `58.64.204.181`.
*   **Bằng chứng:**
    ![Q3 - Artifact kết nối mạng qua lệnh netscan](images/q3.png)
*   **Flag:** `58.64.204.181`

---

### Q4: To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?

*   **Cách làm:** Ứng dụng tình báo nguồn mở (OSINT) để trích xuất thông tin định vị địa lý (Geolocation).
*   **Thao tác thực hiện:** Sử dụng địa chỉ IP máy chủ C2 `58.64.204.181` thu được từ Câu 3 để tiến hành truy vấn trên nền tảng AbuseIPDB. Siêu dữ liệu trả về xác nhận địa chỉ IP này thuộc hệ thống mạng được đăng ký tại khu vực Hong Kong.
*   **Bằng chứng:**
    ![Q4 - Thông tin định vị địa lý trên AbuseIPDB](images/q4.png)
*   **Flag:** `Hong Kong`

---

### Q5: Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?

*   **Cách làm:** Quét cấu trúc dữ liệu tệp trong bộ nhớ, trích xuất tệp tin thực thi và tính toán mã băm định danh.
*   **Thao tác thực hiện:** Tiến hành sử dụng plugin `windows.filescan` nhằm định vị địa chỉ vật lý (Offset/Virtual Address) của tiến trình độc hại trong RAM. Sau khi xác định được địa chỉ `0xca82b85307f0`, sử dụng plugin `windows.dumpfiles` để kết xuất tệp tin ra môi trường phân tích. Cuối cùng, áp dụng tiện ích `sha1sum` để tính toán mã băm của tệp, thu được chuỗi SHA-1 hợp lệ.
*   **Bằng chứng:**
    ![Q5 - Kết quả tính toán mã băm SHA1](images/q5.png)
*   **Flag:** `280c9d36039f9432433893dee6126d72b9112ad2`

---

### Q6: Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?

*   **Cách làm:** Khai thác nền tảng tình báo VirusTotal để phân tích cấu trúc Header của tệp tin.
*   **Thao tác thực hiện:** Sử dụng mã Hash SHA-1 thu thập được tại Câu 5 để thực hiện truy vấn trên nền tảng VirusTotal. Tại thẻ **Details**, khu vực **History** ghi nhận mốc thời gian hệ thống (Creation Time / Compilation Time) là `2019-12-01 08:36:04 UTC`. Tiến hành chuẩn hóa dữ liệu theo định dạng yêu cầu.
*   **Bằng chứng:**
    ![Q6 - Mốc thời gian biên dịch trên VirusTotal](images/q6.png)
*   **Flag:** `2019-12-01 08:36`

---

### Q7: Identifying the domains associated with this malware is crucial for blocking future malicious communications. Can you provide the domain connected to the malware?

*   **Cách làm:** Phân tích đồ thị liên kết mạng để lập bản đồ các tên miền liên quan đến cơ sở hạ tầng độc hại.
*   **Thao tác thực hiện:** Dựa trên báo cáo tổng hợp tại VirusTotal, điều hướng sang thẻ **Relations**. Tại khu vực *Contacted Domains*, hệ thống ghi nhận một tên miền độc hại có liên kết trực tiếp với mã độc này là `dnsnb8.net`. 
*   **Bằng chứng:**
    ![Q7 - Tên miền độc hại trên thẻ Relations](images/q7.png)
*   **Flag:** `dnsnb8.net`
