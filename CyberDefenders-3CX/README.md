# CyberDefenders Lab: 3CX Supply Chain Writeup

**Category:** Threat Intel | **Difficulty:** Easy | **Tools:** VirusTotal, OSINT

**Scenario:** A large multinational corporation heavily relies on the 3CX software for phone communication. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations. As a threat intelligence analyst, your objective is to examine this supply chain attack, uncover how the attackers compromised the 3CX app, identify the potential threat actor, and assess the extent of the incident.

---

### Q1: Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial. How many versions of 3CX running on Windows have been flagged as malware?

*   **Cách làm:** Khai thác các báo cáo tình báo nguồn mở (OSINT) liên quan đến chiến dịch tấn công chuỗi cung ứng 3CX để xác định phạm vi ảnh hưởng trên nền tảng Windows.
*   **Thao tác thực hiện:** Thực hiện truy vấn trên các công cụ tìm kiếm hoặc chuyên trang bảo mật (như Kaspersky, CrowdStrike, Mandiant) với từ khóa "3CX DesktopApp supply chain attack compromised versions Windows". Các báo cáo phân tích đều chỉ rõ có một số lượng phiên bản cụ thể dành riêng cho Windows bị chèn mã độc (thường nhắc đến bản 18.12.407 và 18.12.416). Đếm số lượng phiên bản này để đưa ra kết luận.
*   **Bằng chứng:**
    ![Q1 - Báo cáo OSINT về các phiên bản bị ảnh hưởng](images/q1.png)
*   **Flag:** `[Điền số lượng phiên bản tìm được]`

---

### Q2: Determining the age of the malware can help assess the extent of the compromise. What's the UTC creation time of the .msi malware?

*   **Cách làm:** Phân tích siêu dữ liệu (Metadata) của tệp tin cài đặt (MSI) trên nền tảng VirusTotal để trích xuất mốc thời gian khởi tạo.
*   **Thao tác thực hiện:** Sử dụng mã băm (Hash) của tệp tin `.msi` độc hại (thường được cung cấp trong file lab hoặc tìm qua OSINT) để truy vấn trên VirusTotal. Điều hướng sang thẻ **Details**, kiểm tra khu vực **History** và trích xuất giá trị tại trường **Creation Time**. Chuẩn hóa chuỗi thời gian theo định dạng yêu cầu `YYYY-MM-DD HH:MM` (lược bỏ phần giây).
*   **Bằng chứng:**
    ![Q2 - Creation Time trên VirusTotal](images/q2.png)
*   **Flag:** `[Điền mốc thời gian khởi tạo]`

---

### Q3: Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial. Which malicious DLLs were dropped by the .msi file?

*   **Cách làm:** Phân tích đồ thị hành vi và các tệp tin phái sinh (Dropped Files) sinh ra trong quá trình cài đặt mã độc.
*   **Thao tác thực hiện:** Tại báo cáo của tệp `.msi` trên VirusTotal, chuyển sang thẻ **Relations** (hoặc thẻ **Behavior** trong môi trường Sandbox). Rà soát danh sách tại khu vực *Dropped Files*. Đối chiếu với định dạng gợi ý của hệ thống `ff****.dll,d3*********_**.dll` để xác định chính xác tên của 2 thư viện liên kết động (DLL) độc hại được giải nén vào hệ thống.
*   **Bằng chứng:**
    ![Q3 - Danh sách Dropped Files](images/q3.png)
*   **Flag:** `[Điền tên 2 file DLL, phân cách bằng dấu phẩy]`

---

### Q4: Recognizing the persistence techniques used in this incident is essential. What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?

*   **Cách làm:** Ánh xạ hành vi lạm dụng tiến trình hợp lệ để nạp thư viện độc hại vào khung tiêu chuẩn MITRE ATT&CK.
*   **Thao tác thực hiện:** Dựa trên kỹ thuật mà mã độc sử dụng (chèn DLL độc hại vào cùng thư mục với một tệp thực thi hợp pháp để ép hệ thống tải nó thay vì DLL gốc), tra cứu trên trang chủ `attack.mitre.org` (kỹ thuật DLL Search Order Hijacking / DLL Side-Loading). Hoặc kiểm tra trực tiếp thẻ **Behavior** -> *MITRE ATT&CK Tactics and Techniques* trên VirusTotal của tệp tin. Trích xuất mã Technique ID có định dạng `T****`.
*   **Bằng chứng:**
    ![Q4 - MITRE ATT&CK Technique ID](images/q4.png)
*   **Flag:** `[Điền mã ID T****]`

---

### Q5: Recognizing the malware type (threat category) is essential to your investigation. What is the threat category of the two malicious DLLs?

*   **Cách làm:** Đánh giá danh mục phân loại mối đe dọa từ các công cụ quét bảo mật.
*   **Thao tác thực hiện:** Thực hiện truy vấn băm của 1 trong 2 file DLL thu được ở Câu 3 trên VirusTotal. Quan sát thẻ **Detection** hoặc **Details** (phần *Popular threat label*). Xác định danh mục mã độc mà hệ thống phân loại (ví dụ: Virus, Ransomware, Worm, hoặc Trojan). Định dạng yêu cầu gồm 6 ký tự `T*****`.
*   **Bằng chứng:**
    ![Q5 - Phân loại mã độc trên VirusTotal](images/q5.png)
*   **Flag:** `[Điền danh mục mã độc]`

---

### Q6: It's vital to understand how malware can evade detection in virtualized environments. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

*   **Cách làm:** Phân tích kỹ thuật lẩn tránh (Defense Evasion) của mã độc qua nền tảng Sandbox.
*   **Thao tác thực hiện:** Truy cập thẻ **Behavior** của file DLL trên VirusTotal. Cuộn xuống phần tham chiếu *MITRE ATT&CK*, mục *Defense Evasion*. Tìm kỹ thuật liên quan đến việc lẩn tránh môi trường ảo hóa (Virtualization/Sandbox Evasion) để xác định mã ID cấp một (định dạng `T****`).
*   **Bằng chứng:**
    ![Q6 - Kỹ thuật Sandbox Evasion trên MITRE ATT&CK](images/q6.png)
*   **Flag:** `[Điền mã ID T****]`

---

### Q7: Understanding anti-analysis techniques is vital. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?

*   **Cách làm:** Trích xuất các chuỗi ký tự (Strings) và dữ liệu hành vi để phát hiện dấu hiệu rà quét môi trường ảo.
*   **Thao tác thực hiện:** Trong phân tích hành vi (thẻ **Behavior**) hoặc danh sách các tiến trình/tệp/registry mà `ffmpeg.dll` tìm kiếm, rà soát các từ khóa liên quan đến nền tảng ảo hóa. Thường mã độc sẽ kiểm tra các địa chỉ MAC, tên tiến trình (như `vmtoolsd.exe`), hoặc registry keys đặc thù của một hãng cung cấp giải pháp máy ảo nổi tiếng (có 6 ký tự `******`).
*   **Bằng chứng:**
    ![Q7 - Dấu vết truy vấn Hypervisor](images/q7.png)
*   **Flag:** `[Điền tên Hypervisor]`

---

### Q8: Identifying the cryptographic method used in malware is crucial. What encryption algorithm is used by the ffmpeg.dll file?

*   **Cách làm:** Khai thác báo cáo phân tích tĩnh và động để xác định giao thức mã hóa dữ liệu.
*   **Thao tác thực hiện:** Kiểm tra khu vực *File Actions*, *Network Communication* hoặc các luồng giải mã (Decrypted Strings) tại thẻ **Behavior** của `ffmpeg.dll`. Tìm kiếm thuật toán mã hóa đối xứng kinh điển thường được các nhóm APT sử dụng để ẩn giấu payload trong tệp tin hoặc mã hóa giao tiếp C2 (định dạng 3 ký tự `***`).
*   **Bằng chứng:**
    ![Q8 - Thuật toán mã hóa ghi nhận trên báo cáo](images/q8.png)
*   **Flag:** `[Điền tên thuật toán mã hóa]`

---

### Q9: Identifying the APT group responsible will help you search for their usual TTPs. Which group is responsible for this attack?

*   **Cách làm:** Tổng hợp tình báo chiến lược (Strategic Threat Intel) để thực hiện quy trách nhiệm (Attribution) cho nhóm tấn công.
*   **Thao tác thực hiện:** Dựa trên các TTP (Tactics, Techniques, and Procedures) thu thập được từ Câu 1 đến Câu 8, kết hợp truy vấn hệ thống tin tức an ninh mạng với từ khóa "3CX supply chain attack threat actor attribution". Các hãng bảo mật lớn như Mandiant, CrowdStrike đều thống nhất quy kết trách nhiệm chiến dịch này cho một nhóm APT khét tiếng hoạt động vì mục đích tài chính và tình báo quốc gia.
*   **Bằng chứng:**
    ![Q9 - Báo cáo gán định danh nhóm APT](images/q9.png)
*   **Flag:** `[Điền tên nhóm APT]`
