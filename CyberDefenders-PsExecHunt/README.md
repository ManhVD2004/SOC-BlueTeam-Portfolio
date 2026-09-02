# CyberDefenders Lab: PsExec Hunt Writeup

**Category:** Network Forensics | **Difficulty:** Easy | **Tactics:** Execution, Defense Impairment, Discovery, Lateral Movement | **Tool:** Wireshark

**Scenario:** An alert from the Intrusion Detection System (IDS) flagged suspicious lateral movement activity involving PsExec. This indicates potential unauthorized access and movement across the network. As a SOC Analyst, your task is to investigate the provided PCAP file to trace the attacker's activities. Identify their entry point, the machines targeted, the extent of the breach, and any critical indicators that reveal their tactics and objectives within the compromised environment.

---

### Q1: Can you identify the IP address of the machine from which the attacker initially gained access?
*   **Cách làm:** Thống kê lưu lượng theo từng IP để xác định nguồn phát sinh traffic bất thường.
*   **Thao tác thực hiện:** Tại Wireshark, vào **Statistics → Conversations**, phát hiện một lượng lớn traffic xuất phát từ địa chỉ IP `10.0.0.130`. Áp filter `ip.addr==10.0.0.130` để cô lập luồng lưu lượng của IP này, xác nhận đây chính là máy của attacker — đang thực hiện kỹ thuật **Lateral Movement** sang máy nạn nhân (`10.0.0.133`) thông qua công cụ **PsExec** qua giao thức SMB (cổng 445).
*   **Bằng chứng:**
    ![Q1 - Thống kê Conversations trên Wireshark](images/q1_1.png)
    ![Q1 - Lọc traffic theo IP attacker](images/q1_2.png)
*   **Flag:** `10.0.0.130`

---

### Q2: Can you determine the machine's hostname to which the attacker first pivoted?
*   **Cách làm:** Kiểm tra gói tin khởi tạo kết nối SMB từ attacker để xác định hostname mục tiêu.
*   **Thao tác thực hiện:** Quan sát gói tin attacker khởi tạo kết nối SMB tới máy nạn nhân (`10.0.0.133`), tại trường **Target Name**, xác định được máy bị nhắm tới là `SALES-PC`.
*   **Bằng chứng:**
    ![Q2 - Target Name trong gói tin SMB](images/q2.png)
*   **Flag:** `SALES-PC`

---

### Q3: What is the username utilized by the attacker for authentication?
*   **Cách làm:** Kiểm tra gói tin xác thực SMB (Session Setup Request) để xác định username được sử dụng.
*   **Thao tác thực hiện:** Tại gói tin số **132**, xác định được username mà attacker sử dụng trong quá trình xác thực là `ssales`.
*   **Bằng chứng:**
    ![Q3 - Username trong gói tin xác thực](images/q3.png)
*   **Flag:** `ssales`

---

### Q4: What's the name of the service executable the attacker set up on the target?
*   **Cách làm:** Kiểm tra các gói tin SMB liên quan đến việc tạo và thực thi file trên share ADMIN$.
*   **Thao tác thực hiện:** Tại gói tin số **144** và **145**, xác định attacker đã thực thi file dịch vụ độc hại `PSEXESVC.exe` trên share `ADMIN$` — đây là file thực thi mặc định mà PsExec tạo ra trên máy đích để chạy dịch vụ điều khiển từ xa.
*   **Bằng chứng:**
    ![Q4 - File PSEXESVC.exe trên share ADMIN$](images/q4.png)
*   **Flag:** `PSEXESVC.exe`

---

### Q5: Which network share was used by PsExec to install the service on the target machine?
*   **Cách làm:** Kiểm tra gói tin SMB Tree Connect để xác định share được attacker truy cập nhằm cài đặt dịch vụ.
*   **Thao tác thực hiện:** Quan sát các gói tin SMB liên quan đến việc copy và cài đặt file thực thi, xác định attacker đã sử dụng share `ADMIN$` để đưa và thực thi dịch vụ độc hại trên máy nạn nhân. Đây là share quản trị mặc định của Windows, cho phép PsExec ghi file trực tiếp vào thư mục `%SystemRoot%`.
*   **Bằng chứng:**
    ![Q5 - Share ADMIN$ được dùng để cài đặt dịch vụ](images/q5.png)
*   **Flag:** `ADMIN$`

---

### Q6: Which network share did PsExec use for communication?
*   **Cách làm:** Kiểm tra trường Share Type trong gói tin Tree Connect để xác định cơ chế giao tiếp giữa 2 máy.
*   **Thao tác thực hiện:** Tại gói tin số **135**, xác định attacker đã sử dụng share `IPC$` để giao tiếp giữa 2 tiến trình. Trường **Share Type: Named Pipe** cho thấy đây là cơ chế Inter-Process Communication (IPC), cho phép tiến trình `psexec.exe` (trên máy tấn công) gửi lệnh trực tiếp tới tiến trình `PSEXESVC.exe` (trên máy nạn nhân) và nhận kết quả trả về theo thời gian thực.
*   **Bằng chứng:**
    ![Q6 - Share IPC$ (Named Pipe) dùng để giao tiếp](images/q6.png)
*   **Flag:** `IPC$`

---

### Q7: What is the hostname of the second machine the attacker targeted to pivot within our network?
*   **Cách làm:** Tiếp tục theo dõi luồng SMB2 sau khi chiếm được máy đầu tiên để phát hiện dấu hiệu di chuyển ngang tiếp theo.
*   **Thao tác thực hiện:** Sau khi kiểm soát máy `SALES-PC`, attacker (`10.0.0.130`) tiếp tục mở kết nối SMB2 tới một IP mới trong mạng là `10.0.0.131` (bắt đầu từ gói tin **38512**). Kiểm tra gói tin **38534** (*Session Setup Response — NTLMSSP_CHALLENGE*) do máy `10.0.0.131` phản hồi, trường **Target Name** hiển thị tên máy chủ bị nhắm tới tiếp theo là `MARKETING-PC`.
*   **Bằng chứng:**
    ![Q7 - Target Name của máy pivot thứ hai](images/q7.png)
*   **Flag:** `MARKETING-PC`
