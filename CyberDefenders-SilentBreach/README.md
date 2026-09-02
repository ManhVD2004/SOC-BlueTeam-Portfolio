# CyberDefenders Lab: Silent Breach Writeup

**Category:** Endpoint Forensics | **Difficulty:** Medium | **Tactic:** Execution | **Tools:** FTK Imager, Text Editor, SQLite Viewer, Strings, CyberChef

**Scenario:** The IMF is hit by a cyber attack compromising sensitive data. Luther sends Ethan to retrieve crucial information from a compromised server. Despite warnings, Ethan downloads the intel, which later becomes unreadable. To recover it, he creates a forensic image and asks Benji for help in decoding the files.

---

### Q1: What is the MD5 hash of the potentially malicious EXE file the user downloaded?
*   **Cách làm:** Duyệt forensic image bằng FTK Imager để tìm file thực thi đáng ngờ trong thư mục Downloads, sau đó trích xuất hash để đối chiếu với VirusTotal.
*   **Thao tác thực hiện:** Mở forensic image trong **FTK Imager**, tại thư mục `Downloads`, phát hiện 1 file thực thi đáng ngờ tên `IMF-Info.pdf.exe` — sử dụng **double extension** (`.pdf.exe`) để đánh lừa nạn nhân tưởng đây là file PDF. Dùng chức năng export hash của FTK Imager, thu được mã hash MD5 của file này.
*   **Bằng chứng:**
    ![Q1 - File thực thi IMF-Info.pdf.exe trong Downloads](images/q1_1.png)
    ![Q1 - Export MD5 hash bằng FTK Imager](images/q1_2.png)
*   **Flag:** `336a7cf476ebc7548c93507339196abb`

---

### Q2: What is the URL from which the file was downloaded?
*   **Cách làm:** Trích xuất database `History` (SQLite) của trình duyệt để kiểm tra bảng lưu thông tin download.
*   **Thao tác thực hiện:** Trong FTK Imager, phát hiện nạn nhân có cài cả **Google Chrome** và **Microsoft Edge**. Tiến hành export file `History` của Microsoft Edge, mở bằng **SQLite Viewer**, xác định được đường dẫn đầy đủ của file độc hại đã được tải về.
*   **Bằng chứng:**
    ![Q2 - Cả 2 trình duyệt được cài trên máy nạn nhân](images/q2_1.png)
    ![Q2 - Export file History của Microsoft Edge](images/q2_2.png)
    ![Q2 - URL tải file trong SQLite Viewer](images/q2_3.png)
*   **Flag:** `http://192.168.16.128:8000/IMF-Info.pdf.exe`

---

### Q3: What application did the user use to download this file?
*   **Cách làm:** Dựa trên kết quả phân tích ở Q2 để xác định trình duyệt tương ứng.
*   **Thao tác thực hiện:** Bản ghi download chứa URL tải file độc hại được tìm thấy trong database `History` thuộc thư mục dữ liệu của **Microsoft Edge**, xác nhận đây là ứng dụng nạn nhân đã dùng để tải file về.
*   **Bằng chứng:**
    ![Q3 - Đường dẫn thư mục dữ liệu Microsoft Edge](images/q3.png)
*   **Flag:** `Microsoft Edge`

---

### Q4: By examining Windows Mail artifacts, we found an email address mentioning three IP addresses of servers that are at risk or compromised. What are the IP addresses?
*   **Cách làm:** Xác định vị trí file lưu dữ liệu email của Windows Mail, trích xuất chuỗi ký tự đọc được và lọc theo định dạng IPv4 bằng regex.
*   **Thao tác thực hiện:** Windows Mail hoạt động dưới dạng ứng dụng UWP thuộc gói `microsoft.windowscommunicationsapps`. File cơ sở dữ liệu `HxStore.hxd` — lưu nội dung email, header và metadata ở dạng nhị phân — được tìm thấy tại đường dẫn `Users\ethan\AppData\Local\Packages\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\HxStore.hxd`. Export file này bằng FTK Imager, sau đó trên **Terminal (Kali Linux)**, kết hợp lệnh `strings` với regex để lọc các chuỗi ký tự dạng địa chỉ IPv4 đọc được từ file binary: `strings HxStore.hxd | grep -E "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"`. Kết quả trả về nội dung email chứa cảnh báo về các server bị ảnh hưởng, kèm theo 3 địa chỉ IP tương ứng.
*   **Bằng chứng:**
    ![Q4 - Đường dẫn file HxStore.hxd trong FTK Imager](images/q4_1.png)
    ![Q4 - Kết quả lọc IP bằng strings + regex](images/q4_2.png)
*   **Flag:** `145.67.29.88,212.33.10.112,192.168.16.128`

---

### Q5: By examining the malicious executable, we found that it uses an obfuscated PowerShell script to decrypt specific files. What predefined password does the script use for encryption?
*   **Cách làm:** Trích xuất chuỗi ký tự từ file thực thi độc hại bằng `strings`, sau đó giải mã đoạn base64 tìm được bằng CyberChef.
*   **Thao tác thực hiện:** Export file `IMF-Info.pdf.exe` từ FTK Imager ra môi trường phân tích. Chạy lệnh `strings IMF-Info.pdf.exe > strings_output.txt` để lưu toàn bộ chuỗi ký tự vào file text. Mở file này, phát hiện 1 đoạn code PowerShell bị obfuscate nhiều lớp bằng kỹ thuật đảo ngược chuỗi (`Reverse`) kết hợp mã hóa **Base64**. Copy đoạn chuỗi đó, đưa vào **CyberChef** với recipe `Reverse` (Character) → `From Base64` để giải mã, thu được password định sẵn dùng cho việc mã hóa.
*   **Bằng chứng:**
    ![Q5 - Lệnh strings trích xuất chuỗi từ file exe](images/q5_1.png)
    ![Q5 - Đoạn code obfuscate base64 trong strings_output.txt](images/q5_2.png)
    ![Q5 - Giải mã bằng CyberChef, thu được password](images/q5_3.png)
*   **Flag:** `Imf!nfo#2025Sec$`

---

### Q6: After identifying how the script works, decrypt the files and submit the secret string.
*   **Cách làm:** Trích xuất các file `.enc` bị mã hóa, phân tích cơ chế mã hóa AES trong script gốc, sau đó viết script đảo ngược (decrypt) để khôi phục file.
*   **Thao tác thực hiện:** Export 2 file bị mã hóa `IMF-Secret.enc` và `IMF-Mission.enc` từ thư mục Desktop của user `ethan` (`C:\Users\ethan\Desktop\`) bằng FTK Imager. Phân tích script PowerShell độc hại đã giải mã ở Q5, xác định cơ chế mã hóa sử dụng **AES-CBC (khóa 256-bit, IV 16-byte)**, kết hợp hàm dẫn xuất khóa `Rfc2898DeriveBytes` (10,000 iterations) với password đã thu hồi `Imf!nfo#2025Sec$` và salt cố định (`0x01` đến `0x08`).

    Vì thuật toán này đối xứng, chỉ cần đảo ngược script gốc — thay `$aes.CreateEncryptor()` bằng `$aes.CreateDecryptor()`, và trỏ input là các file `.enc` thay vì `.pdf` — để khôi phục lại nội dung gốc. Chạy script decrypt tùy chỉnh này trên 2 file `.enc` đã export, kết quả sinh ra 2 file `_decrypted.pdf` chứa nội dung gốc. Mở file đã giải mã, tìm thấy secret string.
*   **Script giải mã (rút gọn từ script mã hóa gốc):**
```powershell
    $password = "Imf!nfo#2025Sec$"
    $salt = [Byte[]](0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08)
    $iterations = 10000
    $keySize = 32
    $ivSize = 16
    $deriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, $iterations)
    $key = $deriveBytes.GetBytes($keySize)
    $iv = $deriveBytes.GetBytes($ivSize)

    $inputFiles = @("IMF-Secret.enc", "IMF-Mission.enc")
    foreach ($inputFile in $inputFiles) {
        $outputFile = $inputFile -replace '\.enc$', '_decrypted.pdf'
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor()
        $cipherBytes = [System.IO.File]::ReadAllBytes($inputFile)
        $outStream = New-Object System.IO.FileStream($outputFile, [System.IO.FileMode]::Create)
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $cryptoStream.Write($cipherBytes, 0, $cipherBytes.Length)
        $cryptoStream.FlushFinalBlock()
        $cryptoStream.Close()
        $outStream.Close()
    }
```
*   **Bằng chứng:**
    ![Q6 - Export file .enc từ Desktop bằng FTK Imager](images/q6_1.png)
    ![Q6 - Chạy script decrypt thành công](images/q6_2.png)
    ![Q6 - Nội dung file đã giải mã chứa secret string](images/q6_3.png)
*   **Flag:** `CyberDefenders{N3v3r_eX3cuTe_F!l3$_dOwnL0ded_fr0m_M@lic10u5_$erV3r}`
