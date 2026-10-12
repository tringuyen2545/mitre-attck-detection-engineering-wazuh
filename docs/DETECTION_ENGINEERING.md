# HƯỚNG DẪN KỸ THUẬT PHÁT HIỆN ĐE DỌA (DETECTION ENGINEERING) TRÊN WAZUH

> **Đồ án chuyên ngành:** MÔ PHỎNG TẤN CÔNG VÀ ĐO LƯỜNG KHẢ NĂNG PHÁT HIỆN  
> **Sinh viên:** Nguyễn Minh Trí (MSSV: 92510340016)  
> **Giảng viên hướng dẫn:** ThS. Trương Phạm Hoài Thương  

---

## 1. Nguyên lý vận hành của Bộ máy phân tích Wazuh (Analysis Engine)

Bộ máy phân tích quy tắc của Wazuh (`wazuh-analysisd`) hoạt động dựa trên mô hình phân cấp 2 giai đoạn:

```
[ Raw Log ] 
     │
     ▼
[ Decoders Engine ] ──(Trích xuất trường)──> [ win.eventdata.* / audit.* ]
     │
     ▼
[ Rules Engine ] ────(So khớp logic)─────> [ Rule Match / Alert Trigger ]
     │
     ▼
[ Wazuh Indexer & Dashboard ] (Level 12 - 14 Alert + MITRE ATT&CK Tag)
```

1. **Giai đoạn 1 - Phân tích cú pháp (Parsing / Decoding):**
   - Bản ghi nhật ký thô được đối chiếu với các tệp Decoders nằm trong `/var/ossec/ruleset/decoders/`.
   - Đối với Windows Sysmon: Decoder trích xuất các trường dữ liệu quan trọng từ XML Event Channel như `win.eventdata.image`, `win.eventdata.parentImage`, `win.eventdata.commandLine`, `win.eventdata.originalFileName`, `win.eventdata.targetImage`, `win.eventdata.sourceImage`.
   - Đối với Linux Auditd: Decoder trích xuất `audit.command`, `audit.key`, `audit.syscall`, `audit.exe`.

2. **Giai đoạn 2 - Đánh giá điều kiện và Khớp luật (Rule Evaluation):**
   - Rules Engine duyệt qua các thẻ `<rule>` trong tệp XML.
   - Sử dụng các liên kết phân cấp cha - con (`if_sid`, `if_group`) để kế thừa ngữ cảnh sự kiện.
   - Sử dụng biểu thức chính quy chuẩn Perl (PCRE2) để đối chiếu mẫu hành vi phức tạp.

---

## 2. Các kỹ thuật Detection Engineering nâng cao được áp dụng

### 2.1. Giám sát quan hệ tiến trình Cha - Con (Parent-Child Process Anomaly)
- **Vấn đề:** Các công cụ LOLBins như `cmd.exe`, `powershell.exe`, hay `notepad.exe` là các file sạch, việc cảnh báo khi chúng được gọi sẽ gây bão cảnh báo giả.
- **Giải pháp:** Trong tấn công lạm dụng WMI (T1047), tiến trình máy chủ WMI `wmiprvse.exe` sẽ đóng vai trò là cha sinh ra tiến trình thực thi lệnh con. Trong hoạt động quản trị bình thường, `wmiprvse.exe` hiếm khi sinh ra `cmd.exe` hoặc các shell tương tác. Bằng việc giám sát quan hệ `parentImage` kết hợp với tham số dòng lệnh `process call create`, ta chốt chặn chính xác hành vi lén lút này.

### 2.2. Chống kỹ thuật đổi tên công cụ hệ thống (Anti-Bypass via OriginalFileName)
- **Thủ đoạn của kẻ tấn công:** Tin tặc thường sao chép `schtasks.exe` thành `updater.exe`, hoặc `whoami.exe` thành `test.exe` để qua mặt các tập luật dựa trên đường dẫn tệp (`Image` hoặc `program_name`).
- **Giải pháp:** Sử dụng trường thông tin nội tại của PE Header do Sysmon trích xuất: `win.eventdata.originalFileName`. Bất kể kẻ tấn công đổi tên tệp bề mặt thành gì, trường `originalFileName` vẫn lưu giữ tên gốc `schtasks.exe`, `systeminfo.exe`, giúp loại bỏ hoàn toàn khả năng lẩn tránh này.

### 2.3. Sử dụng Biểu thức chính quy PCRE2 đa lớp (Multi-pattern PCRE2 Regex)
- Sử dụng thuộc tính `type="pcre2"` cho phép áp dụng các cờ Regex nâng cao như `(?i)` (không phân biệt hoa thường) và gom nhóm non-capturing `(?:...)`.
- **Ví dụ trong Rule 100010 (Reverse Shell):**
  ```regex
  ["/](?:ba|da|z)?sh".*"-i"|(?:base64|openssl)".*"(?:--?d|--decode|base64)"|(?:python|perl|ruby)\S*".*"-[ce]"|nc\S*".*"-e"
  ```
  Biểu thức này bắt trọn vẹn cả chuỗi hành vi: giải mã Base64/OpenSSL, gọi mã thực thi nội tuyến `python -c` và chuyển sang interactive shell `bash -i` hoặc `nc -e`.

### 2.4. Khử nhiễu và loại bỏ cảnh báo giả bằng Whitelist (False Positive Suppression)
- **Vấn đề:** Trong Rule 100002 (Bảo vệ vùng nhớ `lsass.exe`), nhiều tiến trình hệ thống hợp lệ của Windows và tiện ích máy ảo (như `svchost.exe`, `csrss.exe`, `vmtoolsd.exe`) liên tục tương tác với LSASS để xác thực phiên làm việc.
- **Giải pháp:** Sử dụng thuộc tính `negate="yes"` tại trường `win.eventdata.sourceImage`:
  ```xml
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)[\\/](svchost|csrss|wininit|services|lsass|smss|lsm|VBoxService|vmtoolsd)\.exe$</field>
  ```
  Mọi tiến trình hợp lệ thuộc danh sách an toàn sẽ được bỏ qua, chỉ có các tiến trình bất thường (như `procdump.exe`, `mimikatz.exe`, `rundll32.exe`) mới bị kích hoạt cảnh báo Level 12.

---

## 3. Danh mục chi tiết các Custom Rules XML

### Rule 100001: Execution qua WMI (T1047)
```xml
<rule id="100001" level="12">
  <if_sid>61603, 92032</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(wmic\.exe|Cmd\.Exe|PowerShell\.EXE|pwsh\.dll)$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)process\s+call\s+create</field>
  <description>Execution: Phát hiện lạm dụng công cụ hệ thống để gọi WMI thực thi mã (T1047)</description>
  <mitre><id>T1047</id></mitre>
</rule>
```

### Rule 100002: Trích xuất bộ nhớ LSASS (T1003.001)
```xml
<rule id="100002" level="12">
  <if_group>sysmon</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)[\\/](svchost|csrss|wininit|services|lsass|smss|lsm|VBoxService|vmtoolsd)\.exe$</field>
  <description>Credential Access: Phát hiện tiến trình bất thường can thiệp bộ nhớ LSASS (T1003.001)</description>
  <mitre><id>T1003.001</id></mitre>
</rule>
```

### Rule 100003: Duy trì truy cập qua Scheduled Task (T1053.005)
```xml
<rule id="100003" level="12">
  <if_sid>61603, 92032</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^schtasks\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)\/create</field>
  <description>Persistence: Phát hiện hành vi tạo lập Scheduled Task (Anti-Bypass T1053.005)</description>
  <mitre><id>T1053.005</id></mitre>
</rule>
```

### Rule 100004: Thu thập thông tin hệ thống (T1082)
```xml
<rule id="100004" level="12">
  <if_sid>61603, 92032</if_sid>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(systeminfo\.exe|whoami\.exe|ipconfig\.exe|route\.exe|net\.exe)$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)\\(powershell\.exe|pwsh\.exe|cmd\.exe|wscript\.exe|cscript\.exe)$</field>
  <description>Discovery: Phát hiện trình thông dịch lệnh thực thi công cụ dò thám hệ thống (Anti-Bypass T1082)</description>
  <mitre><id>T1082</id></mitre>
</rule>
```

### Rule 100005: Mô phỏng Akira Ransomware (T1486 Windows)
```xml
<rule id="100005" level="14">
  <if_group>windows</if_group>
  <regex type="pcre2">(?i)WriteAllBytes|Out-File</regex>
  <regex type="pcre2">(?i)\.onion|torproject|decrypt|recover|encrypted</regex>
  <description>Impact: Phát hiện hành vi sinh file mã hóa kết hợp với thông điệp tống tiền/Darkweb (T1486)</description>
  <mitre><id>T1486</id></mitre>
</rule>
```

### Rule 100007: Xóa nhật ký kiểm toán (T1070.001 Windows)
```xml
<rule id="100007" level="13">
  <if_sid>18104, 18105, 92032, 61603</if_sid>
  <field name="win.system.eventID">^1102$</field>
  <description>Defense Evasion: Nhật ký kiểm toán bảo mật Windows bị xóa bỏ (T1070.001 - Event ID 1102)</description>
  <mitre><id>T1070.001</id></mitre>
</rule>
```

### Rule 100010: Fileless Base64 Reverse Shell (T1059.004 Linux)
```xml
<rule id="100010" level="12">
  <if_group>audit</if_group>
  <regex type="pcre2">["/](?:ba|da|z)?sh".*"-i"|(?:base64|openssl)".*"(?:--?d|--decode|base64)"|(?:python|perl|ruby)\S*".*"-[ce]"|nc\S*".*"-e"</regex>
  <description>Execution: Phát hiện chuỗi hành vi bất biến của Reverse Shell/Fileless Malware (T1059.004)</description>
  <mitre><id>T1059.004</id></mitre>
</rule>
```

### Rule 100012: Can thiệp cấu hình SUDO NOPASSWD (T1548.003 Linux)
```xml
<rule id="100012" level="12">
  <if_group>audit</if_group>
  <field name="audit.key">^(audit_sudoers|sudoers_monitor)$</field>
  <description>Privilege Escalation: Phát hiện tiến trình trái phép can thiệp vào cấu hình SUDO (T1548.003)</description>
  <mitre><id>T1548.003</id></mitre>
</rule>
```

### Rule 100013: Mã hóa tệp và hủy dữ liệu bằng shred (T1486 Linux)
```xml
<rule id="100013" level="14">
  <if_group>audit</if_group>
  <regex type="pcre2">"openssl".*"enc".*"-aes-256-cbc"|"shred".*"-u"</regex>
  <description>Impact: Phát hiện hành vi xóa file an toàn bằng shred hoặc nén mã hóa dữ liệu (T1486)</description>
  <mitre><id>T1486</id></mitre>
</rule>
```

### Rule 100014: Trích xuất tập tin mật khẩu /etc/shadow (T1003.008 Linux)
```xml
<rule id="100014" level="12">
  <if_group>audit</if_group>
  <field name="audit.key">shadow_monitor</field>
  <description>Credential Access: Tiến trình truy cập đọc tệp tin mật khẩu nhạy cảm /etc/shadow (T1003.008)</description>
  <mitre><id>T1003.008</id></mitre>
</rule>
```
