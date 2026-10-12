# MA TRẬN ĐO LƯỜNG ĐỘ PHỦ PHÁT HIỆN (DETECTION COVERAGE MATRIX)

> **Đồ án chuyên ngành:** MÔ PHỎNG TẤN CÔNG VÀ ĐO LƯỜNG KHẢ NĂNG PHÁT HIỆN  
> **Sinh viên:** Nguyễn Minh Trí (MSSV: 92510340016)  
> **Giảng viên hướng dẫn:** ThS. Trương Phạm Hoài Thương  

---

## 1. Bảng đối chiếu định lượng trước và sau tinh chỉnh (Bảng 6.1 trong Đồ án)

Dưới đây là ma trận so sánh chi tiết trên toàn bộ các kỹ thuật thực nghiệm trong phòng Lab Purple Team:

| STT | Mã MITRE | Tên kỹ thuật kiểm thử | Hệ điều hành | Trước tinh chỉnh (Baseline) | Rule ID mới | Sau tinh chỉnh (Retest) | Độ trễ phát hiện |
| :---: | :---: | :--- | :---: | :--- | :---: | :--- | :---: |
| **01** | **T1047** | WMI Process Call Execution | Windows | Level 3 (Chung chung `cmd`/`notepad`) | **100001** | **Level 12** (Critical - WMI Anomaly) | `< 1.2s` |
| **02** | **T1003.001** | LSASS Dump via Procdump | Windows | **Bỏ lọt** (Missed - Công cụ hợp lệ) | **100002** | **Level 12** (Critical - ProcessAccess) | `< 1.0s` |
| **03** | **T1053.005** | Scheduled Task Persistence | Windows | Level 3 (Tạo tiến trình thông thường) | **100003** | **Level 12** (Critical - Anti-Bypass Task) | `< 1.0s` |
| **04** | **T1082** | System Information Discovery | Windows | Level 3 (Lệnh đơn lẻ bị trôi log) | **100004** | **Level 12** (Critical - Parent-Child Anomaly) | `< 1.1s` |
| **05** | **T1486** | Akira Ransomware Simulation | Windows | **Bỏ lọt** (FIM định kỳ không kịp thời) | **100005** | **Level 14** (Emergency - Script Block) | `< 0.9s` |
| **06** | **T1070.001** | Clear Windows Event Logs | Windows | Level 5 (Chỉ ghi nhận Event 1102) | **100007** | **Level 13** (Emergency - Clear Audit Log) | `< 0.8s` |
| **07** | **T1059.004** | Base64 Fileless Reverse Shell | Linux | **Bỏ lọt** (Syslog không giải mã Base64) | **100010** | **Level 12** (Critical - Base64 Pipe Execution) | `< 1.1s` |
| **08** | **T1548.003** | Sudoers.d NOPASSWD Abuse | Linux | **Bỏ lọt** (Chỉnh sửa tệp không cảnh báo) | **100012** | **Level 12** (Critical - Sudoers Realtime) | `< 1.0s` |
| **09** | **T1486** | Linux Ransomware (shred/openssl)| Linux | **Bỏ lọt** (Không gắn nhãn phá hoại) | **100013** | **Level 14** (Emergency - Shred/Openssl) | `< 0.8s` |
| **10** | **T1003.008** | OS Credential Dumping (/etc/shadow)| Linux | **Bỏ lọt** (Lệnh tar hợp lệ bị trôi log) | **100014** | **Level 12** (Critical - Shadow File Access) | `< 1.0s` |

---

## 2. Phân tích định lượng hiệu quả

```
Độ phủ phát hiện (Detection Coverage):
Trước tinh chỉnh (Baseline):  ████████░░░░░░░░░░░░░░  35% (Chủ yếu cảnh báo Level thấp hoặc bỏ lọt)
Sau tinh chỉnh (Retest):      ██████████████████████  100% (Đạt mức cảnh báo nghiêm trọng Level 12-14)

Thời gian phát hiện trung bình (MTTD):
Thời gian đáp ứng của bộ luật: < 1.5 giây (Tất cả cảnh báo sinh ra gần như tức thời)
```

### 2.1. Tỉ lệ cải thiện độ phủ
- **Trước khi áp dụng Detection Engineering:** Hệ thống phòng thủ mặc định bỏ lọt tới **65%** các kịch bản tấn công (đặc biệt là các kỹ thuật Fileless trên Linux, trích xuất mật khẩu và phá hoại dữ liệu kiểu Ransomware). Các kỹ thuật còn lại chỉ được ghi nhận dưới dạng sự kiện thông tin thông thường (Level 3-5), dễ gây hiện tượng kiệt quệ cảnh báo (Alert Fatigue).
- **Sau khi nạp Custom Rules:** Tỉ lệ bao phủ đạt mức tuyệt đối **100%** trên toàn bộ 9 kỹ thuật trọng yếu được chọn lọc. Mọi hành vi nguy hiểm đều được phân loại chính xác ở mức **Level 12 (Critical)** và **Level 14 (Emergency)**.

### 2.2. Đo lường độ trễ (Response Latency)
- Nhờ việc tối ưu hóa luồng dữ liệu tại tầng Kernel (Sysmon trên Windows và Auditd trên Linux), độ trễ chuyển tiếp từ Agent về Manager chỉ mất từ `0.3s - 0.5s`.
- Thời gian phân tích và khớp luật của `wazuh-analysisd` diễn ra dưới `0.5s`.
- **Tổng thời gian từ khi lệnh tấn công bắt đầu thực thi cho đến khi cảnh báo xuất hiện trên Wazuh Dashboard là dưới 1.2 giây**, đảm bảo yêu cầu khắt khe trong vận hành Trung tâm điều hành an ninh mạng (SOC Operations).
