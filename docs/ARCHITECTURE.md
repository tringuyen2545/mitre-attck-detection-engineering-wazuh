# KIẾN TRÚC HỆ THỐNG PHÒNG LAB PURPLE TEAM & LUỒNG DỮ LIỆU TELEMETRY

> **Đồ án chuyên ngành:** MÔ PHỎNG TẤN CÔNG VÀ ĐO LƯỜNG KHẢ NĂNG PHÁT HIỆN - ĐÁNH GIÁ DETECTION COVERAGE CỦA HỆ THỐNG PHÒNG THỦ SIEM BẰNG FRAMEWORK MITRE ATT&CK  
> **Sinh viên thực hiện:** Nguyễn Minh Trí (MSSV: 92510340016 - Lớp: 35CCAN01)  
> **Giảng viên hướng dẫn:** ThS. Trương Phạm Hoài Thương  
> **Đơn vị:** Trường Cao đẳng An ninh mạng iSpace (09/2026)  

---

## 1. Tổng quan kiến trúc hệ thống

Để đáp ứng yêu cầu khắt khe của việc mô phỏng chân thực các cuộc tấn công mạng hiện đại (APT, Ransomware, Living off the Land) mà vẫn bảo đảm tính an toàn tuyệt đối cho hạ tầng công nghệ thông tin thực tế, hệ thống được thiết kế và triển khai theo mô hình **Phòng Lab ảo hóa phân lập hoàn toàn (Isolated Virtual Lab Environment)** trên nền tảng VMware Workstation Pro. 

Mô hình tuân thủ nghiêm ngặt nguyên lý kiến trúc Zero-Trust đối với các mạng bên ngoài, sử dụng cơ chế mạng ảo **Host-Only (VMnet1)** với dải địa chỉ IP tĩnh tiêu chuẩn `192.168.70.0/24`.

![Sơ đồ kiến trúc kết nối mạng](images/network_topology.png)
*Hình 1: Sơ đồ kiến trúc kết nối mạng và các thành phần trong Purple Team Lab*

---

## 2. Các thực thể cốt lõi trong Lab

Kiến trúc hệ thống được phân chia thành 3 thực thể cốt lõi tương tác chặt chẽ với nhau:

### 2.1. Phân vùng Giám sát Trung tâm (SIEM / C2 Server) - `wazuh-manager`
- **Địa chỉ IP:** `192.168.70.100` (Tĩnh)
- **Hệ điều hành:** Ubuntu Server 26.04 / 24.04 LTS
- **Cấu hình phần cứng:** 4 vCPU, 8 GB RAM, 50 GB Disk
- **Vai trò:** Đóng vai trò là "bộ não" điều hành giám sát trung tâm, đảm nhiệm 3 chức năng all-in-one:
  1. **Wazuh Server:** Tiếp nhận luồng nhật ký bảo mật qua giao thức TLS cổng TCP 1514, giải mã sự kiện (Decoders) và đối chiếu tập luật (Rules Engine).
  2. **Wazuh Indexer:** Lưu trữ và đánh chỉ mục dữ liệu sự kiện thời gian thực (chuẩn NoSQL/Elasticsearch).
  3. **Wazuh Dashboard:** Giao diện đồ họa web tương tác, phân tích, trực quan hóa và hiển thị cảnh báo (Cổng HTTPS 443).
  4. **Netcat Listener (C2 Server):** Đóng vai trò trạm lắng nghe tín hiệu Command & Control tại cổng TCP 4444 phục vụ kịch bản kiểm thử Reverse Shell.

### 2.2. Máy chủ Mục tiêu Windows (Victim Windows) - `victim-win`
- **Địa chỉ IP:** `192.168.70.101` (Tĩnh)
- **Hệ điều hành:** Windows Server 2019 Datacenter / Standard
- **Cấu hình phần cứng:** 2 vCPU, 4 GB RAM, 40 GB Disk
- **Cảm biến và công cụ:**
  - **Wazuh Agent:** Đọc và đóng gói nhật ký chuyển tiếp về Manager.
  - **Microsoft Sysmon v15+:** Bộ cảm biến mức nhân với tập cấu hình `sysmonconfig-export.xml` (tinh chỉnh từ SwiftOnSecurity) thu thập chuyên sâu Event ID 1 (Process Creation kèm CommandLine đầy đủ), Event ID 3 (Network Connection), Event ID 10 (ProcessAccess vào LSASS), Event ID 11 (File Creation) và Event ID 12/13 (Registry modification).
  - **Invoke-AtomicRedTeam:** Framework tự động hóa diễn tập tấn công mô phỏng TTPs theo MITRE ATT&CK.

### 2.3. Máy chủ Mục tiêu Linux (Victim Linux) - `victim-linux`
- **Địa chỉ IP:** `192.168.70.102` (Tĩnh)
- **Hệ điều hành:** AlmaLinux 10 (x86_64)
- **Cấu hình phần cứng:** 2 vCPU, 2 GB RAM, 30 GB Disk
- **Cảm biến và công cụ:**
  - **Wazuh Agent:** Dịch vụ nền tích hợp module Syscheck / File Integrity Monitoring (FIM).
  - **Linux Audit Daemon (Auditd):** Bắt toàn bộ lời gọi hàm hệ thống `execve` (x86_64 và 32-bit compatibility) và giám sát chặt chẽ các tệp tin/thư mục đặc quyền (`/etc/shadow`, `/etc/sudoers.d`, `/etc/cron.d`).
  - **Atomic Red Team Repository:** Kho kịch bản kiểm thử TTPs Linux từ Red Canary.

---

## 3. Bảng phân bổ thông số kỹ thuật và tài nguyên Lab

| Tên máy ảo | Hệ điều hành | Địa chỉ IP | Cấu hình phần cứng | Vai trò và Công cụ cài đặt |
| :--- | :--- | :--- | :--- | :--- |
| **wazuh-manager** | Ubuntu Server 26.04 LTS | `192.168.70.100` | 8GB RAM, 4 vCPU, 50GB Disk | Máy chủ SIEM All-in-One (Server, Indexer, Dashboard), Netcat Listener C2 (Port 4444) |
| **victim-win** | Windows Server 2019 | `192.168.70.101` | 4GB RAM, 2 vCPU, 40GB Disk | Nạn nhân Windows: Wazuh Agent, Microsoft Sysmon v15+, Invoke-AtomicRedTeam |
| **victim-linux** | AlmaLinux 10 | `192.168.70.102` | 2GB RAM, 2 vCPU, 30GB Disk | Nạn nhân Linux: Wazuh Agent, Auditd (syscall execve / shadow), FIM realtime |

---

## 4. Luồng dữ liệu giám sát (Telemetry Data Pipeline)

Nền tảng của hệ thống SIEM hiệu quả không nằm ở các biểu đồ màu sắc mà nằm ở **độ sâu, chất lượng và độ trung thực của dữ liệu Telemetry**. Quy trình xử lý luồng dữ liệu bảo mật từ thiết bị đầu cuối về máy chủ trung tâm tuân thủ nghiêm ngặt 5 bước:

![Sơ đồ luồng dữ liệu giám sát](images/telemetry_pipeline.png)
*Hình 2: Sơ đồ luồng dữ liệu giám sát (Telemetry Pipeline 5 bước)*

1. **Bước 1 - Thu thập dữ kiện mức nhân (Sensors):**
   - **Windows:** Sysmon chặn bắt sự kiện tại tầng kernel driver `SysmonDrv`, ghi lại đầy đủ cây tiến trình cha - con, dòng lệnh chi tiết (CommandLine), mã băm SHA-256 và hành vi truy cập bộ nhớ.
   - **Linux:** Auditd móc trực tiếp vào kernel thông qua Netlink socket, chặn bắt toàn bộ các lời gọi hệ thống `execve` và các tương tác đọc/ghi vào các tệp bảo mật hệ thống.
2. **Bước 2 - Đóng gói và chuyển tiếp dữ liệu (Wazuh Agent):**
   - Agent đọc kênh sự kiện `Microsoft-Windows-Sysmon/Operational` và `/var/log/audit/audit.log`. Dữ liệu được mã hóa TLS, nén và chuyển tiếp qua cổng TCP 1514 về máy chủ.
3. **Bước 3 - Giải mã và chuẩn hóa trường (Decoders Engine):**
   - Dịch vụ `wazuh-analysisd` tiếp nhận chuỗi ký tự thô và chạy qua bộ Decoders để bóc tách thành các trường định danh có cấu trúc: `win.eventdata.image`, `win.eventdata.commandLine`, `win.eventdata.parentImage`, `audit.command`, `audit.key`, `syscheck.path`.
4. **Bước 4 - Khớp luật và sinh cảnh báo (Rules Matching Engine):**
   - Dữ liệu được đưa qua bộ luật tùy chỉnh (`custom_wazuh_rules.xml`). Khi một hành vi vi phạm điều kiện logic bất thường (như gọi WMI từ LOLBin hoặc mở handle vào LSASS), hệ thống sinh cảnh báo an ninh với Rule Level từ 10 đến 14 kèm mã MITRE ATT&CK tương ứng.
5. **Bước 5 - Lưu trữ chỉ mục và trực quan hóa (Dashboard):**
   - Cảnh báo được gửi sang Wazuh Indexer để lập chỉ mục và hiển thị tức thời trên giao diện Wazuh Dashboard cho chuyên viên SOC điều tra.
