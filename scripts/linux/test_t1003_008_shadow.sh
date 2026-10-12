#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử T1003.008 - Credential Access: OS Credential Dumping (/etc/shadow)
# Đồ án: Purple Team Detection Engineering Lab
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# Kỹ thuật: MITRE ATT&CK T1003.008
# Quy tắc Wazuh đích: Rule 100014 (Level 12)
# =============================================================================

echo "[*] =========================================================="
echo "[*] THỰC THI MÔ PHỎNG T1003.008 - NÉN & ĐÁNH CẮP /ETC/SHADOW"
echo "[*] =========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Cần quyền root hoặc sudo để đọc tệp /etc/shadow (sudo bash test_t1003_008_shadow.sh)"
  exit 1
fi

echo "[+] Tạo thư mục ẩn /var/tmp/.cache..."
mkdir -p /var/tmp/.cache

echo "[+] Sử dụng tiện ích tar để đóng gói /etc/shadow và /etc/passwd..."
tar -czf /var/tmp/.cache/credentials.tar.gz /etc/shadow /etc/passwd 2>/dev/null || true

echo ""
echo "[✓] Đã nén tệp mật khẩu! Vui lòng kiểm tra cảnh báo Rule 100014 trên Wazuh Dashboard."
