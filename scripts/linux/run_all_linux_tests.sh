#!/bin/bash
# =============================================================================
# Tập lệnh tự động chạy toàn bộ các kịch bản kiểm thử trên Linux (AlmaLinux 10)
# Đồ án: Đánh giá Detection Coverage của hệ thống phòng thủ SIEM bằng MITRE ATT&CK
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# =============================================================================

echo "=========================================================="
echo " BẮT ĐẦU CHUỖI KIỂM THỬ PURPLE TEAM TRÊN LINUX"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy tập lệnh dưới quyền sudo/root: sudo bash run_all_linux_tests.sh"
  exit 1
fi

TESTS=(
    "T1059.004: Reverse Shell (Fileless Base64)|test_t1059_004_reverse_shell.sh"
    "T1548.003: Sudo Caching (Sudoers.d NOPASSWD)|test_t1548_003_sudoers.sh"
    "T1486: Ransomware Simulation (shred & openssl)|test_t1486_ransomware.sh"
    "T1003.008: OS Credential Dumping (/etc/shadow)|test_t1003_008_shadow.sh"
)

for item in "${TESTS[@]}"; do
    NAME=$(echo "$item" | cut -d'|' -f1)
    SCRIPT=$(echo "$item" | cut -d'|' -f2)
    
    echo ""
    echo ">>> [RUNNING] $NAME..."
    if [ -f "$SCRIPT" ]; then
        bash "$SCRIPT"
    else
        echo "[-] Không tìm thấy $SCRIPT"
    fi
    echo "[+] Tạm dừng 5 giây để SIEM Wazuh tiếp nhận log..."
    sleep 5
done

echo ""
echo "=========================================================="
echo " [✓] ĐÃ HOÀN TẤT CHUỖI KIỂM THỬ TRÊN LINUX!"
echo " Vui lòng mở Wazuh Dashboard để đối chiếu kết quả cảnh báo."
echo " Chạy sudo bash cleanup_linux_tests.sh để dọn dẹp hệ thống."
echo "=========================================================="
