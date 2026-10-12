#!/bin/bash
# =============================================================================
# Tập lệnh dọn dẹp môi trường sau kiểm thử trên Linux (AlmaLinux 10)
# Đồ án: Đánh giá Detection Coverage của hệ thống phòng thủ SIEM bằng MITRE ATT&CK
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# =============================================================================

echo "=========================================================="
echo " [CLEANUP] BẮT ĐẦU DỌN DẸP MÔI TRƯỜNG THỬ NGHIỆM LINUX"
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "[-] Vui lòng chạy dưới quyền root/sudo (sudo bash cleanup_linux_tests.sh)"
  exit 1
fi

# 1. Xóa cấu hình NOPASSWD độc hại
echo "[+] Xóa tệp cấu hình leo thang đặc quyền /etc/sudoers.d/malicious..."
rm -f /etc/sudoers.d/malicious

# 2. Xóa tệp mật khẩu nén bị đánh cắp
echo "[+] Xóa tệp mật khẩu giả lập /var/tmp/.cache/credentials.tar.gz..."
rm -rf /var/tmp/.cache

# 3. Dọn dẹp thư mục web bị mã hóa
echo "[+] Dọn dẹp tệp tin mã hóa /var/www/html.enc và tệp rác..."
rm -f /var/www/html.enc
rm -f /var/www/html/secret.txt

echo ""
echo "[✓] Dọn dẹp hoàn tất! Hệ thống Linux đã trở về trạng thái bình thường."
