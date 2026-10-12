#!/bin/bash
# =============================================================================
# ĐỒ ÁN AN NINH MẠNG: PURPLE TEAM DETECTION ENGINEERING LAB
# TẬP LỆNH CÀI ĐẶT MÁY CHỦ WAZUH ALL-IN-ONE (UBUNTU SERVER 26.04 / 24.04 LTS)
# Sinh viên thực hiện: Nguyễn Minh Trí (MSSV: 92510340016)
# IP Máy chủ: 192.168.70.100 (Host-Only Network)
# =============================================================================

set -e

echo "[*] ========================================================"
echo "[*] Bắt đầu cài đặt Wazuh SIEM All-in-One (Phiên bản 4.8)"
echo "[*] Sinh viên: Nguyễn Minh Trí - MSSV: 92510340016"
echo "[*] ========================================================"

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "[-] LỖI: Vui lòng chạy tập lệnh này dưới quyền root (sudo bash install_wazuh_server.sh)"
  exit 1
fi

# Cập nhật repository và cài đặt các gói phụ trợ
echo "[+] Cập nhật hệ thống và cài đặt gói phụ trợ (curl, netcat, tar, ufw)..."
apt update -y && apt install -y curl tar netcat-traditional ufw

# Tải và chạy tập lệnh unattended chính thức từ Wazuh
echo "[+] Đang tải tập lệnh cài đặt wazuh-install.sh..."
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh

echo "[+] Bắt đầu quá trình cài đặt Wazuh All-in-One (có thể mất 5-10 phút)..."
bash ./wazuh-install.sh -a

# Lưu mật khẩu ban đầu
if [ -f "wazuh-passwords.txt" ]; then
  echo "[+] Thông tin tài khoản quản trị:"
  cat wazuh-passwords.txt
  cp wazuh-passwords.txt /root/wazuh-passwords.txt
fi

# Kiểm tra trạng thái hoạt động của các dịch vụ cốt lõi
echo "[+] Kiểm tra trạng thái dịch vụ Wazuh..."
systemctl status wazuh-manager --no-pager
systemctl status wazuh-indexer --no-pager
systemctl status wazuh-dashboard --no-pager

# Cấu hình mở port tường lửa nội bộ VMnet1
echo "[+] Cấu hình tường lửa mở các cổng hoạt động (1514, 1515, 443, 4444)..."
ufw allow 1514/tcp comment "Wazuh Agent communication"
ufw allow 1515/tcp comment "Wazuh Agent enrollment"
ufw allow 443/tcp comment "Wazuh Dashboard Web GUI"
ufw allow 4444/tcp comment "Netcat C2 Listener for Reverse Shell"

# Tích hợp Custom Rules nếu có tệp sẵn
RULES_SRC="../../rules/custom_wazuh_rules.xml"
if [ -f "$RULES_SRC" ]; then
  echo "[+] Nạp bộ luật Custom Wazuh Rules vào /var/ossec/etc/rules/local_rules.xml..."
  cat "$RULES_SRC" >> /var/ossec/etc/rules/local_rules.xml
  systemctl restart wazuh-manager
  echo "[+] Wazuh Manager đã được khởi động lại thành công với bộ luật tùy chỉnh!"
fi

echo "[*] ========================================================"
echo "[*] CÀI ĐẶT HOÀN TẤT!"
echo "[*] Truy cập Wazuh Dashboard tại: https://192.168.70.100"
echo "[*] Để lắng nghe C2 Reverse Shell cổng 4444: nc -lvnp 4444"
echo "[*] ========================================================"
