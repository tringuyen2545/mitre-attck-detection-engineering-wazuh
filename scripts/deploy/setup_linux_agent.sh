#!/bin/bash
# =============================================================================
# ĐỒ ÁN AN NINH MẠNG: PURPLE TEAM DETECTION ENGINEERING LAB
# THIẾT LẬP AGENT TRÊN LINUX (ALMALINUX 10 / IP: 192.168.70.102)
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# =============================================================================

set -e

echo "[*] =========================================================="
echo "[*] BẮT ĐẦU THIẾT LẬP MÁY NẠN NHÂN LINUX (ALMALINUX 10)"
echo "[*] =========================================================="

# Kiểm tra quyền root
if [ "$EUID" -ne 0 ]; then
  echo "[-] LỖI: Vui lòng chạy tập lệnh dưới quyền root (sudo bash setup_linux_agent.sh)"
  exit 1
fi

# 1. Cài đặt Audit Daemon (Auditd)
echo "[+] Cài đặt gói audit và công cụ hỗ trợ..."
if command -v dnf &> /dev/null; then
    dnf install -y audit audispd-plugins git python3 tar openssl
elif command -v apt &> /dev/null; then
    apt update -y && apt install -y auditd audispd-plugins git python3 tar openssl
fi

# 2. Cấu hình tập luật Auditd Syscall Rules
echo "[+] Cấu hình tập luật giám sát Syscall và tệp nhạy cảm..."
AUDIT_RULES_SRC="../../configs/linux/audit.rules"
AUDIT_RULES_DEST="/etc/audit/rules.d/audit.rules"

if [ -f "$AUDIT_RULES_SRC" ]; then
    cp "$AUDIT_RULES_SRC" "$AUDIT_RULES_DEST"
else
    cat << 'EOF' > "$AUDIT_RULES_DEST"
## Giám sát tệp tin mật khẩu và tác vụ định kỳ
-w /etc/shadow -p rwxa -k shadow_monitor
-w /etc/passwd -p rwxa -k passwd_monitor
-w /etc/cron.d -p wa -k cron_monitor
-w /etc/sudoers.d -p wa -k audit_sudoers
-w /etc/ssh/sshd_config -p wa -k sshd_config_monitor

## Bắt trọn vẹn toàn bộ lời gọi hệ thống execve (thực thi tiến trình)
-a always,exit -F arch=b64 -S execve -k exec_monitor
-a always,exit -F arch=b32 -S execve -k exec_monitor
EOF
fi

# Khởi động lại dịch vụ Auditd
echo "[+] Nạp luật và khởi động lại dịch vụ auditd..."
if command -v augenrules &> /dev/null; then
    augenrules --load
fi
systemctl enable auditd
systemctl restart auditd
echo "[✓] Dịch vụ auditd đã vận hành và nạp quy tắc thành công!"

# 3. Cấu hình module Syscheck (FIM) trên Wazuh Agent
echo "[+] Cấu hình FIM giám sát thời gian thực trên /var/ossec/etc/ossec.conf..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [ -f "$OSSEC_CONF" ]; then
    # Kiểm tra xem đã cấu hình realtime syscheck cho /etc/sudoers.d chưa
    if ! grep -q "/etc/sudoers.d" "$OSSEC_CONF"; then
        sed -i '/<syscheck>/a \    <!-- Cấu hình FIM giám sát realtime cho đồ án Purple Team -->\n    <directories check_all="yes" realtime="yes">/etc/systemd/system,/etc/sudoers.d,/etc/ssh</directories>' "$OSSEC_CONF"
        echo "[✓] Đã bổ sung cấu hình realtime FIM vào ossec.conf!"
    fi
    systemctl restart wazuh-agent
    echo "[✓] Đã khởi động lại wazuh-agent!"
else
    echo "[!] Chú ý: Chưa tìm thấy $OSSEC_CONF. Hãy cài đặt Wazuh Agent trước khi chạy bước này."
fi

# 4. Clone repo Atomic Red Team
echo "[+] Clone repository Atomic Red Team..."
TARGET_USER=${SUDO_USER:-$USER}
USER_HOME=$(eval echo "~$TARGET_USER")

if [ ! -d "$USER_HOME/atomic-red-team" ]; then
    git clone https://github.com/redcanaryco/atomic-red-team.git "$USER_HOME/atomic-red-team"
    chown -R "$TARGET_USER":"$TARGET_USER" "$USER_HOME/atomic-red-team"
    echo "[✓] Đã tải Atomic Red Team về $USER_HOME/atomic-red-team"
else
    echo "[i] Atomic Red Team đã tồn tại tại $USER_HOME/atomic-red-team"
fi

echo "[*] =========================================================="
echo "[*] HOÀN TẤT CẤU HÌNH MÁY VICTIM-LINUX (192.168.70.102)"
echo "[*] =========================================================="
