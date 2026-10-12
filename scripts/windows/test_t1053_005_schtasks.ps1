<#
.SYNOPSIS
    Kịch bản kiểm thử T1053.005 - Persistence: Scheduled Task/Job: Scheduled Task
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1053.005
    Quy tắc Wazuh đích: Rule 100003 (Level 12)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1053.005 - TẠO SCHEDULED TASK" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Cách 1: Sử dụng Atomic Red Team
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Chạy Atomic Red Team Test Case 1 cho T1053.005..." -ForegroundColor Green
    Invoke-AtomicTest T1053.005 -TestNumbers 1
} else {
    # Cách 2: Lệnh trực tiếp tạo Scheduled Task bằng schtasks.exe
    Write-Host "[+] Thực thi lệnh schtasks /create để tạo tác vụ ẩn danh..." -ForegroundColor Yellow
    schtasks.exe /create /tn "WindowsUpdater" /tr "cmd.exe /c echo Persistence_Triggered" /sc onlogon /ru "SYSTEM" /f
}

Write-Host "`n[✓] Đã tạo Scheduled Task! Vui lòng kiểm tra cảnh báo Rule 100003 trên Wazuh Dashboard." -ForegroundColor Green
