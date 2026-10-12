<#
.SYNOPSIS
    Kịch bản kiểm thử T1070.001 - Defense Evasion: Clear Windows Event Logs
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1070.001
    Quy tắc Wazuh đích: Rule 100007 (Level 13 - Emergency) / Event ID 1102
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1070.001 - XÓA EVENT LOG HỆ THỐNG" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Kiểm tra quyền Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[-] Cần quyền Administrator để xóa nhật ký bảo mật hệ thống!"
}

Write-Host "[+] Thực thi lệnh wevtutil để xóa nhật ký System và kiểm toán..." -ForegroundColor Yellow
wevtutil.exe cl "System"
wevtutil.exe cl "Windows PowerShell"

Write-Host "`n[✓] Đã xóa nhật ký! Vui lòng kiểm tra cảnh báo Level 13 (Rule 100007 / Event ID 1102) trên Wazuh Dashboard." -ForegroundColor Green
