<#
.SYNOPSIS
    Kịch bản kiểm thử T1047 - Execution: Windows Management Instrumentation (WMI)
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1047
    Quy tắc Wazuh đích: Rule 100001 (Level 12)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1047 - WMI PROCESS CALL" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Cách 1: Sử dụng Atomic Red Team (Nếu có module Invoke-AtomicTest)
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Chạy bài kiểm thử thông qua Invoke-AtomicTest (Test Case 5)..." -ForegroundColor Green
    Invoke-AtomicTest T1047 -TestNumbers 5
} else {
    # Cách 2: Thực thi trực tiếp lệnh WMIC
    Write-Host "[+] Thực thi trực tiếp lệnh WMIC Process Call Create..." -ForegroundColor Yellow
    wmic process call create "notepad.exe"
}

Write-Host "`n[✓] Đã kích hoạt lệnh WMI! Vui lòng kiểm tra cảnh báo Rule 100001 trên Wazuh Dashboard." -ForegroundColor Green
