<#
.SYNOPSIS
    Kịch bản kiểm thử T1082 - Discovery: System Information Discovery
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1082
    Quy tắc Wazuh đích: Rule 100004 (Level 12)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1082 - DÒ THÁM THÔNG TIN HỆ THỐNG" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Cách 1: Sử dụng Atomic Red Team
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Chạy Atomic Red Team Test Case 1 cho T1082..." -ForegroundColor Green
    Invoke-AtomicTest T1082 -TestNumbers 1
} else {
    # Cách 2: Thực thi chuỗi lệnh điều tra môi trường từ PowerShell
    Write-Host "[+] Thực thi chuỗi lệnh Reconnaissance hệ thống..." -ForegroundColor Yellow
    
    Write-Host "  -> Running systeminfo..." -ForegroundColor Gray
    systeminfo.exe | Out-Null
    
    Write-Host "  -> Running whoami..." -ForegroundColor Gray
    whoami.exe | Out-Null
    
    Write-Host "  -> Running ipconfig /all..." -ForegroundColor Gray
    ipconfig.exe /all | Out-Null
    
    Write-Host "  -> Running route print..." -ForegroundColor Gray
    route.exe print | Out-Null

    Write-Host "  -> Running net user..." -ForegroundColor Gray
    net.exe user | Out-Null
}

Write-Host "`n[✓] Đã kích hoạt chuỗi lệnh Discovery! Vui lòng kiểm tra cảnh báo Rule 100004 trên Wazuh Dashboard." -ForegroundColor Green
