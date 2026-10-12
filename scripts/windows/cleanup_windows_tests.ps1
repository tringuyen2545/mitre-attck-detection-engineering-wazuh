<#
.SYNOPSIS
    Tập lệnh dọn dẹp các artifact sinh ra sau quá trình kiểm thử Windows
.DESCRIPTION
    Đồ án: Đánh giá Detection Coverage của hệ thống phòng thủ SIEM bằng MITRE ATT&CK
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [CLEANUP] BẮT ĐẦU DỌN DẸP MÔI TRƯỜNG THỬ NGHIỆM WINDOWS" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Dọn dẹp Scheduled Task
Write-Host "[+] Xóa Scheduled Task WindowsUpdater..." -ForegroundColor Yellow
schtasks.exe /delete /tn "WindowsUpdater" /f 2>$null

# 2. Xóa tệp dump LSASS
Write-Host "[+] Xóa tệp dump bộ nhớ lsass.dmp..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Temp\lsass.dmp" -Force -ErrorAction SilentlyContinue

# 3. Dọn dẹp thư mục mô phỏng Ransomware
Write-Host "[+] Xóa thư mục thử nghiệm Ransomware..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Temp\Ransomware_Test" -Recurse -Force -ErrorAction SilentlyContinue

# 4. Tắt tiến trình notepad nếu còn chạy
Write-Host "[+] Tắt các tiến trình notepad thử nghiệm..." -ForegroundColor Yellow
Stop-Process -Name "notepad" -Force -ErrorAction SilentlyContinue

# 5. Dọn dẹp Atomic Red Team nếu dùng Invoke-AtomicTest
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Dọn dẹp Atomic Red Team tests..." -ForegroundColor Yellow
    Invoke-AtomicTest T1047 -TestNumbers 5 -Cleanup -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1003.001 -TestNumbers 1 -Cleanup -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1053.005 -TestNumbers 1 -Cleanup -ErrorAction SilentlyContinue
    Invoke-AtomicTest T1486 -TestNumbers 10 -Cleanup -ErrorAction SilentlyContinue
}

Write-Host "`n[✓] Dọn dẹp hoàn tất! Hệ thống đã trở về trạng thái sạch ban đầu." -ForegroundColor Green
