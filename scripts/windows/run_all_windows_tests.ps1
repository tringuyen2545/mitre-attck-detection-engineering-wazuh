<#
.SYNOPSIS
    Tập lệnh tự động chạy toàn bộ các kịch bản kiểm thử trên Windows Server 2019
.DESCRIPTION
    Đồ án: Đánh giá Detection Coverage của hệ thống phòng thủ SIEM bằng MITRE ATT&CK
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
#>

Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host " BẮT ĐẦU CHUỖI KIỂM THỬ PURPLE TEAM TRÊN WINDOWS SERVER" -ForegroundColor Magenta
Write-Host "==========================================================" -ForegroundColor Magenta

$tests = @(
    @{ Name = "T1047: WMI Process Call"; Script = ".\test_t1047_wmi.ps1" },
    @{ Name = "T1003.001: LSASS Memory Dump"; Script = ".\test_t1003_001_lsass.ps1" },
    @{ Name = "T1053.005: Scheduled Tasks"; Script = ".\test_t1053_005_schtasks.ps1" },
    @{ Name = "T1082: System Discovery"; Script = ".\test_t1082_discovery.ps1" },
    @{ Name = "T1486: Ransomware Simulation"; Script = ".\test_t1486_ransomware.ps1" },
    @{ Name = "T1070.001: Clear Logs"; Script = ".\test_t1070_001_clearlog.ps1" }
)

foreach ($t in $tests) {
    Write-Host "`n>>> [RUNNING] $($t.Name)..." -ForegroundColor Yellow
    if (Test-Path $t.Script) {
        & $t.Script
    } else {
        Write-Warning "[-] Không tìm thấy tệp $($t.Script)"
    }
    Write-Host "[+] Tạm dừng 5 giây để SIEM Wazuh tiếp nhận và phân tích log..." -ForegroundColor Gray
    Start-Sleep -Seconds 5
}

Write-Host "`n==========================================================" -ForegroundColor Magenta
Write-Host " [✓] ĐÃ HOÀN TẤT CHUỖI KIỂM THỬ TRÊN WINDOWS!" -ForegroundColor Green
Write-Host " Vui lòng mở Wazuh Dashboard để đối chiếu kết quả cảnh báo." -ForegroundColor Magenta
Write-Host " Chạy .\cleanup_windows_tests.ps1 để dọn dẹp môi trường khi hoàn tất." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Magenta
