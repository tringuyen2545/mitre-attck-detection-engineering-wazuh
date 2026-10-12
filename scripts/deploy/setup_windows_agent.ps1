# =============================================================================
# ĐỒ ÁN AN NINH MẠNG: PURPLE TEAM DETECTION ENGINEERING LAB
# THIẾT LẬP AGENT TRÊN WINDOWS SERVER 2019 (VICTIM-WINDOWS: 192.168.70.101)
# Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
# =============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [1] BẮT ĐẦU THIẾT LẬP MÁY NẠN NHÂN WINDOWS SERVER 2019" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Kiểm tra quyền Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[-] Vui lòng chạy PowerShell dưới quyền Administrator!"
    Exit 1
}

# 1. Cài đặt Microsoft Sysmon v15+
Write-Host "`n[*] Bước 1: Kiểm tra và cài đặt Microsoft Sysmon..." -ForegroundColor Yellow
$sysmonPath = ".\Sysmon64.exe"
$configPath = "..\..\configs\windows\sysmonconfig-export.xml"

if (-not (Test-Path $sysmonPath)) {
    Write-Host "[+] Đang tải Sysmon từ Microsoft Sysinternals..." -ForegroundColor Gray
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"
    Expand-Archive -Path "Sysmon.zip" -DestinationPath ".\" -Force
    Remove-Item "Sysmon.zip"
}

if (Test-Path $configPath) {
    Write-Host "[+] Cài đặt Sysmon với tệp cấu hình chuyên sâu: $configPath" -ForegroundColor Green
    & .\Sysmon64.exe -accepteula -i $configPath
} else {
    Write-Warning "[-] Không tìm thấy $configPath, vui lòng kiểm tra lại đường dẫn."
}

# Kiểm tra trạng thái dịch vụ Sysmon64
$sysmonService = Get-Service Sysmon64 -ErrorAction SilentlyContinue
if ($sysmonService -and $sysmonService.Status -eq "Running") {
    Write-Host "[✓] Dịch vụ Sysmon64 đang chạy bình thường!" -ForegroundColor Green
} else {
    Write-Warning "[-] Dịch vụ Sysmon64 chưa kích hoạt hoặc bị lỗi."
}

# 2. Cấu hình Wazuh Agent đọc kênh Sysmon
Write-Host "`n[*] Bước 2: Cấu hình Wazuh Agent thu thập Sysmon..." -ForegroundColor Yellow
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
    [xml]$xml = Get-Content $ossecConf
    $alreadyConfigured = $xml.ossec_config.localfile | Where-Object { $_.location -eq "Microsoft-Windows-Sysmon/Operational" }
    
    if (-not $alreadyConfigured) {
        Write-Host "[+] Bổ sung cấu hình Microsoft-Windows-Sysmon/Operational vào ossec.conf..." -ForegroundColor Green
        $newLocalFile = $xml.CreateElement("localfile")
        $newLoc = $xml.CreateElement("location")
        $newLoc.InnerText = "Microsoft-Windows-Sysmon/Operational"
        $newFormat = $xml.CreateElement("log_format")
        $newFormat.InnerText = "eventchannel"
        $newLocalFile.AppendChild($newLoc) | Out-Null
        $newLocalFile.AppendChild($newFormat) | Out-Null
        $xml.ossec_config.AppendChild($newLocalFile) | Out-Null
        $xml.Save($ossecConf)
        Write-Host "[✓] Đã cập nhật ossec.conf thành công!" -ForegroundColor Green
    } else {
        Write-Host "[i] Kênh Sysmon đã được cấu hình trước đó trong ossec.conf." -ForegroundColor Cyan
    }

    # Khởi động lại dịch vụ Wazuh
    Write-Host "[+] Khởi động lại dịch vụ WazuhSvc..." -ForegroundColor Yellow
    Restart-Service WazuhSvc
    Write-Host "[✓] Dịch vụ WazuhSvc đã được khởi động lại!" -ForegroundColor Green
} else {
    Write-Warning "[-] Không tìm thấy ossec.conf. Hãy đảm bảo Wazuh Agent đã được cài đặt qua file MSI."
}

# 3. Cài đặt framework Atomic Red Team (Invoke-AtomicRedTeam)
Write-Host "`n[*] Bước 3: Cài đặt Invoke-AtomicRedTeam..." -ForegroundColor Yellow
try {
    Set-ExecutionPolicy Bypass -Scope Process -Force
    IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
    Install-AtomicRedTeam -getAtomics -Force
    Write-Host "[✓] Cài đặt Invoke-AtomicRedTeam hoàn tất!" -ForegroundColor Green
} catch {
    Write-Warning "[-] Có lỗi xảy ra khi tải Atomic Red Team (vui lòng kiểm tra kết nối mạng): $_"
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " HOÀN TẤT CẤU HÌNH MÁY VICTIM-WINDOWS (192.168.70.101)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
