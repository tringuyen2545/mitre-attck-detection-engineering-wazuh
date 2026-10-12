<#
.SYNOPSIS
    Kịch bản kiểm thử T1486 - Impact: Data Encrypted for Impact (Mô phỏng Ransomware Akira)
.DESCRIPTION
    Đồ án: Purple Team Detection Engineering Lab
    Sinh viên: Nguyễn Minh Trí (MSSV: 92510340016)
    Kỹ thuật: MITRE ATT&CK T1486
    Quy tắc Wazuh đích: Rule 100005 (Level 14 - Critical/Emergency)
#>

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "[*] THỰC THI MÔ PHỎNG T1486 - GIẢ LẬP RANSOMWARE TRÊN WINDOWS" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Cách 1: Sử dụng Atomic Red Team (Test Case 10 - Akira Ransomware Simulation)
if (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue) {
    Write-Host "[+] Chạy Atomic Red Team Test Case 10 cho T1486..." -ForegroundColor Green
    Invoke-AtomicTest T1486 -TestNumbers 10
} else {
    # Cách 2: Mô phỏng hành vi đặc trưng của Ransomware (WriteAllBytes + Ransom Note Darkweb)
    Write-Host "[+] Thực thi mô phỏng mã hóa tệp và để lại thông điệp tống tiền..." -ForegroundColor Yellow
    $testDir = "C:\Windows\Temp\Ransomware_Test"
    New-Item -Path $testDir -ItemType Directory -Force | Out-Null
    
    # 1. Giả lập ghi tệp mã hóa bằng WriteAllBytes
    $fakeEncryptedBytes = [System.Text.Encoding]::UTF8.GetBytes("ENCRYPTED_DATA_SIMULATION_PURPLE_TEAM")
    [System.IO.File]::WriteAllBytes("$testDir\financial_records.xlsx.akira", $fakeEncryptedBytes)
    [System.IO.File]::WriteAllBytes("$testDir\database_backup.bak.akira", $fakeEncryptedBytes)
    
    # 2. Sinh thông điệp tống tiền với từ khóa .onion / recover / decrypt
    $ransomNote = @"
=== YOUR FILES HAVE BEEN ENCRYPTED BY AKIRA RANSOMWARE ===
All your documents, databases and backups are encrypted.
To decrypt and recover your data, contact us via Tor Browser:
Website: http://akiransom7x2k91lq.onion
Follow instructions to pay ransom and receive your decryptor tool.
Do not modify or rename encrypted files.
"@
    $ransomNote | Out-File -FilePath "$testDir\akira_readme.txt" -Encoding utf8
}

Write-Host "`n[✓] Đã kích hoạt mô phỏng Ransomware! Vui lòng kiểm tra cảnh báo Level 14 (Rule 100005) trên Wazuh Dashboard." -ForegroundColor Red
