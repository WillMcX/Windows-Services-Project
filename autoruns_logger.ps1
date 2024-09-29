# Path for Autoruns logs
$desktopPath = [Environment]::GetFolderPath("Desktop")
$downloadFolder = "$desktopPath\AutorunsServiceLogs"
$autorunsPath = "C:\SysinternalsSuite\autorunsc.exe"  # Path to autorunsc.exe

# Create download folder if it doesn't exist
If (!(Test-Path -Path $downloadFolder)) {
    New-Item -Path $downloadFolder -ItemType Directory
}

while ($true) {
    # Prepare log file path
    $logFile = "$downloadFolder\autoruns_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

    # Run Autoruns with the appropriate switches to accept EULA and log output
    & $autorunsPath -accepteula -a * -h -s -ct > $logFile

    # Sleep for 5 minutes
    Start-Sleep -Seconds 300
}
