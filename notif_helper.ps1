param (
    [string]$PositivesFilePath = "C:\WinSP\positives.txt",
    [string]$CacheFilePath = "C:\WinSP\notif_cache.txt",
    [string]$LockFilePath = "C:\WinSP\notif_lock.txt"
)

if (-not (Get-Module -ListAvailable -Name BurntToast)) {
    Install-Module -Name BurntToast -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module BurntToast -Force

function Download-Image {
    param (
        [string]$ImageUrl,
        [string]$DestinationPath
    )

    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($ImageUrl, $DestinationPath)
        return $DestinationPath
    } catch {
        Write-Host "Failed to download image: $_"
        return $null
    }
}

function Send-Notification {
    param (
        [string]$Message,
        [string]$ImagePath
    )

    try {
        if (-not (Test-Path $ImagePath)) {
            Write-Host "Image path does not exist: $ImagePath"
            $ImagePath = $null
        }

        New-BurntToastNotification -Text "WinSP Notification", $Message -AppLogo $ImagePath
    } catch {
        Write-Host "Failed to send notification: $_"
    }
}

if (Test-Path $LockFilePath) {
    $existingPID = Get-Content -Path $LockFilePath -ErrorAction SilentlyContinue
    if (Get-Process -Id $existingPID -ErrorAction SilentlyContinue) {
        Write-Host "Another instance of the notif helper is already running (PID: $existingPID). Exiting..."
        exit
    }
}

$PID | Set-Content -Path $LockFilePath -Force

if (-not (Test-Path $CacheFilePath)) {
    New-Item -Path $CacheFilePath -ItemType File -Force | Out-Null
}

Write-Host "Monitoring $PositivesFilePath for changes..."
$lastModifiedTime = $null

$logoUrl = "https://raw.githubusercontent.com/WillMcX/Windows-Services-Project-WinSP/refs/heads/main/WinSP_logo.png"
$tempLogoPath = "$env:TEMP\WinSP_logo.png"

if (-not (Test-Path $tempLogoPath)) {
    Download-Image -ImageUrl $logoUrl -DestinationPath $tempLogoPath | Out-Null
}

try {
    while ($true) {
        if (Test-Path $PositivesFilePath) {
            $currentModifiedTime = (Get-Item $PositivesFilePath).LastWriteTime

            if ($currentModifiedTime -ne $lastModifiedTime) {
                $lastModifiedTime = $currentModifiedTime

                $currentValue = (Get-Content -Path $PositivesFilePath -Raw).Trim()
                $lastSentValue = Get-Content -Path $CacheFilePath -ErrorAction SilentlyContinue

                if ($lastSentValue -ne $currentValue) {
                    Set-Content -Path $CacheFilePath -Value $currentValue

                    if ([int]$currentValue -eq 0) {
                        Send-Notification "No positives found!! The system is clean and secure!" $tempLogoPath
                    } else {
                        Send-Notification "Detected $currentValue positive(s)! Check the VirusTotal report for details." $tempLogoPath
                    }
                }
            }
        } else {
            Write-Host "Positives file not found. Retrying..."
        }

        Start-Sleep -Seconds 1
    }
} catch {
    Write-Host "Error in monitoring: $_"
} finally {
    if (Test-Path $LockFilePath) {
        Remove-Item -Path $LockFilePath -Force
    }
}
