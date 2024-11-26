param (
    [string]$PositivesFilePath = "C:\WinSP\positives.txt",
    [string]$CacheFilePath = "C:\WinSP\notif_cache.txt",
    [string]$LockFilePath = "C:\WinSP\notif_lock.txt"
)

# Ensure BurntToast module is installed
if (-not (Get-Module -ListAvailable -Name BurntToast)) {
    Install-Module -Name BurntToast -Scope CurrentUser -Force -SkipPublisherCheck
}
Import-Module BurntToast -Force

# Function to download and save an image locally
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

# Function to send a notification
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

# Check if the lock file exists (to ensure only one instance runs)
if (Test-Path $LockFilePath) {
    $existingPID = Get-Content -Path $LockFilePath -ErrorAction SilentlyContinue
    if (Get-Process -Id $existingPID -ErrorAction SilentlyContinue) {
        Write-Host "Another instance of the notif helper is already running (PID: $existingPID). Exiting..."
        exit
    }
}

# Create a lock file with the current process ID
$PID | Set-Content -Path $LockFilePath -Force

# Initialize tracking file
if (-not (Test-Path $CacheFilePath)) {
    New-Item -Path $CacheFilePath -ItemType File -Force | Out-Null
}

Write-Host "Monitoring $PositivesFilePath for changes..."
$lastModifiedTime = $null

# Set the logo URL and local path
$logoUrl = "https://raw.githubusercontent.com/WillMcX/Windows-Services-Project-WinSP/refs/heads/main/WinSP_logo.png"
$tempLogoPath = "$env:TEMP\WinSP_logo.png"

# Download the logo image
if (-not (Test-Path $tempLogoPath)) {
    Download-Image -ImageUrl $logoUrl -DestinationPath $tempLogoPath | Out-Null
}

try {
    while ($true) {
        if (Test-Path $PositivesFilePath) {
            $currentModifiedTime = (Get-Item $PositivesFilePath).LastWriteTime

            if ($currentModifiedTime -ne $lastModifiedTime) {
                $lastModifiedTime = $currentModifiedTime

                # Ensure currentValue is treated as an integer for comparison
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
    # Remove the lock file on exit
    if (Test-Path $LockFilePath) {
        Remove-Item -Path $LockFilePath -Force
    }
}