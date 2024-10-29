# Setting and checking for admin level permissions
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if (-not (Test-IsAdmin)) {
    Write-Host "This script requires administrator privileges. Restarting with elevated permissions..."
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

Write-Host "Running script with administrator privileges..."

# Pathing Schema
$nssmDownloadUrl = "https://nssm.cc/release/nssm-2.24.zip"
$downloadFolderNSSM = "C:\\nssm"
$autorunsDownloadUrl = "https://download.sysinternals.com/files/Autoruns.zip"
$autorunsFolder = "C:\\SysinternalsSuite"
$autorunsZipPath = "$autorunsFolder\\Autoruns.zip"
$autorunsPath = "$autorunsFolder\\autorunsc.exe"  
$serviceName = "AutorunsPeriodicScannerTestv6.5"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$arl = "$desktopPath\\autoruns_logger.ps1" 

# Install Non-Sucking Service Manager
function Install-NSSM {
    Write-Host "NSSM not found. Downloading NSSM..."
    if (-not (Test-Path $downloadFolderNSSM)) {
        New-Item -Path $downloadFolderNSSM -ItemType Directory
    }
    $zipPath = "$downloadFolderNSSM\nssm.zip"
    Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $zipPath
    Write-Host "NSSM downloaded. Extracting..."
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $downloadFolderNSSM)
    Write-Host "NSSM extracted successfully."
}

# Install AutoRuns
function Install-Autoruns {
    Write-Host "Autoruns not found. Downloading Autoruns..."
    if (-not (Test-Path $autorunsFolder)) {
        New-Item -Path $autorunsFolder -ItemType Directory
    }
    Invoke-WebRequest -Uri $autorunsDownloadUrl -OutFile $autorunsZipPath

    Write-Host "Autoruns downloaded. Extracting..."
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($autorunsZipPath, $autorunsFolder)
    Write-Host "Autoruns extracted successfully."
}

# Check Installations of needed components
$nssmPath = "$downloadFolderNSSM\nssm-2.24\win64\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Install-NSSM
} else {
    Write-Host "NSSM is already installed. Path: $nssmPath"
}

if (-not (Test-Path $autorunsPath)) {
    Install-Autoruns
} else {
    Write-Host "Autoruns is already installed. Path: $autorunsPath"
}

# Check if the service exists/status when running + action items
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

# Display service status
if ($service) {
    Write-Host "Service '$serviceName' already exists."
    $serviceStatus = $service.Status
    Write-Host "Current Status: $serviceStatus"
} else {
    Write-Host "Service '$serviceName' does not exist."
}

$userInput = Read-Host "What would you like to do? (stop/restart/install/uninstall/exit)"

switch ($userInput.ToLower()) {
    "stop" {
        if ($serviceStatus -eq "Running") {
            Stop-Service -Name $serviceName
            Write-Host "Service stopped."
        } else {
            Write-Host "Service is not running."
        }
    }
    "restart" {
        if ($serviceStatus -eq "Running") {
            Restart-Service -Name $serviceName
            Write-Host "Service restarted."
        } else {
            Write-Host "Service is not running, attempting to start it..."
            Start-Service -Name $serviceName
            Write-Host "Service started."
        }
    }
    "install" {
        if (-not $service) {
            Write-Host "Installing NSSM service..."
            & $nssmPath install $serviceName powershell.exe "-ExecutionPolicy Bypass -File `"$arl`""
            & $nssmPath set $serviceName Start SERVICE_AUTO_START
            Start-Service -Name $serviceName
            Write-Host "Service '$serviceName' installed and started successfully."
        } else {
            Write-Host "Service '$serviceName' already exists. No action taken."
        }
    }
    "uninstall" {
        if ($service) {
            Write-Host "Uninstalling service '$serviceName'..."
            Stop-Service -Name $serviceName -Force
            & $nssmPath remove $serviceName confirm
            Write-Host "Service '$serviceName' uninstalled successfully."
        } else {
            Write-Host "Service '$serviceName' does not exist. No action taken."
        }
    }
    "exit" {
        exit
    }
    default {
        Write-Host "Invalid option selected. Exiting script."
        exit
    }
}

Write-Host "The service '$serviceName' is set up to run the Autoruns logger every 5 minutes."
