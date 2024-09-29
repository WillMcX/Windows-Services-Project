# Function to check if script is running as admin
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Relaunch script as Administrator if not already elevated
if (-not (Test-IsAdmin)) {
    Write-Host "This script requires administrator privileges. Restarting with elevated permissions..."
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Now proceed with the script as it will have elevated permissions
Write-Host "Running script with administrator privileges..."

# Define variables
$nssmDownloadUrl = "https://nssm.cc/release/nssm-2.24.zip"
$downloadFolderNSSM = "C:\nssm"
$autorunsFolder = "C:\SysinternalsSuite"
$autorunsPath = "$autorunsFolder\autorunsc.exe"  # Path to autorunsc.exe
$serviceName = "AutorunsPeriodicScannerTestv2.4"
$desktopPath = [Environment]::GetFolderPath("Desktop")
$scriptToRun = "$desktopPath\autoruns_logger.ps1" # Path to the updated autoruns_logger.ps1

# Function to download and install NSSM if not installed
function Install-NSSM {
    Write-Host "NSSM not found. Downloading NSSM..."

    # Create download folder if it doesn't exist
    if (-not (Test-Path $downloadFolderNSSM)) {
        New-Item -Path $downloadFolderNSSM -ItemType Directory
    }

    # Define the ZIP file download path
    $zipPath = "$downloadFolderNSSM\nssm.zip"

    # Download NSSM zip file
    Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $zipPath

    Write-Host "NSSM downloaded. Extracting..."

    # Extract the ZIP file
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $downloadFolderNSSM)
    Write-Host "NSSM extracted successfully."
}

# Check if NSSM is installed
$nssmPath = "$downloadFolderNSSM\nssm-2.24\win64\nssm.exe"
if (-not (Test-Path $nssmPath)) {
    Install-NSSM
} else {
    Write-Host "NSSM is already installed. Path: $nssmPath"
}

# Check if Autoruns is installed
if (-not (Test-Path $autorunsPath)) {
    Write-Host "Autoruns is not installed. Please download it manually."
    exit
} else {
    Write-Host "Autoruns is already installed. Path: $autorunsPath"
}

# Check if the service exists
$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

# Check service status and prompt user if already running
if ($service) {
    Write-Host "Service '$serviceName' already exists."
    $serviceStatus = $service.Status
    Write-Host "Current Status: $serviceStatus"

    if ($serviceStatus -eq "Running") {
        $userInput = Read-Host "Would you like to stop/restart the service? (stop/restart/exit)"
        if ($userInput -eq "stop") {
            Stop-Service -Name $serviceName
            Write-Host "Service stopped."
        } elseif ($userInput -eq "restart") {
            Restart-Service -Name $serviceName
            Write-Host "Service restarted."
        } elseif ($userInput -eq "exit") {
            exit
        }
    }
} else {
    Write-Host "Service does not exist. Installing NSSM service..."

    # Install the service using NSSM with the PowerShell script
    & $nssmPath install $serviceName powershell.exe "-ExecutionPolicy Bypass -File `"$scriptToRun`"" 

    # Set the service to start automatically
    & $nssmPath set $serviceName Start SERVICE_AUTO_START
    
    # Start the service
    Start-Service -Name $serviceName
    Write-Host "Service '$serviceName' installed and started successfully."
}

Write-Host "The service '$serviceName' is set up to run the Autoruns logger every 5 minutes."
