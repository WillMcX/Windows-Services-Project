Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
    }
"@

$consoleWindow = (Get-Process -Id $PID).MainWindowHandle
[Win32]::ShowWindowAsync($consoleWindow, 0)

# Define paths and variables
$desktopPath = [Environment]::GetFolderPath("Desktop")
$apiKeyPath = "C:\AutorunsScanTool\apikey.txt"
$nssmDownloadUrl = "https://nssm.cc/release/nssm-2.24.zip"
$downloadFolderNSSM = "C:\nssm"
$autorunsDownloadUrl = "https://download.sysinternals.com/files/Autoruns.zip"
$autorunsFolder = "C:\SysinternalsSuite"
$autorunsZipPath = "$autorunsFolder\Autoruns.zip"
$autorunsPath = "$autorunsFolder\autorunsc.exe"
$serviceName = "AutorunsPeriodicScannerTestv8.1"
$logFilePath = "C:\AutorunsScanTool\autoruns_service_log.txt"

function Ensure-LogFile {
    $logDirectory = [System.IO.Path]::GetDirectoryName($logFilePath)
    
    if (-not (Test-Path $logDirectory)) {
        New-Item -Path $logDirectory -ItemType Directory | Out-Null
    }

    if (-not (Test-Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType File | Out-Null
    }
}

function Run-AutorunsLogger {
    $loggerScript = "$desktopPath\autoruns_logger.ps1"
    Ensure-LogFile  

    if (Test-Path $loggerScript) {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$loggerScript`"" -NoNewWindow -RedirectStandardOutput $logFilePath -RedirectStandardError $logFilePath -Wait
    } else {
        Write-Log "autoruns_logger.ps1 not found."
    }
}

function Write-Log {
    param (
        [string]$message,
        [ref]$textBox
    )
    $textBox.Value.AppendText("$message`r`n")
}

# Function to check if the user is an administrator
function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    exit
}

# Functions to handle service actions/installs
function Install-NSSM {
    Write-Log "NSSM not found. Downloading NSSM..." ([ref]$outputBox)
    if (-not (Test-Path $downloadFolderNSSM)) {
        New-Item -Path $downloadFolderNSSM -ItemType Directory
    }
    $zipPath = "$downloadFolderNSSM\nssm.zip"
    Invoke-WebRequest -Uri $nssmDownloadUrl -OutFile $zipPath
    Write-Log "NSSM downloaded. Extracting..." ([ref]$outputBox)
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $downloadFolderNSSM)
    Write-Log "NSSM extracted successfully." ([ref]$outputBox)
}

function Install-Autoruns {
    Write-Log "Autoruns not found. Downloading Autoruns..." ([ref]$outputBox)
    if (-not (Test-Path $autorunsFolder)) {
        New-Item -Path $autorunsFolder -ItemType Directory
    }
    Invoke-WebRequest -Uri $autorunsDownloadUrl -OutFile $autorunsZipPath
    Write-Log "Autoruns downloaded. Extracting..." ([ref]$outputBox)
    Add-Type -AssemblyName 'System.IO.Compression.FileSystem'
    [System.IO.Compression.ZipFile]::ExtractToDirectory($autorunsZipPath, $autorunsFolder)
    Write-Log "Autoruns extracted successfully." ([ref]$outputBox)
}

function Install-Service {
    $nssmPath = "$downloadFolderNSSM\nssm-2.24\win64\nssm.exe"
    if (-not (Test-Path $nssmPath)) {
        Install-NSSM
    } else {
        Write-Log "NSSM is already installed. Path: $nssmPath" ([ref]$outputBox)
    }

    if (-not (Test-Path $autorunsPath)) {
        Install-Autoruns
    } else {
        Write-Log "Autoruns is already installed. Path: $autorunsPath" ([ref]$outputBox)
    }

    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Log "Installing NSSM service..." ([ref]$outputBox)
        & $nssmPath install $serviceName powershell.exe "-ExecutionPolicy Bypass -File `"$desktopPath\\autoruns_logger.ps1`"" -NoNewWindow -RedirectStandardOutput $logFilePath -RedirectStandardError $logFilePath
        & $nssmPath set $serviceName Start SERVICE_AUTO_START
        Start-Service -Name $serviceName
        Write-Log "Service '$serviceName' installed and started successfully." ([ref]$outputBox)
    } else {
        Write-Log "Service '$serviceName' already exists. No action taken." ([ref]$outputBox)
    }
}

function Restart-ServiceAction {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Restart-Service -Name $serviceName
            Write-Log "Service restarted successfully." ([ref]$outputBox)
        } else {
            Write-Log "Service is not running, attempting to start it..." ([ref]$outputBox)
            Start-Service -Name $serviceName
            Write-Log "Service started." ([ref]$outputBox)
        }
    } else {
        Write-Log "Service '$serviceName' does not exist. Please install it first." ([ref]$outputBox)
    }
}

function Stop-ServiceAction {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq 'Running') {
            Stop-Service -Name $serviceName
            Write-Log "Service stopped successfully." ([ref]$outputBox)
        } else {
            Write-Log "Service is already stopped." ([ref]$outputBox)
        }
    } else {
        Write-Log "Service '$serviceName' does not exist." ([ref]$outputBox)
    }
}

function Uninstall-ServiceAction {
    $nssmPath = "$downloadFolderNSSM\nssm-2.24\win64\nssm.exe"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Uninstalling service '$serviceName'..." ([ref]$outputBox)
        Stop-Service -Name $serviceName -Force
        & $nssmPath remove $serviceName confirm
        Write-Log "Service '$serviceName' uninstalled successfully." ([ref]$outputBox)
    } else {
        Write-Log "Service '$serviceName' does not exist." ([ref]$outputBox)
    }
}

function Edit-ApiKey {
    $apiForm = New-Object system.Windows.Forms.Form
    $apiForm.Text = "Edit API Key"
    $apiForm.Size = New-Object System.Drawing.Size(400,200)
    $apiForm.StartPosition = "CenterScreen"

    $apiLabel = New-Object system.Windows.Forms.Label
    $apiLabel.Text = "Current API Key:"
    $apiLabel.AutoSize = $true
    $apiLabel.Location = New-Object System.Drawing.Point(10,20)
    $apiForm.Controls.Add($apiLabel)

    $apiKeyDisplay = New-Object system.Windows.Forms.TextBox
    $apiKeyDisplay.Location = New-Object System.Drawing.Point(10,50)
    $apiKeyDisplay.Width = 300
    if (Test-Path $apiKeyPath) {
        $apiKeyDisplay.Text = Get-Content -Path $apiKeyPath
    } else {
        $apiKeyDisplay.Text = "No API Key found"
    }
    $apiForm.Controls.Add($apiKeyDisplay)

    $apiKeyLabel = New-Object system.Windows.Forms.Label
    $apiKeyLabel.Text = "Enter New API Key:"
    $apiKeyLabel.AutoSize = $true
    $apiKeyLabel.Location = New-Object System.Drawing.Point(10,80)
    $apiForm.Controls.Add($apiKeyLabel)

    $apiKeyBox = New-Object system.Windows.Forms.TextBox
    $apiKeyBox.Location = New-Object System.Drawing.Point(10,110)
    $apiKeyBox.Width = 300
    $apiForm.Controls.Add($apiKeyBox)

    $submitApiButton = New-Object system.Windows.Forms.Button
    $submitApiButton.Text = "Submit API Key"
    $submitApiButton.Location = New-Object System.Drawing.Point(10,140)
    $submitApiButton.Add_Click({
        $newApiKey = $apiKeyBox.Text
        if ($newApiKey) {
            Set-Content -Path $apiKeyPath -Value $newApiKey
            Write-Log "API Key updated successfully." ([ref]$outputBox)
            $apiForm.Close()
        } else {
            [System.Windows.Forms.MessageBox]::Show("Please enter a valid API Key.")
        }
    })
    $apiForm.Controls.Add($submitApiButton)

    $apiForm.Add_Shown({$apiForm.Activate()})
    [void]$apiForm.ShowDialog()
}

function View-Logs {
    Ensure-LogFile  
    $logForm = New-Object system.Windows.Forms.Form
    $logForm.Text = "Autoruns Service Log"
    $logForm.Size = New-Object System.Drawing.Size(600, 400)
    $logForm.StartPosition = "CenterScreen"

    $logTextBox = New-Object system.Windows.Forms.TextBox
    $logTextBox.Multiline = $true
    $logTextBox.ScrollBars = "Vertical"
    $logTextBox.Dock = "Fill"
    $logTextBox.ReadOnly = $true
    $logForm.Controls.Add($logTextBox)

    if (Test-Path $logFilePath) {
        $logContent = Get-Content -Path $logFilePath -Raw
        $logTextBox.Text = $logContent
    } else {
        $logTextBox.Text = "Log file not found."
    }

    $logForm.Add_Shown({$logForm.Activate()})
    [void]$logForm.ShowDialog()
}

function Check-ServiceStatus {
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        $status = $service.Status
        [System.Windows.Forms.MessageBox]::Show("Service '$serviceName' is currently: $status")
    } else {
        [System.Windows.Forms.MessageBox]::Show("Service '$serviceName' does not exist.")
    }
}

$form = New-Object system.Windows.Forms.Form
$form.Text = "Autoruns Service Manager"
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = "CenterScreen"

$outputBox = New-Object system.Windows.Forms.TextBox
$outputBox.Multiline = $true
$outputBox.ScrollBars = "Vertical"
$outputBox.Location = New-Object System.Drawing.Point(10,200)
$outputBox.Size = New-Object System.Drawing.Size(560,150)
$form.Controls.Add($outputBox)

$installButton = New-Object system.Windows.Forms.Button
$installButton.Text = "Install Service"
$installButton.Location = New-Object System.Drawing.Point(20,20)
$installButton.Add_Click({
    Install-Service
    [System.Windows.Forms.MessageBox]::Show("Service Installed")
})
$form.Controls.Add($installButton)

$restartButton = New-Object system.Windows.Forms.Button
$restartButton.Text = "Restart Service"
$restartButton.Location = New-Object System.Drawing.Point(120,20)
$restartButton.Add_Click({
    Restart-ServiceAction
})
$form.Controls.Add($restartButton)

$stopButton = New-Object system.Windows.Forms.Button
$stopButton.Text = "Stop Service"
$stopButton.Location = New-Object System.Drawing.Point(20,60)
$stopButton.Add_Click({
    Stop-ServiceAction
})
$form.Controls.Add($stopButton)

$uninstallButton = New-Object system.Windows.Forms.Button
$uninstallButton.Text = "Uninstall Service"
$uninstallButton.Location = New-Object System.Drawing.Point(120,60)
$uninstallButton.Add_Click({
    Uninstall-ServiceAction
})
$form.Controls.Add($uninstallButton)

$editApiKeyButton = New-Object system.Windows.Forms.Button
$editApiKeyButton.Text = "Edit API Key"
$editApiKeyButton.Location = New-Object System.Drawing.Point(20,100)
$editApiKeyButton.Add_Click({
    Edit-ApiKey
})
$form.Controls.Add($editApiKeyButton)

$viewLogsButton = New-Object system.Windows.Forms.Button
$viewLogsButton.Text = "View Logs"
$viewLogsButton.Location = New-Object System.Drawing.Point(120,100)
$viewLogsButton.Add_Click({
    View-Logs
})
$form.Controls.Add($viewLogsButton)

$statusButton = New-Object system.Windows.Forms.Button
$statusButton.Text = "Service Status"
$statusButton.Location = New-Object System.Drawing.Point(220,20)
$statusButton.Add_Click({
    Check-ServiceStatus
})
$form.Controls.Add($statusButton)

$closeButton = New-Object system.Windows.Forms.Button
$closeButton.Text = "Close Window"
$closeButton.Location = New-Object System.Drawing.Point(20,140)
$closeButton.Add_Click({
    $form.Close()
})
$form.Controls.Add($closeButton)

$form.Add_Shown({$form.Activate()})
[void]$form.ShowDialog()
