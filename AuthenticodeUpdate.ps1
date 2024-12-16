function Ensure-CsvFile {
    param (
        [string]$FilePath
    )
    if (-not (Test-Path $FilePath)) {
        try {
            @() | Export-Csv -Path $FilePath -NoTypeInformation -Force
            Log "CSV file created: $FilePath" -Color Green
        } catch {
            Log "Failed to create CSV file: $FilePath. Error: $($_.Exception.Message)" -Color Red
        }
    } else {
        Log "CSV file already exists: $FilePath" -Color Green
    }
}

$DirectoriesToScan = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64",
    "C:\Windows\SoftwareDistribution",
    "C:\Program Files",
    "C:\Program Files (x86)" 
)

$OutputFile = "C:\WinSP\SystemAuthenticodes.csv"

function Log {
    param (
        [string]$Message,
        [string]$Color = "White"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] $Message" -ForegroundColor $Color
}

Ensure-CsvFile -FilePath $OutputFile

function Split-IntoBatches {
    param (
        [array]$Items,
        [int]$BatchSize
    )
    $Batches = @()
    for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
        $Batches += ,($Items[$i..([math]::Min($i + $BatchSize - 1, $Items.Count - 1))])
    }
    return $Batches
}

$VerifyFilesFunctionContent = @'
function Verify-Files {
    param (
        [string]$Directory
    )

    $Results = @()
    try {
        # Get relevant files
        Get-ChildItem -Path $Directory -Recurse -File -Include *.exe, *.dll, *.sys -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $certificate = Get-AuthenticodeSignature -FilePath $_.FullName
                $Results += [PSCustomObject]@{
                    FilePath = $_.FullName
                    Status   = $certificate.Status
                    Issuer   = if ($certificate.SignerCertificate) { $certificate.SignerCertificate.Issuer } else { "Unknown" }
                }
            } catch {
                $Results += [PSCustomObject]@{
                    FilePath = $_.FullName
                    Status   = "Error"
                    Issuer   = "Unknown"
                }
            }
        }
    } catch {
        Write-Host "Error accessing directory: $Directory" -ForegroundColor Red
    }
    return $Results
}
'@

Log "Starting Authenticode Update (Estimated time til completion: 10 min) DONT NOT EXIT THE WINDOW..." -Color Green

$BatchSize = 1
$Batches = Split-IntoBatches -Items $DirectoriesToScan -BatchSize $BatchSize

$Jobs = @()
foreach ($Batch in $Batches) {
    Log "Starting job for batch: $($Batch -join ', ')" -Color Cyan

    $Jobs += Start-Job -ScriptBlock {
        param ($Directories, $VerifyFunctionContent)

        Invoke-Expression $VerifyFunctionContent

        $BatchResults = @()
        foreach ($Directory in $Directories) {
            Write-Host "Scanning directory: $Directory" -ForegroundColor Yellow
            $BatchResults += Verify-Files -Directory $Directory
        }
        return $BatchResults
    } -ArgumentList $Batch, $VerifyFilesFunctionContent
}

$Results = @()
foreach ($Job in $Jobs) {
    Log "Waiting for job to complete..." -Color Yellow
    $JobResults = Receive-Job -Job $Job -Wait
    if ($JobResults) {
        Log "Job completed. Collecting results..." -Color Green
        $Results += $JobResults
    } else {
        Log "No results returned from job." -Color Red
    }
}

if ($Results.Count -gt 0) {
    Log "Saving results to $OutputFile..." -Color Cyan
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Force
    Log "Scan complete. Results saved to $OutputFile" -Color Green
} else {
    Log "No files were scanned. Please verify permissions and directory contents." -Color Red
}
