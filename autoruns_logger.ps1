# Define paths
$downloadFolder = "C:\WinSP\WinSPServiceLogs"
$autorunsPath = "C:\SysinternalsSuite\autorunsc.exe"
$whitelistFilePath = "C:\WinSP\whitelist.csv"
$apiKeyPath = "C:\WinSP\apikey.txt"
$virusTotalCsvPath = "$downloadFolder\VirusTotalReport.csv"
$logFilePath = "C:\WinSP\winsp_service_log.txt"
$settingsPath = "C:\WinSP\settings.json"


$global:LastClearedDate = Get-Date -Format "yyyy-MM-dd"

function Load-Interval {
    if (Test-Path $settingsPath) {
        try {
            $settings = Get-Content -Path $settingsPath | ConvertFrom-Json
            return $settings.Interval
        } catch {
            Log-Message "Error reading interval from settings.json: $_"
            return 86400  # Default interval (1 day)
        }
    } else {
        Log-Message "Settings file not found. Using default interval of 86400 seconds (1 day)."
        return 86400
    }
}

function Log-Message {
    param (
        [string]$message
    )
    $currentDate = Get-Date -Format "yyyy-MM-dd"
    if ($global:LastClearedDate -ne $currentDate) {
        Clear-Content -Path $logFilePath
        $global:LastClearedDate = $currentDate
        "$currentDate - Log file cleared for new day." | Out-File -FilePath $logFilePath -Append
    }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logFilePath -Append
}

function Load-Whitelist {
    param (
        [string]$whitelistFilePath
    )

    $whitelist = @()
    if (Test-Path $whitelistFilePath) {
        try {
            $whitelist = Import-Csv -Path $whitelistFilePath -Header "Hash" | ForEach-Object { $_.Hash.Trim() }
        } catch {
            Log-Message "Error reading whitelist file: $_"
        }
    } else {
        Log-Message "Whitelist file not found. Creating an empty whitelist."
        New-Item -Path $whitelistFilePath -ItemType File -Force
    }
    return $whitelist
}

function Perform-ThreatAssessment {
    param (
        [string]$differencesFilePath,
        [string]$checkFilePath
    )

    $whitelist = Load-Whitelist -whitelistFilePath $whitelistFilePath

    try {
        if (Test-Path $checkFilePath) {
            Clear-Content -Path $checkFilePath
        } else {
            New-Item -Path $checkFilePath -ItemType File -Force
        }

        if (Test-Path $differencesFilePath) {
            try {
                $jsonContent = Get-Content -Path $differencesFilePath -Raw | ConvertFrom-Json
            } catch {
                Log-Message "Error reading or parsing differences.json: $_"
                return
            }

            foreach ($entry in $jsonContent) {
                try {
                    # Default to Md5Hash if no specific hash modification is detected
                    $hashToCheck = $entry.NewAttributes.Md5Hash

                    if ($entry.ChangeType -eq "Modified") {
                        # Check for hash modifications
                        if ($entry.ModifiedProperties) {
                            foreach ($modification in $entry.ModifiedProperties) {
                                if ($modification.Property -match "Hash") {
                                    # Use the hash type being modified
                                    $hashType = $modification.Property
                                    $hashToCheck = $entry.NewAttributes.$hashType
                                    Log-Message "Detected modification in $hashType for item: $($entry.ItemName). Hash: $hashToCheck"
                                    break
                                }
                            }
                        }
                    }

                    # Skip if the hash is whitelisted
                    if ($whitelist -contains $hashToCheck) {
                        Log-Message "Skipping whitelisted entry: $($entry.NewAttributes.ItemName) - Hash: $hashToCheck"
                        continue
                    }

                    # Add the hash to check.txt
                    Add-Content -Path $checkFilePath -Value $hashToCheck
                    Log-Message "Added hash to check.txt: $hashToCheck for item: $($entry.NewAttributes.ItemName)"

                } catch {
                    Log-Message "Error processing entry for $($entry.ItemName): $_"
                }
            }

            Log-Message "Threat assessment completed. check.txt has been updated."
        } else {
            Log-Message "Differences file not found at $differencesFilePath"
        }
    } catch {
        Log-Message "Error processing the differences file: $_"
    }
}


if (-not (Test-Path $whitelistFilePath)) {
    New-Item -Path $whitelistFilePath -ItemType File -Force
    Log-Message "Created empty whitelist.csv at $whitelistFilePath"
}

function Check-VirusTotal {
    param (
        [string]$apiKeyPath,
        [string]$checkFilePath,
        [string]$outputCsvPath
    )

    if (-not (Test-Path $apiKeyPath)) {
        Log-Message "API key file not found. Please run the setup to provide an API key."
        return
    }

    $apiKey = (Get-Content -Path $apiKeyPath -Raw).Trim()
    Log-Message "Using API key: $apiKey"

    if (-not (Test-Path $checkFilePath)) {
        Log-Message "Check file not found: $checkFilePath"
        return
    }

    if (Test-Path $outputCsvPath) {
        try {
            Clear-Content -Path $outputCsvPath
        } catch {
            Log-Message "Error clearing VirusTotalReport.csv: $_"
        }
    } else {
        try {
            New-Item -Path $outputCsvPath -ItemType File -Force | Out-Null
            Log-Message "Created VirusTotalReport.csv for new data."
        } catch {
            Log-Message "Error creating VirusTotalReport.csv: $_"
        }
    }

    $hashes = Get-Content -Path $checkFilePath
    $results = @()

    foreach ($hash in $hashes) {
        Log-Message "Checking VirusTotal for hash: $hash"
        try {
            $uriBuilder = New-Object System.UriBuilder("https://www.virustotal.com/vtapi/v2/file/report")
            $uriBuilder.Query = "apikey=$apiKey&resource=$hash"
            $fullUri = $uriBuilder.Uri.AbsoluteUri
            Log-Message "Prepared request URI: $fullUri"

            $response = Invoke-RestMethod -Uri $fullUri -Method Get -ContentType "application/x-www-form-urlencoded"
            Log-Message "VirusTotal response received for hash: $hash"

            if ($response.response_code -eq 1) {
                $programName = if ($response.PSObject.Properties["magic"]) { $response.magic } else { "Unknown" }
                $results += [PSCustomObject]@{
                    Hash         = $hash
                    ProgramName  = $programName
                    Positives    = $response.positives
                    TotalScans   = $response.total
                    ScanDate     = $response.scan_date
                    ScanResult   = ($response.scans | Get-Member -MemberType Properties | ForEach-Object { $_.Name + ": " + $response.scans.$($_.Name).result }) -join "; "
                }
            } else {
                $results += [PSCustomObject]@{
                    Hash         = $hash
                    ProgramName  = "Unknown"
                    Positives    = 0
                    TotalScans   = 0
                    ScanDate     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                    ScanResult   = "Not Found on VT, Please manually check this service"
                }
                Log-Message "No VirusTotal results found for hash: $hash"
            }

            Start-Sleep -Seconds 20  # Rate limit delay

        } catch {
            Log-Message "Error querying VirusTotal for hash: $hash - $_"
        }
    }

    if ($results.Count -gt 0) {
        try {
            $results | Export-Csv -Path $outputCsvPath -NoTypeInformation -Force
            Log-Message "VirusTotal scan results successfully saved to $outputCsvPath"
        } catch {
            Log-Message "Error saving VirusTotal scan results to CSV: $_"
        }
    } else {
        Log-Message "No VirusTotal scan results to save."
    }
}






while ($true) {
    try {
        if (-not (Test-Path -Path $downloadFolder)) {
            New-Item -Path $downloadFolder -ItemType Directory -Force
            Log-Message "Created log folder: $downloadFolder"
        } else {
            Log-Message "Log folder already exists: $downloadFolder"
        }
    } catch {
        Log-Message "Error creating or accessing the log folder: $_"
        exit
    }

    try {
        Get-ChildItem -Path $downloadFolder -Filter "*.xml" | ForEach-Object {
            Remove-Item $_.FullName -Force
            Log-Message "Deleted old XML file: $($_.Name)"
        }
    } catch {
        Log-Message "Error deleting old XML files: $_"
    }

    $logFile = "$downloadFolder\winsp_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    $jsonFile = "$downloadFolder\winsp_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    Log-Message "Running Autoruns and saving the output to $logFile"
    try {
        & $autorunsPath -accepteula -a * -h -s -x -nobanner > $logFile
        Log-Message "Autoruns XML log generated: $logFile"
    } catch {
        Log-Message "Error running Autoruns: $_"
    }

    if (Test-Path -Path $logFile) {
        Log-Message "Converting XML log: $logFile to JSON"
        try {
            [xml]$xmlContent = Get-Content -Path $logFile

            $logEntries = $xmlContent.autoruns.item | ForEach-Object {
                [PSCustomObject]@{
                    Location       = $_.location
                    ItemName       = $_.itemname
                    Enabled        = $_.enabled
                    Profile        = $_.profile
                    LaunchString   = $_.launchstring
                    Description    = $_.description
                    Company        = $_.company
                    Signer         = $_.signer
                    Version        = $_.version
                    ImagePath      = $_.imagepath
                    Time           = $_.time
                    Md5Hash        = $_.md5hash
                    Sha1Hash       = $_.sha1hash
                    Pesha1Hash     = $_.pesha1hash
                    Sha256Hash     = $_.sha256hash
                    Pesha256Hash   = $_.pesha256hash
                    ImpHash        = $_.imphash
                }
            }

            $jsonContent = $logEntries | ConvertTo-Json -Depth 10 -Compress:$false
            Set-Content -Path $jsonFile -Value $jsonContent -Force
            Log-Message "Converted XML to JSON: $jsonFile"
            Remove-Item -Path $logFile -Force
            Log-Message "Deleted XML file: $logFile"
        } catch {
            Log-Message "Error converting log file to JSON: $_"
        }
    } else {
        Log-Message "Log file does not exist for conversion."
    }

    $jsonFiles = Get-ChildItem -Path $downloadFolder -Filter "winsp_log_*.json" | Sort-Object LastWriteTime -Descending
    if ($jsonFiles.Count -gt 2) {
        $jsonFiles | Select-Object -Skip 2 | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force
                Log-Message "Deleted old JSON file: $($_.Name)"
            } catch {
                Log-Message "Error deleting JSON file: $_"
            }
        }
    }

    $differenceFileName = "winsp_differences.json"
    $differenceFilePath = Join-Path -Path $downloadFolder -ChildPath $differenceFileName
    $checkFilePath = "$downloadFolder\check.txt"

    if ($jsonFiles.Count -ge 2) {
        $jsonFile1 = $jsonFiles[0].FullName
        $jsonFile2 = $jsonFiles[1].FullName

        Log-Message "Comparing JSON files: $jsonFile1 and $jsonFile2"
        try {
            $jsonContent1 = Get-Content -Path $jsonFile1 | ConvertFrom-Json
            $jsonContent2 = Get-Content -Path $jsonFile2 | ConvertFrom-Json
        } catch {
            Log-Message "Error reading JSON files: $_"
            continue
        }

        $hash1 = @{ }
        foreach ($entry in $jsonContent1) {
            $hash1[$entry.ItemName] = $entry
        }

        $hash2 = @{ }
        foreach ($entry in $jsonContent2) {
            $hash2[$entry.ItemName] = $entry
        }

        $differences = @()

        foreach ($entry in $hash2.Keys) {
            if (-not $hash1.ContainsKey($entry)) {
                $differences += [PSCustomObject]@{
                    ChangeType         = "Removed"
                    ItemName           = $entry
                    PreviousAttributes = $hash2[$entry]
                    NewAttributes      = $null
                }
            } else {
                $attributes1 = $hash1[$entry]
                $attributes2 = $hash2[$entry]

                $modifiedAttributes = @()
                foreach ($property in $attributes1.PSObject.Properties) {
                    if ($property.Name -ne "Description" -and $attributes2.$($property.Name) -ne $attributes1.$($property.Name)) {
                        $modifiedAttributes += [PSCustomObject]@{
                            Property   = $property.Name
                            OldValue   = $attributes1.$($property.Name)
                            NewValue   = $attributes2.$($property.Name)
                        }
                    }
                }

                if ($modifiedAttributes.Count -gt 0) {
                    $differences += [PSCustomObject]@{
                        ChangeType         = "Modified"
                        ItemName           = $entry
                        PreviousAttributes = $attributes1
                        NewAttributes      = $attributes2
                        ModifiedProperties = $modifiedAttributes
                    }
                }
            }
        }

        foreach ($entry in $hash1.Keys) {
            if (-not $hash2.ContainsKey($entry)) {
                $differences += [PSCustomObject]@{
                    ChangeType         = "Added"
                    ItemName           = $entry
                    PreviousAttributes = $null
                    NewAttributes      = $hash1[$entry]
                }
            }
        }

        if ($differences.Count -gt 0) {
            if (Test-Path -Path $differenceFilePath) {
                Remove-Item -Path $differenceFilePath -Force
                Log-Message "Deleted existing differences file: $differenceFileName"
            }
            $differencesContent = $differences | ConvertTo-Json -Depth 10 -Compress:$false
            Set-Content -Path $differenceFilePath -Value $differencesContent -Force
            Log-Message "Differences report generated: $differenceFilePath"
        } else {
            $noDiffContent = @{"Message"="No differences found at this time"}
            Set-Content -Path $differenceFilePath -Value ($noDiffContent | ConvertTo-Json -Compress:$false) -Force
            Log-Message "No differences found between the two JSON files. Created a log stating no differences."
        }

        Perform-ThreatAssessment -differencesFilePath $differenceFilePath -checkFilePath $checkFilePath
        Check-VirusTotal -apiKeyPath $apiKeyPath -checkFilePath $checkFilePath -outputCsvPath $virusTotalCsvPath

    } else {
        Log-Message "Not enough JSON files available for comparison."
    }

    $interval = Load-Interval
    Log-Message "Waiting for $interval seconds."
    Start-Sleep -Seconds $interval
}
