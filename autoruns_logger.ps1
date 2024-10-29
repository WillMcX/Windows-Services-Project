$desktopPath = [Environment]::GetFolderPath("Desktop")
$downloadFolder = "C:\AutorunsScanTool\AutorunsServiceLogs"
$autorunsPath = "C:\SysinternalsSuite\autorunsc.exe"
$whitelistFilePath = "C:\AutorunsScanTool\whitelist.csv" 
$apiKeyPath = "C:\AutorunsScanTool\apikey.txt"
$virusTotalCsvPath = "$downloadFolder\\VirusTotalReport.csv"

function Load-Whitelist {
    param (
        [string]$whitelistFilePath
    )

    $whitelist = @()
    if (Test-Path $whitelistFilePath) {
        try {
            $whitelist = Import-Csv -Path $whitelistFilePath -Header "Hash" | ForEach-Object { $_.Hash.Trim() }
        } catch {
            Write-Host "Error reading whitelist file: $_"
        }
    } else {
        Write-Host "Whitelist file not found. Creating an empty whitelist."
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
                Write-Host "Error reading or parsing differences.json: $_"
                return
            }

            foreach ($entry in $jsonContent) {
                try {
                    $hash = $entry.NewAttributes.Md5Hash

                    if ($whitelist -contains $hash) {
                        Write-Host "Skipping whitelisted entry: $($entry.NewAttributes.ItemName) - Hash: $hash"
                        continue
                    }

                    Add-Content -Path $checkFilePath -Value $hash

                } catch {
                    Write-Host "Error processing entry for $($entry.ItemName): $_"
                }
            }

            Write-Host "Threat assessment completed, check.txt has been updated."
        } else {
            Write-Host "Differences file not found at $differencesFilePath"
        }
    } catch {
        Write-Host "Error processing the differences file: $_"
    }
}

if (-not (Test-Path $whitelistFilePath)) {
    New-Item -Path $whitelistFilePath -ItemType File -Force
    Write-Host "Created empty whitelist.csv at $whitelistFilePath"
}

function Check-VirusTotal {
    param (
        [string]$apiKeyPath,
        [string]$checkFilePath,
        [string]$outputCsvPath
    )

    if (-not (Test-Path $apiKeyPath)) {
        Write-Host "API key file not found. Please run the setup to provide an API key."
        return
    }

    $apiKey = Get-Content -Path $apiKeyPath -Raw

    if (-not (Test-Path $checkFilePath)) {
        Write-Host "Check file not found: $checkFilePath"
        return
    }

    $hashes = Get-Content -Path $checkFilePath
    $virusTotalUrl = "https://www.virustotal.com/vtapi/v2/file/report"
    $results = @()

    foreach ($hash in $hashes) {
        Write-Host "Checking VirusTotal for hash: $hash"
        try {
            $params = @{
                apikey   = $apiKey
                resource = $hash
            }
            $response = Invoke-RestMethod -Uri $virusTotalUrl -Method Get -Body $params

            if ($response.response_code -eq 1) {
                $results += [PSCustomObject]@{
                    Hash         = $hash
                    Positives    = $response.positives
                    TotalScans   = $response.total
                    ScanDate     = $response.scan_date
                    ScanResult   = ($response.scans | Get-Member -MemberType Properties | ForEach-Object { $_.Name + ": " + $response.scans.$($_.Name).result }) -join "; "
                }
            } else {
                Write-Host "No VirusTotal results found for hash: $hash"
            }
            #Start-Sleep -Seconds 15  (to avoid rate limit)

        } catch {
            Write-Host "Error querying VirusTotal for hash: $hash - $_"
        }
    }

    # Output the results to a CSV file
    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $outputCsvPath -NoTypeInformation
        Write-Host "VirusTotal scan results saved to $outputCsvPath"
    } else {
        Write-Host "No results to save."
    }
}



while ($true) {
    try {
        if (-not (Test-Path -Path $downloadFolder)) {
            New-Item -Path $downloadFolder -ItemType Directory -Force
            Write-Host "Created log folder: $downloadFolder"
        } else {
            Write-Host "Log folder already exists: $downloadFolder"
        }
    } catch {
        Write-Host "Error creating or accessing the log folder: $_"
        exit
    }

    try {
        Get-ChildItem -Path $downloadFolder -Filter "*.xml" | ForEach-Object {
            Remove-Item $_.FullName -Force
            Write-Host "Deleted old XML file: $($_.Name)"
        }
    } catch {
        Write-Host "Error deleting old XML files: $_"
    }

    $logFile = "$downloadFolder\autoruns_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
    $jsonFile = "$downloadFolder\autoruns_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"

    Write-Host "Running Autoruns and saving the output to $logFile"
    try {
        & $autorunsPath -accepteula -a * -h -s -x -nobanner > $logFile
        Write-Host "Autoruns XML log generated: $logFile"
    } catch {
        Write-Host "Error running Autoruns: $_"
    }

    if (Test-Path -Path $logFile) {
        Write-Host "Converting XML log: $logFile to JSON"
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
            Write-Host "Converted XML to JSON: $jsonFile"
            Remove-Item -Path $logFile -Force
            Write-Host "Deleted XML file: $logFile"
        } catch {
            Write-Host "Error converting log file to JSON: $_"
        }
    } else {
        Write-Host "Log file does not exist for conversion."
    }

    $jsonFiles = Get-ChildItem -Path $downloadFolder -Filter "autoruns_log_*.json" | Sort-Object LastWriteTime -Descending
    if ($jsonFiles.Count -gt 2) {
        $jsonFiles | Select-Object -Skip 2 | ForEach-Object {
            try {
                Remove-Item $_.FullName -Force
                Write-Host "Deleted old JSON file: $($_.Name)"
            } catch {
                Write-Host "Error deleting JSON file: $_"
            }
        }
    }

    $differenceFileName = "autoruns_differences.json"
    $differenceFilePath = Join-Path -Path $downloadFolder -ChildPath $differenceFileName
    $checkFilePath = "$downloadFolder\check.txt"

    if ($jsonFiles.Count -ge 2) {
        $jsonFile1 = $jsonFiles[0].FullName
        $jsonFile2 = $jsonFiles[1].FullName

        Write-Host "Comparing JSON files: $jsonFile1 and $jsonFile2"
        try {
            $jsonContent1 = Get-Content -Path $jsonFile1 | ConvertFrom-Json
            $jsonContent2 = Get-Content -Path $jsonFile2 | ConvertFrom-Json
        } catch {
            Write-Host "Error reading JSON files: $_"
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
                Write-Host "Deleted existing differences file: $differenceFileName"
            }
            $differencesContent = $differences | ConvertTo-Json -Depth 10 -Compress:$false
            Set-Content -Path $differenceFilePath -Value $differencesContent -Force
            Write-Host "Differences report generated: $differenceFilePath"
        } else {
            $noDiffContent = @{"Message"="No differences found at this time"}
            Set-Content -Path $differenceFilePath -Value ($noDiffContent | ConvertTo-Json -Compress:$false) -Force
            Write-Host "No differences found between the two JSON files. Created a log stating no differences."
        }

        Perform-ThreatAssessment -differencesFilePath $differenceFilePath -checkFilePath $checkFilePath
        Check-VirusTotal -apiKeyPath $apiKeyPath -checkFilePath $checkFilePath -outputCsvPath $virusTotalCsvPath

    } else {
        Write-Host "Not enough JSON files available for comparison."
    }

    Write-Host "Sleeping for 5 minutes..."
    Start-Sleep -Seconds 300
}
