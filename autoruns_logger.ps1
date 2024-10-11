$desktopPath = [Environment]::GetFolderPath("Desktop")
$downloadFolder = "$desktopPath\AutorunsServiceLogs"
$autorunsPath = "C:\SysinternalsSuite\autorunsc.exe"

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


        $hash1 = @{}
        foreach ($entry in $jsonContent1) {
            $hash1[$entry.ItemName] = $entry
        }

        $hash2 = @{}
        foreach ($entry in $jsonContent2) {
            $hash2[$entry.ItemName] = $entry
        }

        $differences = @()

        foreach ($entry in $hash2.Keys) {
            if (-not $hash1.ContainsKey($entry)) {
                $differences += [PSCustomObject]@{
                    ChangeType         = "Removed"
                    ItemName           = $entry
                    PreviousAttributes  = $hash2[$entry]
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
                        PreviousAttributes  = $attributes1
                        NewAttributes      = $attributes2
                        ModifiedProperties  = $modifiedAttributes
                    }
                }
            }
        }

        foreach ($entry in $hash1.Keys) {
            if (-not $hash2.ContainsKey($entry)) {
                $differences += [PSCustomObject]@{
                    ChangeType         = "Added"
                    ItemName           = $entry
                    PreviousAttributes  = $null
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
            Write-Host "No differences found between the two JSON files."
        }
    } else {
        Write-Host "Not enough JSON files available for comparison."
    }

    Write-Host "Sleeping for 5 minutes..."
    Start-Sleep -Seconds 300
}
