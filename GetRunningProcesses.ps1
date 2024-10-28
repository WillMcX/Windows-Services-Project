Get-Service | Where-Object { $_.Status -eq 'Running' } | 
Select StartType, ServiceType, Status, Name, DisplayName | 
Export-Csv -Path "$([Environment]::GetFolderPath('Desktop'))\RunningServices.csv" -NoTypeInformation
