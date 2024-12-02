# Windows-Services-Project
- Independent Study project on the Windows Services and the Vulnerabilities that can be exploited within them.
- W.I.P - Making a service extension / application that scans all currently running processs on the system on an interval and then after that will gather differences and check for potentially risky services running on the computer and notify the user

# Week 11-12
- Added a Dependency of Powershell 7 Core, replacing Powershell 5.1 thats natively installed for Windows OS
  - Powershell 7 implemented for paralell processing and task time improvements
- Notifications system implemented, so that after scans it will notify you of any positives detected
- Implementation of the Get-AuthentiCode function from powershell in order to authorize and confirm valid windows programs, using the Authenticode Update button in app to store valid Autheticodes
- Automated whitelist generation when running the Authenticode Update in program
