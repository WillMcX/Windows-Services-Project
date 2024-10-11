# Windows-Services-Project
- Independent Study project on the Windows Services and the Vulnerabilities that can be exploited within them.
- W.I.P - Making a service extension that scans all currently running processs on the system on an interval and then after that will gather differences and check for potentially risky services running on the computer

- As of now in order to execute this you must have both of the ps1 files in the same directory and then do:
- `powershell -ExecutionPolicy Bypass -File "C:{path_to_desired_location}\setup_autoruns_service.ps1"`
