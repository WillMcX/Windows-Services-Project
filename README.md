
# **WinSP Documentation / Setup**

## Created by: William McCoy

---

## **Overview**

The **Windows Service Protector** or **WinSP** is a comprehensive Windows service management tool designed to monitor system changes and assess potential threats using **Sysinternals Autoruns** and **VirusTotal** API integration. This solution is ideal for administrators and security analysts who require automation in system monitoring, service management, logging, and threat assessment.

---

## Installer Link / Instructions**

   The `WinSP.exe` is now available to download from : [WinSP Installer](https://drive.google.com/file/d/16CaJVxOxX-QlInnZ5p9jC3Y2AaUgBlv7/view?usp=sharing)

   - Currently this is running a self signed certificate, and will prompt a Defender Smartscreen notification. I can assure (as well as you may code review) see that this program is for the quick opposite purpose
   - 
   


---

## **System Features**

### 1. **Service Management**
- Install, start, stop, restart, and uninstall the **WinSP Service** in app.
- Automatically manages required dependencies like **Autoruns** and **NSSM**.

### 2. **Threat Monitoring**
- Scans system changes and generates logs of new or modified items.
- Uses **VirusTotal** API for hash-based threat analysis of system changes.
- Maintains a whitelist of trusted files to avoid repeated checks.

### 3. **Logging and Reporting**
- Generates daily logs for service actions and system monitoring.
- Converts Autoruns' XML logs into JSON for easier processing and comparisons.
- Detects and logs differences between successive scans.

### 4. **Whitelist Management**
- Allows editing, generating, and maintaining a whitelist of trusted hashes.
- Integrates a GUI for manual whitelist updates.

### 5. **Integration with VirusTotal**
- Automatically checks hashes of unwhitelisted files against **VirusTotal** API.
- Retrieves detailed scan results, including positives and scan dates.
- Maintains a CSV report for VirusTotal results, with interactive GUI for expanded information.

### 6. **Notifications**
- Uses the **BurntToast** module to send Windows notifications.
- Sends real-time updates when VirusTotal detects positive threats or confirms a clean system.

### 7. **Authenticode Verification**
- Scans key directories for executables, DLLs, and system files to verify their signatures.
- Maintains a CSV log of file authentications for auditing, and building/maintaning the automatic whitelist.

### 8. **Configuration Options**
- Allows setting custom intervals for scans through a settings interface.
- Provides a GUI to update the **VirusTotal API Key**.

---

## **System Components**

### **1. PowerShell Scripts**
1. **setup_autoruns_service.ps1**  
   Automates the setup and configuration of the WinSP service, including dependencies and configuration GUIs, Frontend of the application.

2. **autoruns_logger.ps1**  
   Core script executed by the WinSP service to run system scans, log results, and assess threats, backend of the application.

3. **authenticodeupdater.ps1**  
   Scans critical system directories to verify file signatures and logs results in a CSV.

4. **notif_helper.ps1**  
   Sends real-time desktop notifications based on VirusTotal scan results.

---

## **File and Folder Structure**

| **Path**                    | **Description**                                                                 |
|-----------------------------|---------------------------------------------------------------------------------|
| `C:\WinSP`                  | Main directory for storing logs, settings, and supporting files.                |
| `C:\SysinternalsSuite`      | Directory for Sysinternals tools, including Autoruns.                           |
| `C:\nssm`                   | Directory for NSSM (Non-Sucking Service Manager).                               |
| `C:\WinSP\winsp_service_log.txt` | Main log file for service actions and system monitoring.                     |
| `C:\WinSP\whitelist.csv`    | Whitelist file containing trusted hashes.                                       |
| `C:\WinSP\apikey.txt`       | Stores the VirusTotal API key.                                                  |
| `C:\WinSP\settings.json`    | Stores configuration settings such as scan intervals.                          |
| `C:\WinSP\systemauthenticodes.csv` | Stores the authenticode verification results.                            |
| `C:\WinSP\WinSPServiceLogs` | Folder for storing Autoruns logs and VirusTotal reports.                        |

---

## **Core Processes**

### **0. Installer**
- The `WinSP.exe` file:
  - Installs necessary tools: PowerShell 7 and grabs the latest release to install to user system from Github.
  - Configures the WinSP service to run the `setup_autoruns_service.ps1` (frontend) script.
  - Sets up file paths and initializes configurations.

### **1. Initial Setup**
- The `setup_autoruns_service.ps1` script:
  - Installs necessary tools: PowerShell 7, NSSM, and Autoruns.
  - Configures the WinSP service to run the `autoruns_logger.ps1` script.
  - Sets up file paths and initializes configurations.

### **2. Service Execution**
- The WinSP service runs `autoruns_logger.ps1` at configured intervals.
- Key steps:
  1. Run Autoruns to generate a system log.
  2. Convert the Autoruns log to JSON for processing.
  3. Compare the latest JSON log with the previous log to detect changes.
  4. Perform a threat assessment on new or modified items.
  5. Query VirusTotal API for untrusted hashes.
  6. Log results in CSV files and notify users of threats.

### **3. Threat Detection**
- **Whitelist Management**:
  - Avoids re-checking known safe files.
- **VirusTotal Integration**:
  - Sends hash queries to VirusTotal.
  - Logs results, including positive detections, in `VirusTotalReport.csv`.

### **4. Real-Time Notifications**
- The `notif_helper.ps1` script:
  - Monitors VirusTotal scan results.
  - Sends notifications when threats are detected or when the system is confirmed clean.

### **5. Authenticode Verification**
- Scans critical directories for file signatures.
- Logs results in `systemauthenticodes.csv` for auditing purposes.

---

## **Key Scripts and Functions**

### **setup_autoruns_service.ps1**
- **Purpose**: Automates the setup and configuration of the WinSP service.
- **Some Key Functions**:
  - `Install-Service`: Installs the WinSP service using NSSM.
  - `Edit-ApiKey`: Provides a GUI to update the VirusTotal API key.
  - `View-Logs`: Opens a GUI to inspect service logs.
  - `Restart-ServiceAction`: Restarts the WinSP service.

### **autoruns_logger.ps1**
- **Purpose**: Core script for monitoring and threat assessment.
- **Key Functions**:
  - `Perform-ThreatAssessment`: Identifies untrusted changes in system logs.
  - `Check-VirusTotal`: Queries VirusTotal API for hash-based threat assessment.

### **authenticodeupdater.ps1**
- **Purpose**: Verifies digital signatures of critical system files.
- **Key Functions**:
  - `Verify-Files`: Scans directories for file authentications.

### **notif_helper.ps1**
- **Purpose**: Sends real-time desktop notifications based on VirusTotal scan results.
- **Key Functions**:
  - `Send-Notification`: Uses BurntToast to display notifications.

---

## **Prerequisites**

1. **Windows 10/11** or **Windows Server 2019/2022**.
2. **PowerShell 7.x** (Installed Dependency).
3. **NSSM (Non-Sucking Service Manager)**.
4. **Sysinternals Autoruns**.
5. **BurntToast PowerShell Module** (for notifications).

---

## **Usage Instructions**

1. **Initial Setup**:
   - Run `setup_autoruns_service.ps1` with administrator privileges.
   - Follow prompts to configure the VirusTotal API key and install the service.

2. **Start the Service**:
   - Use the GUI or PowerShell commands to start the **WinSP Service**.

3. **Monitor Logs**:
   - Use the **View Logs** GUI to inspect service activity.

4. **Check Threat Reports**:
   - Open `VirusTotalReport.csv` for detailed scan results.

5. **Update Whitelist**:
   - Use the **Whitelist Management** GUI to add trusted files.

6. **Customize Settings**:
   - Adjust scan intervals through the **Settings** menu.

---

## **Maintenance and Troubleshooting**

- **Logs**:
  - Check `winsp_service_log.txt` for detailed activity logs.
- **Service Issues**:
  - Restart the service using the GUI or `Restart-Service` PowerShell cmdlet.
- **API Key**:
  - Update the VirusTotal API key using the GUI or modifying `apikey.txt`.

---

## **Disclaimer**

This tool is currently a working and stable **work-in-progress** tool. 


