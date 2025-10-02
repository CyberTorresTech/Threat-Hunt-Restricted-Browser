# Official [Andres Home Lab]() Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/CyberTorresTech/Threat-Hunt-Restricted-Browser/blob/main/Scenario%20Break%20Down)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for any file that has the string "tor". Right away, I noticed a device called "edr-andres" with numerous detected "tor" strings. Updating the table with DeviceName "edr-andres" along with any file that contains "tor," we are presented with a downloaded TOR installer and multiple TOR-related files copied to the desktop, with one in particular being called "tor-shopping-list.txt". With these detected files, we are given a timestamp of when these events occurred, which gives us a TimeStamp reference to add into our query table. Event began at: 2025-09-30T17:29:29.5168439Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "edr-andres"
| where InitiatingProcessAccountName == "irlab14#"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-30T17:16:50.6304292Z) and Timestamp <= datetime(2025-09-30T17:29:40.5168439Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1130" height="616" alt="image" src="https://github.com/user-attachments/assets/d52e7d08-ec6f-4821-9bc6-aa2d38496d78" />






---

### 2. Searched the `DeviceProcessEvents` Table

To investigate any executed processes, I searched within the DeviceProcessEvents table with an added ProcessCommandLine query of the suspicious "tor-browser-windows-x86" file discovered earlier in FileEvents. I am presented with a process creation event via the ProcessCommandLine of a silent install listed as "tor-browser-windows-x86_64-portable-14.5.7.exe /S"

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "edr-andres"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1063" height="615" alt="image" src="https://github.com/user-attachments/assets/f7727df5-2ab1-4b76-9c21-554c1de5245a" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

I then searched to see if the "irlab14#" user did in fact run the TOR browser that was downloaded. Again, I looked within DeviceProcessEvents with key FileName strings such as "tor.exe", "firefox.exe", and "tor-browser.exe". Investigating the ProcessCreated metadata of firefox.exe, I noticed the FolderPath leading to the execution of the TOR browser (aka firefox.exe) initiating from:
C:\Users\IRLab14#\Desktop\Tor Browser\Browser\firefox.exe

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "edr-andres"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1063" height="597" alt="image" src="https://github.com/user-attachments/assets/fa07bb71-7b72-48b5-93d1-ee6a39c41b7c" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I next investigated successful connectivity over the TOR network within DeviceNetworkEvents initiated by DeviceName "edr-andres". I narrowed down my results by referencing TOR’s network ports for connectivity and included those ports in my query with "Successful connection" as the ActionType. It’s important that I included InitiatingProcessFolderPath to see exactly where the network connectivity was initiated from on a file level.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "edr-andres"
| where RemotePort in ("9150", "9151", "9050", "9051", "9001", "9030", "8080")
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1045" height="547" alt="image" src="https://github.com/user-attachments/assets/5cebe005-3357-477e-b00b-efcf3e585de0" />


---

## Chronological Event Timeline 

### 1. Download and File Creation Events

- **Timestamp:** `2025-09-30T17:29:29Z – 17:51Z`
- **Event:** The user "irlab14#" downloaded a file named `tor-shopping-list.txt` & `tor.exe` to the Desktop folder.
- **Action:** File creation detected.
- **File Path:** `C:\Users\IRLab14#\Desktop\Tor Browser\`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-09-30T18:36 PM UTC`
- **Event:** The user "irlab14#" executed the file `tor-browser-windows-x86_64-portable-14.5.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.7.exe /S`
- **File Path:** `C:\Users\IRLab14#\Downloads\tor-browser-windows-x86_64-portable-14.5.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-09-30T19:26 PM UTC`
- **Event:** User "irlab14#" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\IRLab14#\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-09-30T19:29 PM UTC`
- **Event:** User "irlab14#" establishes successful network connections through Tor-related ports of 127.0.0.1:9151 & Outbound connections to a remote IP 68.67.32.3:9001
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Ssers\Irlab14#\Desktop\Tor Browser\Browser\Torbrowser\Tor\tor.exe`


---

## Summary

This threat hunt identified a full chain of Tor Browser activity on the endpoint “edr-andres” for user “irlab14” on September 30, 2025. The chain began with the presence and creation of multiple Tor artifacts and installer files on the desktop. Shortly after, the Tor Browser was silently installed and launched, spawning several “firefox.exe” processes and the background “tor.exe” process tied directly to the Tor Browser directory. Evidence confirms not just installation and execution, but also successful network communication out to the Tor network, with traffic seen flowing through the expected Tor proxy ports and relays. All actions are tightly correlated in time and sequence, constituting a clear and validated instance of Tor Browser usage from download through network activity.

---

## Response Taken

TOR usage was confirmed on endpoint edr-andres. The device was isolated and the user's direct manager was notified.

---
