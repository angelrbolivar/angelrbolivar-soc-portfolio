# SOC Tier 1 – Useful SPL Searches (BOTSv3)

### 1. Failed Logons (Windows)
index=botsv3 sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, src_ip, dest
| sort -count


### 2. Successful Logons after Failed Attempts
index=botsv3 sourcetype=WinEventLog:Security (EventCode=4625 OR EventCode=4624)
| transaction Account_Name maxspan=10m
| where eventcount > 3 AND searchmatch("EventCode=4624")


### 3. Suspicious PowerShell / Command Execution
index=botsv3 (sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational)
(EventCode=4688 OR EventCode=1)
| search CommandLine="powershell" OR CommandLine="cmd.exe" OR CommandLine="-enc" OR CommandLine="Invoke-"
| table _time, host, User, CommandLine


### 4. Lateral Movement (SMB / RDP)
index=botsv3 (EventCode=4624 Logon_Type=3 OR EventCode=4624 Logon_Type=10)
| stats count by Account_Name, src_ip, dest_ip, Logon_Type
| sort -count


### 5. New Process Creation (Sysmon)
index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| table _time, host, User, Image, CommandLine, ParentImage
| sort -_time


### 6. DNS Queries to Suspicious Domains
index=botsv3 sourcetype=stream:dns
| stats count by query, src_ip
| sort -count


### 7. Network Connections (Sysmon)
index=botsv3 sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3
| table _time, host, User, Image, DestinationIp, DestinationPort

### 8. Cleartext Credentials / Passwords in Logs
index=botsv3 ("password" OR "passwd" OR "pwd" OR "credential")
| table _time, host, sourcetype, _raw
text


### 9. Timeline of a Specific Host
index=botsv3 host="HOSTNAME" earliest=-1d
| sort _time
| table _time, sourcetype, EventCode, User, _raw


### 10. Top Source IPs with Multiple Failed Logons
index=botsv3 EventCode=4625
| stats count by src_ip
| where count > 10
| sort -count
