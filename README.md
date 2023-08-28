# awesome-soc-analyst

We just collected useful resources for SOC analysts and SOC analyst candidates. 

This repository is maintained by [**LetsDefend**](https://letsdefend.io/). Feel free to add new resources here.


Table of Contents
=================

  * [Books](#books)
  * [Malware Analysis](#malware-analysis)
  * [Practice Labs](#practice-labs)
  * [Phishing Analysis](#phishing-analysis)
  * [Tools for Investigation](#tools-for-investigation)
  * [Network Log Sources](#network-log-sources)
     * [Network Devices Logs](#network-devices-logs)
     * [Linux Firewall Logs](#linux-firewall-logs)
     * [SMB Logs](#smb-logs)
     * [Windows Firewall Logs](#windows-firewall-logs)
  * [Network Security Devices Logs](#network-security-devices-logs)
     * [IDS/IPS Logs](#idsips-logs)
     * [Network Firewall Logs](#network-firewall-logs)
     * [Web Application Firewall (WAF) Logs](#web-application-firewall-waf-logs)
  * [Web Server Logs](#web-server-logs)
     * [Apache Logs](#apache-logs)
     * [IIS Logs](#iis-logs)
     * [Nginx Logs](#nginx-logs)
  * [Forensics Artifacts](#forensics-artifacts)
     * [Browser History and Cache](#browser-history-and-cache)
     * [DNS Cache/History](#dns-cachehistory)
     * [Hosts File](#hosts-file)
     * [Remote Desktop Protocol (RDP) Cache/History/Logs](#remote-desktop-protocol-rdp-cachehistorylogs)
  * [Important Windows Logs for Investigation](#important-windows-logs-for-investigation)
     * [DLP Logs](#dlp-data-loss-prevention-logs)
     * [Endpoint Security Solutions Logs](#endpoint-security-solutions-logs)
     * [Event Logs](#event-logs)
     * [File Integrity Monitoring Logs](#file-integrity-monitoring-fim-logs)
     * [Event Logs](#event-logs)
     * [Honeypot Logs](#honeypot-logs)
     * [MSSQL Logs](#mssql-logs)
     * [Powershell Logs](#powershell-logs)
     * [Task Scheduler Logs](#task-scheduler-logs)
     * [Windows Defender](#windows-defender)
     * [WMI Logs](#wmi-logs)
   * [Linux System Logs](#linux-system-logs)
     * [Auth Log](#auth-log)
     * [Kernel Log](#kernel-log)
     * [Syslog](#syslog)


## Books

- Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software
- Blue Team Field Manual (BTFM)
- Applied Network Security Monitoring: Collection, Detection, and Analysis
- Blue Team Handbook: Incident Response Edition: A condensed field guide for the Cyber Security Incident Responder
- The Practice of Network Security Monitoring: Understanding Incident Detection and Response
- Jump-start Your SOC Analyst Career: A Roadmap to Cybersecurity Success


## Malware Analysis
- [**VirusTotal**](https://virustotal.com) - Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.
- [**Hybrid Analysis**](https://www.hybrid-analysis.com/) - This is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology.
- [**YARA**](https://virustotal.github.io/yara/) - YARA is a multi-platform program running on Windows, Linux and Mac OS X.
- [**Malware Analysis Fundamentals**](https://app.letsdefend.io/training/lessons/malware-analysis-fundamentals)
- [**Cuckoo Sandbox**](https://cuckoosandbox.org/) - You can throw any suspicious file at it and in a matter of minutes Cuckoo will provide a detailed report outlining the behavior of the file when executed inside a realistic but isolated environment.
- [**IDA**](https://hex-rays.com/ida-pro/) - IDA Pro as a disassembler is capable of creating maps of their execution to show the binary instructions that are actually executed by the processor in a symbolic representation.
- [**DOCGuard**](https://www.docguard.io/) - Zero Miss for Office Malware Threats
- [**Immunity Debugger**](https://www.immunityinc.com/products/debugger/) - Immunity Debugger is a dynamic analysis tool that allows executables to be analyzed at the assembly language level with reverse engineering techniques.

## Practice Labs
- [**DetectionLab**](https://detectionlab.network/) - DetectionLab is a repository containing a variety of Packer, Vagrant, Powershell, Ansible, and Terraform scripts that allow you to automate the process of bringing an ActiveDirectory environment online complete with logging and security tooling using a variety of different platforms.
- [**LetsDefend**](https://letsdefend.io/) - Hands-on SOC Analyst training
- [**attack_range**](https://github.com/splunk/attack_range) - The Splunk Attack Range is an open-source project maintained by the Splunk Threat Research Team. It builds instrumented cloud and local environments, simulates attacks, and forwards the data into a Splunk instance.
- [**BlueTeam.Lab**](https://github.com/op7ic/BlueTeam.Lab) - The goal of this project is to provide the red and blue teams with the ability to deploy an ad-hoc detection lab to test various attacks and forensic artifacts on the latest Windows environment and then to get a 'SOC-like' view into generated data.

## Phishing Analysis
- [**MxToolbox**](https://mxtoolbox.com/) - It will list MX records for a domain in priority order.
- [**Phishing email analysis course - FREE** ](https://app.letsdefend.io/training/lessons/phishing-email-analysis) - Learn how to analysis of the most common attack vector in the cyber security industry.

## Tools for Investigation
- [**Process Hacker**](https://processhacker.sourceforge.io/) - Great tool for monitoring the system and detecting suspicious situations. It’s also free.
- [**Procmon**](https://learn.microsoft.com/tr-tr/sysinternals/downloads/procmon) - Procmon(Process Monitor) tool is a useful tool that provides real-time information by monitoring the activities of processes on Windows.
- [**Volatility**](https://www.volatilityfoundation.org/) - Volatility is a tool that enables the analysis of memory dumps taken from a compromised machine during the incident response process.
- [**Wireshark**](https://www.wireshark.org/ ) - Wireshark is a tool that allows capturing, analyzing, and recording network packets passing through network interfaces on the system.
- [**BrowsingHistoryView**](https://www.nirsoft.net/utils/browsing_history_view.html) - It gives you the history of different browsers in one table.

## Network Log Sources
### Network Devices Logs
Network devices can sometimes be targeted by attackers because network devices such as routers and switches are capable of packet routing. If the attacker interferes with the management of such a device and changes the existing lists, it may change the course and effect of the attack. It is useful to check the lists of network devices regularly to detect these situations. In addition, if there are logs produced by the device, such records should also be examined.

### Linux Firewall Logs
UFW (Uncomplicated Firewall) is a firewall tool that allows us to perform port and firewall operations on both the console and GUI (graphical interface). It comes installed in Linux systems but must be activated. It performs operations just like other firewall software. When analyzing Linux systems, Linux firewall logs should be examined.

### SMB Logs
Server Message Block (SMB) is a network protocol that enables the communication between server and client. The SMB protocol provides access to shared files, network communication, printer sharing, and various connections. SMB connections are frequently used on Windows systems. Its importance is noticed especially in domain environments. The SMB protocol, which is seen as an important source of vulnerability for attackers, needs to be followed carefully by the analyst on the defense side. Therefore, SMB protocol logs should be examined with high priority.

### Windows Firewall Logs
Windows Firewall is a Microsoft-developed firewall software that comes installed with the operating system. Windows firewalls can configure incoming and outgoing traffic. This configuration is provided by rules. Windows firewall logs are one of the resources that can be examined by the network.

## Network Security Devices Logs
### IDS/IPS Logs
Intrusion detection and prevention (IDS/IPS) devices placed inside the organization or on the external interface of the organization record information about the violations they encounter. Examination of these logs by the analyst may reveal the type of attack and some network movements related to the attack.

### Network Firewall Logs
Hardware firewall devices are where the attacks to the institution are first met and the packages are filtered according to certain rules. They can be used in the external side of the organization or to perform certain network segmentation within the organization and to ensure its security. In both cases, it may be possible to detect the network movements of the attacker in the logs of these devices. It is one of the points that must be examined.

### Web Application Firewall (WAF) Logs
It is the firewall installed on the web side that corresponds to the threats that may occur in the application layer. Important records can be obtained in this section in response to application-level attack violations.

## Web Server Logs
### Apache Logs
Apache is an open-source web server software that is free to access. It is widely used in the IT industry. It can be preferable because it works on both Unix and Windows servers. Apache web server software records the access logs of the requests received. It also keeps error logs. These logs must be examined in order to see external threats to the web server.

### IIS Logs
IIS (Internet Information Services) is a web server developed by Microsoft and embellished in Windows systems. It was founded and used by Microsoft ages ago. Considering its use in the IT sector, it can be said that it is quite frequently used. In order to see the attacks and violations attempted to the IIS web server, logs of the IIS must be examined.

### Nginx Logs
Nginx is a web server software with much higher performance,it is faster and requires less resource consumption than its competitors. Due to its preference and widespread use, many attacks can be developed against this web server. In order to view and analyze these attacks, the web server logs should be handled and examined just like we do with the Apache and IIS web server.

## Forensics Artifacts
### Browser History and Cache
A browser is a software in which web pages can be viewed. Since it can be used by the attacker in a seized system, the parts that may be important such as the addresses connected to the scanner during the analysis phase should be examined as they may contain a trace of the attacker.

### DNS Cache/History
DNS Cache is the section where DNS analyses queried in the system are recorded. It could help us locate the command and control center the attacker was using. It must be checked as it may contain important information about the attack.

### Hosts File
The hosts file is one of the first places where we start a DNS analysis to find an IP address before referring to the DNS server. In a seized system, a new record may have been added to this file by the attacker. It is one of the files that should be checked during the forensic analysis phase as it may contain the domain name or command control server IP address of the attacker.

### Remote Desktop Protocol (RDP) Cache/History/Logs
The RDP protocol is a protocol that enables remote connection to the target system. In the analyzed system, information about systems with an RDP connection is saved in the RDP cache. If the attacker has made an RDP connection, IP address information of the attacker can be obtained in the cache. It is one of the points that should be examined while analyzing a system.

## Important Windows Logs for Investigation
### Application Logs
Applications installed on the Windows operating system may have their own special logs and these logs are the source that should be examined by the analyst regarding that application.

### DLP (Data Loss Prevention) Logs
DLP software is security software installed in the system to prevent data leakage. This software can keep logs on the transactions it performs, and these logs are one of the points that the analyst should examine in order to detect violations.

### Endpoint Security Solutions Logs
Endpoint security solutions are security software aimed at ensuring the security installed on end-user devices and reducing data breaches. This software can create important and comprehensive logs in case of violation. In order to understand whether the violation has occurred and to see the details, the analyst should examine these logs.

### Event Logs
Event logs are a comprehensive resource that collects logs from many points of the system that are included in the Windows operating system. These logs include a wide variety of log types. This is the most important log source that the security analyst should examine.

### File Integrity Monitoring (FIM) Logs
File integrity monitoring software is the security software that follows the changes and accesses of the files in the system. In order to obtain information about which files have been changed in case of an attack violation, the analyst must examine the logs of these software.

### Honeypot Logs
Honeypot systems are trap systems that are a copy of real systems specially installed for the attacker. Since the attack methods on Honeypot systems may be an attack vector that the attacker can use against the real system, the logs obtained through these systems enable measures to be taken against significant attacks. Therefore, these logs may contain critical information.

### MSSQL Logs
MSSQL is Microsoft’s relational database management system. It is often used as a database. It is important to review the logs of the MSSQL database to view unauthorized access to the MSSQL database or to view error messages.

### Powershell Logs
PowerShell is an inter-platform task automation solution consisting of a command line shell, a script language, and a configuration management framework. PowerShell runs on Windows, Linux, and macos. It is often preferred by attackers because attacks can be more effective when performed with powershell. Powershell’s logs must be examined in order to detect the harmful commands run in the system and to reveal the attack.

### Task Scheduler Logs
Scheduled tasks are used in windows to perform certain operations at certain times. The intruder infiltrating the system can use this to ensure persistence. The analyst can examine logs of scheduled tasks while securing the system and detecting attacks.

### Windows Defender
Windows defender is the most basic structure that is responsible for protecting the system that comes with the Windows operating system against attackers and malware. Logs related to the scans or findings of Windows defender may contain some important details. Therefore, examining the logs in this section can provide new information related to the attack details.

### WMI Logs
WMI (Windows Management Instrumentation) is a technology that enables almost every object to be controlled in Windows operating systems and can perform operations and management functions in the operating system. The operations that can be performed with WMI commands on the system are numerous and if the attacker has run WMI commands in the system, the logs of WMI must be examined and evaluated.

## Linux System Logs
### Auth Log
The log file in which successful or unsuccessful login and authentication processes are recorded is called auth log. The auth log file, where attack attempts against important accounts can be seen, has an important place in the examination of Linux systems.

### Kernel Log
This is the file where warning, information and error records of the Kernel are kept. It is usually examined in kernel-related error situations.

### Syslog
In Linux systems, the log source that shows general information and messages about the system is called syslog. It is one of the first points in the study of Linux systems.
