---
Title: Security Tools
Type: Doc
Nature: Notes
Création: 15/05/2020
---

# Security Tools
---
**Sommaire**

- **[Security](#Security)**
  - [Hacking OS distro](#Hacking-OS-distro)
  - [SIEM - Log analyzer](#SIEM---Log-analyzer)
  - [Vulnerability Scan](#Vulnerability-Scan)
  - [Pentest](#Pentest)
  - [Forensics](#Forensics)
  - [Hardening](#Hardening)
  - [Detection](#Detection)
  - [Docker security](#Docker-security)
  - [Password](#Password)
  - [Monitoring](#Monitoring)
  - [Encrytion](#Encrytion)
  - [CyberThreat](#CyberThreat)
  - [Others](#Others)
    - [Security Check](#Security Check)
- **[Liens](#Liens)**
---

## Security
### Hacking
- OS distro :
  - [Kali](https://www.kali.org/) : Offensive security
  - [Parrot](https://parrotlinux.org/) : All-in-one framework for Cyber Security, Software Development and Privacy Defense
  - [REMnux Distro](https://remnux.org/docs/distro/tools/) :  Forensics distro
  - [Caine](https://www.caine-live.net/) : Computer Forensics Linux Live Distro
- Vuln box :
  - [Metasploitable](https://github.com/rapid7/metasploitable3) : Vulnerable Linux system
  - [DVWA](http://www.dvwa.co.uk/) : PHP/MySQL vulnerable web application
  - [bWAPP](https://sourceforge.net/projects/bwapp/) : PHP/MySQL vulnerable web application
  - [Mullitidae](https://sourceforge.net/projects/mutillidae/) : PHP/MySQL vulnerable web application
  - [vulnhub](https://www.vulnhub.com/) : Vulnerable test VM
  - [vulnweb](http://www.vulnweb.com/) : Vulnerable test websites (for Acunetix Web Vulnerability Scanner)

### SIEM - Log analyzer
- [Suit Elastic](https://www.elastic.co/fr/) : Opensource, mais certains composants sont payants
- [LogPoint](https://www.logpoint.com/en/) : propriétaire
- [Splunk](https://www.splunk.com/) : propriétaire
- [GrayLog](https://www.graylog.org) : Opens source and Entreprise
- [Apache Log Viewer](https://www.apacheviewer.com/) : With apache logs viewer you can easily filter and analyze Apache/IIS/nginx log files.
- [GoAccess](https://goaccess.io/) : GoAccess is an open source real-time web log analyzer and interactive viewer that runs in a terminal in unix systems or through your browser.

### Vulnerability Scan
- [outpost24 HIAB](https://outpost24.com/) : Pro Full stack security assessment platform and penetration testing
- [Nessus](https://fr.tenable.com/products/nessus) : Pro/Free powerful vulnerability scan and assessment tools
- [OpenVas](https://www.openvas.org/) : Open source full-featured vulnerability scanner
- [UpGuard](https://webscan.upguard.com/) : Online Pro/Free Website Security Scan
- [SiteGuarding](https://www.siteguarding.com/en) : Online Pro/Free Website Security Services (antivirus, scan, ...)
- [Intruder](https://www.intruder.io/) : powerful cloud-based vulnerability scanner to find weaknesses
- [Detectify](https://detectify.com/) : Online - Scan your web apps for 2000+ vulnerabilities and track assets across your tech stack
- [pentest-tools.com](https://pentest-tools.com/home) : Online - Pentest-Tools.com allows you to quickly discover and report vulnerabilities in websites and network infrastructures
- [SearchSploit](https://www.exploit-db.com/searchsploit) : command line search tool for Exploit-DB that also allows you to take a copy of Exploit Database with you, everywhere you go
- [RapidScan](https://github.com/skavngr/rapidscan) : The Multi-Tool Web Vulnerability Scanner
- [Qualys VMDR](https://www.qualys.com/subscriptions/vmdr/) : All-in-One Vulnerability Management, Detection, and Response

### Pentest
- [NMAP | NMAP NSE](https://nmap.org/) : Network exploration tool and security / port scanner
- [Burp suite](https://portswigger.net/) : web security scanner and proxy
- [Nikto](https://cirt.net/nikto2) : Open Source (GPL) web server scanner
- [Vega](https://subgraph.com/vega/) : Open Source web server vulnerability scanner (XSS, SQL injcetion and more)
- [WPScan](https://wpscan.org/) : WordPress Security Scanner
- [typo3scan](https://github.com/whoot/Typo3Scan) : TypO3 Security Scanner
- [SQLmap](http://sqlmap.org/) : Sql injection scanner
- [Metasploit](https://www.metasploit.com/) : Pentest framework
- [HTTrack](https://www.httrack.com/) : HTTrack est un aspirateur de sites web facile d'utilisation et libre (GPL, logiciel libre).
- [wafw00f](https://github.com/enablesecurity/wafw00f/wiki) : WAFW00F can detect a number of Web Application firewalls
- [VScan](https://github.com/xvass/vscan) : vulnerability scanner tool is using nmap and nse scripts to find vulnerabilities
- [Trape](https://github.com/jofpin/trape) : OSINT Tool - People tracker on the Internet: Learn to track the world, to avoid being traced
- [Pentest box](https://pentestbox.org/fr/#features) : Open source Windows pentest framework
- [Havij](https://sourceforge.net/directory/os:windows/?q=+havij) : Advanced SQL injection tool with GUI
- [Fiddler](https://www.telerik.com/fiddler) : The Web Debugging Proxy Tool Loved by Users
- [Hashcat](https://hashcat.net/hashcat/) : Advanced password recovery
- [Impacket](https://www.secureauth.com/labs/open-source-tools/impacket) : Impacket is a collection of Python classes for working with network protocols (SMB, Kerberos,...)
- [mimikatz](https://github.com/gentilkiwi/mimikatz) : mimikatz is a tool that makes some "experiments" with Windows security. It's well-known to extract plaintexts passwords, hash, PIN code and kerberos tickets from memory
- [Ncrack](https://nmap.org/ncrack/) : Ncrack is a high-speed network authentication cracking tool. It was built to help companies secure their networks by proactively testing all their hosts and networking devices for poor passwords
- [LightBulb](https://github.com/lightbulb-framework/lightbulb-framework) : LightBulb is an open source python framework for auditing web application firewalls and filters.
- [Zenscrape](https://zenscrape.com/) : A Simple Web Scraping Solution for Penetration Testers

### Social Ingeneering
- [Shellphis](https://github.com/thelinuxchoice/shellphish) : Phishing Tool for Instagram, Facebook, Twitter, Snapchat, Github, Yahoo, Protonmail ...

### Forensics
- [Volatility](https://www.volatilityfoundation.org/) : Extraction of digital artifacts from volatile memory (RAM) samples framework
- [peepdf](https://github.com/jesparza/peepdf) : Python tool to explore PDF files in order to find out if the file can be harmful or not
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [PDF Examiner](https://www.pdfexaminer.com/) : Online PDF Examiner
- [GRR](https://grr-doc.readthedocs.io/en/latest/) : Rapid Response is an incident response framework focused on remote live forensics
- [Windows Sysinternals Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/) : Windows forensics Small Utilities
- [The Sleuth Kit®](https://www.sleuthkit.org/sleuthkit/) :  Collection of command line tools and a C library that allows you to analyze disk images and recover files from them
- [Autopsy](https://www.sleuthkit.org/autopsy/) :  GUI-based program that allows you to efficiently analyze hard drives and smart phones.
- [Online EMailTracer](http://www.cyberforensics.in/OnlineEmailTracer/index.aspx) : tool to track email sender’s identity.
- [MX Toolbox](https://mxtoolbox.com/) : list MX records for a domain in priority order
- [MailXaminer](https://www.mailxaminer.com/) : SysTools Email Examiner Software to Analyze Emails for Investigators with Speed, Accuracy & Ease
- [Free OST Viewer Tool](https://datahelp.in/ost/viewer.html) : Open Offline Outlook Data File Free of Cost & Without Exchange Server Environment
- [MISP](https://www.misp-project.org/tools/) : Malwares sharing plateforme
- [TheHive](https://thehive-project.org/) : Open Source and Free Security Incident Response Platform (can be integrated with MISP)
- [Cortex](https://github.com/TheHive-Project/CortexDocs) : Powerful Observable Analysis and Active Response Engine (from thehive-project.org )
- [Snadfly Security](https://www.sandflysecurity.com/) : Sandfly is an agentless compromise and intrusion detection system for Linux (with UI). It automates security investigation and forensic evidence collection on Linux.
- [DFIR ORC](https://dfir-orc.github.io/) : ANSSI DFIR ORC “Outil de Recherche de Compromission” is a modular and scalable tool to collect artefacts on Microsoft Windows systems, in a decentralized manner.
- [Polichombr](https://github.com/ANSSI-FR/polichombr) : This ANSSI FR's tool aim to provide a collaborative malware analysis framework.
- [Velociraptor](https://github.com/Velocidex/velociraptor) : Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries
- [EventID](http://eventid.net/) : Online  windows events Searcher
- [Browser History Capturer](https://www.foxtonforensics.com/browser-history-capturer/) : BHC is free forensic tool to capture web browser history.
- [ADS Spy](https://www.bleepingcomputer.com/download/ads-spy/) : Ads Spy is a tool that can be used to search for and remove Alternate Data Streams (ADS) from NTFS file systems (like backdoors)
- [Encase](https://www.guidancesoftware.com/encase-forensic) : The Gold Standard in Forensic Investigations – including Mobile Acquisition
- [NirSoft utilities](https://www.nirsoft.net/) : NirSoft web site provides a unique collection of small and useful freeware utilities for forensic
- [Forensic Toolkit (FTK)](https://accessdata.com/products-services/forensic-toolkit-ftk) : Digital Investigations Toolkit
- [Mft2Csv](https://github.com/jschicht/Mft2Csv/wiki/Mft2Csv) : This tool is for parsing, decoding and logging information from the Master File Table ($MFT) to a csv
- [ExifTool](https://exiftool.org/) : ExifTool is a platform-independent Perl library plus a command-line application for reading, writing and editing meta information in a wide variety of files.
- [IOC Editor](https://www.fireeye.com/services/freeware/ioc-editor.html#dismiss-lightbox) : Free tool that provides an interface for managing data and manipulating the logical structures of IOCs.
- [Microsoft Project Freta](https://docs.microsoft.com/fr-fr/security/research/project-freta/) : Microsoft Project Freta is a free, cloud-based offering from the New Security Ventures (NSV) team at Microsoft Research that provides automated full-system volatile memory inspection of Linux systems.
- [Rshipp Awesome malware analysis](https://github.com/rshipp/awesome-malware-analysis) : Collection of malwares analysis and détection tools
- [Pestudio](https://www.winitor.com/) : The goal of pestudio is to spot suspicious artifacts within executable files in order to ease and accelerate Malware Initial Assessment.
- [ProcDot](https://www.procdot.com/) : It processes Sysinternals Process Monitor (procmon) logfiles and PCAP logs (Windump, tcpdump) to generate a graph via the GraphViz suite
- [FakeDNS](https://github.com/Crypt0s/FakeDns) : Fake DNS Server for intercepting requests
- [INetSim](https://www.inetsim.org/) : INetSim is a software suite for simulating common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples
- [RegistryChangesView](https://www.nirsoft.net/utils/registry_changes_view.html) :  NirSoft's tool that allows you to take a snapshot of Windows Registry and later compare it with another Registry snapshots
- [Oledump](https://blog.didierstevens.com/programs/oledump-py/) : Didier Stevens Suite that parse and anlyse OLE (.doc, .xls, .ppt, ...) files
- [pdf-parser](https://github.com/DidierStevens/DidierStevensSuite) : Didier Stevens Suite that parse and anlyse pdf file


### Hardening
- [SElinux](https://doc.fedora-fr.org/wiki/SELinux), [ApparMor](https://doc.ubuntu-fr.org/apparmor) : renforcement permissions Linux
- [AIDE](https://aide.github.io/) : audit d'intégrité de fichiers
- [Lynis](https://cisofy.com/lynis/) : audit de configuration et de conformité d'un système
- [Falco](https://falco.org/) : Cloud-Native runtime security (Audit de sécurité docker, kubernetes, OS)
- [OpenSCAP Tools](https://www.open-scap.org/tools/) : suite d'outils de scan et d'évaluation de conformité (OS, docker)
- [checksec](https://github.com/slimm609/checksec.sh),
- [winchecksec](https://github.com/trailofbits/winchecksec) et [otool]() : Vérificateurs de la présence de drapeaux de sécurité sur un logiciel
- [SSLtest](https://www.ssllabs.com/ssltest/) : SSL verificator
- [GreekFlare Tools](https://gf.dev/toolbox) : set of tools for security or dns checking
- [RKhunter](http://rkhunter.sourceforge.net/) : Rootkit Hunter is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [Chkrootkit](http://www.chkrootkit.org/) : Check Rootkit is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [BotHunter]()
- [arpwatch](https://linux.die.net/man/8/arpwatch) : ARP monitoring software
- [Tripwire FIM](https://www.tripwire.com/solutions/file-integrity-and-change-monitoring) : File Integrity Monitoring & Change Management
- [CheckPoint CheckMe](http://www.cpcheckme.com/checkme/#) : CheckMe runs a serie of simulations that test if your existing security technologies can block standard and advanced attacks
- [Microsoft Security Compliance Toolkit (SCT)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10) : The Security Compliance Toolkit (SCT) is a set of tools that allows enterprise security administrators to download, analyze, test, edit, and store Microsoft-recommended security configuration baselines for Windows and other Microsoft products
- [Microsoft WAF Bench (WB) Tool Suits](https://github.com/microsoft/wafbench) : WAF (Web Application Firewall) Bench tool suits is designed to verify the correctness and measure the performance of WAF.
- [WAF Testing Framework](https://www.imperva.com/lg/lgw_trial.asp?pid=483) : A WAF testing tool by Imperva.
- [owasp-crs-regressions](https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/v3.1/dev/util/regression-tests) : the OWASP Core Rule Set regression testing suite. This suite is meant to test specific rules in OWASP CRS version 3
- [BMC-Tools](https://github.com/ANSSI-FR/bmc-tools) : ANSSI FR's RDP Bitmap Cache parser.

### Detection
- [Yara](https://virustotal.github.io/yara/) : Identification et détection des IOC des malwares
- [Clamav](https://www.clamav.net/) : Antivirus opensource
- [Blazescan](https://github.com/Hestat/blazescan) : Blazescan is a linux webserver malware scanning and incident response tool
- [Linux Malware Detect](https://github.com/rfxn/linux-malware-detect) : Linux Malware Detect (LMD) is a malware scanner for Linux released
- [VirusTotal](https://virustotal.com) : Multi scan virus analysis
- [MetaDefender](https://metadefender.opswat.com/) : Multi scan virus analysis like VirusTotal
- [Cuckoo Sandbox](https://cuckoosandbox.org/) : Cuckoo Sandbox is free software that automated the task of analyzing any malicious file under Windows, macOS, Linux, and Android.
- [Cuckoo CERT](https://cuckoo.cert.ee/) : Online Sandbox for malwares IoC analysis
- [Any Run](https://any.run/) : Malware hunting with live access to the heart of an incident
- [Inquest Labs](https://labs.inquest.net/) : The InQuest platform provides high-throughput Deep File Inspection (DFI) for threat and data leakage prevention, detection, and hunting.
- [Rshipp Awesome malware analysis](https://github.com/rshipp/awesome-malware-analysis) : Collection of malwares analysis and détection tools
- [Infosec CERT-PA Analyzer](https://infosec.cert-pa.it/analyze/search.html)
- [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) : détection d'intrusion et blocage d'IP malveillantes
- [Snort](https://www.snort.org/) : open source intrusion prevention system
- [ModSecurity](https://modsecurity.org/) : Open source Web Application Firewall (WAF)
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [Snadfly Security](https://www.sandflysecurity.com/pricing/) : Sandfly is an agentless compromise and intrusion detection system for Linux (with UI). It automates security investigation and forensic evidence collection on Linux.
- [Phishtank](https://www.phishtank.com/) : Online phising detector
- [ISIT Phising](https://www.isitphishing.ai/) : VadeSecure Online phising detector
- [Spamhaus](https://www.spamhaus.org/lookup/) : This lookup tool checks to see if the IP Address you enter is currently listed in the live Spamhaus IP blocklists: SBL, XBL and PBL
- [AbuseIpDB](https://www.abuseipdb.com/) : making the internet safer, one IP at a time
- [Bulkcheck](https://github.com/AdmiralSYN-ACKbar/bulkcheck) : This is a Bash Script (with GUI) for running bulk checks of IP addresses against `AbuseIpDB`
- [Security Task Manager](https://www.neuber.com/taskmanager/francais/index.html?ref=fichier.net) : Security Task Manager detects viruses and Trojans that may be similar to Windows processes
- [immuniweb](https://www.immuniweb.com/free/) : Set of Free Security Tests
for Web, Mobile and Domain Security
- [BloodHound](https://bloodhound.readthedocs.io/en/latest/index.html) : BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory environment
- [Hybrid analysis](https://www.hybrid-analysis.com/) : This is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology
- [joesandbox](https://www.joesandbox.com/) : (Online) Joe Sandbox detects and analyzes potential malicious files and URLs on Windows, Android, Mac OS, Linux, and iOS for suspicious activities
- [FEODO Tracker](https://feodotracker.abuse.ch/) : Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with the Feodo malware family (Dridex, Emotet/Heodo).
- [#TotalHash](https://totalhash.cymru.com/) : #totalhash provides static and dynamic analysis of Malware samples.
- [URLVoid](https://www.urlvoid.com/) : Website Reputation Checker (This service helps you detect potentially malicious websites)
- [Packet Total](https://packettotal.com/) : PacketTotal is an engine for analyzing, categorizing, and sharing .pcap files.
- [URLhaus](https://urlhaus.abuse.ch/) : URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.


### Docker security
- [Dagda](https://github.com/eliasgranderubio/dagda) : Scan de vulnérabilités docker
- [Atomic](http://www.projectatomic.io/) : Hôte pour les conteneurs mais aussi outil de scan
- [Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md) : docker Vulnerability scanner
- [Harbor](https://goharbor.io/) : registry  et scanneur de vulnérabilités docker et kubernetes
- [Portus](http://port.us.org/features/6_security_scanning.html) : scanneur de vulnérabilités docker
- [Anchore](https://anchore.com/) : scanneur de vulnérabilités docker (Entreprise/Opensource)

### Password
- [Keepass](https://keepass.info/) : Free, open source, light-weight and easy-to-use password manager
- [Dashlane password-generator](https://www.dashlane.com/fr/features/password-generator) : générateur de mot de passe online
- [password strength test](https://www.my1login.com/resources/password-strength-test/) : Online password checker
- [1password password-generator](https://1password.com/fr/password-generator/) : générateur de mot de passe online
- [haveibeenpwned](https://haveibeenpwned.com/) : vérificateur de mot de passe ou email compromis online
- [DNS Checker](https://dnschecker.org/all-tools.php) : These tools help people with interest in DNS Lookups, IP Whois, Domain Whois, and Network tools to do various lookups related to internet and websites.
- [pass](https://www.passwordstore.org/) : the standard unix password manager
- [John the Ripper](https://www.openwall.com/john/) : fast password cracker
- [Medusa](http://foofus.net/goons/jmk/medusa/medusa.html) : speedy, massively parallel, modular, login brute-forcer
- [Patator](https://github.com/lanjelot/patator) : Patator was written out of frustration from using Hydra, Medusa, Ncrack, Metasploit modules and Nmap NSE scripts for password guessing attacks
- [fcrackzip](https://github.com/hyc/fcrackzip) : fcrackzip is a zip password cracker

### Monitoring
- [CheckMK](https://checkmk.com/) : infrastructure & application monitoring
- [Shinken](http://www.shinken-monitoring.org/) : open source monitoring framework written in Python
- [GLPI](https://glpi-project.org/fr/) : GLPI est un outil ITSM , puissant et tout intégré pour la gestion de votre parc et de votre centre de services
- [Apps tracker](https://sourceforge.net/projects/appstracker/) : Computer monitoring & time tracking app
- [Watchman](https://facebook.github.io/watchman/) : Watchman exists to watch files and record when they change.

### Encrytion
- [sks-keyserver](https://github.com/SKS-Keyserver/sks-keyserver) : GnuGPG infrastructure keys

### CyberThreat
- [Kaspersky Cyber Threat Map](https://cybermap.kaspersky.com/stats) : Online CYBERTHREAT REAL-TIME MAP
- [FireEye Cyber Threat Map](https://www.fireeye.com/cyber-map/threat-map.html) : FireEye Online Cyber Threat Map
- [Bitdefender Cyber Threat Map](https://threatmap.bitdefender.com/) : Bitdefender Online CYBERTHREAT REAL-TIME MAP
- [Threatbutt Attack Map](https://threatbutt.com/map/) : Threatbutt Internet Hacking Attack Attribution Map


## Others
- [sha512.fr](https://www.sha512.fr/) : codage sha512, bcrypt, ... online
- [Wappalyzer](https://www.wappalyzer.com/) : Identify technology on websites (Browser extension)
- [FoxyProxy](https://getfoxyproxy.org/) : Proxy switcher (Browsers extension)
- [hstspreload.org](https://hstspreload.org/) : Check HTST preload status and eligibilty
- [Phising IQ Test](https://phishing-iq-test.com/) : Interactive Phising Game
- [KeePassHttp-Connector](https://addons.mozilla.org/fr/firefox/addon/keepasshttp-connector/) : It provides secure access to your credentials stored in KeePass over HTTP
- [RemoteProcess](https://www.fichier.net/freeware/remoteprocess.html) : Remote process Visualization
- [CVE Mitre](http://cve.mitre.org/cve/search_cve_list.html) : Search CVE List
- [hackertarget HTTP Header Check](https://hackertarget.com/http-header-check/) : Review the HTTP Headers from a web server with this quick check. Also, contents many other network and scan tools
### Security Check
- [EmoCheck](https://github.com/JPCERTCC/EmoCheck) : Emotet detection tool for Windows OS.
- [ZeroLogon testing script](https://github.com/SecuraBV/CVE-2020-1472) : A Python script that uses the Impacket library to test vulnerability for the Zerologon exploit (CVE-2020-1472)


## Liens
- [Top 125 Security Tools | sectools.org](https://sectools.org/)
- [Penetration Testing Tools | Kali Linux Tools Listing](https://tools.kali.org/tools-listing)
- [Parot Linux tools list](https://github.com/ParrotSec/parrot-tools/blob/master/debian/control)
- [Rshipp Github | awesome malware analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Vulnerability Scanning Tools | OWASP](https://owasp.org/www-community/Vulnerability_Scanning_Tools )
- [Source Code Analysis Tools | OWASP](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [REMnux Distro » Forensics Tools](https://remnux.org/docs/distro/tools/)
- [29 Docker security tools compared. | Sysdig](https://sysdig.com/blog/20-docker-security-tools/ )
- [Top 15 Paid and Free Vulnerability Scanner Tools](https://www.dnsstuff.com/network-vulnerability-scanner)
- [11 Online scan website security vulnerabilities](https://geekflare.com/online-scan-website-security-vulnerabilities/)
- [Important Tools and Resources For Security Researcher, Malware Analyst](https://gbhackers.com/most-important-tools/)
- [100 Best Hacking Tools for Security Professionals in 2020](https://gbhackers.com/hacking-tools-list/ )
- [Free Open Source Windows Security Software](https://sourceforge.net/directory/security-utilities/security/os:windows/)
- [6 best FIM Softwares](https://www.dnsstuff.com/file-integrity-monitoring-software)
- [30 Online Malware Analysis Sandboxes](https://medium.com/@su13ym4n/15-online-sandboxes-for-malware-analysis-f8885ecb8a35)
- [ANSSI FR tools](https://github.com/ANSSI-FR)
- [Forensics courses by Udemy](https://www.udemy.com/topic/computer-forensics/)
- [Penetration Testing, Incident Response and Forensics | Coursera](https://www.coursera.org/learn/ibm-penetration-testing-incident-response-forensics)
- [Kali training](https://kali.training/)
