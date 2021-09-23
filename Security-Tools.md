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
  - [Forensics and incident response](#Forensics-and-incident-response)
  - [Hardening](#Hardening)
  - [Detection](#Detection)
  - [Docker security](#Docker-security)
  - [Password](#Password)
  - [Monitoring](#Monitoring)
  - [Encrytion](#Encrytion)
  - [CyberThreat](#CyberThreat)
  - [Others](#Others)
    - [Security Check](#Security Check)
    - [Social Ingeneering](#Social-Ingeneering)
    - [Data Leak Checker And OSINT Tool](#Data-Leak-Checker-And-OSINT-Tool)
    - [Anonymity and privacy](#Anonymity-and-privacy)
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
  - [vulnarable-AD](https://github.com/WazeHell/vulnerable-AD) : Create a vulnerable active directory that's allowing you to test most of active directory attacks in local lab

### SIEM - Log analyzer
- [Suit Elastic](https://www.elastic.co/fr/) : Opensource, mais certains composants sont payants
- [LogPoint](https://www.logpoint.com/en/) : propriétaire
- [Splunk](https://www.splunk.com/) : propriétaire
- [GrayLog](https://www.graylog.org) : Opens source and Entreprise
- [Security Onion](https://securityonionsolutions.com/) : is a free and open platform for threat hunting, network security monitoring, and log management. Security Onion includes best-of-breed free and open tools including Suricata, Zeek, Wazuh, the Elastic Stack and many others.
- [Apache Log Viewer](https://www.apacheviewer.com/) : With apache logs viewer you can easily filter and analyze Apache/IIS/nginx log files.
- [GoAccess](https://goaccess.io/) : GoAccess is an open source real-time web log analyzer and interactive viewer that runs in a terminal in unix systems or through your browser.
- [LogScan](https://github.com/thomst/logscan) : ogscan is a command-line-tool to get time-specific access to logfiles
- [Log Parser](https://www.microsoft.com/en-us/download/details.aspx?id=24659) : Log parser is a powerful, versatile tool that provides universal query access to text-based data such as log files, XML files and CSV files, as well as key data sources on the Windows
- [Praeco](https://opensourcelibs.com/lib/praeco) : Praeco is an alerting tool for Elasticsearch – a GUI for ElastAlert, using the ElastAlert API is a fork.

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
- [ChopChop](https://github.com/michelin/ChopChop) : is a command-line tool for dynamic application security testing on web applications, initially written by the Michelin CERT.
- [Vulners](https://vulners.com/) : Online vulnerability assessment platform (vulnerabilities and exploits database, network scanner, linux scanner)

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
- [CVE](https://cve.mitre.org/) : CVE is a list of entries—each containing an identification number, adescription, and at least one public reference—for publicly known cybersecurity vulnerabilities.
- [NVD NIST](https://nvd.nist.gov/general/nvd-dashboard) : NATIONAL VULNERABILITY DATABASE
- [SSLMap](https://github.com/iphelix/sslmap) : SSLMap is a lightweight TLS/SSL cipher suite scanner

### Forensics and incident response
- [Volatility](https://www.volatilityfoundation.org/) : Extraction of digital artifacts from volatile memory (RAM) samples framework
- [Volatility Workbecnh](https://www.osforensics.com/tools/volatility-workbench.html) : Volatility Workbench is a graphical user interface (GUI) for the Volatility tool
- [peepdf](https://github.com/jesparza/peepdf) : Python tool to explore PDF files in order to find out if the file can be harmful or not
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [PDF Examiner](https://www.pdfexaminer.com/) : Online PDF Examiner
- [GRR](https://grr-doc.readthedocs.io/en/latest/) : Rapid Response is an incident response framework focused on remote live forensics
- [Windows Sysinternals Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/) : Windows forensics Small Utilities
- [The Sleuth Kit®](https://www.sleuthkit.org/sleuthkit/) :  Collection of command line tools and a C library that allows you to analyze disk images and recover files from them
- [Autopsy](https://www.sleuthkit.org/autopsy/) :  GUI-based program that allows you to efficiently analyze hard drives and smart phones.
- [Belkasoft](https://belkasoft.com/ram-capturer) : Belkasoft Live RAM Capturer is a tiny free forensic tool that allows to reliably extract the entire contents of computer’s volatile memory
- [Online EMailTracer](http://www.cyberforensics.in/OnlineEmailTracer/index.aspx) : tool to track email sender’s identity.
- [MX Toolbox](https://mxtoolbox.com/EmailHeaders.aspx) : This tool will make email headers human readable by parsing them according to RFC 822
- [EmailHeaders.net](https://packagecontrol.io/packages/Email%20Header) : EmailHeaders.net brings forth the most effective solutions to investigate Email Header and forensics issues
- [EmailHeader](https://packagecontrol.io/packages/Email%20Header) : This Sublime Text plugin will parse .eml or .msg files for email message headers
- [MailXaminer](https://www.mailxaminer.com/) : SysTools Email Examiner Software to Analyze Emails for Investigators with Speed, Accuracy & Ease
- [Free OST Viewer Tool](https://datahelp.in/ost/viewer.html) : Open Offline Outlook Data File Free of Cost & Without Exchange Server Environment
- [MISP](https://www.misp-project.org/tools/) : Malwares sharing plateforme
- [TheHive](https://thehive-project.org/) : Open Source and Free Security Incident Response Platform (can be integrated with MISP)
- [Cortex](https://github.com/TheHive-Project/CortexDocs) : Powerful Observable Analysis and Active Response Engine (from thehive-project.org )
- [Snadfly Security](https://www.sandflysecurity.com/) : Sandfly is an agentless compromise and intrusion detection system for Linux (with UI). It automates security investigation and forensic evidence collection on Linux.
- [DFIR ORC](https://dfir-orc.github.io/) : ANSSI DFIR ORC “Outil de Recherche de Compromission” is a modular and scalable tool to collect artefacts on Microsoft Windows systems, in a decentralized manner.
- [Polichombr](https://github.com/ANSSI-FR/polichombr) : This ANSSI FR's tool aim to provide a collaborative malware analysis framework.
- [Velociraptor](https://www.velocidex.com/) : Velociraptor provides the next generation in endpoint monitoring, digital forensic investigations and cyber incident response.
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
- [HashMyFiles](https://www.nirsoft.net/utils/hash_my_files.html) : HashMyFiles is small utility that allows you to calculate the MD5 and SHA1 hashes of one or more files in your system
- [Floss](https://github.com/fireeye/flare-floss) : FireEye Labs Obfuscated String Solver uses advanced static analysis techniques to automatically deobfuscate strings from malware binaries. You can use it just like `strings utility`
- [RegRipper](https://tools.kali.org/forensics/regripper) : Open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis
- [Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md) : Forensics toolkits (MFTECmd, Registry Explorer, Hasher, Timeline Explorer, ...)
- [ADTimeLine](https://github.com/ANSSI-FR/ADTimeline)(ANSSI) : The ADTimeline script generates a timeline based on Active Directory replication metadata for objects considered of interest.
- [X-Ways](https://www.x-ways.net/forensics/) : X-Ways Forensics is an advanced work environment for computer forensic examiners and our flagship product.
- [Awesome Incident Response](https://asmen.icopy.site/awesome/awesome-incident-response/) : A curated list of tools and resources for security incident response, aimed to help security analysts and DFIR teams.
- [oletools](https://github.com/decalage2/oletools) : python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging.
- [OfficeDissector](https://www.officedissector.com/) : Python toolkit to analyze Microsoft Office Open XML (OOXML) files and documents—the format.



### Hardening
- [SElinux](https://doc.fedora-fr.org/wiki/SELinux), [ApparMor](https://doc.ubuntu-fr.org/apparmor) : renforcement permissions Linux
- [AIDE](https://aide.github.io/) : audit d'intégrité de fichiers
- [Lynis](https://cisofy.com/lynis/) : audit de configuration et de conformité d'un système
- [Falco](https://falco.org/) : Cloud-Native runtime security (Audit de sécurité docker, kubernetes, OS)
- [OpenSCAP Tools](https://www.open-scap.org/tools/) : suite d'outils de scan et d'évaluation de conformité (OS, docker)
- [checksec](https://github.com/slimm609/checksec.sh),
- [winchecksec](https://github.com/trailofbits/winchecksec) et [otool]() : Vérificateurs de la présence de drapeaux de sécurité sur un logiciel
- [SSLtest](https://www.ssllabs.com/ssltest/) : SSL verificator
- [Mozilla Website Observatory](https://observatory.mozilla.org/) : Mozilla website scanner helps how to configure websites safely and securely by identifiant misconviguration and issues.
- [Security Headers](https://securityheaders.com/) :  Security Headers checks issues on security headers like CSP and HSTS to a web site
- [GreekFlare Tools](https://gf.dev/toolbox) : set of tools for security or dns checking
- [RKhunter](http://rkhunter.sourceforge.net/) : Rootkit Hunter is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [Chkrootkit](http://www.chkrootkit.org/) : Check Rootkit is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [BotHunter]()
- [arpwatch](https://linux.die.net/man/8/arpwatch) : ARP monitoring software
- [Tripwire FIM](https://www.tripwire.com/solutions/file-integrity-and-change-monitoring) : File Integrity Monitoring & Change Management
- [CheckPoint CheckMe](http://www.cpcheckme.com/checkme/#) : CheckMe runs a serie of simulations that test if your existing security technologies can block standard and advanced attacks
- [BMC-Tools](https://github.com/ANSSI-FR/bmc-tools) : ANSSI FR's RDP Bitmap Cache parser.
- [Regshot](https://sourceforge.net/projects/regshot/) : Allows you to quickly take a snapshot of your registry and then compare it with a second one
- [RegistryChangesView](https://www.nirsoft.net/utils/registry_changes_view.html) :  NirSoft's tool allows you to take a snapshot of Windows Registry and later compare it with another Registry snapshots
- [Secure Bytes Free Security Tools](http://www.secure-bytes.com/product.php) : Set of free security tools to perform security checks (Windows, Oracle, SQL, ..;)
- [SecureAPplus](https://www.secureaplus.com/) : SecureAPlus is a cloud based antivirus that Uses up to 12 Cloud Anti-Virus Engines for higher detection rates & low false positives
- [360 Total Security](https://www.360totalsecurity.com/en/) : Your Unified Solution For PC Security and Performance
- [Decontamine_Linux](https://whatsecurity.org/contents/projects/decontamine_linux.php) : Decontamine_Linux is an USB devices cleaning station for Linux
- [Firetools](https://firejailtools.wordpress.com/) : Firetools is the graphical user interface of Firejail security sandbox. Firejail is a SUID sandbox program that reduces the risk of security breaches by restricting the running environment of untrusted applications using Linux namespaces, seccomp-bpf and Linux capabilities
- [Wazuh](https://wazuh.com/) : Wazuh is a free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.
- [Chef InSpec](https://docs.chef.io/inspec/) : is an open-source framework for testing and auditing your applications and infrastructure

### Detection
- [Yara](https://virustotal.github.io/yara/) : Identification et détection des IOC des malwares
- [Sigma](https://github.com/SigmaHQ/sigma) : Generic Signature Format for SIEM Systems. Sigma is for log files what Snort is for network traffic and YARA is for files.
- [Clamav](https://www.clamav.net/) : Antivirus opensource
- [Blazescan](https://github.com/Hestat/blazescan) : Blazescan is a linux webserver malware scanning and incident response tool
- [Linux Malware Detect](https://github.com/rfxn/linux-malware-detect) : Linux Malware Detect (LMD) is a malware scanner for Linux released
- [VirusTotal](https://virustotal.com) : Multi scan virus analysis
- [MetaDefender](https://metadefender.opswat.com/) : Multi scan virus analysis like VirusTotal
- [Threat Miner](https://www.threatminer.org/) : ThreatMiner is a threat intelligence portal designed to enable analysts to research under a single interface
- [aWebAnalysis](https://awebanalysis.com/en/) : offers hundreds of free online tools related to cryptocurrencies, networks, programming and other Internet related topics
- [Cuckoo Sandbox](https://cuckoosandbox.org/) : Cuckoo Sandbox is free software that automated the task of analyzing any malicious file under Windows, macOS, Linux, and Android.
- [LISA](https://github.com/danieluhricek/LiSa) : Linux Sandbox is project providing automated Linux malware analysis on various CPU architectures
- [Cuckoo CERT](https://cuckoo.cert.ee/) : Online Sandbox for malwares IoC analysis
- [Any Run](https://any.run/) : Malware hunting with live access to the heart of an incident
- [Intezer Analyze (Community Edition)](https://analyze.intezer.com/) : Quickly analyze files and devices to immediately understand the What, Who, & How of a potential cyber incident.
- [IRIS-H Digital Forensics](https://iris-h.services/pages/dashboard#/pages/dashboard) : IRIS-H is an online digital forensics tool that performs automated static analysis of files stored in a directory-based or strictly structured formats
- [Inquest Labs](https://labs.inquest.net/) : The InQuest platform provides high-throughput Deep File Inspection (DFI) for threat and data leakage prevention, detection, and hunting.
- [Rshipp Awesome malware analysis](https://github.com/rshipp/awesome-malware-analysis) : Collection of malwares analysis and détection tools
- [Infosec CERT-PA Analyzer](https://infosec.cert-pa.it/analyze/search.html)
- [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) : détection d'intrusion et blocage d'IP malveillantes
- [CrowdSec](https://crowdsec.net/) :  parses logs to assess the behavior of IP addresses coming to your apps, websites, services, etc
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
- [Cape Sandbox](https://capesandbox.com/) : CAPE ('Config And Payload Extraction') is a malware sandbox. It was derived from Cuckoo with the goal of adding automated malware unpacking and config extraction.. 
- [FEODO Tracker](https://feodotracker.abuse.ch/) : Feodo Tracker is a project of abuse.ch with the goal of sharing botnet C&C servers associated with the Feodo malware family (Dridex, Emotet/Heodo).
- [#TotalHash](https://totalhash.cymru.com/) : #totalhash provides static and dynamic analysis of Malware samples.
- [URLVoid](https://www.urlvoid.com/) : Website Reputation Checker (This service helps you detect potentially malicious websites)
- [Packet Total](https://packettotal.com/) : PacketTotal is an engine for analyzing, categorizing, and sharing .pcap files.
- [URLhaus](https://urlhaus.abuse.ch/) : URLhaus is a project from abuse.ch with the goal of sharing malicious URLs that are being used for malware distribution.
- [TALOS](https://talosintelligence.com/) : CISCO Talos’ IP and Domain Data Center is the world’s most comprehensive real-time threat detection network.
- [multirbl](http://multirbl.valli.org/) : The complete IP check for sending Mailservers
- [PowerDMARC](powerdmarc.com) : Stop Hackers From Sending Emails from your Domain with DMARC (Domain-based Message Authentication, Reporting and Conformance)
- [Open CTI](https://www.opencti.io/en/) : Open threat intelligence platform
- [GitGuardian](https://www.gitguardian.com/) : Automated secrets detection & remediation
- [Continus](https://continus.io/) : Continus.io is an automated DevSecOps solution that brings together SAST, DAST and SCA in one tool to secure your DevOps pipelines and continuously assess the security of your source code, 3rd party components, containers and APIs
- [Automater](https://tools.kali.org/information-gathering/automater) : Automater is a URL/Domain, IP Address, and Md5 Hash OSINT tool aimed at making the analysis process easier for intrusion Analysts
- [MalPedia](https://malpedia.caad.fkie.fraunhofer.de/) : The primary goal of Malpedia is to provide a resource for rapid identification and actionable context when investigating malware
- [Malwoverview](https://github.com/alexandreborges/malwoverview) : Malwoverview.py is a first response tool for threat hunting, which performs an initial and quick triage of malware samples, URLs, IP addresses, domains, malware families, IOCs and hashes.
- [VirusTotal Tools](https://blog.didierstevens.com/programs/virustotal-tools/) : Didier Steven's Python programs to search VirusTotal for hashes or to submit files.
- [Online IDE Search](https://redhuntlabs.com/online-ide-search) : Custom Search Tool by @RedHuntLabs Team looks for keywords/strings in following Online IDEs, Paste(s) sites and Code Sharing Platforms. See other free tools [here](https://redhuntlabs.com/open-source-free-tools).
- [vuldb](https://vuldb.com/fr/?) : Vulnerabilities database


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
- [Specops Password Policy](https://specopssoft.com/product/specops-password-policy/) : Enforce compliance requirements, block leaked passwords, and help users create stronger passwords in Active Directory.
- [Specops Password Auditor](https://specopssoft.com/product/specops-password-auditor/) : scans your Active Directory and identifies password-related vulnerabilities.
- [Autofill extension](https://chrome.google.com/webstore/detail/microsoft-autofill/fiedbfgcleddlbcmgdigjgdfcggjcion) :  This Microsoft Autofill extension lets you your password safely in your account

### Monitoring
- [CheckMK](https://checkmk.com/) : infrastructure & application monitoring
- [Shinken](http://www.shinken-monitoring.org/) : open source monitoring framework written in Python
- [GLPI](https://glpi-project.org/fr/) : GLPI est un outil ITSM , puissant et tout intégré pour la gestion de votre parc et de votre centre de services
- [Apps tracker](https://sourceforge.net/projects/appstracker/) : Computer monitoring & time tracking app
- [Watchman](https://facebook.github.io/watchman/) : Watchman exists to watch files and record when they change.

### Encrytion
- [sks-keyserver](https://github.com/SKS-Keyserver/sks-keyserver) : GnuGPG infrastructure keys
- [tbs certifcats generator](https://www.tbs-internet.com/php/HTML/pages/aideCreatCSR.php) : This too helps to genrate OpenSSL certificat.

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
- [CyberChef](https://gchq.github.io/CyberChef/) : A simple, intuitive web app for analysing and decoding data without having to deal with complex tools or programming languages
- [AMTSO Security Features Check Tools](https://www.amtso.org/security-features-check/) : The AMTSO Security Features Check (SFC) tools verify that your security solution is properly configured and operating as expected.
- [SQLitBrowser](https://sqlitebrowser.org/) : open source tool to create, design, and edit database files compatible with SQLite

### Security Check
- [EmoCheck](https://github.com/JPCERTCC/EmoCheck) : Emotet detection tool for Windows OS.
- [ZeroLogon testing script](https://github.com/SecuraBV/CVE-2020-1472) : A Python script that uses the Impacket library to test vulnerability for the Zerologon exploit (CVE-2020-1472)
- [Atomic Red Team](https://atomicredteam.io/) : Atomic Red Team allows every security team to test their controls by executing simple "atomic tests" that exercise the same techniques used by adversaries (all mapped to Mitre's ATT&CK).
- [Cladera](https://caldera.readthedocs.io/en/latest/) : Mittre Att&ck testing tool like Atomic red team
- [APT Simulator](https://github.com/NextronSystems/APTSimulator) : APT Simulator is a Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
- [RedHunt Linux Distribution](https://github.com/redhuntlabs/RedHunt-OS) : Virtual Machine for Adversary Emulation and Threat Hunting by RedHunt Labs
- [BT3](https://www.bt3.no/features/) : Blue Team Training Toolkit (BT3) is software for defensive security training, which will bring your network analysis training sessions, incident response drills and red team engagements to a new level.
- [RTA](https://github.com/endgameinc/RTA) : Red Team Automation (RTA) : RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
- [Microsoft Security Compliance Toolkit (SCT)](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-compliance-toolkit-10) : The Security Compliance Toolkit (SCT) is a set of tools that allows enterprise security administrators to download, analyze, test, edit, and store Microsoft-recommended security configuration baselines for Windows and other Microsoft products
- [Microsoft WAF Bench (WB) Tool Suits](https://github.com/microsoft/wafbench) : WAF (Web Application Firewall) Bench tool suits is designed to verify the correctness and measure the performance of WAF.
- [WAF Testing Framework](https://www.imperva.com/lg/lgw_trial.asp?pid=483) : A WAF testing tool by Imperva.
- [owasp-crs-regressions](https://github.com/SpiderLabs/owasp-modsecurity-crs/tree/v3.1/dev/util/regression-tests) : the OWASP Core Rule Set regression testing suite. This suite is meant to test specific rules in OWASP CRS version 3
- [knowbe4 Free IT Security Tools](https://www.knowbe4.com/free-it-security-tools) : Free security tools for many testing purposes (ransomware test, email, malware, ...)


### Social Ingeneering
- [Shellphis](https://github.com/thelinuxchoice/shellphish) : Phishing Tool for Instagram, Facebook, Twitter, Snapchat, Github, Yahoo, Protonmail ...
- [Fake Mailer](https://github.com/htr-tech/fake-mailer) : Fake Mailer is tool to Send Mail Anonymously from a different Email

### Data Leak Checker And OSINT Tool
- [OSINT Framework](https://osintframework.com/) : OSINT framework focused on gathering information from free tools or resources. The intention is to help people find free OSINT resources
- [Firefox Monitor](https://monitor.firefox.com/) : can help you to check if your email address has been found in leaks
- [SolarWinds Identity Monitor](https://www.solarwinds.com/identity-monitor) : can help you to check if your email address has been found in leaks
- [CheckUserNames](https://checkusernames.com/) : Check the use of your brand or username on 160 Social Networks
- [HaveIbeenPwned](https://haveibeenpwned.com) :  can help you to check if your account has been compromised in the past
- [Dehashed](https://dehashed.com/) : can help you to check if your account has been found in leaks
- [Censys](https://censys.io/) : is a wonderful search engine used to get the latest and most accurate information about any device connected to the internet
- [Shodan](https://www.shodan.io/) :  is a network security monitor and search engine focused on the deep web & the internet of things.
- [Oblivion](https://kalilinuxtutorials.com/oblivion/) : is a tool focused in real time monitoring of new data leaks, notifying if the credentials of the user has been leak out
- [HTTPCS Cyber Vigilance](https://www.httpcs.com/en/data-leakage-detection-darkweb-crawl-tool) :  watches continuously the web, deep web and dark web to collect information (documents, data leakage, sensitive information, security flaws…) which relates to your company and alerts your teams in real time.
- [Avast Hack Check](https://www.avast.com/hackcheck) : can help you to check if your email address has been found in leaks
- [F-Secure Identity Theft Checker](https://www.f-secure.com/en/home/free-tools/identity-theft-checker) : can help you to check if your email address has been found in leaks

### Anonymity and privacy
- [TOR Browser](https://www.torproject.org/download/) : Browser which keeps your anonymity and privacy in the internet.
- [TAILS](https://tails.boum.org/index.fr.html) : OS for anonymity and privacy using TOR for any activity.
- [ZSVPN](https://zsvpn.com/) : VPN connecting safely in the Internet.
- [PrivacyTools](https://www.privacytools.io/) : PrivacyTools provides services, tools and knowledge to protect your privacy against global mass surveillance


## Liens
- [Top 125 Security Tools | sectools.org](https://sectools.org/)
- [Penetration Testing Tools | Kali Linux Tools Listing](https://tools.kali.org/tools-listing)
- [Parot Linux tools list](https://github.com/ParrotSec/parrot-tools/blob/master/debian/control)
- [Awesome Incident Response](https://asmen.icopy.site/awesome/awesome-incident-response/)
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
- [Free Automated Malware Analysis Sandboxes and Services](https://zeltser.com/automated-malware-analysis/)
- [Free Online Tools for Looking up Potentially Malicious Websites](https://zeltser.com/lookup-malicious-websites/)
- [Free Blocklists of Suspected Malicious IPs and URLs](https://zeltser.com/malicious-ip-blocklists/)
- [Antivirus multi engines](https://www.geckoandfly.com/24224/antivirus-multi-engines/)
- [Top 25 OSINT Tools for Penetration Testing](https://securitytrails.com/blog/osint-tools )
- [List of Adversary Emulation Tools](https://pentestit.com/adversary-emulation-tools-list/ )
