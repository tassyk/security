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
  - [Others](#Others)
    - [Monitoring](#Monitoring)
- **[Liens](#Liens)**
---

## Security
### Hacking OS distro
- [Kali](https://www.kali.org/) : Offensive security
- [Parrot](https://parrotlinux.org/) : All-in-one framework for Cyber Security, Software Development and Privacy Defense
- [REMnux Distro](https://remnux.org/docs/distro/tools/) :  Forensics distro
- [Caine](https://www.caine-live.net/) : Computer Forensics Linux Live Distro


### SIEM - Log analyzer
- [Suit Elastic](https://www.elastic.co/fr/) : Opensource, mais certains composants sont payants
- [LogPoint](https://www.logpoint.com/en/) : propriétaire
- [Splunk](https://www.splunk.com/) : propriétaire
- [GrayLog](https://www.graylog.org) : Opens source and Entreprise

### Vulnerability Scan
- [outpost24 HIAB](https://outpost24.com/) : Pro Full stack security assessment platform and penetration testing
- [Nessus](https://fr.tenable.com/products/nessus) : Pro/Free powerful vulnerability scan and assessment tools
- [OpenVas](https://www.openvas.org/) : Open source full-featured vulnerability scanner
- [UpGuard](https://webscan.upguard.com/) : Online Pro/Free Website Security Scan
- [SiteGuarding](https://www.siteguarding.com/en) : Online Pro/Free Website Security Services (antivirus, scan, ...)
- [Intruder](https://www.intruder.io/) : powerful cloud-based vulnerability scanner to find weaknesses
- [Detectify](https://detectify.com/) : Online - Scan your web apps for 2000+ vulnerabilities and track assets across your tech stack
- [pentest-tools.com](https://pentest-tools.com/home) : Online - Pentest-Tools.com allows you to quickly discover and report vulnerabilities in websites and network infrastructures

### Pentest
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

### Forensics
- [Volatility](https://www.volatilityfoundation.org/) : Extraction of digital artifacts from volatile memory (RAM) samples framework
- [peepdf](https://github.com/jesparza/peepdf) : Python tool to explore PDF files in order to find out if the file can be harmful or not
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [PDF Examiner](https://www.pdfexaminer.com/) : Online PDF Examiner
- [GRR](https://grr-doc.readthedocs.io/en/latest/) : Rapid Response is an incident response framework focused on remote live forensics
- [Windows Sysinternals Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/) : Windows forensics Small Utilities
- [Autopsy](https://www.sleuthkit.org/autopsy/) :  GUI-based program that allows you to efficiently analyze hard drives and smart phones.
- [Online EMailTracer](http://www.cyberforensics.in/OnlineEmailTracer/index.aspx) : tool to track email sender’s identity.
- [MX Toolbox](https://mxtoolbox.com/) : list MX records for a domain in priority order
- [MailXaminer](https://www.mailxaminer.com/) : SysTools Email Examiner Software to Analyze Emails for Investigators with Speed, Accuracy & Ease
- [MISP](https://www.misp-project.org/tools/) : Malwares sharing plateforme
- [TheHive](https://thehive-project.org/) : Open Source and Free Security Incident Response Platform (can be integrated with MISP)
- [Cortex](https://github.com/TheHive-Project/CortexDocs) : Powerful Observable Analysis and Active Response Engine (from thehive-project.org )
- [Snadfly Security](https://www.sandflysecurity.com/pricing/) : Sandfly is an agentless compromise and intrusion detection system for Linux (with UI). It automates security investigation and forensic evidence collection on Linux.
- [DFIR ORC](https://dfir-orc.github.io/) : ANSSI DFIR ORC “Outil de Recherche de Compromission” is a modular and scalable tool to collect artefacts on Microsoft Windows systems, in a decentralized manner.
- [EventID](http://eventid.net/) : Online  windows events Searcher
- [Browser History Capturer](https://www.foxtonforensics.com/browser-history-capturer/) : BHC is free forensic tool to capture web browser history.
- [Browser History Examiner](https://www.foxtonforensics.com/browser-history-examiner/) : Like BHC with more features (capturing, analysing and reporting (local and remote host)). (Free Trial)
- [SQLite viewer software](https://www.foxtonforensics.com/sqlite-database-examiner/) : Free tool for inspecting the contents of SQLite databases.

### Hardening
- [SElinux](https://doc.fedora-fr.org/wiki/SELinux), [ApparMor](https://doc.ubuntu-fr.org/apparmor) : renforcement permissions Linux
- [AIDE](https://aide.github.io/) : audit d'intégrité de fichiers
- [Lynis](https://cisofy.com/lynis/) : audit de configuration et de conformité d'un système
- [Falco](https://falco.org/) : Cloud-Native runtime security (Audit de sécurité docker, kubernetes, OS)
- [OpenSCAP Tools](https://www.open-scap.org/tools/) : suite d'outils de scan et d'évaluation de conformité (OS, docker)
- [checksec](https://github.com/slimm609/checksec.sh),
- [winchecksec](https://github.com/trailofbits/winchecksec) et [otool]() : Vérificateurs de la présence de drapeaux de sécurité sur un logiciel
- [SSLtest](https://www.ssllabs.com/ssltest/) : SSL verificator
- [RKhunter](http://rkhunter.sourceforge.net/) : Rootkit Hunter is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [Chkrootkit](http://www.chkrootkit.org/) : Check Rootkit is a common open source program or tool used for scanning rootkits, botnets, malwares, etc
- [BotHunter]()
- [arpwatch](https://linux.die.net/man/8/arpwatch) : ARP monitoring software

### Detection
- [Yara](https://virustotal.github.io/yara/) : Identification et détection des IOC des malwares
- [Clamav](https://www.clamav.net/) : Antivirus opensource
- [VirusTotal](https://virustotal.com) : Collection d'antivirus en ligne
- [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) : détection d'intrusion et blocage d'IP malveillantes
- [Snort](https://www.snort.org/) : open source intrusion prevention system
- [ModSecurity](https://modsecurity.org/) : Open source Web Application Firewall (WAF)
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [Snadfly Security](https://www.sandflysecurity.com/pricing/) : Sandfly is an agentless compromise and intrusion detection system for Linux (with UI). It automates security investigation and forensic evidence collection on Linux.

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
- [dnschecker](https://dnschecker.org/all-tools.php) : tools help solving DNS problems
- [pass](https://www.passwordstore.org/) : the standard unix password manager
- [John the Ripper](https://www.openwall.com/john/) : fast password cracker
- [Medusa](http://foofus.net/goons/jmk/medusa/medusa.html) : speedy, massively parallel, modular, login brute-forcer

## Others
- [sha512.fr](https://www.sha512.fr/) : codage sha512, bcrypt, ... online
- [Wappalyzer](https://www.wappalyzer.com/) : Identify technology on websites (Browser extension)
- [FoxyProxy](https://getfoxyproxy.org/) : Proxy switcher (Browsers extension)

### Monitoring
- [CheckMK](https://checkmk.com/) : infrastructure & application monitoring
- [Shinken](http://www.shinken-monitoring.org/) : open source monitoring framework written in Python
- [GLPI](https://glpi-project.org/fr/) : GLPI est un outil ITSM , puissant et tout intégré pour la gestion de votre parc et de votre centre de services


## Liens
- [Top 125 Security Tools | sectools.org](https://sectools.org/)
- [ Penetration Testing Tools | Kali Linux Tools Listing](https://tools.kali.org/tools-listing)
- [Parot Linux tools list](https://github.com/ParrotSec/parrot-tools/blob/master/debian/control)
- [Vulnerability Scanning Tools | OWASP](https://owasp.org/www-community/Vulnerability_Scanning_Tools )
- [Source Code Analysis Tools | OWASP](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [REMnux Distro » Forensics Tools](https://remnux.org/docs/distro/tools/)
- [29 Docker security tools compared. | Sysdig](https://sysdig.com/blog/20-docker-security-tools/ )
- [Top 15 Paid and Free Vulnerability Scanner Tools](https://www.dnsstuff.com/network-vulnerability-scanner)
- [11 Online scan website security vulnerabilities](https://geekflare.com/online-scan-website-security-vulnerabilities/)
- [Important Tools and Resources For Security Researcher, Malware Analyst](https://gbhackers.com/most-important-tools/)
- [100 Best Hacking Tools for Security Professionals in 2020](https://gbhackers.com/hacking-tools-list/ )