---
Title: Tools
Type: Doc
Nature: Notes
Création: 15/05/2020
---

# Tools
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
  - [Autres](#Autres)
- **[Liens](#Liens)**
---

## Security
### Hacking OS distro
- [Kali](https://www.kali.org/) : Offensive security
- [Parrot](https://parrotlinux.org/) : All-in-one framework for Cyber Security, Software Development and Privacy Defense
- [REMnux Distro](https://remnux.org/docs/distro/tools/) :  Forensics distro
-
### SIEM - Log analyzer
- [Suit Elastic](https://www.elastic.co/fr/) : Opensource, mais certains composants sont payants
- [LogPoint](https://www.logpoint.com/en/) : propriétaire
- [Splunk](https://www.splunk.com/) : propriétaire
- [GrayLog](https://www.graylog.org) : Opens source and Entreprise

### Vulnerability Scan
- [outpost24 HIAB](https://outpost24.com/) : propriétaire
- [Nessus](https://fr.tenable.com/products/nessus) : propriétaire, mais existe une version communautaire

### Pentest
- [Burp suite](https://portswigger.net/) : web security scanner and proxy
- [Nikto](https://cirt.net/nikto2) : Open Source (GPL) web server scanner
- [Vega](https://subgraph.com/vega/) : Open Source web server vulnerability scanner (XSS, SQL injcetion and more)
- [WPScan](https://wpscan.org/) : WordPress Security Scanner
- [SQLmap](http://sqlmap.org/) : Sql injection scanner
- [Metasploit](https://www.metasploit.com/) : Pentest framework
- [pentest-tools.com](https://pentest-tools.com/home) : outils de pentest en ligne

### Forensics
- [Volatility](https://www.volatilityfoundation.org/) : Extraction of digital artifacts from volatile memory (RAM) samples framework
- [peepdf](https://github.com/jesparza/peepdf) : Python tool to explore PDF files in order to find out if the file can be harmful or not
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool
- [PDF Examiner](https://www.pdfexaminer.com/) : Online PDF Examiner
- [GRR](https://grr-doc.readthedocs.io/en/latest/) : Rapid Response is an incident response framework focused on remote live forensics
- [Windows Sysinternals Utilities](https://docs.microsoft.com/en-us/sysinternals/downloads/) : Windows forensics Utilities
- [Autopsy](https://www.sleuthkit.org/autopsy/) :  GUI-based program that allows you to efficiently analyze hard drives and smart phones.
- [Online EMailTracer](http://www.cyberforensics.in/OnlineEmailTracer/index.aspx) : tool to track email sender’s identity.
- [MX Toolbox](https://mxtoolbox.com/) : list MX records for a domain in priority order

### Hardening
- [SElinux](https://doc.fedora-fr.org/wiki/SELinux), [ApparMor](https://doc.ubuntu-fr.org/apparmor) : renforcement permissions Linux
- [AIDE](https://aide.github.io/) : audit d'intégrité de fichiers
- [Lynis](https://cisofy.com/lynis/) : audit de configuration et de conformité d'un système
- [Falco](https://falco.org/) : Cloud-Native runtime security (Audit de sécurité docker, kubernetes, OS)
- [OpenSCAP Tools](https://www.open-scap.org/tools/) : suite d'outils de scan et d'évaluation de conformité (OS, docker)
- [checksec](https://github.com/slimm609/checksec.sh), [winchecksec](https://github.com/trailofbits/winchecksec) et [otool]() : Vérificateurs de la présence de drapeaux de sécurité sur un logiciel
- [SSLtest](https://www.ssllabs.com/ssltest/) : SSL verificator

### Detection
- [Yara](https://virustotal.github.io/yara/) : Identification et détection des IOC des malwares
- [Clamav](https://www.clamav.net/) : Antivirus opensource
- [VirusTotal](https://virustotal.com) : Collection d'antivirus en ligne
- [Fail2ban](https://www.fail2ban.org/wiki/index.php/Main_Page) : détection d'intrusion et blocage d'IP malveillantes
- [Snort](https://www.snort.org/) : open source intrusion prevention system
- [ModSecurity](https://modsecurity.org/) : Open source Web Application Firewall (WAF)
- [MISP](https://www.misp-project.org/tools/) : Malwares sharing plateforme
- [Sysdig](https://github.com/draios/sysdig/wiki) : Audit and analysis tool

### Docker security
- [Dagda](https://github.com/eliasgranderubio/dagda) : Scan de vulnérabilités docker
- [Atomic](http://www.projectatomic.io/) : Hôte pour les conteneurs mais aussi outil de scan
- [Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md) : docker Vulnerability scanner
- [Harbor](https://goharbor.io/) : registry  et scanneur de vulnérabilités docker
- [Portus](http://port.us.org/features/6_security_scanning.html) : scanneur de vulnérabilités docker
- [Anchore](https://anchore.com/) : scanneur de vulnérabilités docker (Entreprise/Opensource)

## Autres
- [sha512.fr](https://www.sha512.fr/) : codage sha512, bcrypt, ... en ligne
- [haveibeenpwned](https://haveibeenpwned.com/) : vérificateur de mot de passe ou email compromis en ligne


## Liens
- [Top 125 Security Tools | sectools.org](https://sectools.org/)
- [ Penetration Testing Tools | Kali Linux Tools Listing](https://tools.kali.org/tools-listing)
- [Parot Linux tools list](https://github.com/ParrotSec/parrot-tools/blob/master/debian/control)
- [Vulnerability Scanning Tools | OWASP](https://owasp.org/www-community/Vulnerability_Scanning_Tools )
- [Source Code Analysis Tools | OWASP](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [REMnux Distro » Forensics Tools](https://remnux.org/docs/distro/tools/)
- [29 Docker security tools compared. | Sysdig](https://sysdig.com/blog/20-docker-security-tools/ )
- [Top 15 Paid and Free Vulnerability Scanner Tools](https://www.dnsstuff.com/network-vulnerability-scanner)
- [Important Tools and Resources For Security Researcher, Malware Analyst](https://gbhackers.com/most-important-tools/)
- [100 Best Hacking Tools for Security Professionals in 2020](https://gbhackers.com/hacking-tools-list/ )
