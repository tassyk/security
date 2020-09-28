---
Title: Forensics Labs
Type: Doc
Nature: Notes
Création: 28/09/2020
---

#  Forensics Labs
---
**Sommaire**

- **[Prerequis](#Prerequis)**
- **[Environnement du lab](#Environnement-du-lab)**
  - [Virtualisation](#Virtualisation)
  - [VM Forensics](#VM-Forensics)
  - [Outils d'analyse dynamique](#Outils-d'analyse-dynamique)
  - [Outils d'analyse statique](#Outils-d'analyse-statique)
  - [Outils d'analyse des indices de compromission (IoC)](#Outils-d'analyse-des-indices-de-compromission-(IoC))
- **[Liens](#Liens)**
---
## Prerequis
- Avoir une plateforme de virtualisation pour créer et déployer des machines virtuelles
- Avoir un accès à internet pour pouvoir installer les outils nécessaires pour l'analyse
- Bien isoler l'environnement **avant d'entammer une quelconque analyse** (couper les accès réseaux interne/internet, couper les partages de dossier entre les VM et l'hôte)

## Environnement du lab
### Virtualisation
- Utiliser une plateforme de Virtualisation (VirtualBox, Vmware, Hyper-V, ...)
- Créer des réseaux host-only pour que les VM n'aient pas accès à internet
> Note : L'environnement doit etre complètement isolé pour éviter tout risque d'infection avant de commencer l'analyse. Avant l'analyse, il faut au préalable installer tous les outils nécessaires.
-

### VM Forensics
Il existe des distributions (Linux, windows) dédiées aux forensics. Parmi ceci, on a :
- [REMnux](https://remnux.org/) : Distribution Linux disposant d'une collection d'outils pour Forensics
- [Flare VM](https://github.com/fireeye/flare-vm) : Distribution Windows  disposant d'une collection d'outils pour Forensics
> Note : Flare doit être installé sur une VM Windows. On peut récupérer une VM Windows depuis le site de [Microsoft Edge Developer](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/).

> **Attention**:
  - Ces VM doivent être connectés aux cartes réseaux "host-only" configurées précédemment dans le cas d'une analyse dynamique de malwares
  - Il faut prendre des Snapshots pour revenir en arrière en cas de risque

### Outils d'analyse dynamique
Grâce à certains outils, on peut analyser/étduier le comporetemnt/fonctionnement du malware dans notre lab. Parmi ces outils, on peut citer :
- [Process Hacker](https://processhacker.sourceforge.io/) : A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware.
- [Process Monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) : Process Monitor is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity
- [Autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) :  shows you what programs are configured to run during system bootup or login, and when you start various built-in Windows applications like Internet Explorer, Explorer and media players.
- [RegistryChangesView](https://www.nirsoft.net/utils/registry_changes_view.html) :  NirSoft's tool allows you to take a snapshot of Windows Registry and later compare it with another Registry snapshots
- [ProcDot](https://www.procdot.com/) : It processes Sysinternals Process Monitor (procmon) logfiles and PCAP logs (Windump, tcpdump) to generate a graph via the GraphViz suite
- [Wireshark](https://www.inetsim.org/about.html) : world’s foremost and widely-used network analyzer.
- [FakeDNS](https://github.com/Crypt0s/FakeDns) : Fake DNS Server for intercepting requests
- [INetSim](https://www.inetsim.org/) : INetSim is a software suite for simulating common internet services in a lab environment, e.g. for analyzing the network behaviour of unknown malware samples

### Outils d'analyse statique
Parfois, on a besoin d'analyser le code source du malware pour comprendre son fonctionnement.
- [Pestudio](https://www.winitor.com/) : The goal of pestudio is to spot suspicious artifacts within executable files in order to ease and accelerate Malware Initial Assessment.
- [IDA Freeware](https://www.hex-rays.com/products/ida/support/download_freeware/) : Assembler level analysing debugger
- [x64dbg](https://x64dbg.com/#start) : An open-source x64/x32 debugger for windows.
- [OllyDbg](http://www.ollydbg.de/) : OllyDbg is a 32-bit assembler level analysing debugger for Microsoft Windows
> Note : L'analyse statique d'un binaire fait appel à des compétences en Assembleur.

### Outils d'analyse des indices de compromission (IoC)

- [VirusTotal](https://virustotal.com) : Multi scan virus analysis
- [MetaDefender](https://metadefender.opswat.com/) : Multi scan virus analysis like VirusTotal
- [Any Run](https://any.run/) : Malware hunting with live access to the heart of an incident
- [Hybrid analysis](https://www.hybrid-analysis.com/) : This is a free malware analysis service for the community that detects and analyzes unknown threats using a unique Hybrid Analysis technology
- [#TotalHash](https://totalhash.cymru.com/) : #totalhash provides static and dynamic analysis of Malware samples.
- [URLVoid](https://www.urlvoid.com/) : Website Reputation Checker (This service helps you detect potentially malicious websites)
- [AbuseIpDB](https://www.abuseipdb.com/) : making the internet safer, one IP at a time
- [Yara](https://virustotal.github.io/yara/) : Identification et détection des IOC des malwares


## Liens
- [How to Get and Set Up a Free Windows VM for Malware Analysis](https://zeltser.com/free-malware-analysis-windows-vm/)
- [Introduction to Malware analysis RSA Conference 2019](https://zeltser.com/media/docs/intro-to-malware-analysis-ir.pdf)
- [HackingTutorials | Malware analysis tutorials](https://www.hackingtutorials.org/malware-analysis-tutorials/dynamic-malware-analysis-tools/ )
- [Windows Virtual Machines](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/)
