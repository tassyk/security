---
Title: Scan Vulnérabilité OpenSCAP Daemon et Timony
Type: Doc
Nature: Notes
Création: 27/04/2020
---

# Scan de vulnérabilité via OpenSCAP Daemon et Timony
****
## Table of Contents

- **[Introduction](#introduction)**
- **[Scan via OpenSCAP Daemon](##Scan-via-OpenSCAP-Daemon)**
  - [Installation d'OpenSCAP Daemon](#Installation-de-OpenSCAP-Daemon)
  - [Réalisation d'un scan via OpenSCAP Daemon](#Réalisation-d'un-scan-via-OpenSCAP-Daemon)
    - [Description de la commande oscapd-cli d'OpenSCAP Daemon](Description-de-la-commande-oscapd-cli-d'OpenSCAP-Daemon)
    - [Scan en mode interactif via OpenSCAP Daemon](#Scan-en-mode-interactif-via-OpenSCAP-Daemon)
    - [Résultat de scan d'OpenSCAP Daemon](#Résultat-de-scan)

- **[Scan via SCAP Timony ou OpenSCAP Foreman](#Scan-via-SCAP-Timony-ou-OpenSCAP-Foreman)**
  - [Installation d'OpenSCAP Foreman](#Installation-d'OpenSCAP-Foreman)

- **[Terminologies](#Terminologies)**
- **[Sources](#Sources)**
****

## Introduction
OpenSCAP est une suite d'outils qui offrent la possibilité d'évaluer le niveau de sécurité d'un système par rapport à des référentiels de sécurité ([Security Policy](https://www.open-scap.org/security-policies/choosing-policy/)) distigués à travers le monde comme [STIGs](http://iase.disa.mil/stigs/Pages/index.aspx), [NIST](https://web.nvd.nist.gov/view/ncp/repository), [PCI-DSS](https://www.pcisecuritystandards.org/security_standards/documents.php?association=PCI-DSS), ... C'est une implémentation opensource du protocole [SCAP (Security Content Automation Protocol)](https://csrc.nist.gov/projects/security-content-automation-protocol) qui fournit un mécanisme de vérification de la sécurité des configurations, de gestion des vulnérabilités et d'évaluation de la conformité des politiques pour une variété de systèmes. Ses outils peuvent être utilisés pour scanner un serveur physique, une machine virtuelle, des conteneurs.

Cette [suite d'outils](https://www.open-scap.org/tools/), est composée entre autre de :
- **OpenSCAP Base (scanner)** : pour scanner le système à l'aide des ligne de commande;
- **SCAP Workbench** : pour réaliser des scan à l'aide d'une interface graphique;
- **OSCAP Anaconda Add-on** : pour scanner les systèmes dès lors installation;
- **OpenSCAP Daemon**: un démon qui tourne continuellement pour une évaluation continue du niveau de sécurité;
- **SCAPTimony** : outil offrant la possibilité de centraliser les résultats des scan (idéal dans un environnement multi machines).

Pour la réalisation des scan, chaque outil se base sur des politiques de sécurité ([security policy](https://www.open-scap.org/security-policies/)). Chaque politique contient de nombreux profils disposant chacun de nombreuses règles. A la fin de chaque scan, un rapport de scan contenant les résultats est disponible. Pour chaque vulnérabilité (ou défaut de configuration) identifiée, des mesures de correction sont proposées.

Les scans peuvent être réalisé sur un hôte local ou distant. Ceci peut être une machine physique, machine virtuelle, ou un conteneur.

Dans une une précédente note, nous avons découvert `SCAP Workbench` et `OpenSCAP Base (scanner)`. A travers celle-ci note, nous allons tenter d'explorer **OpenSCAP Daemon** et **SCAPTimony**.

## Scan via OpenSCAP Daemon
[OpenSCAP Daemon](https://github.com/OpenSCAP/openscap-daemon/blob/master/README.md) permet de réaliser des scans manuellement ou péridiquement (scans plannifiés). C'est un bon outil pour effecuter une évaluation continue du niveau de sécurité et des vulnérabilités des systèmes locaux ou distants. La commande `oscapd-cli` fournit permet d'intéragir avec l'outil.
> Note : On peut scanner des conteneurs via OpenSCAP-Daemon à l'aide de la commande `atomic scan` mais il faut installer déjà Atomic sur la machine.

### Installation d'OpenSCAP Daemon
> Prérequis:
>* [*python2*](http://python.org) >= 2.6 OR [*python3*](http://python.org) >= 3.2
>* full source compatibility with *python2* and *python3*
>* [*OpenSCAP*](http://open-scap.org) >= 1.2.6
>* [*dbus-python*](http://www.freedesktop.org/wiki/Software/DBusBindings/)
>* (optional) [*Atomic*](http://www.projectatomic.io) >= 1.4
>* (optional) [*docker*](http://www.docker.com)

OpenSCAP Daemon peut s'installer de différente manières: par source, via un conteneur, via rpm. Nous allons faire l'installation avec la dernière méthode en utilisant les commandes ci-dessous :
```
# Installation des dépendances
sudo yum update -y
sudo yum install -y openscap python dbus-python python-flask
# installation de l'outil
sudo yum install openscap-daemon
# installer une politique de sécurité (ici, scap-security-guide)
sudo yum install scap-security-guide
# démarrer le service
sudo systemctl start oscapd
sudo systemctl enable oscapd
# vérifier le status
sudo systemctl status oscapd
```
> Note :
>* le paquet dans le dépôt EPEL. S'il n'est pas déjà installé, il faut utiliser la commande (pour CentOs 7) :
>* `sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm`

### Réalisation d'un scan via OpenSCAP Daemon
#### Description de la commande oscapd-cli d'OpenSCAP Daemon
L'outil fournit une CLI (Ligne de commande) `oscapd-cli` qui permet de gérer les différents scan (création, plannification, visulation des résultats, ...). La commande peut être utilisée en mode interactif grâce à l'option `-i`. Sa syntaxe est la suivante :
```
oscapd-cli [-h] {eval,scan,task,task-create,status,result}
```
Où :
- eval   Évaluation interactive et ponctuelle de toute cible supportée par
OpenSCAP Daemon
- task : Montre les informations des tâches déjà définies
- task-create : crée une nouvelle tâche
- status : Affiche les tâches plannifiées et leur état
- result : Affiche les détails des scans précédents
> Note: `man oscapd-cli` fournit plus d'information

#### Scan en mode interactif via OpenSCAP Daemon
L'option `-i` lance le scan en mode interactif :
```
sudo oscapd-cli task-create -i
```
Une fois lancée, il faut suivre les intructions :
- **Title** : définir le nom du scan
- **Target (empty for localhost)**: définir la cible de scan (localhost par défaut)
> Note :
> - On peut aussi chosir une cible distante aussi. A noter que dans ce cas, la cible doit avoir SSH, et OpenSCAP (openscap-scanner ou openscap-utils)
> Après avoir tapé sur ENTRER, une liste de groupe de profiles de sécurité est proposé

- **Choose SSG content by number (empty for custom content)**: Entrer le numéro qui vous correspond (ici, 2 pour `ssg-centos7-ds.xml`)
- **Tailoring file (absolute path, empty for no tailoring)**: si le fichier est un profile personnalisé ou non. taper ENTRER (pour chosir `no tailoring`)
- **Found the following possible profiles**: les profiles de scan disponibles dans le SSG content chosi sont affichés
- **Choose profile by number (empty for (default) profile)**: Entrer le numéro du profile (ici, 3 pour standard)
- **Online remediation (1, y or Y for yes, else no)**: si on souhaite appliquer les remédiations automatiquement lors du scan ou non (ici, no)
> Note: après cette étape, on accède à la plannification du scan

- **not before (YYYY-MM-DD HH:MM in UTC, empty for NOW)**: Choisir la date de lancement du scan selon le format proposé (ex: 2020-04-28 01:00) (ici, NOW)
- **- repeat after (hours or @daily, @weekly, @monthly, empty or 0 for no repeat)**: Choisir une fréquence de répétition du scan (ici, @daily)
> Note: Task created with ID '1'. It is currently set as disabled. You can enable it with `oscapd-cli task 1 enable`.

Comme le suggère le messgage, il faut **activer** le scan pour qui'l soit lancé, à l'aide de la commande :
```
sudo oscapd-cli task 1 enable
```
> Note :
> - `oscapd-cli task --help` explique comment utiliser cette commande
> - `sudo oscapd-cli task 1 info` affiche les informations sur le scan. `sudo systemctl status -l oscapd` ou `sudo journalctl -u oscapd` ou `udo grep oscapd /var/log/messages` peut être utile aussi.
> - les tâches sont répertoiriés dans `/var/lib/oscapd/tasks/` et les résultats `/var/lib/oscapd/results`

#### Résultat de scan d'OpenSCAP Daemon
 Pour voir tous les résultats de cette tâche, on utilise l'action `result` de la commande `oscapd-cli` :
```
sudo oscapd-cli result 1
```
> Note : comme c'est une tâche plannifiée, il se peut que vous ayez plusieurs résultats disponibles, chacun étant identifié par son ID.

On peut générer un rapport pour un résultat donné de cette tâche. Pour cela, il faut spécifier l'**ID** du résultat sur la commande `oscapd-cli result` suivi de l'option `report`(pour HTML) ou `arf` (pour ARF):
```
sudo oscapd-cli result 1 ID_résultat report > oscapd-scan-report.html
sudo oscapd-cli result 1 ID_résultat arf > oscapd-scan-report.arf
```
> Note :
> - Pour plus d'informations sur l'outil, reportez vous à la [documentation](https://github.com/OpenSCAP/openscap-daemon/blob/master/README.md) ou au fichier `/usr/share/doc/openscap-daemon/README.md`
>
> Bugs:
> - Si vous rencontrez l'erreur [(UnicodeEncodeError: 'ascii' codec can't encode character u'\u2026...)](https://bugzilla.redhat.com/show_bug.cgi?id=1601901), ajoutez, dans `/bin/oscapd-cli`, après `import io`, ce bout de code:
> ```
import io
reload(sys)
sys.setdefaultencoding('utf8')
  ```

## Scan via OpenSCAP ScapTimony (foreman openscap)
ScapTimony est remplacé par ce nouveau projet [foreman_openscap](https://github.com/theforeman/foreman_openscap)

## Terminologies
- Acronymes OpenSCAP
  - SCAP (Security Content Automation Protocol)
  - OVAL (Open Vulnerability and Assessment Language)
  - XCCDF (Extensible Configuration Checklist Description Format)
  - OCIL (Open Checklist Interactive Language)
  - CPE (Common Platform Enumeration)
  - CCE (Common Configuration Enumeration)
  - CVE (Common Vulnerabilities and Exposures)
  - CVSS (Common Vulnerability Scoring System)
- Autres acronymes
  - NIST (National Checklist Program Repository)
  - PCI-DSS (Payment Card Industry Data Security Standard)

## Sources
- Documentation
  - [Site officiel d'OpenSCAP](https://www.open-scap.org/)
  - [OpenSCAP Tools](https://www.open-scap.org/tools/)
  - [Documentation & User Manuals](https://www.open-scap.org/resources/documentation/)
  - [OpenSCAP Daemon](https://github.com/OpenSCAP/openscap-daemon/blob/master/README.md)
  - [Foreman Openscap](https://github.com/theforeman/foreman_openscap)
  - [Foreman OpenSCAP manual]()
  - [Github OpenSCAP Security Guide Project](https://github.com/ComplianceAsCode/content/wiki)
  - [OVAL visualization](https://github.com/OpenSCAP/OVAL-visualization-as-graph/blob/master/docs/GUIDE.md)
  - [Acronymes](https://www.open-scap.org/resources/acronyms/)
- Tutoriels :
  - [Get started with OpenSCAP](https://www.open-scap.org/getting-started/)
  - [Foreman Quickstart Guide](https://theforeman.org/manuals/2.0/quickstart_guide.html)
  - [Redhat Vulnerability Scanning](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/vulnerability-scanning_scanning-the-system-for-configuration-compliance-and-vulnerabilities)
