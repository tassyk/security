---
Title: Scan Vulnérabilité OpenSCAP Workbech et Scanner
Type: Doc
Nature: Notes
Création: 21/04/2020
---

# Scan de vulnérabilité via OpenSCAP Workbech et Scanner
****
## Table of Contents

- **[Introduction](#introduction)**
- **[Scan via SCAP Workbench](##Scan-via-SCAP-Workbench)**
  - [Installation de SCAP Workbench](#Installation-de-SCAP-Workbench)
  - [Paramétrage de scan pour SCAP Workbench](#Paramétrage-de-scan-pour-SCAP-Workbench)
  - [Résultat de scan de SCAP Workbench](#Résultat-de-scan-de-SCAP-Workbench)
- **[Scan via OpenSCAP scanner](#Scan-via-OpenSCAP-scanner)**
  - [Installation d'OpenSCAP scanner](#Installation-d'OpenSCAP-scanner)
  - [Sélection d'un profile de scan pour OpenSCAP scanner](#Sélection-d'un-profile-de-scan-pour-OpenSCAP-scanner)
  - [Réalisation d'un scan via oscap](#Réalisation-d'un-scan-via-oscap)
  - [Application des remédiations](#Application-des-remédiations)
    - [Remédiation online](#Méthode-de-remédiation-online)
    - [Remédiation par scripts](#Remédiation-via-par-scripts)
- **[Autres utilitaires](#Autres-utilitaires)**
  - [Scan des machines distantes via oscap-ssh](#Scan-des-machines-distantes-via-oscap-ssh)
  - [Scan des conteneurs Docker via oscap-docker](#Scan-des-conteneurs-Docker-via-oscap-docker)
  - [Scan des VM à l'aide de oscap-vm](#Scan-des-VM-à-l'aide-de-oscap-vm)
  - [Scan de systèmes de fichiers arbitarires via oscap-chroot](#Scan-de-systèmes-de-fichiers-arbitarires-via-oscap-chroot)
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

A travers cette note, nous allons essayer d'explorer deux de ces outils, `SCAP Workbench` et `OpenSCAP Base (scanner)`. Et dans une autre note, nous découvrirons `OpenSCAP Daemon` et `SCAPTimony`.

## Scan via SCAP Workbench
SCAP Workbench permet de réaliser les mêmes types que "OpenSCAP scanner" grâce à l'aide d'une interface graphique. Il est facile à installer sur de nombreuses ditributions notamment Redhat, Centos, Fedora. Pour plus de renseignement sur l'outil, voir [SCAP Workbench User Manual](https://static.open-scap.org/scap-workbench-1.1/).

#### Installation de SCAP Workbench
L'installation se fait via la simple commande ci-dessous :
```
sudo yum install scap-workbench
```
Une fois installé, l'icône de l'outil apparaît dans la liste des applications. On peut l'ouvrir en cliquant sur cette icône ou en utilisant la commande ci-dessous depuis le terminal :
```
scap-workbench
```
#### Paramétrage de scan pour SCAP Workbench
Sur la fenêtre "**Openscap security guide**" qui s'ouvrir, sélectionnez votre distribution (ici Centos 7) puis cliquez sur le bouton "**Load Content**" pour charger le contenu de la politique de sécurité choisie. Vous accédez alors à une fenêtre où vous pouvez configurer les paramètres de votre scan (checklist, profil, Target, rules, ...). Libre à vous de choisir à votre convenence parmi les choix possibles.
> Remarque :
> - Il est aussi possible de personnaliser un profil donné en cliquant sur le bouton "Customize" pour générer le fichier XML du profil et le modifier.
> - Pour la cible de scan (Target), on peut choisir "Remote machine" pour scanner une machine distante. Dans ce cas, il faut s'assurer que celle-ci dispose bien SSH et openscap.
> - Avant de lancer le scan (bouton "SCAN"), on peut sélectionner d'autres paramètres supplémentaires comme :
>      - la généreration d'un script de remédiation ("Geneate remediation role");
>      - la remédiation automatique après le scan (case "Remediate").

Une fois tout est configuré, cliquez sur le bouton **SCAN** pour lancer le scan.

#### Résultat de scan de SCAP Workbench
Pour chaque règle (Rules), le scan vous indiquera ce qui a réussi ou échoué ou encore non vérifié dans l'interface de l'outil.

Quand le scan est complet, vous pouvez générer le rapport de scan dans plsieurs formats HTML, ARF, ou XCCDF ("Save Results"), voir immédaitement le rapport de scan ("Show Report"), générer le script de remédiation ("Generate remediation role").


## Scan via OpenSCAP scanner
**OpenSCAP scanner** est l'outil d'OpenSCAP permettant de réaliser des scan en ligne de commande.

#### Installation d'OpenSCAP scanner
L'outil se base sur des politiques de sécurité (Security Policy) pour les scans. Contrairement à Workbench où les politiques sont incorporées dans l'interface, pour le scanner, il faut installer une politique de sécurité lors de son installation. Ici, nous allons travailler avec la politique par défaut ([SCAP Security Guide (SSG)](https://github.com/ComplianceAsCode/content/wiki)). Voici donc les commandes d'installation :
```
sudo yum -y install openscap-scanner scap-security-guide
```

Les profiles de scan SCAP de SSG sont installés dans le répertoire `/usr/share/xml/scap/ssg/content/`. Ce sont des fichiers XML. Les profiles sont définis aux formats XCCDF, OVAL ou DataStream (-ds). On peut voir le contenu de ce répertoire à l'aide des commandes ci-dessous :
```
# voir toutes les politiques
sudo ls -l /usr/share/xml/scap/ssg/content/
# Voir uniquement les politiques ssg pour centos
sudo ls -1 /usr/share/xml/scap/ssg/content/ssg-centos*.xml
```
#### Sélection d'un profile de scan pour OpenSCAP scanner
Comme déjà expliqué plus haut, chaque security policy dispose des profiles de scan. Ce sont ces derniers qui déterminent les règles de scan. Dans notre cas, nous allons choisir le profile `ssg-centos7-xccdf.xml` pris au hasard.

A l'aide de la commande `oscap info`, on voir la description du profile de scan :
```
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```
> Cette commande nous renseigne certains détails sur le profile comme le status (draft), le type de profile (XCCDF), la version du Checklist, les référentiels appliqués dans ce profile (PCI-DSS v3.2.1 Control Baseline, Standard System Security Profile), ...


#### Réalisation d'un scan via oscap
Après avoir choisi le profile de scan, on peut maintenant réaliser un scan à l'aide de la commande `oscap`. Voici la sysntaxe de cette commande pour un scan :
```
sudo oscap [options] module eval [module_operation_options_and_arguments]
```
> Remarque :
>  - Les modules déterminent le type d'opération. Ils sont nombreux : xccdf, oval, cpe, cvss, .... Chaque module possède maintes options
>  - Plus de détails sur cette commande, cf [OpenSCAP oscap user_manual](https://static.open-scap.org/openscap-1.2/oscap_user_manual.html) ou `man oscap`

Pour lancer un scan, on peut utiliser la commande ci-dessous :
```
sudo oscap xccdf eval \
--profile standard \
--report report-ssg-centos7-xccdf.html \
/usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```
> Remarque :
>  - pour type de profile, on a sélectionné ici "standard" (Cf, oscap info). Mais on pouvait aussi choisir "pci-dss" si on souhaitait se conformer à ça. On choisit les profiles par leur ID.
>  - l'option ``-- report`` spécifie le fichier rapport (ici, report-ssg-centos7-xccdf.html)

Si on le souhaite, on peut aussi récupérer le résultat de scan dans un fichier XML (ex: arf-report-ssg-centos7-xccdf.xml). Pour cela, il suffit d'ajouter l'option `--results-arf` suivi du nom d'un fichier XML.
```
sudo oscap xccdf eval \
--profile standard \
--report report-ssg-centos7-xccdf.html \
--results-arf arf-report-ssg-centos7-xccdf.xml \
/usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```
> arf permet d'obtenir tous les résultats de scan.

A la fin du scan, on voit les échecs et les réussites du scan. Le rapport `report-ssg-centos7-xccdf.html` est généré contenant les détails du résultat du scan.

### Application des remédiations
Dans les rapports de scan, certaines recommandations sont proposées afin de remédier aux différentes de vulnérabilités ou défauts de configuration identifiés. Il existe plusieurs manière d'appliquer ces remédiations via OpenSCAP.

> Attention : Il faut appliquer les remédiations avec précaution.

#### Remédiation online
Dans ce cas, les remédiations sont appliquées lors du scan en ajoutant l'option `--remediate` à la commande `oscap` de scan ci-dessus :
```
sudo oscap xccdf eval \
--profile standard \
-- remediate \
--report report-ssg-centos7-xccdf.html \
/usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```
#### Remédiation par scripts
Les scripts de remédiation sont placés dans le répertoire `/usr/share/scap-security-guide/` lors de l'installation `scap-security-guide`.

Ces scripts sont disponibles en Bash, Ansible et kickstart. Ils sont situés dans les répertoires Bash, Ansible et kickstart pour chaque profile de scan. Exécutez les commandes ci-dessous pour explorer leur contenus :
```
# ansible
sudo ls -l /usr/share/scap-security-guide/ansible
# bash
sudo ls -l /usr/share/scap-security-guide/bash
# kickstart
sudo ls -l /usr/share/scap-security-guide/kickstart
```
**Ansible** :
Pour appliquer une remédiation via ansible, on utilise une des méthodes ci-dessous :
```
$ ansible-playbook -i "192.168.1.155," playbook.yml
$ ansible-playbook -i inventory.ini playbook.yml

# Exemple
 ansible]$ ansible-playbook -i "localhost," -c local /usr/share/scap-security-guide/ansible/ssg-centos7-role-default.yml
```
> Note : Dans chaque playbook ansible de remédiation, il est expliqué comment l'utiliser.

**Bash** :
Pour les scripts Bash, il faut simplement les exécuter comme indiqués dans chaque script :
```
# How to apply this remediation role:
# $ sudo ./remediation-role.sh
```


### Autres utilitaires
#### Scan des machines distantes via oscap-ssh
Sur OpenSCAP Workbench, nous avons vu que, pour le scan, on pouvait choisir une cible distante (Target: Remote machine). En ligne de commande, il est possible aussi de scanner une machine distante via l'outil `oscap-ssh` fournit avec OpenSCAP. Son utilisation est comme `oscap`. En reprenant notre exemple, on utilisera cette commande :
```
oscap-ssh root@remote_machine 22 xccdf eval \
--profile standard \
--report report-ssg-centos7-xccdf.html \
--results-arf arf-report-ssg-centos7-xccdf.xml \
/usr/share/xml/scap/ssg/content/ssg-centos7-xccdf.xml
```
> Note :
> - sur l'hôte distant SSH et OpenSCAP (openscap-scanner ou openscap-utils) doivent être installés;
> - l'utilisateur ssh doit exister sur la machine distante et avoir des droits suffisants pour effectuer ces opérations;
> - l'outil ne peut évaluer que les profiles DataStreams ou OVAL.

#### Scan des conteneurs Docker via oscap-docker
OpenSCAP fournit la commande `oscap-docker` afin de réaliser des scans sur les conteneurs Docker. Le scan est réalisé en mode offline. En effet, les systèmes de fichiers du conteneur sont montés sur un répertoire de la machine locale. Ce qui fait que le conteneur subit aucune altération pour le scan.
> Prérequis: pour utiliser cette commande, il faut remplir certaines conditions :
>  - Avoir docker sur la machine
>  - Avoir les images docker à scaner
>  - installer Atomic sur la machine. Atomic est une solution de gestion des conteneurs. C'est ce dernier qui permet à oscap-docker d'accéder au conteneur à scanner.

Les syntaxes de la commande sont les suivantes :
```
# Compliance scan of Docker image
    Usage: oscap-docker image IMAGE_NAME OSCAP_ARGUMENT [OSCAP_ARGUMENT...]
# Compliance scan of Docker container
    Usage: oscap-docker container CONTAINER_NAME OSCAP_ARGUMENT [OSCAP_ARGUMENT...]
# Vulnerability scan of Docker image
    Usage: oscap-docker image-cve IMAGE_NAME [--results oval-results-file.xml [--report report.html]]
# Vulnerability scap of Docker container
    Usage: oscap-docker container-cve CONTAINER_NAME [--results oval-results-file.xml [--report report.html]]
```
> Note : pour plus de détails, cf `man oscap-docker`

Pour ce scan, nous allons procéder comme suit :
1. Installer Atomic sur la machine locale
```
sudo yum install -y atomic
```
2. Télécharger un conteneur docker rhel7
```
# chercher les images rhel7
docker search rhel7
# télécharger une image
docker pull lionelman45/rhel7
```
2. Scanner l'image via la commande `oscap-docker`
  - Scan de vulnérabilité de l'image via l'option `image-cve`:
```
sudo oscap-docker image-cve lionelman45/rhel7 --report report-docker-rhel7-vuln.html
```
 - Scan de conformité de l'image rhel7 par rapport au profile `ssg-rhel7-ds.xml`
```
# info du profile
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
# lancer le scan
 sudo oscap-docker image lionelman45/rhel7 xccdf eval --report report-docker-rhel7-compliance.html --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
```
> Attention : bien choisir le bon profile

#### Scan des VM à l'aide de oscap-vm
OpenSCAP fournit également la commande `oscap-vm` qui permet de scanner des machines virtuelles depuis une plateforme de virtualisation (Vmware, Proxmox, ...). A l'image de `oscap-docker`, le se scan est fait en mode `offline`.
La syntaxe de cette commande est :
```
oscap-vm domain VM_DOMAIN [OSCAP_OPTIONS] INPUT_CONTENT
oscap-vm image VM_STORAGE_IMAGE [OSCAP_OPTIONS] INPUT_CONTENT
```
Par exemple, pour évaluer un contenu OVAL pour une VM rhel6, on peut utiliser la commande ci-dessous :
```
oscap-vm image /var/lib/libvirt/images/rhel6.qcow2 oval eval \
--report report.html --results results.xml \
com.redhat.rhsa-RHEL6.xml
```
> Note :
> Cette commande s'appuie sur bash, guestmount, mktemp et umount pour bien fonctionner. Pour disposer de guestmount, installer le paquet libguestfs et libguestfs-tools: `sudo yum install -y libguestfs libguestfs-tools`
> Pour plus d'info, cf `man oscap-vm`.

#### Scan de systèmes de fichiers arbitarires via oscap-chroot
La commande `oscap-chroot` d'OpenSCAP donne la possibilité de scanner un système de fichier monté sur un répertoire arbitraire sur le système (un objet qu'on ne peut scanner via oscap-docker ou oscap-vm). Dans ce cas également, le scan est en mode offline.
Sa syntaxe est :
```
# Evaluation of XCCDF content
oscap-chroot CHROOT_PATH xccdf eval [options] INPUT_CONTENT
# Evaluation of OVAL content
oscap-chroot image CHROOT_PATH oval eval [options] INPUT_CONTENT
```


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
  - [Github OpenSCAP Security Guide Project](https://github.com/ComplianceAsCode/content/wiki)
  - [Acronymes](https://www.open-scap.org/resources/acronyms/)
  - [Atomic Docker Scan](http://www.projectatomic.io/)
- Tutoriels :
  - [Get started with OpenSCAP](https://www.open-scap.org/getting-started/)
  - [Redhat Vulnerability Scanning](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/vulnerability-scanning_scanning-the-system-for-configuration-compliance-and-vulnerabilities)
  - [Tuto userver-world.info sur OpenSCAP](https://www.server-world.info/en/note?os=CentOS_7&p=openscap)
  - [the-practical-linux-hardening-guide](https://github.com/trimstray/the-practical-linux-hardening-guide/blob/master/README.md)
