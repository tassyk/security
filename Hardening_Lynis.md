---
Title: Audit Configuration Lynis
Type: Doc
Nature: Notes
Création: 14/05/2020
---

# Audit de configuration via Lynis
---
**Sommaire** 
- [Introduction](#Introduction)
- [Installation](#Installation)
- [Utilisation de Lynis](#Utilisation-de-Lynis)
---
## Introduction
Lynis est un outil d'audit de conformité d'un système. Il analyse un système afin d'identifier ses défauts de configuration. L'outil est très simple à utiliser.

Cette note décrit comment mettre en place cet outil sur un Centos7.

## Installation
L'installation peut se faire via `yum` :
```
sudo yum install -y epel-release
sudo yum --enablerepo=epel -y install lynis
```
> Note: Pour info :
> - fichier de configuration : `sudo vi /etc/lynis/default.prf`
> - fichier log : `/var/log/lynis.log`
> - rapport d'analyse : `/var/log/lynis-report.dat`

## Utilisation de Lynis
Pour auditer le système, on peut lancer un scan à l'aide de la commande ci-dessous :
```
sudo lynis audit system
```
> Note: Pour plus d'info sur la commande, cf `man lynis`

Cette commande scanne le système et affiche les défauts de configuration sur la sortie standard (par défaut). Voici un exemple de rapport :
```
...
* Consider hardening SSH configuration [SSH-7408]
    - Details  : PermitRootLogin (YES --> (NO|PROHIBIT-PASSWORD|WITHOUT-PASSWORD))
      https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : Port (22 --> )
      https://cisofy.com/lynis/controls/SSH-7408/

  * Consider hardening SSH configuration [SSH-7408]
    - Details  : TCPKeepAlive (YES --> NO)
      https://cisofy.com/lynis/controls/SSH-7408/
...
```
> Note :
> - avant chaque scan, on peut mettre à jour l'outil avec la commande `sudo lynis update check`
> - les informations sont affichées dans `stdout` par défaut. Mais pour plus de détails, voir le rapport `/var/log/lynis-report.dat`


## Sources
- Documentation
  - [Doc cisofy](https://cisofy.com/lynis/)
  - [Lynis security controle](https://cisofy.com/lynis/controls/file-integrity/)
- Tutorials
  - [cisofy Get started](https://cisofy.com/documentation/lynis/get-started/)
  - [server-world.info](https://www.server-world.info/en/note?os=CentOS_7&p=lynis)
  - [it-connect.fr](https://www.it-connect.fr/scan-de-votre-systeme-unix-avec-lynis/)
