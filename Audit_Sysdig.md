---
Title: Audit - Analyse via Sysdig
Type: Doc
Nature: Notes
Création: 10/05/2020
---

# Audit - Analyse système via Sysdig

## Introduction
[Sysdig](https://github.com/draios/sysdig/wiki) est un outil d'audit et d'analyse d'un système (VM, Conteneurs). Il permet d'analyser les activiés des utilisateurs, des processus, l'utilisation des CPU , ... sur une machine, mais aussi les flux réseaux, les connexions entrantes et sortantes, pour ne citer que ça. Il peut être utilisé même pour les investigations forensiques. D'autres outils comme [Falco](https://falco.org/#resources) utilisent les filtres de Sysdig. Pour interagir avec l'outil, on utilise la commande `sysdig`.

## Notions à connaître
Pour mieux comprendre Sysdig, certains éléments sont à connaître :
- [Filtres](https://github.com/draios/sysdig/wiki/Sysdig-User-Guide) : Ce sont des expressions à utiliser pour surveiller un événement (ex: lecture, ouverture d'un fichier, processus, ...). Ils classés par catégories (`fd`, `process`, `evt`, `user`, `group`, `container`, `k8s`, ...). Voici quelques exemples de filtre :
  - `evt.type` : type d'événement
  - `proc.name`: nom du processus
  - `fd.filename`: nom d'un fichier
  - `user.name` : nom de l'utilisateur et `user.shell`, son shell
- [Chisels](https://github.com/draios/sysdig/wiki/Chisels-User-Guide) : ce sont des mini fonctions (script) qui analysent les flux d'événements de sysdig pour effectuer un ensemble d'actions (ex: tracer les activités des utilisers, fichiers les plus consultés, ...). Pour invoquer un chisel avec la commande `sysdig`, on utilise l'option `-c` (ex: `sysdig -c topfiles_bytes`). Et l'option `-i` permet d'afficher les détails sur un chisel donné (ex: `sysdig -i spy_ip`). Comme exemples de chisel, on peut citer :
  - `topfiles_bytes` : utilisations disque par les fichiers
  - `spy_users` : activités des utilisateurs
  - `spy_ip` : activités d'une IP
  - `topscalls_time` : appels systèmes plus longs
- [Tracers](https://github.com/draios/sysdig/wiki/Tracers) : permettent de suivre et de mesurer les durées d'exécution dans un système logiciel
- ``Outputs`` : correspondent aux sorties de la commande `sysdig`. Ils sont formés des filtres précédés du signe `%`. Ils sont invoqués avec l'option `-p` (ex: `sysdig -p"%evt.arg.path"`)

On peut combiner tous ces trois éléments pour affiner l'analyse et la recherche d'un événement.

On peut  le format de sotie de la commande sysdig en utilisant le même

## Installation de sysdig
Plusieurs méthodes sont fournies pour [l'installation](https://github.com/draios/sysdig/wiki/How-to-Install-Sysdig-for-Linux) de l'outil, notamment un script. Dans cette note, nous allons utiliser ce script pour installer Sysdig :
```
curl -s https://s3.amazonaws.com/download.draios.com/stable/install-sysdig | sudo bash
```
> Note : si curl n'est pas installé, il faut le faire avant.

## Utilisation de sysdig
La commande permet d'interagir avec l'outil. Voici quelques exemples d'utilisation de la commande :
- ouvertures de fichiers
```
# ouverture de fichier /etc/passwd
sudo sysdig "fd.filename=passwd and evt.type=open"
# échecs d'ouverture par httpd
sudo sysdig "proc.name=httpd and evt.type=open and evt.failed=true"
```
- observer les activités sur SSH
```
sudo sysdig -A -c echo_fds fd.name=/dev/ptmx and proc.name=sshd
```
- répertoires consultés par un utilisateur
```
sudo sysdig -p"%evt.arg.path" "evt.type=chdir and user.name=root"
```
- Analyser les fichiers les plus accédés
```
sudo sysdig -c topfiles_bytes  
# excluant le répertoire /dev
sudo sysdig -c topfiles_bytes "not fd.name contains /dev"
# ouverts par l'éditeur vi
sudo sysdig -c topfiles_bytes "proc.name=vi"  
# ouverts par l'utilisateur user
sudo sysdig -c topfiles_bytes "user.name=user"  
```
- connexions établies sur les ports
```
sudo sysdig -c fdcount_by fd.sport "evt.type=accept"  
```

D'autres exemples sont disponibles sur le [github de sysdig ](https://github.com/draios/sysdig/wiki/Sysdig-Examples). Les deux liens ci-dessous montrent comment utiliser sysdig dans le cadre d'une analyse forensique :
- [Fishing for Hackers: Analysis of a Linux Server Attack](http://draios.com/fishing-for-hackers/)
- [Fishing for Hackers (Part 2): Quickly Identify Suspicious Activity With Sysdig](http://draios.com/fishing-for-hackers-part-2/)
