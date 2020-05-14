---
Title: Détection rootkits
Type: Doc
Nature: Notes
Création: 14/05/2020
---

# Détection des rootkits via RkHunter
## Introduction
Les Rootkits sont des programmes permettant de dissimuler une activité, malveillante ou non, sur une machine.
Cette note décrit comment mettre en place l'outil Rkhunter afin de détecter des `rootkits` sur un système Centos7.

## Installation
L'installation peut se faire via `yum` :
```
sudo yum install -y epel-release
sudo yum --enablerepo=epel -y install rkhunter
```
> Note : si on le souhaite, on peut modifier les paramètres de configuration dans `/etc/rkhunter.conf`

Ensuite, il faut mettre la base de données et les propriétés du système de fichier :
```
sudo rkhunter --update
sudo rkhunter --propupd
```
> Note :
> - si certaines bases n'ont pas pu êtres installées, cf `/var/log/rkhunter/rkhunter.log`, pour voir les commandes d'installation.
> - cette opération peut prendre quelques minutes

## Recherche des rootkits
On peut analyser le système à l'aide de la commande ci-dessous :
```
sudo rkhunter --check --sk
```

## Sources
- Documentation
  - [Rootkits sur wikipedia](https://en.wikipedia.org/wiki/Linux_malware#Rootkits)
- Tutorials
  - [server-world.info](https://www.server-world.info/en/note?os=CentOS_7&p=rkhunter)
  - [www.theurbanpenguin.com/](https://www.theurbanpenguin.com/install-rkhunter-on-centos-7/)
