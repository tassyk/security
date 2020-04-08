---
Title: Mise en place de Fail2ban
Catégorie: Hardening system
Date: 02/02/2020
Auteur: TK
---

# Mise en place de Fail2ban

## Introduction
Fail2ban est un outil de détection d'intrusion de la catégorie `HDIS (Host-based Intrusion Detection System)`. Il permet de bloquer des attaques par force brute sur bon nombre de services comme SSH, FTP, ... sur une machine (hôte). Il analyse les fichiers de log pour détecter les accès frauduleux ou suspects sur l'hôte puis s'appuie sur le firewall local (Iptables, Firewalld) pour banir les IP suspectes.
A l"heure actuelle, il est plus évolué et offre plus de possibilités que ces concurrents `Denyhost` ou encore `SSHGuard`.

## Installation de Fail2ban
Fail2ban est disponible sous forme de paquet sur une majorité de distribution Linux. Pour Centos, il existe dans les dépôts `EPEL`.
Pour l'installer, suivre les étapes suivantes:
1. Mettre à jour les paquets et installer le dépôt EPEL si ce n'est pas fait
```
sudo yum update -y
sudo yum install epel-release -y
```
2. Installer le paquet fail2ban
```
sudo yum install fail2ban -y
```
Cette commande installe tout un tas de paquets :
- fail2ban-server
- fail2ban-systemd
- fail2ban-mail
- fail2ban-firewalld
- fail2ban-sendmail
- fail2ban

3. Démarrer le service fail2ban
```
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

## Configuration de fail2ban
L'installation de fail2ban crée les fichiers et répertoires ci-dessous:
- action.d
- fail2ban.conf
- fail2ban.d
- filter.d
- jail.conf
- jail.d
- paths-common.conf
- paths-fedora.conf

Par défaut, fail2ban lit ses configurations et les banissements (jails) respectivement dans les fichiers `fail2ban.conf` et `jail.conf`. Il est recommandé de ne pas les modifier directement. Il faut les costumiser de deux manières :
1. en créant des fichiers `fail2ban.local` et `jail.local`
2. ou en créant des fichiers dans de configuration `fail2ban.d` et les jails (banissements) dans `jail.d`.

Nous allons laisser les configurations par défaut de fail2ban (niveau de log, fichier de log, ...) comme tels.

Pour définir les jails, nous allons choisir la deuximème méthode.

## Protection des services
Le fichier `jail.conf` propose des protections contre la plupart des services comme SSH, FTP, Dropbear, Apache, Selinux, ... Donc c'est une bonne référence!
### Protection SSH
Pour contrer les connexions frauduleuses sur SSH, créer un fichier `ssh.local` dans `jail.d` et ajouter ces contenus:
```
# /etc/fail2ban/jail.d/sshd.local

[DEFAULT]
bantime = 86400
ignoreip = 78.197.22.147 163.172.63.88

[sshd]
enabled = true
```
Où:
- `[DEFAULT]`: dans cette section, on définit les paramètres par défaut à tous les services qu'on souhaite protéger dans ce fichier.
  - `bantime`: défini en seconde, il exprime la durée pendant laquelle l'IP suspecte est bloquée (ici une heure)
  - `ignoreip`: indique les IP qui sont ignorer par fail2ban (pour éviter de banir ses propres ip!)
- `[sshd]`: dans cette section, on définit les paramètres pour le service sshd.
  - `enabled`: active la protection pour sshd

## Exploitation des résultats de fail2ban
- `sudo fail2ban-client status` affiche les status des jails
  - jail sshd: `fail2ban-client status sshd`
- `sudo tail -f /var/log/fail2ban.log`: analyse les logs pour voir les jails

## Quelques usages de la commande fail2ban-client
**Explorer les informations d'un jail :** Pour voir les informations sur jail (ex: sshd), taper la commande:
```
sudo fail2ban-client status sshd
```

**Débanir une IP :**
 Après le temps de banissement, l'IP est débloquée automatiquement. Mais si on souhaite le faire manuellement, voici-la commande.
```
sudo fail2ban-client set YOURJAILNAMEHERE unbanip IPADDRESSHERE
```
**Autres actions :** Pour voir les autres possibilités, taper cette commande sans options
```
sudo fail2ban-client | more
```



## Sources
- Fail2ban
  - [Tuto Fail2ban Microlinux](https://www.microlinux.fr/fail2ban-centos-7/)
  - [Tuto Fail2ban Tecmint](https://www.tecmint.com/use-fail2ban-to-secure-linux-server/)
  - [Tuto Fail2ban Ubuntu](https://doc.ubuntu-fr.org/fail2ban)

- IDS: 
  - [Liste IDS Wikipédia](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_d%C3%A9tection_d%27intrusion#Syst%C3%A8mes_de_d%C3%A9tection_d'intrusion_h%C3%B4tes)
  - Autre HIDS: Denyhost
    - [Tuto Denyhost www.it-connect.fr](https://www.it-connect.fr/proteger-son-acces-ssh-avec-denyhosts%EF%BB%BF/)
    - [Tuto Denyhost linoxide.co](https://linoxide.com/tools/install-denyhosts-centos-7/)
    - [Tuto Denyhost www.cyberciti.biz](https://www.cyberciti.biz/faq/rhel-linux-block-ssh-dictionary-brute-force-attacks/)
  -  [fail2ban vs denyhosts](https://qastack.fr/server/128962/denyhosts-vs-fail2ban-vs-iptables-best-way-to-prevent-brute-force-logons)
