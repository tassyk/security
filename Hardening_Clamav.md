---
Title: Mise en place de Clamav
Catégorie: Hardening système
Nature: Notes
Date de création: 14/04/2020
---

# Mise en place de l'antivirus Clamav

## Introduction
ClamAV ou Clam Antivirus est un antivirus opensource pour les distributions UNIX. Il fournit une suite d'outils pour effectuer diverses opérations telles que la mise à jour de la base de signatures de l'antivirus, le scan du système.
Cet article décrit comment le mettre en oeuvre sur une machine CentOS 7.

## Installation
Les paquets d'installation de Clamav sont disponibles dans le dépôt EPEL. Tout d'abord, il faut mettre à jour le système puis installer ce dépôt si ce n'est déjà fait, puis installer les différents paquets de Clamav.
```
# Mise à jour
sudo  yum -y update

# dépôt EPEL & mis à jour
sudo yum -y install epel-release
sudo yum -y update

# Nettoyage des caches
sudo yum clean all

# Clamav
sudo yum -y install clamav-server clamav-data clamav-update clamav-filesystem clamav clamav-scanner-systemd clamav-devel clamav-lib clamav-server-systemd
```

Après ces commandes, si SELinux est activé sur la machine, il faut activer les politiques SELinux (booléens) pour l'antivirus pour que Clamv fonctionne :
```
# Voir le status de SELinux
sudo sestatus

# Voir les booléens pour l'antivirus et leur état
sudo semanage boolean -l | antivirus

# activer ces booléens
sudo setsebool -P antivirus_can_scan_system 1
sudo setsebool -P antivirus_use_jit 1
```
> Vous pouvez revérifier si les booléens sont biens activés (cf `sudo semanage boolean -l | antivirus`)

## Configuration
Par défaut, deux fichiers de configurations sont générés par l'installation :
- **/etc/freshclam.conf** : fichier de configuration pour la base de données de l'antivirus Clam AntiVirus
- **/etc/clamd.d/scan.conf** : fichier de configuration du daemon de l'antivirus Clam Antivirus

> ***Remarques*** :
  - Dans les deux fichiers, il faut s'assurer que la ligne commençant par ***Example*** est commenté ou supprimé sinon l'antivirus ne fonctionne. En effet, avec mot, ces fichiers sont considérés comme des exemples.
  - Aussi, dans le fichier ***/etc/clamd.d/scan.conf***, il faut s'assurer que la ***LocalSocket /var/run/clamd.scan/clamd.sock*** est décommenté.

Excepté ces remarques ci-dessus, les fichiers de configuration n'ont pas besoin d'être changés dans la plupart du temps, sauf si on souhaite modifier les valeurs de certains paramètres comme :
- ***LogFile*** : pour changer le fichier de log
- ***LogSyslog***: pour l'envoie des log vers syslog ou non (par défaut, c'est yes)
- Et autres paramètres comme l'utilisateur, la verbosité des logs, les rotations des fichiers de logs, la facility syslog, ...
> ***Remarque*** :
  - *LogFile* et *LogSyslog* ne fonctionnent pas ensemble. Il faut définir l'un ou l'autre.
  - Pour plus d'info, cf `man freshclam.conf` et `man clamd.conf`ou explorer le contenu de ces fichiers de configuration

Pour vérifier si les configurations sont correctes, on peut utiliser la commande ci-dessous :
```
sudo clamconf
```
> ***Remarque*** : en ajoutant `-g CONFIG_NAME ou --generate-config=CONFIG_NAME` cette commande peut nous regénérer un exemple fichier de configuration. Les valeurs valables pour `CONFIG_NAME` sont : `clamd.d/scan.conf, freshclam.conf, mail/clamav-milter.conf`. Par exemple :
- Générer un exemple de configuration de scan.conf
```
sudo clamconf -g clamd.d/scan.conf >> myclamd.conf
```

## Lancement des services
Après avoir revu les configurations, on peut lancer une première commande pour mettre à jour la base de données de l'antivirus :
```
sudo freshclam
```
Une fois cette opération réalisée, on peut maintenant démarrer les services :
```
# Démarrage de freshclam
sudo systemctl start clamav-freshclam
sudo systemctl enable clamav-freshclam

# Démarrage de Clamd
sudo systemctl start clamd@scan
sudo systemctl enable clamd@scan
```

## Mise à jour et scan
C'est la commande `freshclam [options]` qui permet de mettre à jour la base de signatures de l'antivirus Clam AV. Par exemple, pour mettre à jour manuellement la base :
```
sudo freshclam
```
Pour les [opréations de scan](https://www.clamav.net/documents/scanning), on peut utiliser la commande `clamscan [options] [file/directory/-]`. Sans options, elle scanne le répertoire courant. Par exemple pour scanner les fichiers infectés des répertoires /home /root
```
sudo clamscan --infected --recursive /home /root
# et supprimer les fichiers infectés
sudo clamscan --infected --remove --recursive /home /root
# et stoquer les résultats vers un fichier
sudo clamscan --infected --recursive /home /root -l result.txt
```

Pour réaliser ces opérations automatiquement, ont peut créer des tâches cron. Pour ce faire :
1. Lancer crontab de l'utilisateur qui va exécuter ces tâches
```
[sudo] crontab -e
```
2. Ajouter les tâches de mise à jour et/ou le scan
```
# mise à jour de la base à 1h et 13h
00 01,13 * * *  /usr/bin/freshclam --quiet
# scanner des fichiers infectés des répertoires /bin /sbin /root
00 04 * * * /usr/bin/clamscan --infected --recursive /bin /sbin /root --quiet -l result.txt
```

## (Optionnel) changement des noms des services clamav-freshclam et clamd@scan
Si les noms des services ne vous plaisent pas, il est possible de les changer par quelque chose de plus court comme clamd et freshclam. Pour cela, procédez comme suit :
1. renommer les fichiers des services :
```
# Copier d'abord avant de supprimer
sudo cp /usr/lib/systemd/system/clamd@.service  /usr/lib/systemd/system/clamd.service
sudo cp /usr/lib/systemd/system/clamav-freshclam.service /usr/lib/systemd/system/freshclam.service
```
2. Dans le fichier clamd.service, remplacer %i.conf" par le nom du fichier de configuration (par défaut, "scan.conf")
```
ExecStart = /usr/sbin/clamd -c /etc/clamd.d/%i.conf
```
devient
```
ExecStart = /usr/sbin/clamd -c /etc/clamd.d/scan.conf
```
3. recharger le daemon systemd :
```
# daemon relod
sudo systemctl daemon-reload
```
4. redémarrer les nouveaux services :
```
# démarrage clamd
sudo systemctl start clamd
sudo systemctl enable clamd
# démarrage freshclam
sudo systemctl start freshclam
sudo systemctl enable freshclam
```
5. Vérifier que les démons sont bien démarrés
```
sudo systemctl status freshclam
sudo systemctl status clamd
```
6. Arrêter et désactiver les anciens services
```
# Démarrage de freshclam
sudo systemctl stop clamav-freshclam
sudo systemctl disable clamav-freshclam
#  Clamd
sudo systemctl stop clamd@scan
sudo systemctl disable clamd@scan
```
7. Supprimer les anciens fichiers de service
```
sudo rm -f /usr/lib/systemd/system/clamd@.service /usr/lib/systemd/system/clamav-freshclam.service
# puis un peu de reload
sudo systemctl daemon-reload
```

## Liens
- [Clamav documentation](https://www.clamav.net/documents/clam-antivirus-user-manual)
- [Tuto Clamav Hostpresto](https://hostpresto.com/community/tutorials/how-to-install-clamav-on-centos-7/)
- [Tuto Clamav Hostinger](https://www.hostinger.com/tutorials/how-to-install-clamav-centos7)
- [Clamav ansible role](https://github.com/geerlingguy/ansible-role-clamav)
- [Troubleshooting](https://www.clamav.net/documents/troubleshooting-faq)
