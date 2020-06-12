---
Title: Mise en place de Fail2ban
Catégorie: Hardening system
Date: 02/02/2020
Auteur: TK
---

# Mise en place de Fail2ban

## Introduction
Fail2ban est un outil de détection d'intrusion de la catégorie `HDIS (Host-based Intrusion Detection System)`. Il permet de bloquer des attaques par force brute sur bon nombre de services comme SSH, FTP, ... sur une machine (hôte). A l'aide des filtres, il analyse les fichiers de log pour détecter les événements suspects sur l'hôte puis déclenche une action grâce au firewall local (Iptables, Firewalld) pour banir les IP/hôtes suspects.
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
- action.d : répertoire des actions (fichiers contenant des règles de firewall par exemple)
- fail2ban.conf : fichier de configuration principal de l'outil
- fail2ban.d : répertoire des fichiers de configuration utilisateurs
- filter.d : répertoire pour les filtres (se sont des fichiers contenant des expressions régulières)
- jail.conf : fichier de configuration principal relatifs aux jails 
- jail.d : répertoire pour les jails (chaque service surveillé constitue un jail)
- paths-common.conf : fichier de configuration définissant les chemins des fichiers de log commons
- paths-fedora.conf : fichier de configuration définissant certains chemins des fichiers de log spéficiques

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
# cat /etc/fail2ban/jail.d/sshd.local

[DEFAULT]
bantime = 86400
ignoreip = 127.0.0.1

[sshd]
port = ssh
enabled = true
maxretry = 3
logpath = %(sshd_log)s
```
Où:
- `[DEFAULT]`: dans cette section, on définit les paramètres par défaut à tous les services qu'on souhaite protéger dans ce fichier.
  - `bantime`: défini en seconde, il exprime la durée pendant laquelle l'IP suspecte est bloquée (ici une heure)
  - `ignoreip`: indique les IP qui sont ignorer par fail2ban (pour éviter de banir ses propres ip!)
- `[sshd]`: dans cette section, on définit les paramètres pour le service sshd.
  - `enabled`: active la protection pour sshd
  - `port`: spécifie le port de SSH (ici ssh, mais on peut mettre autre chose comme 22, 2222, ...)
  - `maxretry`: spécifie le nombre d'essaie d'authentification autorisé
  - `logpath`: spécifie le chemin du fichier où trouver les logs du service à surveiller (ici, la valeur par défaut, mais on peut mettre par exemple /var/log/auth.log ou autre chose selon le service)

 **Remarque sur la gestion des log :** 
 - si on souhaite envoyer les journaux d'événement de fail2ban plutôt vers Syslog, on peut créer un fichier `.local` dans le répertoire de configuration de fail2ban et y spécifier le paramètre `logtarget` comme ceci:
 ```
 #cat /etc/fail2ban/fail2ban.d/fail2ban.local
 [DEFAULT]
 logtarget = SYSLOG
 ```
- si par contre, si on envoie les logs vers un autre fichier (ex: `/var/log/fail2ban/fail2ban.log`), il ne faut pas oublier d'indiquer ce chemin dans le fichier de rotation `/etc/logrotate.d/fail2ban`

### Protection du service Apache
On peut aussi définir un jail pour contrôler d'autres services. Par exemple, pour bloquer les accès frauduleux vers le serveur web apache (httpd)  :
```
# cat /etc/fail2ban/jail.d/httpd.local
[DEFAULT]
bantime = 24h
ignoreself = True
ignoreip = 127.0.0.1

[apache-auth]
port     = http,https
logpath  = %(apache_error_log)s

[apache-badbots]
port     = http,https
logpath  = %(apache_access_log)s
bantime  = 48h
maxretry = 1

[apache-noscript]
port     = http,https
logpath  = %(apache_error_log)s
```
## Notification par mail
Si la machine dispose d'un service SMTP, alors Fail2ban peut être configuré pour envoyer des notifications via mail en cas détection. Pour cela, ajouter les lignes ci-dessous au niveau de la section **DEFAULT** de chaque jail :
```
# cat /etc/fail2ban/jail.d/httpd.local
[DEFAULT]
...
mta = sendmail
destemail = emal@adress
sender = fail2ban
action = %(action_mwl)s
```
Où :
- `mta` : spécifie le service de mail (sendmail)
- `destemail` : spécifie le destinataire
- `sender` : (optionnel) spécifie l'expéditeur
- `action` : spécifie l'action d'envoie de mail (%(action_mwl)s, ici, pour inclure les logs). Mais on peut choisir aussi `%(action_mw)s` pour ne pas inclure les logs.

## Exploitation des résultats de fail2ban
Fail2ban fournit un utilitaire, `fail2ban-client` très complet. Il permet de réaliser l'ensemble des configurations possible avec les fichiers de configuration (fail2ban.conf, jail.conf), mais aussi d'exploiter les résultats.

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

## Quelques mots sur les filtres
Les filtres sont des expressions régulières permettant de parser (analyser) un type de logs afin de chercher des événements particuliers. Le répertoire **filtre.d** contient un ensemble de filtres pour la plupart des applications et services très connus. Ce qui dispense de dépenser son énergie pour en créer. Mais il est tout à fait possible de définir ses propres filtres.

### Définition d'un filtre
Considérons la ligne de log ci-dessous :
```
Jan 10 07:02:37 homebrou sshd[18419]: Failed password for root from 222.76.213.151 port 55236 ssh2
```
On peut chercher l'événement **Failed password for root from 222.76.213.151** dans cette ligne à l'aide du filtre ci-dessous:
```
Failed [-/\w]+ for .* from <HOST>
```
A l'aide de l'utilitaire `fail2ban-regex` de Fail2ban, on peut tester si notre filtre est bon ou pas. La syntaxe de la commande est :
```
fail2ban-regex <fichier-de-log | string-représentant-une-ligne-de-log> <chemin-du-filtre | string-regex> [<chemin-du-filtre | string-ignoregex]
```
Pour notre exemple, on peut donc écrire ceci :
```
sudo fail2ban-regex 'Jan 10 07:02:37 homebrou sshd[18419]: Failed password for root from 222.76.213.151 port 55236 ssh2' 'Failed [-/\w]+ for .* from <HOST>'
```

Quand le test est concluant, on peut alors créer un filtre nommé **myssh-filter** dans le répertoire des filtres pour chercher de tels événements :
```
# cat /etc/fail2ban/filter.d/myssh-filter.conf

[Definition]
failregex =  Failed [-/\w]+ for .* from <HOST>
ignoreregex =
```

### Utilisation d'un filtre
Une fois que le filtre est créé, on peut l'utiliser en définissant un jail dans lequel on spécifie ce filtre comme suit :
```
[myssh]
enabled = true
filter = myssh-filter
port = 22 
logpath = /var/log/secure
maxretry = 5
findtime = 120
bantime = 300
```

**Remarque sur les filtres multi lignes :**

On peut utiliser plusieurs expressions régulières dans un filtre. Dans ce cas, chaque expression est écrite sur une ligne. Si on applique à notre exemple de log ci-dessous, on peut utiliser ce filtre ci-dessous :
```
failregex = Authentication failure for .* from <HOST>
            Failed [-/\w]+ for .* from <HOST>
            ROOT LOGIN REFUSED .* FROM <HOST>
            [iI](?:llegal|nvalid) user .* from <HOST>
```

## Sources
- Fail2ban
  - [Fail2ban Main page](https://www.fail2ban.org/wiki/index.php/Main_Page)
  - [Fail2ban Github](https://github.com/fail2ban/fail2ban)
  - [Tuto Fail2ban Microlinux](https://www.microlinux.fr/fail2ban-centos-7/)
  - [Tuto Fail2ban Tecmint](https://www.tecmint.com/use-fail2ban-to-secure-linux-server/)
  - [Tuto Fail2ban Ubuntu](https://doc.ubuntu-fr.org/fail2ban)
  - [Tuto Fail2ban Buzut](https://buzut.net/installer-et-parametrer-fail2ban/)
  - [Tuto Fail2ban Ubuntu | Protection apache](https://www.digitalocean.com/community/tutorials/how-to-protect-an-apache-server-with-fail2ban-on-ubuntu-14-04)
  - [Options de configuration des jails](https://www.systutorials.com/docs/linux/man/5-jail.conf/)
  - [Installation via Ansible](https://github.com/tassyk/ansible-fail2ban)

- IDS: 
  - [Liste IDS Wikipédia](https://fr.wikipedia.org/wiki/Syst%C3%A8me_de_d%C3%A9tection_d%27intrusion#Syst%C3%A8mes_de_d%C3%A9tection_d'intrusion_h%C3%B4tes)
  - Autre HIDS: Denyhost
    - [Tuto Denyhost www.it-connect.fr](https://www.it-connect.fr/proteger-son-acces-ssh-avec-denyhosts%EF%BB%BF/)
    - [Tuto Denyhost linoxide.co](https://linoxide.com/tools/install-denyhosts-centos-7/)
    - [Tuto Denyhost www.cyberciti.biz](https://www.cyberciti.biz/faq/rhel-linux-block-ssh-dictionary-brute-force-attacks/)
  -  [fail2ban vs denyhosts](https://qastack.fr/server/128962/denyhosts-vs-fail2ban-vs-iptables-best-way-to-prevent-brute-force-logons)
