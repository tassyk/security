---
Title: Mise en place d'AIDE
Catégorie: Hardening système
Nature: Notes
Date de création: 13/04/2020
---

# Mise en place d'AIDE
## Introduction
[AIDE](https://aide.github.io/) (Advanced Intrusion Detection Environment) est une solution de monitoring (contrôle) d'intégrité des systèmes de fichiers. A l'image de [Auditd](https://github.com/tassyk/security/blob/master/hardening_auditing_system.md), il surveille un système de fichiers afin de détecter les différentes modifications qui y sont apportées.
A travers cet article, nous allons montrer comment mettre en place cette solution sur un serveur Centos7 afin de contrôler l'intégrité des fichiers du système.

## Installation de l'AIDE
L'installation est simple. Il suffit d'exécuter les commandes ci-dessous:
```
sudo yum update
sudo yum install aide
```
La solution AIDE se base sur l'utilisation d'une base de données (ou base de signature pour être plus exact) contenant toutes les signatures (les hash, permettant le contrôle d'intégrité) des fichiers et dossiers à surveiller. Cette base de données est initialisée à l'aide de la comande :
```
sudo aide --init
```
L'opération peut prendre quelques minutes en fonction de l'état de système et du nombre de fichiers et dossiers à surveiller (par défaut, c'est tout le système de fichiers qui est concerné).
La commande crée la base de données **/var/lib/aide/aide.db.new.gz**. Mais il faut renommer ce fichier pour qu'AIDE puisse opérer :
```
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```
A présent, nous pouvons effectuer une première comparaison entre l'état enregistré de nos fichiers dans la base de signature et leur état actuel grâce à la commande ci-dessous :
```
sudo aide --check
```
Comme aucune modification n'a été effectuée sur le système depuis l'initialisation de la base de données d'AIDE, il se peut que la commande n'ait rien à signaler à cette étape.

Pour voir AIDE en action, on peut faire un test de vérification du fonctionnement en créant par exemple un fichier sur le système :
```
sudo touch /usr/local/bin/test
```
En vérifiant à nouveau à l'aide de la commande `sudo aide --check`, AIDE nous révèle les modifications apportées au système:
```
AIDE 0.15.1 found differences between database and filesystem!!
Start timestamp: 2020-04-13 14:29:40

Summary:
  Total number of files:        77074
  Added files:                  1
  Removed files:                0
  Changed files:                1


---------------------------------------------------
Added files:
---------------------------------------------------

added: /usr/local/bin/test
```
Pour prendre en compte une modification légitime, il faut mettre à jour la base de données d'AIDE puis utiliser celle-ci :
```
sudo aide --update
sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
```
## Configuration d'AIDE
Par défaut, la configuration d'AIDE se trouve dans le fichier **/etc/aide.conf**.
### Structure du fichier de configuration
Le fichier est riche en informations :
- répertoires de la base et des logs :
```
@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide
```
- Les différets paramètres pour construire les règles :
```
# These are the default rules.
#p:      permissions
#i:      inode:
#n:      number of links
#u:      user
#g:      group
#s:      size
#b:      block count
#m:      mtime
...
```
- Construction des règles de contrôle d'intégrité :
```
# For directories, don't bother doing hashes.
DIR = p+i+n+u+g+acl+selinux+xattrs
# Access control only.
PERMS = p+u+g+acl+selinux+xattrs
...
```
- Les fichiers et répertoires à surveiller avec la règle de contrôle associée pour chaque élément. Ces fichiers sont classés par catégories (database, network, ...) :
```
# trusted databases
/etc/hosts$ CONTENT_EX
/etc/host.conf$ CONTENT_EX
/etc/hostname$ CONTENT_EX
/etc/issue$ CONTENT_EX
...
# networking
/etc/hosts.allow$   CONTENT_EX
/etc/hosts.deny$    CONTENT_EX
/etc/firewalld/ CONTENT_EX
...
```
### Explication de certains attributs
- Le **$** à la fin est le même $ que dans une expression régulière, donc précise la fin du mot. Exemple pour indiquer exactement un fichier :
```
/etc/hosts.allow$
```
- Le **!** indique l'exclusion. Par exemple, pour exclure tout le contenu de /etc :
```
!/etc/.*~
```
- Le **=** indique que l'on contrôlera un dossier, mais pas ses objets enfants. Exemple :
```
=/tmp
```
Pour plus d'informations sur ce fichier, voir `man aide.conf`

### Configurations personnalisées
A travers le fichier de configuration, on remarque qu'AIDE surveille tout le système de fichier. Cependant, rien ne nous oblige à surveiller tous les fichiers, d'autant plus que le contrôle peut devenir très fastidieux si les fichiers changent très souvent sur le serveur.
On peut modifier ce fichier de configuration ou en créer un pour définir ses propres contrôles. Et dans ce cas, l'option **-c** de la commande ci-dessous spécifie à AIDE le fichier à utiliser :
-  Pour vérifier que la configuration est correcte :
```
sudo aide -c /etc/aide_perso.conf --config-check
```
- Pour initialiser une base avec ce nouveau fichier de configuraton :
```
sudo aide -c /etc/aide_perso.conf --init
```
- Pour vérifier l'intégrité du système via ce nouveau fichier de configuration :
```
sudo aide -c /etc/aide_perso.conf --check
```
- Pour mettre à jour la base avec ce nouveau fichier de configuration :
```
sudo aide -c /etc/aide_perso.conf --update
```

## Vérification automatique
Comme vu plus haut, l'option **--check** permet de vérifier l'état d'intégrité du système. L'idéal serait d'automatiser cette vérification en créant une tâche dans le cron :
```
05 4 * * * root /usr/sbin/aide --check [-c config_file]
```
Ensuite, si on dispose d'un serveur smtp, on peut envoyer une notification par mail:
```
05 4 * * * root /usr/sbin/aide --check [-c config_file] | /bin/mail -s "Aide check $(date)" email@domain.com
```

## Liens
- [AIDE Redhat doc](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using-aide)
- [Tuto AIDE it-connect](https://www.it-connect.fr/aide-utilisation-et-configuration-dune-solution-de-controle-dintegrite-sous-linux/)
- [Tuto sbarjatiya.com](https://www.sbarjatiya.com/notes_wiki/index.php/Configuring_basic_AIDE_server)
