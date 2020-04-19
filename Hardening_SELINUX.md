---
Title:  Utilisation de SELINUX
Nature : Tutorial
Catégorie: Hardening
Date: 18/02/2020
Auteur: TK
---


# Quelques notes sur l'utilisation de SELINUX

## Introduction
SElinux (Security-Enhanced Linux) permet de définir des politiques d'accès à différents éléments du système d'exploitation. Ces éléments peuvent être des processus (démons), ou encore des fichiers. Il ne remplace pas les droits de permissions classiques sur les systèmes de fichiers mais vient complément afin de renforcer d'avantage le niveau de sécurité du système.
Dans le contexte SElinux, "chaque processus est confiné à un (voire plusieurs) domaine, et les fichiers sont étiquetés en conséquence. Pour simplifier, un processus ne peut accéder qu'aux fichiers étiquetés pour le domaine auquel il est confiné."


## Commandes utiles
Les commandes ci-dessous peuvent être utiles lorsque l'on veut utiliser SELinux...

**Consultation :**
- `sestatus` : afficher le status actuel de SELinux ;
- `getenforce`: obtenir le mode SELinux courant de votre machine ;
- `ls -Z`: afficher la liste des fichiers et dossiers ainsi que leur contexte SELinux avec la commande `ls`;
- `ps -Z`: afficher la liste des processus ainsi que leur contexte SELinux avec la commande `ps`;
- `sesearch`: effectuer une recherche dans la politique actuellement configurée pour votre machine;
- `getsebool`: obtenir des informations sur les booléens ;
- `matchpathcon`: afficher le contexte que devrait posséder un fichier.

**Modification :**
- `setenforce`: modifier le mode SELinux de votre machine ;
- `setsebool`: modifier la valeur d'un booléen ;
- `restorecon`: restaurer un contexte en fonction de la politique courante ;
- `chcon`: modifier le contexte SELinux d'un fichier ;
- `semanage`: gérer les politiques SELinux

**Remarque :**
- Les booléens permettent de modifier une politique SELinux
- La commande `semanage boolean` permet d'obtenir plus d'information sur les booleéns que `setsebool` ou `getsebool`.
- Pour plus d'informations sur l'une des commandes pré-citées, je vous invite à consulter la page de manuel correspondante (`man macommande`).

## Quelques notions à connaître
### Les modes
SElinux propose trois modes :
- **Enforcing** : c'est le mode par défaut. Dans ce mode, les accès sont restreints en fonction des règles SELinux en vigueur sur la machine ;
- **Permissive** : c'est un mode pour débogage (les restrictions ne sont pas appliquées mais justes journalisées);
- **Disabled** : dans ce mode, SElinux est désactivé.

### Présentation du contexte SELinux
Un contexte SELinux se présente comme suit :
```
utilisateur:rôle:type:niveau
```
Par exemple, pour le contexte du dossier /var/www/html:
```
system_u:object_r:httpd_sys_content_t:s0
```
### Utilisateurs SELinux
Tout l'utilsateur du système est mappé à un utilisateur SELinux. La commande ci-dessous liste les utilisateurs SELinux :
```
semanage login -l
```
### Les booléens
Les booléens permettent de modifier une politique SELinux pour un processus/service donné (par exemple httpd). En effet, pour pouvoir utiliser certaines fonctionnalités pour un service donné, il faut vérifier si elle est permise par la politique ou pas.

## Quelques cas d'usage sur les commandes
### Gestion des modes
Les commandes `getenforce` et `setenforce` permettent respectivement de voir et de modifier le mode SElinux du système:
- `setenforce 0` : rend le mode **Permissive**
- `setenforce 1` : rend le mode **Enforcing**
On peut aussi gérer le mode directement depuis le fihcier **/etc/selinux/config**.

**Remarque :**

En passant du mode Permissive ou Disabled au mode Enforcing, il faut ré-etiqueter l'intégralité du système pour éviter certains problèmes. Ceci peut être fait :
- soit en créant le fichier *.autorelabel* puis redémarrer le système :
```
# touch /.autorelabel
# reboot
```
- soit en utilisant les commandes ci-dessous :
```
# fixfiles -F onboot
# reboot
```

### Gestion des status
- La commande `sestatus` affiche l'état actuel de SElinux sur le système.
- L'option `-Z` sur les commandes `ls` ou `ps` permet de consulter les informations du contexte atuel de SElinux:
  - `ps -ef -Z` : liste les contextes pour tous les processus.
  - ` ls -alZ /var/www/`: liste le contexte des fichiers du dossier /var/www/.

### Consultation des contextes accessibles
La commande `sesearch` permet de rechercher les contextes auxquels un processus peut accéder. Par exemple, pour httpd, on peut utiliser ceci  :
```
sesearch --allow -s httpd_t -c file -p write
```
### Rétablir un contexte
Après certaines opérations effectuées (exemple mv, cp, ...) dans le système, on est parfois obligé de rétablir le contexte SELinux du/des fichiers pour éviter les problèmes. Pour cela on a deux possibilités :
1. restaurer le contexte par défaut du chemin;
2. spécifier un contexte « manuellement ».

#### Restauration du contexte par défaut
Dans ce cas, on peut utiliser la commande `matchpathcon` pour connaître le contexte à appliquer sur ledit fichier puis `restorecon`. Exemple :
```
matchpathcon chemin/fichier
restorecon -v chemin/fichier
```
#### Spécification du contexte manuellement
Deux solutions sont possibles :
1. utiliser la commande `chcon`;
2. utiliser la commande `semanage`.

La commande `chcon` de permet de changer le contexte SELinux d'un fichier ou dossier donné de façon permanente. En effet, après un redémarrage du système ou une restauration du contexte (restorecon), le contexte est modifié. Exemple d'utilisaion :
```
chcon -t selinux_contexte chemin/fichier
# Exemple
chcon -t httpd_sys_content_t connexion.php
```

La commande `semanage` permet de définir un contexte par défaut pour un répertoire et tout son contenu. Par exemple, si on souhaite définir le contexte httpd, **httpd_sys_content_t**, pour un répertoire comme **/srv/web**, on peut utiliser cette commande ci-dessous :
```
semanage fcontext -a -t httpd_sys_content_t '/srv/web(/.*)?'
```
Ensuite, il faut appliqué ce contexte sur ce répertoire :
```
restorecon -R -v /srv/web
```

**Remarque** : si jamais, on souhaite enlèver ce contexte, on peut utiliser cette commande :
```
semanage fcontext -d '/srv/web(/.*)?'
```

### Gestion des politiques SELinux
Les booléens permettent de modifier une politique SELinux.
Pour les lister les politiques, on peut utiliser l'une des deux commandes ci-dessous :
```
semanage boolean -l
getsebool -a
```
Mais `semanage` permet d'obtenir quelques informations sur l'utilité de chacun. Par exemple, lister les politiques pour httpd :
```
semanage boolean -l |  grep httpd
```
Et pour activer une politique, on utilise la commande `setsebool`. Par exemple, pour mettre l'envoi des mails via le web, il faut activer la politique **httpd_can_sendmail** comme suit :
```
setsebool -P httpd_can_sendmail on
```
**Atention** : L'option `-P` permet de rendre la directive permanente. A utiliser donc avec précaution.

## Gestion de SELinux via l'interface graphique
Sur les systèmes de la faimille Redhat disposant d'une GUI, il est possible de manager SELnux via une interface graphique à l'aide de l'utilitaire `system-config-selinux`. S'il n'est pas nativement installé, il faut l'installer comme suit :
```
yum install policycoreutils-gui
```

## Liens
- Documentations officielles :
  - [Doc Redhat](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/part_i-selinux)
- Tutorials :
  - [wiki Fedora sur selinux](https://doc.fedora-fr.org/wiki/SELinux)
  - [Redhat doc: sec-using-aide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using-aide)
  - [Microlinux : SELINUX aux admins](https://www.microlinux.fr/selinux/)
  - [DigitalOcean : Selinux](https://www.digitalocean.com/community/tutorials/?q=selinux)
