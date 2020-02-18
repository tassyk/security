---
Title: Mise en place et sécurisation de Mysql/Mariadb
Nature : Tutorial
Catégorie: Sécurité Mysql/Mariadb
Date: 16/02/2020
Auteur: TK
---

# Mise en place et sécurisation de Mysql/Mariadb
## Introduction
Cet article porte sur la mise en place et la sécurisation du serveur de base de données Maraidb (Mysql).
Mariadb est une fork de Mysql qui est devenu propriété d'Oracle.
Mise à part le changement de nom, les commandes pour Mysql et Mariadb restent les mêmes.

## Installation de Mariadb/Mysql
L'installation de mariadb se fait via les commandes ci-dessous:
```
sudo yum install -y mariadb-server mariadb

# démarrage du service
sudo systemctl enable mariadb
sudo systemctl start mariadb
```
**Remarque** : pour installer Mysql, remplacer **mariadb** par **mysql**.

## Sécurisation du serveur Mysql/Mariadb
**mysql_secure_installation** est un programme conçu pour sécuriser le serveur Mysql/Mariadb. Lancer cette commande pour commencer le processus :
```
sudo mysql_secure_installation
```
Répondre aux questions :
```
- Enter current password for root (enter for none):  taper ENTRER
- Set root password? [Y/n] : Y (pour définir un mot de passe pour root)
- New password: Password
- Re-enter new password: Password
- Remove anonymous users? [Y/n] Y (pour supprimer les comptes anonymes)
- Disallow root login remotely? [Y/n] Y (pour désactiver le login à distance via root)
- Remove test database and access to it? [Y/n] Y (supprimer la base de données test)
- Reload privilege tables now? [Y/n] Y (Pour charger les privilèges sur les tables)

# Message à la fin
All done!  If you've completed all of the above steps, your MariaDB
installation should now be secure.

Thanks for using MariaDB!

```



## Liens
- Documentations officielles :
  - [Doc Mariadb](https://mariadb.org/documentation/)
  - [Doc Mysql](https://dev.mysql.com/doc/)
- Tutorials :
  - [Microlinux : Serveur bdd mysql/mariadb](https://www.microlinux.fr/mysql-centos-7/)
