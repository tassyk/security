---
Title: Mise en place et sécurisation de Mariadb
Nature : Tutorial
Catégorie: Sécurité Mariadb
Date: 16/02/2020
Auteur: TK
---

# Mise en place et sécurisation de Mariadb
## Introduction
Cet article porte sur la mise en place et la sécurisation du serveur de base de données Mariadb.
Mariadb est une fork de Mysql qui est devenu propriété d'Oracle.
Mise à part le changement de nom, les commandes pour Mysql et Mariadb restent les mêmes.

## Installation de Mariadb.
Nous allons installer Maraidb/Mysql sur un serveur Centos7 avec Firewalld installé et Selinux désactivé.
Si vous avez Selinux activé, je vous laisse regarder la documentation de Redhat ci-dessous dans ce cas.
Sur Centos7, c'est la version 5 de Mariadb/Mysql qui existe par défaut. Mais cette version ne sera plus maintenue d'ici peu. De ce fait, nous allons utiliser le dépôt officiel de MariaDB.
Pour l'installation de MariaDB depuis le [dépôt officiel pour Centos7](https://mariadb.com/kb/en/yum/), procédez comme suit :
1. Ajoutez ce contenu dans le fichier **/etc/yum.repos.d/MariaDB.repo**
```
# MariaDB 10.4 CentOS repository list - created 2020-02-23 19:32 UTC
# http://downloads.mariadb.org/mariadb/repositories/
[mariadb]
name = MariaDB
baseurl = http://yum.mariadb.org/10.4/centos7-amd64
gpgkey=https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
gpgcheck=1
```
2. Importez la clé
```
sudo rpm --import https://yum.mariadb.org/RPM-GPG-KEY-MariaDB
```

3. Installez le serveur et le client MariaDB puis démarrez le service.
```
sudo yum install mariadb-server mariadb-client

# démarrage du service
sudo systemctl enable mariadb
sudo systemctl start mariadb
```

L'installation crée les fichiers et réertoires ci-dessous :
- **/etc/my.cnf** : le fichier de configuration principal ;
- **~/.my.cnf** : le fichier de configuration pour l'utilisateur ;
- **/etc/my.cnf.d/** : le dossier contenant les fichiers de configuration ;
- **/var/log/mariadb/mariadb.log** : le journal du serveur ;
- **/var/lib/mysql/** : le dossier contenant les données du serveur (les bases de données).

## Sécurisation du serveur Mariadb
### Définition du mot de root et suppression des utilisateurs et bases de test.
**[mysql_secure_installation](https://mariadb.com/kb/en/mysql_secure_installation/)** est un programme conçu pour sécuriser le serveur Mysql/Mariadb. Il permet de définir le mot de passe root, supprime l'utilisateur anonyme, interdit le login root à distance, supprime la base de données test. Lancer cette commande pour commencer le processus :
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

### Renforcement de la politique des mots de passe pour Mariadb
Le plugin **MariaDB-cracklib-password-check** permet de renforcer la politique des mots de passe pour les utilisateurs de Mariadb.
Cela évite de définir des mots de passe trop laxistes.
Pour l'installer:
1. Utilisez la commande :
```
sudo yum install MariaDB-cracklib-password-check
```
2. Connectez-vous vous à au serveur mariadb puis activer le plugin
```
mysql -u root -p
INSTALL SONAME 'cracklib_password_check';
```
Pour vérifier, tentez de créer un utilisateur avec un mot de passe faible. Vous allez tomber sur un message d'erreur:
```
MariaDB [mysql]> CREATE USER 'myuser'@locahost IDENTIFIED BY 'mypassword';

# Message d'erreur
ERROR 1819 (HY000): Your password does not satisfy the current policy requirements
```

### Changement des adresses d'écoute en local
Localement, MariaDB/Mysql écoute par défaut sur les adresses **locahost**, **127.0.0.1** et **::1**. Pour plus de sécurité, nous allons laisser uniquement **locahost**. Pour ce faire, procéder comme suite :

1. Connectez-vous à MariaDB via la commande ci-dessous (Entrez le mot de passe root) :
```
mysql -u root -p ou mysql --user=root --password
```
**NB**: S'assurez-vous d'avoir installé la bonne version de Maraidb :
```
MariaDB [(none)]> select version();
```
2. Affichez les bases de données par défaut (3 bases) et sélectionnez Mysql:
```
MariaDB [(none)]> show databases;
MariaDB [(none)]> use mysql;
```
3. Affichez les utilisateurs, le host et leur mot de passe :
```
MariaDB [mysql]> select user, host, password from user;
```
4. Pour garder uniquement **localhost**, tapez :
```
MariaDB [mysql]> delete from user where host!='localhost';
```
5. Revérifiez qu'il n'y a que localhost :
```
MariaDB [mysql]> select user, host, password from user;
```
6. Quittez la console avec la commande :
```
MariaDB [mysql]> quit;
```
## (Optionnel) Changement du répertoire data par défaut
Pour renforcer un plus encore la sécurité de notre serveur Mariadb/Mysql, on peut changer le répertoire des données. Pour cela :
1. Créez un nouveau répertoire qui accueillir les données :
```
sudo mkdir -p /mysql
```
2. Copiez les fichiers de la base de données dans le nouveau répertoire :
```
sudo cp -R /var/lib/mysql/* /mysql/
```
3. Attribuez les bons droits aux fichiers :
```
sudo chown -R mysql:mysql /mysql
```
4. Modifiez le **datadir** dans le fichier de configuration de Mariadb/Mysql **/etc/my.cnf** :
```
[mysqld]
datadir=/mysql
```
5. Redémarrez le serveur pour prendre en compte les modifications :
```
sudo systemctl restart mariadb.service
```

## Administration de bases de données
Comme le serveur Mariadb est maintenant mieux sécurisé, nous allons commencer à créer une base de données, un utilisateur et lui attribuer des privilèges sur la base de données. Pour ce faire :
1. Connectez-vous à MariaDB via la commande ci-dessous (Entrez le mot de passe root) :
```
mysql -u root -p
```
2. Créez la base de données (mydb) :
```
mysql> create database mydb;
```
3. Créez un utilisateur (administrateur de cette base) :
```
CREATE USER 'myuser' IDENTIFIED BY 'mypassword';
```
4. Donnez tous les droits sur cette base de données à l'utilisateur :
```
mysql> GRANT USAGE ON mydb.* TO 'myuser'@localhost IDENTIFIED BY 'mypassword';
```
5. Quittez
```
mysql> quit;
```


## Liens
- Documentations officielles :
  - [Doc Mariadb](https://mariadb.org/documentation/)
  - [Doc Mysql](https://dev.mysql.com/doc/)
  - [Mariadb install](https://mariadb.com/kb/en/yum/#updating-the-mariadb-yum-repository-to-a-new-major-release)
  - [cracklib-password-check-plugin](https://mariadb.com/kb/en/cracklib-password-check-plugin/)
- Tutorials :
  - [Redhat Doc : Mariadb](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/chap-managing_confined_services-mariadb)
  - [Fedora Doc : Mariadb](https://doc.fedora-fr.org/wiki/Installation_et_configuration_de_MariaDB)
  - [Microlinux : Serveur bdd mysql/mariadb](https://www.microlinux.fr/mysql-centos-7/)
  - [Linode : how-to-install-mariadb-on-centos-7](https://www.linode.com/docs/databases/mariadb/how-to-install-mariadb-on-centos-7/)
  - [Delete user](https://www.cyberciti.biz/faq/how-to-delete-remove-user-account-in-mysql-mariadb/)
