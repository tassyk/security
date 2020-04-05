---
Title: Création de certificat avec Let's Encrypt
Nature : Tutorial
Catégorie: Web security
Date: 06/02/2020
Auteur: TK
---

# Création de certificat avec Let's Encrypt
## Introduction
[Let’s Encrypt](https://letsencrypt.org/fr/) est une autorité de certification qui vous permet de disposer gratuitement des certificats SSL reconnus. Grâce à l'outil, [Certbot](https://certbot.eff.org/), letsencrypt vous permet de génerer facilement un certficat SSL pour sécuriser vos sites web. Pour utiliser cet outil, il faut au préalable disposer d'un domaine valable.

## Génération de certificat avec Certbot
Grâce à l'outil Certbot, nous allons montrer comment créer un certificat pour un site web basé sur Apache et hébergé sur un serveur Centos7.
Sur le site de Certbot, on peut être guidé pour l'installation. Pour cela, il suffit de choisir le software (apache, nginx, ...) et le système (Centos7, Debian, ...) que vous souhaitez utiliser pour la création de votre certificat.

### Prérequis
1. Connectez vous par SSH sur le serveur qui héberge votre site en tant qu'un utilisateur sudo.
2. Activer les dépôts EPEL si ce n'est déjà fait.
```
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
```
3. Installer Certbot et le plugin pour apache
```
sudo yum install certbot python2-certbot-apache
```
4. Disposez d'un virtualhost pour votre site comme cet exemple.
  ```
  <VirtualHost *:80>

   ServerName mysite.org
   DocumentRoot /var/www/html

   ErrorLog  /var/log/httpd/mysite.org-err.log
   CustomLog /var/log/httpd/mysite.org-access.log combined
   <Directory /var/www/html>
       Options -Indexes -MultiViews
       AllowOverride all
       Order allow,deny
       allow from all
   </Directory>
</VirtualHost>

  ```
### Création du certificat
Pour l'installation, nous allons utiliser la méthode interactive. Pour une méthode non interactive, je vous laisse regarder les liens des tutos ci-après.

1. Suivez l'une des méthodes suivantes qui vous convient puis passez au (2).
  1. **Méthode 1 :** Certbot peut vous aider à configurer votre apache à votre place en utilisant la commande:
  ```
  sudo certbot --apache
  ```
  2. **Méthode 2 :** Sinon, si vous souhaitez configurer Apache par vous-même, générez uniquement le certificat, vous pouvez lancer la commande ci-dessous:
  ```
  sudo certbot certonly --apache
  ```
2. Suivez les instruction de l'assistant d'installation
- Entrez une adresse mail de conatact (celui-ci sera utilisé pour vous prévenir quand le certificat arrive à expiration)
- Acceptez les conditions de la licence en répondant **A**
- Répondez si vous souhaitez ou non de partager votre adresse mail avec **Electronic Frontier Foundation** (qui développe Certbot)
- Entrez votre nom de domaine de votre site (domaine valide!)

Si tout ce passe, vous allez voir un message de **Congratulation**. Sinon, il faut corriger les erreurs soulignées par certbot.

Les certificats sont stockés dans le répertoire /etc/letsencrypt/live/mysite.org

## Renouvellement de certificats
Par défaut, les certificats letsencrypt ont une durée de vie de 3 mois (90 jours). Ce qui n'est as énorme. De ce fait, il faut renouveler vos certificats. Pour ce faire automatiquement, ajoutez la ligne ci-dessous dans votre crontab.
```
# Renouveler le certificat SSL le 1er du mois à 4h30
30 4 1 * * certbot renew
```
Cette commande renouvelle tous les certificats disponibles sur la machine qui nécessitent un renouvellement.

`NB` : Pour ouvrir le crontab de l'utilisateur, taper `crontab -e `

## Vérification
Pour vérifier que tout fonctionne bien, tentez d'accéder à votre site en HTTPS. Si vous y arrivez, alors tout fonctionne bien.

## Tester la robustesse de son certificat
Sur le site https://www.ssllabs.com/ssltest/ vous pouvez tester si votre installation de certificat est correcte ou pas.

# Liens
- Liens éditeur:
  - letsencrypt: https://letsencrypt.org/fr/getting-started/
  - Certbot apache/cento7: https://certbot.eff.org/lets-encrypt/centosrhel7-apache
- Tutos:
  - Création certificat SSL sur Centos7: https://www.microlinux.fr/certbot-centos-7/
  - Création certficat SSL pour apache sur Debian: https://www.memoinfo.fr/tutoriels-linux/configurer-lets-encrypt-apache/
  - Apache centos 7: https://www.microlinux.fr/apache-centos-7/
  - Apache https centos 7: https://www.microlinux.fr/apache-ssl-centos-7/
