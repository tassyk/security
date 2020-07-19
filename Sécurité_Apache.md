---
Title: Sécurité serveur web apache
Nature : Note
Catégorie: Hardening
Date: 16/02/2020
Auteur: TK
---

# Sécurisation d'un serveur web apache
Cette note décrit quelques bonnes pratiques de configuration afin de sécuriser au minimum son serveur web Apache.

Environnement :
- OS : Centos
- Apache_dir : /etc/httpd
- Webroot : /var/www/html

> Pour toutes les modifications apportées au serveur, il faut redémarrer le service ou recharcher la configuration pour prendre en compte les modifications. Mais avant d'appliquer les modifications, vérifier d'abord que la configuration est bonne via la commande `apachectl configtest`

```
# redémarrer le système entièrement
systemctl restart httpd.service
# recharger uniquement la configuration
systemctl reload httpd.service
# recharger la configuration sans affecter de requête active
apachectl graceful
```

## Sécurisation de l'installation
### Installer la dernière version d'Apache
Lors de l'installation d'Apache, il faut installer la dernière version qui est plus sécurisée et maintenue.

### Mettre à jour régulièrement le paquet
Une fois installé, Apache doit subir régulièrement des mises à jour pour bénéficier des derniers correctifs.

### Ne pas exécuter Apache en tant que root
L'exécution du service Apache par root ou compte à privilège est un risque pour la sécurité du serveur. En effet, quand il est compromis, l'attaquant aura tout le contrôle du serveur. Pour éviter cela :
- créer un utilisateur spécifique :
```
$ groupadd apache
$ useradd –G apache apache
$ chown –R apache:apache $Webroot
```
- Puis configurer Apache à utiliser cet utilisateur :
```
$ cat $Apache_dir/conf/httpd.conf
User apache
Group apache
```
- S'assurer que le service tourne bien sous l'utilisateur spécifié :
```
ps –ef | grep http
```

### Proteger les répertoires bin et conf
Par défaut, les répertoires `bin` et `conf` d'Apache sont en `read/write` par tous les utilisateurs du serveur. Pour éviter cela, on peut définir des permissions plus strictes :
```
cd $Apache_dir
chmod –R 750 bin conf
```

### Désactiver les modules non utilisés
Par défaut, Apache est installé avec [plusieurs modules](http://httpd.apache.org/docs/2.4/mod/). Cependant il est recommander de désactiver les modules non utilisés. On peut désactiver un module en commentant la ligne `LoadModule` correpondante. Les fichiers de configuration des modules se trouvent dans `$Apache_dir/conf.modules.d`
> Les modules sont localisés dans `$Apache_dir/modules` ou `/usr/lib64/httpd/modules/`

### Ne pas utiliser les modules obsolètes
Certains modules ont été supprimés ou remplacés par d'autres. Dans ce cas, il est fortement conseillé de ne pas les utiliser. Voici quelques modules non plus supportés :
```
mod_perl
mod_authz_ldap : remplacé par mod_authnz_ldap
mod_auth_mysql, mod_auth_pgsql : remplacés par mod_authn_dbd
```

## Durcissement des configurations
## Désactiver la directive server-info
Si la directive `<Location /server-info>` dans le fichier de configuration `$Apache_dir/conf/httpd.conf` est activée, vous pouvez voir des informations sur la configuration d'Apache en accédant à la page /server-info (par exemple, http://www.example.com/server-info). Cela pourrait potentiellement inclure des informations sensibles sur les paramètres du serveur. On peut désactiver cela, en désactivant le module `mod_info` dans `$Apache_dir/conf/httpd.conf` ou `$Apache_dir/conf.modules.d/00-base.conf` :
```
#LoadModule info_module modules/mod_info.so
```

### Désactiver la directive server-status
http://www.example.com/server-status peut afiicher les informations sur le status du serveur et ses performances si la directive `<Location /server-status>` est activé. Un attaquant peut alors se servir des informations. Pour la désactiver, commenter les lignes ci-dessous dans `$Apache_dir/conf/httpd.conf` :
```
#<Location /server-status>
# SetHandler server-status
# Order deny,allow
# Deny from all
# Allow from .your_domain.com
#</Location>
```


### Cacher les bannières du serveur
Les informations du serveur web tels que la version, l'OS, peuvent source de menace. On peut les cacher à l'aide des directives :
```
$ cat $Apache_dir/conf/httpd.conf
ServerTokens Prod
ServerSignature Off
```
### Désactiver le listing des répertoires du site
Grâce aux Opyions `-Indexes ou None`, on peut interdire les utilisateurs de voir le contenu des répertoires de vos sites :
```
$ cat $Apache_dir/conf/httpd.conf
<Directory /var/www/html>
Options -Indexes # None
</Directory>
```
### Désactiver l'Etag
Il permet aux attaquants d'obtenir des informations sensibles comme le numéro d'inode, la limite MIME en plusieurs parties et le processus enfant par le biais de l'en-tête Etag. On peut le désactiver, via :
```
$ cat $Apache_dir/conf/httpd.conf
FileETag None
```

### Protéger les paramètres système du serveur
Par défaut, les utilisateurs peuvent surcharger la configuration d'Apache grâce à l'utilisation des fichiers `.htaccess`. Pour éviter cela, mettez la dircetive `AllowOverride` à `None` :
```
$ cat $Apache_dir/conf/httpd.conf
<Directory />
Options -Indexes
AllowOverride None
</Directory>
```
### Limiter l'utilisation des méthodes HTTP
Généralement, les méthodes `GET, POST, et HEAD` suffisent à une application web pour bien fonctionner. Par conséquent, on peut interdire l'utilisation des autres méthodes `OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT`.
```
$ cat $Apache_dir/conf/httpd.conf
<LimitExcept GET POST HEAD>
deny from all
</LimitExcept>
```

### Désactiver HTTP Trace Request
Activé par défaut, HTTP Trace peut être dangereux à laisser dans la mesure où il peut entraîner un vol de cookies par un attaquant (Cross Site Tracing attack). Pour le désactiver :
```
$ cat $Apache_dir/conf/httpd.conf
TraceEnable off
```

### Mettre sur les cookies les drapeaux HttpOnly et Secure
Cela peut limiter les attaques XXS (Cross Site Scripting) sur les cookies :
```
$ cat $Apache_dir/conf/httpd.conf
Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure
```

### Empêcher le Clickjacking Attack
Clickjacking est une vulnérabilité web très connue. Pour limiter, ajouter ceci :
```
$ cat $Apache_dir/conf/httpd.conf
Header always append X-Frame-Options SAMEORIGIN
```
> X-Frame-Options : peut prendre d'autres valeurs

### Empêcher le Server Side Include (SSI)
SSI permet d'injecter des scripts dans les pages HTML ou exécuter des codes à distance. Il peut entraîner aussi une surcharge du serveur web, réduisant ainsi les performances. Pour éviter cela, ajouter l'option `-Includes` comme ceci :
```
<Directory $Webroot>
Options –Indexes -Includes
Order allow,deny
Allow from all
</Directory>
```

### Empêcher l'utilisation des scripts CGI
L'emploi des scripts CGI doit être interdit si cela n'est pas nécessaire. Cela peut être désactivé à l'aide de l'option `-ExecCGI`
```
<Directory $Webroot>
Options –Indexes -Includes -ExecCGI -FollowSymLinks
...
</Directory>
```

### Se proteger contre les X-XSS
Pour se protéger contre les attaques XSS, on peut ajouter ces configurations :
```
$ cat $Apache_dir/conf/httpd.conf
Header set X-XSS-Protection "1; mode=block"
```

### Désactiver le protocole HTTP 1.0
HTTP 1.0 est un protocol avec plusieurs failles de sécurité. Il doit être désactivé :
```
$ cat $Apache_dir/conf/httpd.conf
RewriteEngine On
RewriteCond %{THE_REQUEST} !HTTP/1.1$
RewriteRule .* - [F]
```

### Définir une petite valeur pour le Timeout
Par défaut, le Timeout est défini à 600s. Une grande valeur de Timeout peut favoriser des attaques par deni de service. Pour éviter cela, on peut réduire cette valeur, comme par exemple :
```
$ cat $Apache_dir/conf/httpd.conf
Timeout 60
```
### Restreindre les accès à une interface ou IP spécique
Si le serveur ne doit être exposé au public, il faut restreindre l'accès au serveur web aux seules IP acceptées. Exemple :
```
<Directory $Webroot>
Options None
AllowOverride None
Order deny,allow
Deny from all
Allow from 10.20.0.0/24
</Directory>
```

## Confidentialité des données
### Activer HTTPS
Avec HTTP, les flux transitent en clair. Il doit être remplacé par HTTPS afin de chiffrer les flux. Sous les distributions Redhat, [HTTPS peut être fourni par le module `mod_ssl` ou `mod_nss`](https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-web_servers#s2-apache-mod_ssl).
> S'il n'y pas de contrainte, le module `mod_nss` doit être privilégié  car étant plus sécurisé. En effet, avec `OpenSSL`, des certificats discrets et des clés privées se trouvent dans les fichiers PEM. Avec `NSS`, ces fichiers sont stockés dans une base de données. Chaque certificat et chaque clé est associé à un jeton, et chaque jeton peut avoir un mot de passe le protégeant

### Créer un certificat fiable
Lors de la génération du certificat SSL/TLS, le nombre de bit du doit être au moins égal à `2048 bits (RSA)`.
> On peut générer un certificat SSL de différentes manières :
> - via Openssl. Il peut être installé via `yum install openssl`
> - via le paquet crypto-utils, qui est un utilitaire disposant d'une interface graphique. Il peut être installé via  `yum install crypto-utils`
> - via [let's Encrypt](https://letsencrypt.org/fr/). Il peut être installé via l'utilitaire [Certbot](https://certbot.eff.org/)

### Définir des suites de chiffrement SSL sûres
```
$ cat $Apache_dir/conf.d/ssl.conf
SSLCipherSuite HIGH:!MEDIUM:!aNULL:!MD5:!RC4
```
> Attention : Ne pas définir des suites de chiffrement faibles, non plus, dans les `virtualhost`

### Désactiver SSLv1, SSLv2 & SSLv3 et TLSv1.0
Les protocols SSLv1, 2 et 3, et TLS 1.0 ne sont plus fiables et sont sujets à beaucoup d'[attaques MIM (Man-In-the-Midle)](https://korben.info/les-attaques-ssltls.html). Ils doivent être désactiver au profit de `TLSv1.2` au moins.
```
# Pour ssl
$ cat $Apache_dir/conf.d/ssl.conf
SSLProtocol –ALL +TLSv1.2
#
# Pour nss
$ cat $Apache_dir/conf.d/ssl.conf
NSSProtocol TLSv1.2
```
> Attention : ces protocoles ne doivent pas être activés dans les `virtualhost`

### Activer HTTP strict - HTST
[HTTP Strict Tranport Security](https://fr.wikipedia.org/wiki/HTTP_Strict_Transport_Security) force les naviagteurs à utiliser le HTTPS pour votre site. Cela renforce la sécurité d'un site. Il doit être activé, s'il n'existe aucune contrainte pour cela.
```
$ cat $Apache_dir/conf.d/ssl.conf
Header always set Strict-Transport-Security \
  "max-age=63072000; includeSubDomains"
```

## Protection contre les attaques du 1O OWASP
On peut protéger son serveur web contre les [attaques du top 10 d'OWASP](https://owasp.org/www-project-top-ten/) en mettant en place un WAF (Web application Firwall). Parmi les WAF Opensource, [Mod Security](https://github.com/tassyk/security/blob/master/Web_security_modsecurity.md) fait partie des incontournables.

## Test et vérification
On peut vérifier la robustesse de son certificat SSL/TLS  à l'aide des outils en ligne comme [Qualys SSLtest](https://www.ssllabs.com/ssltest/).

On peut aussi vérifier si un protocol est activé ou non via la commande `openssl s_client -connect hostname:port -protocol`. Exemple : `openssl s_client -connect localhost:443 -ssl3`

# Liens
- Documentation :
  - [Redhat doc](https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/7/html/system_administrators_guide/ch-web_servers)
  - [Apache httpd](http://httpd.apache.org/)
  - [Apache foundation](http://www.apache.org/)
- Tutoriels :
  - [GeekFlare | Apache Web Server Hardening and Security Guide](https://geekflare.com/apache-web-server-hardening-security/)
  - [GeekFlare | 10 Best Practices To Secure and Harden Your Apache Web Server](https://geekflare.com/10-best-practices-to-secure-and-harden-your-apache-web-server/)
  - [Acunetix | Apache Security – 10 Tips for a Secure Installation](https://www.acunetix.com/blog/articles/10-tips-secure-apache-installation/)
  - [WpBuffs | The 14-Step Apache Security Best Practices Checklist](https://wpbuffs.com/apache-security-best-practices/)
  - [Apache | Conseils sur la sécurité](https://httpd.apache.org/docs/2.4/fr/misc/security_tips.html)
  - [Microlinux | Apache SSL Centos7](https://blog.microlinux.fr/apache-ssl-centos-7/)
- Tools :
  - [10 SSL checker](https://geekflare.com/ssl-test-certificate/)
