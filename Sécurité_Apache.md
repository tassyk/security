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

## Durcissement de la configuration de httpd.conf
### Cacher les informations du serveur
Les informations du serveur web tels que la version, l'OS, peuvent source de menace. On peut les cacher à l'aide des directives :
```
$ cat $Apache_dir/conf/httpd.conf
ServerTokens Prod
ServerSignature Off
```
### Désactiver le listage des répertoires du site
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
## Confidentialité des données
### Activer HTTPS
Avec HTTP, les flux transitent en clair. Il doit être remplacé par HTTPS afin de chiffrer les flux.

### Créer un certificat fiable
Lors de la génération du certificat SSL/TLS, le nombre de bit du doit être au moins égal à `2048 bits (RSA)`.

### Définir des suites de chiffrement SSL sûres
```
$ cat $Apache_dir/conf.d/ssl.conf
SSLCipherSuite HIGH:!MEDIUM:!aNULL:!MD5:!RC4
```

### Désactiver SSL v1, v2 & v3
Les protocols SSLv1, 2 et 3 ne sont plus fiables et sont sujets à beaucoup d'[attaques MIM (Man-In-the-Midle)](https://korben.info/les-attaques-ssltls.html). Ils doivent être désactiver au profit de `TLSv1.2` au moins.
```
$ cat $Apache_dir/conf.d/ssl.conf
SSLProtocol –ALL +TLSv1.2
```
> On peut vérifier la robustesse de son certificat SSL.TLS à l'aide des outils en ligne comme [Qualys SSLtest](https://www.ssllabs.com/ssltest/)

## Protection contre les attaques du 1O OWASP
On peut protéger son serveur web contre les [attaques du top 10 d'OWASP](https://owasp.org/www-project-top-ten/) en mettant en place un WAF (Web application Firwall). Parmi les WAF Opensource, [Mod Security](https://github.com/tassyk/security/blob/master/Web_security_modsecurity.md) fait partie des incontournables.


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
- Tools :
  - [10 SSL checker](https://geekflare.com/ssl-test-certificate/)
