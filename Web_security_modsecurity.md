---
Title: Mise en place du WAF ModSecurity
Nature : Tutorial
Catégorie: Hardening serveur web
Date: 16/02/2020
Auteur: TK
---

# Mise en place du WAF ModSecurity


## Introduction
ModSecurity est un WAF (Web Application Firewall) opensource. Il permet de protéger une application ou un site web contre les menaces externes (DDoS, Top 10 des vulnérabilités OWASP, ...). Développé à la base comme étant un module du serveur web Apache, il est devenu un outil de sécurité à part entière. Dans cet article, nous allons voir comment le mettre en oeuvre sur un serveur Centos7 afin de protéger notre site web sous Apache.

## Installation de ModeSecurity
ModSecurity existe sous forme de paquet RPM, ce qui facilite son installation :
```
sudo yum install mod_security mod_security_crs
```
**mod_security_crs**: contient un ensemble de règles permettant de détecter et de bloquer les menaces identifiées dans le Top 10 d'OWASP. Ces règles sont mises à disposition par l'OWASP.

## Configuration de ModSecurity
L'installation de ModSecurity génère le fichier de configuration  **/etc/httpd/conf.d/mod_security.conf**. Ce fichier contient plusieurs paramètres :
```
# sudo vi /etc/httpd/conf.d/mod_security.conf

<IfModule mod_security2.c>
    # ModSecurity Core Rules Set configuration
        IncludeOptional modsecurity.d/*.conf
        IncludeOptional modsecurity.d/activated_rules/*.conf

    # Default recommended configuration
    SecRuleEngine On
    SecRequestBodyAccess On
    SecRule REQUEST_HEADERS:Content-Type "text/xml" \
         "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
    SecRequestBodyLimit 13107200
    SecRequestBodyNoFilesLimit 131072
    SecRequestBodyInMemoryLimit 131072
    SecRequestBodyLimitAction Reject
    ....
```

Cependant, le plus important est **SecRuleEngine**. En mettant celui à **on**, on peut bloquer les attaques.

## Redémarrage d'apache
Pour prendre en charge ces modifications, il suffit de redémarrer le serveur apache
```
sudo systemctl restart httpd
```

## Vérification du fonctionnement de ModSecurity
Pour tester si ModeSecurity fonctionne :
- analyser les logs d'Apache :
```
# sudo tail /var/log/httpd/error_log

[Mon Feb 17 21:25:57.988920 2020] [:notice] [pid 22943] ModSecurity: APR compiled version="1.4.8"; loaded version="1.4.8"
[Mon Feb 17 21:25:57.988923 2020] [:notice] [pid 22943] ModSecurity: PCRE compiled version="8.32 "; loaded version="8.32 2012-11-30"
[Mon Feb 17 21:25:57.988926 2020] [:notice] [pid 22943] ModSecurity: LUA compiled version="Lua 5.1"
```
- Tenter une injection SQL (`1 or '1'='1' -- `) sur le formulaire de votre site ou tenter d'exploiter une faille XSS avec cette requête javascript (`<script><b onmouseover=alert('Wufff!')>click me!</b></script>`). Vous allez recevoir un message de ce genre :
```
Forbidden

You don't have permission to access /login2.php on this server.
```
## Liens
- Documentations officielles:
  - [Site Web ModSecurity](https://modsecurity.org/)
  - [Documentation ModSecurity](https://github.com/SpiderLabs/ModSecurity/wiki)
  - [OWASP ModSecurity rules](https://owasp.org/www-project-modsecurity-core-rule-set/)
- Tutoriels :
  - [tecadmin : install-modsecurity-with-apache-on-centos-rhel](https://tecadmin.net/install-modsecurity-with-apache-on-centos-rhel/)
  - [server-world.info : install modsecurity](https://www.server-world.info/en/note?os=CentOS_7&p=httpd2&f=8)
  - [liquidweb : Modesecurity whitelist](https://www.liquidweb.com/kb/whitelisting-in-modsec/)
  - [infosecinstitute : avoiding modsecurity false positives whitelisting](https://resources.infosecinstitute.com/avoiding-mod-security-false-positives-white-listing/)
