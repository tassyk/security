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
> L'ensemble des paramètres de configuration se trouvent dans `/etc/httpd/modsecurity.d/modsecurity_crs_10_config.conf`
> tandis que les règles activées se trouvent dans `/etc/httpd/modsecurity.d/activated_rules/`

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

Par défaut, les log d'audit de ModSecurity sont stockés dans `/var/log/httpd/modsec_audit.log`. Vous pouvez inspecter son contenu pour voir les requêtes bloquées.
```
$ sudo tail -f /var/log/httpd/modsec_audit.log
--abdd0b6e-C--
login=%3Cscript%3E%3Cb+onmouseover%3Dalert%28%27Wufff%21%27%29%3Eclick+me%21%3C%2Fb%3E%3C%2Fscript%3E&mdp=bonjour&connexion=
--abdd0b6e-F--
HTTP/1.1 403 Forbidden
Content-Length: 212
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1
...
```

## Liens
- Documentations officielles:
  - [Site Web ModSecurity](https://modsecurity.org/)
  - [Documentation ModSecurity](https://github.com/SpiderLabs/ModSecurity/wiki)
  - [OWASP ModSecurity rules](https://owasp.org/www-project-modsecurity-core-rule-set/)
- Tutoriels :
  - [tecadmin : install-modsecurity-with-apache-on-centos-rhel](https://tecadmin.net/install-modsecurity-with-apache-on-centos-rhel/)
  - [server-world.info : install modsecurity](https://www.server-world.info/en/note?os=CentOS_7&p=httpd2&f=8)
  - [Faq : Modesecurity whitelist](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-Frequently-Asked-Questions-%28FAQ%29#How_do_I_whitelist_an_IP_address_so_it_can_pass_through_ModSecurity)
  - [Mod_security Exceptions](https://www.modsecurity.org/CRS/Documentation/exceptions.html)

