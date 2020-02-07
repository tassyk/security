# Tutorial Shinken
## Description de l'outil
[Shinken](https://shinken.readthedocs.io/en/latest/01_introduction/index.html) est une framework de monitoring développé en Python. Il est une fork du fameux outil de monitoring Nagios.
A la base un plugin de Nagios, il est devenu une framework complète de monitoring disponible sur maintes distributions
(Linux, Windows, ...). Il peut exporter les données vers plusieurs base de données comme Graphite, InfluxDB, RRD, GLPI.
Il peut aussi s'intégrer avec des WUI (Web User Interface) comme PNP4Nagios, Centreon, WebUI (Shinken own UI). Il peut importer des
configurations à partir outils comme GLPI, Amazon EC2, MySQL, MongoDB. Enfin, d'après le site de l'éditeur, Shinken fournit des ensembles de configuration, sous forme de paquets,
pour un grand nombre de services:


- Databases (Mysql, Oracle, MSSQL, memcached, mongodb, influxdb etc.)
- Routers, Switches (Cisco, Nortel, Procurve etc.)
- OS (Linux, windows, Aix, HP-UX etc.)
- Hypervisors (VMWare, Vsphere)
- Protocols (HTTP, SSH, LDAP, DNS, IMAP, FTP, etc.)
- Application (Weblogic, Exchange, Active Directory, Tomcat, Asterisk, etc.)
- Storage (IBM-DS, Safekit, Hacmp, etc.)

## Installation de Shinken
Nous allons procéder à l'[installation](https://shinken.readthedocs.io/en/latest/02_gettingstarted/installations/index.html) de l'outil sous Linux (Ubuntu).
Pour fonctionner correctement, Shinken a besoin de python et de certaines librairies. Ces preérequis peuvent être dans la section [Requirements](https://shinken.readthedocs.io/en/latest/02_gettingstarted/installations/shinken-installation.html#mandatory-requirements) de la documentation officielle. Sous linux, l'outil peut être installé de différentes manières (Pip, Paquet, from sources). Ici, nous allons voir la première méthode.

### Installation de Shinken via Pip
L'installation est très simple. Elle se fait avec les commandes ci-dessous:
```
[sudo] apt-get update -y
[sudo] apt-get install python-pip python-pycurl
[sudo] adduser shinken
[sudo] pip install shinken
```
Pour terminer l'installation via Pip, une étape supplémentaire est nécessaire (ce qui n'est pas le cas avec l'installation par paquet). Il faut configurer le redémarrage de l'outil au boot du système. Sur un OS basé sur systemd, la commande ci-dessus crée le service shinken:
```
for i in arbiter poller reactionner scheduler broker receiver; do
systemctl enable shinken-$i.service;
done
```
**Notes**: Si on n'est pas sous root (comme mon cas), cette commande va échouer. Pour éviter cela, on peut créer un script avec ce bout de code ci-dessus, puis le lancer (avec un privilège sudo).

Ensuite, activer le service via la commande:
```
[sudo] update-rc.d shinken defaults
```
Enfin, démarrer le service shinken via l'une des méthodes ci-dessous:
```
[sudo] /etc/init.d/shinken start
[sudo] service shinken start
[sudo] systemctl start shinken
```
## Configuration de Shinken
