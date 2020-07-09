---
Title: Mise en place d'OSSEC
Catégorie: Hardening système
Nature: Notes
Date de création: 13/04/2020
---

# Mise en place d'OSSEC
## Introduction
[OSSEC](https://www.ossec.net/docs/) est un HIDS (Host-Based Intrusion Detection) Open source. Il permet entre autres la détéction des malwares et rootkits sur le système, le monitoring d'intégrité des fichiers (FIM - File Monitoring Integrity) et la gestion des logs. Contrairement à d'autres soltuions de FIM comme AIDE, OSSEC repose sur une architecture Client (Agent)/Serveur, ce qui permet de monitorer un ensemble de clients (Unix, Windows, ) de manière centralisée. Il est possible aussi d'installer avec OSSEC le module Web (OSSEC Web UI) pour disposer d'une interface graphique. Mais le projet semble ne pas évoluer au profit du projet [Wazuh](https://wazuh.com/migrating-from-ossec/)

Enviroonement d'installation :
- Centos 7 (192.168.1.50) : server OSSEC
- Centos 7 (192.168.1.62) :  client(Agent OSSEC)
-  Selinux et Firewalld désactivés


## Installation et configuration OSSEC
Il existe différentes manières [d'installer OSSEC](https://www.ossec.net/downloads/) : From source, via des paquets (RPM/Deb). Il existe aussi sous forme d'Appliance ou de conteneur Docker.

### Installation du serveur et de l'agent OSSEC
Pour [l'installation d'OSSEC from source](http://www.ossec.net/downloads/), on peut procéder comme suite :
- Mise à jour des paquets (optionnel)
```
sudo yum update -y
```
- Récupérer le repo `EPEL`:
```
sudo yum install epel-release -y
```
- Installer les paquets nécessaires :
```
# sur le serveur
sudo yum install -y gcc make libevent-devel zlib-devel openssl-devel pcre2 pcre2-devel wget php php-cgi php-devel inotify-tools httpd mysql-devel postgresql-devel
# sur l'agent
sudo yum install zlib-devel pcre2-devel make gcc zlib-devel pcre2-devel sqlite-devel openssl-devel libevent-devel
```
- Récupérer une [version stable](https://www.ossec.net/downloads/) d'ossec-hids:
```
git clone  https://github.com/ossec/ossec-hids.git
```
- Exécuter le script d'installation d'ossec-hids :
```
cd ossec-hids
sudo ./install.sh
```
- Suivre les instructions de l'assistant d'installation
> Type d'installation: serveur (sur le serveur ossec) et agent (sur l'agent ossec)
> Laisser les autres options par défaut, ou les adapter à votre convenence

- Démarrer le serveur ossec-hids
```
sudo /var/ossec/bin/ossec-control start
# sudo /var/ossec/bin/ossec-control restart # pour redémarrer
# sudo /var/ossec/bin/ossec-control status # pour voir le status
```
> Remarques :
> Si un problème lié aux `queue`, arrêter le service ossec sur le serveur et sur l'agent, supprimer le répertoire `/var/ossec/queue/rids` sur les deux, puis redémarrer les services ossecs
> Aidez-vous des fichiers de logs dans `/var/ossec/logs/`

### Configuration du serveur et de l'agent OSSEC
Au besoin, OSSEC peut être configuré à l'aide du fichier `/var/ossec/etc/ossec.conf` (format XML). On y trouve, entre autres, les directives ci-dessous :
- `global` : pour spécifier les paramètres globaux
- `rules` : contenant des inclusions pour les fichiers de règle
- `syscheck` : pour le monitoring d'intégrité
- `rootcheck` : pour la détection des rootkits
- `remote` : pour les connexions distantes vers des serveurs `syslog`
- `alerts` : pour configurer les paramètres d'alertes
- `localfile` : pour les fichiers de log
- `server` : pour spécifier l'IP du serveur OSSEC (sur l'agent)
- `frequency` : pour changer la fréquence de scan
> Voir les exemples de configuration dans [Configuration Examples](https://www.ossec.net/docs/docs/manual/syscheck/index.html)

Le serveur OSSEC peut alerter par mail. Si on a un serveur de mail installé, on peut définir les paramètres de notification comme suit (si ce n'est pas déjà fait lors de l'installation):
```
<global>
    <email_notification>yes</email_notification>
    <email_to>root@localhost</email_to>
    <smtp_server>127.0.0.1</smtp_server>
    <email_from>ossecm@localhost</email_from>
  </global>
```
> Note : seule la ligne `<email_notification>yes</email_notification>` est importante

Par défaut, OSSEC (serveru et agent) n'envoie pas d'alerte en cas d'ajout de nouveaux fichiers et la fréquence de vérification est longue (default to every 22 hours). Pour changer cela, modifier les lignes `frequency` comme suit :
```
<syscheck>
    <!-- Frequency that syscheck is executed - default to every 60 seconds -->
    <frequency>60</frequency>
    <alert_new_files>yes</alert_new_files>
```
De plus, par défaut, les alertes ne se font pas en temps réel. Pour changer cela, modifier les lignes `<directories check_all="yes">` :
```
<directories report_changes="yes" realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
<directories report_changes="yes" realtime="yes" check_all="yes">/var/www,/bin,/sbin</directories>
```
> Note : On peut aussi adapter les répertoires à surveiller. Et dans les directives `ignore`, on peut définir la liste des fichiers/répertoires à ignorer.

Les règles pour détecter les nouveaux fichiers sont définies dans `/var/ossec/rules/local_rules.xml`. On peut ajouter les lignes ci-dessous dans ce fichier entre les sections `group` :
```
<rule id="554" level="7" overwrite="yes">
    <category>ossec</category>
    <decoded_as>syscheck_new_entry</decoded_as>
    <description>File added to the system.</description>
    <group>syscheck,</group>
</rule>
```

Ensuite, il faut redémarrer le service pour prendre en compte les modifications :
```
sudo /var/ossec/bin/ossec-control restart
```
> Le redémrrage du service affiche des messages et génère une alerte. Si on a un serveur SMPT installé, on peut voir ces alertes avec la commande `sudo mail`.
> Sinon, il faut vérifier les messages d'alertes dans `/var/ossec/logs/alerts/alerts.log`, et les autres messages d'erreur dans `/var/ossec/logs/ossec.log`

Mais OSSEC dispose aussi d'une interface UI qu'on peut installer pour mieux surveiller les changements et alertes.

### Installation d'OSSEC Web-UI sur le serveur
[OSSEC Web-UI](https://github.com/ossec/ossec-wui) est une interface qu'on peut installer pour faciliter l'exploitation d'OSSEC.
> Note : OSSEC Web-UI est marqué comme déprécié (il semble ne plus être maintenu depuis 2013)
> Prerequisites :
> - Apache with PHP (>= 4.1 or >= 5.0) installed.
> - OSSEC (version >= 0.9-3) already installed.

Pour l'installer, on peut procéder comme suit :
- Installer les prérequis
```
# PHP
sudo yum install -y php # php-72 (remi-php72.repo)
# Apache et démarrage
sudo yum install -y httpd # httpd-2.4.6
sudo systemctl start httpd
sudo systemctl enable httpd
```
- Récupérer le paquet
```
# cloner le dépôt
git clone https://github.com/ossec/ossec-wui.git
# déplacer le répertoire dans un dossier web
sudo mv ossec-wui* /var/www/html/ossec-wui
# Exécuter le scrip
cd /var/www/html/ossec-wui
sudo ./setup.sh
```
> Entrer le user, le mot de passe et l'utilisateur apache

- Redémarrer httpd `sudo systemctl restart httpd`
> Note : accepter les services http et https si firewalld est en place

- On peut accéder à l'interface vi cette adresse : http://your-server-ip/ossec-wui


## Intégration des agents dans OSSEC server
### Actions sur le serveur OSSEC
> Note : Si le firewall est en place, activer le port `udp 1514`

- Taper la commande
```
sudo /var/ossec/bin/manage_agents
```
- Taper `A` pour ajouter un agent.
> Entrer un nom pour l'agent et son IP. Un ID est généré par défaut. Enfin, taper `y` pour confirmer l'ajout.

- Ensuite taper `E` pour extraire la clé de l'agent.
> Entrer l'ID de l'agent demandé. Quand la clé est générée, on voit un message qui ressemble à ceci :

```
Agent key information for '001' is:
MDAyIHZ1bG5jZW43IDE5Mi4xNjguMS42MiA5MDk5NjdhMTI3ZjM4ZWYyMjVmODE4ZmI1ZDMzMGEyMDY2NWUxNzE2ZmEzMDMzZWEwMTcwMWVmMTQ4ZDliZjNj
```
- Taper sur `ENTRER` puis cliquer `Q` pour quitter.
- Redémarrer le serveur OSSEC `sudo /var/ossec/bin/ossec-control restart`

### Actions sur les agents OSSEC
- Editer le fichier `/var/ossec/etc/ossec.conf` de l'agent pour spécifier l'IP du serveur OSSEC dans la section `client` (si ce n'est pas fait lors de l'installation):
```
<server-ip>192.168.1.50</server-ip>
```
- Ensuite taper la commande ci-dessous :
```
sudo /var/ossec/bin/manage_agent
```
- Taper `I` pour importer la clé générée par le serveur. Coller la clé.
- Confirmer l'action, puis taper sur `Q` pour quitter.
- Redémarrer ensuite l'agent : `sudo /etc/init.d/ossec-hids restart`

# Liens
- Documentation :
  - [OSSEC Documentation](https://www.ossec.net/docs/)
  - [OSSEC FAQ](https://www.ossec.net/docs/faq/index.html)
- Tutoriels :
  - [Blog Rapid7 | How to Install and Configure OSSEC on Ubuntu Linux](https://blog.rapid7.com/2017/06/30/how-to-install-and-configure-ossec-on-ubuntu-linux/)
  - [Blog Tensult | FIM and SIEM with OSSEC](https://blogs.tensult.com/2018/04/24/fim-and-siem-with-ossec/)
  - [Blog AlibabaCloud | How to Install OSSEC on Ubuntu 16.04 ](https://www.alibabacloud.com/blog/how-to-install-ossec-on-ubuntu-16-04_595080)
  - [All-it-network | OSSEC](https://all-it-network.com/ossec/)
  - [CodeFlow Local OSSEC](https://www.codeflow.site/fr/article/how-to-set-up-a-local-ossec-installation-on-fedora-21)
- Autres solutions de FIM :
  - [Dnsstuff | 6 Best File Integrity Monitoring Software in 2020](https://www.dnsstuff.com/file-integrity-monitoring-software)
    - [Security Event Manager](https://www.solarwinds.com/security-event-manager?CMP=ORG-BLG-DNS)
    - [Qualys FIM](https://www.qualys.com/apps/file-integrity-monitoring/)
    - [Trustwave Endpoint Protection](https://www.trustwave.com/en-us/services/managed-security/managed-threat-detection-and-response/)
    - [Tripwire FIM](https://www.tripwire.com/solutions/file-integrity-and-change-monitoring)
    - [Wazuh](https://github.com/wazuh)
