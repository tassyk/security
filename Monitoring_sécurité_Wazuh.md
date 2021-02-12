---
Title: Monitoring sécurité Wazuh
Type: Doc
Nature: Notes
Création: 24/05/2020
---

# Monitoring sécurité avec Wazuh

## Introduction
[Wazuh](https://wazuh.com/) est une solution Open source de monitoring de sécurité. Il permet, entre autres, de détecter les intrusions, de surveiller l'intégrité des fichiers, de détecter les vulnérabilités, d'analyser les logs d'un système.
Il peut être installé de différentes manières : Yum/Apt, docker, Ansible, Chef, via un script, ... Wazuh se base sur une architecture client/serveur (ou agent / masteur). Le server (Wazuh-server) s'appuie sur les composants d'Elastic stack : Elasticsearch pour le stockage des informations, Kibana pour la visualisation des données et Filebeat pour la collecte des logs. L'agent (Wazuh-agent) s'occupe de la collecte des informations sur les clients.

## Installation de Wazuh  
Wazuh peut-être installé suivant deux modes :
- mode all-in-one (standalone) : tous les composants sur un même serveur.
- en mode distribué : composants installés sur plusieurs serveurs.
Pour une meilleure performance, certaines caractéristiques doivent être respectées au niveau du système : voir [requirements](https://documentation.wazuh.com/4.0/installation-guide/requirements.html)
> Note : Dans notre cas, nous allons installer la solution sur Ubuntu 18.04.5 LTS en mode standalone

### Installation de Wazuh server
Nous allons installer Wazuhr server (wazuh manager) à l'aide du [script de déploiement automatique](https://documentation.wazuh.com/4.0/installation-guide/open-distro/all-in-one-deployment/unattended-installation.html). Pour ce faire, rien de plus simple. Il suffit de le télécharger et de l'exécuter ensuite (par root).
```
apt-get update -y
curl -so ~/all-in-one-installation.sh https://raw.githubusercontent.com/wazuh/wazuh-documentation/4.0/resources/open-distro/unattended-installation/all-in-one-installation.sh && bash ~/all-in-one-installation.sh
```
> Note : l'installation peut prendre quelques minutes: le script installe toutes les dépendances et applique les configurations.
> Remarque : le script vérifie aussi les caractéristiques du serveur. Vous pouvez omettre cela en ajoutant l'option `--ignore-healthcheck (ou -i)`

Si l'installation s'est correctement terminée, on peut accéder à l'interface de Kiban via https://wazuh_server_ip
> Note : user=admin, password=admin
>
> Remarque :
> - On peut personnaliser les configurations de Kibana (`/etc/kibana/kibana.yml`), d'Elasticsearch (`/etc/elasticsearch/elasticsearch.yml`), de Filebeat (`/etc/filebeat/filebeat.yml`) ou de Wazuh (`/var/ossec/etc/ossec.conf`).
> - Il est aussi fortement recommandé de changer le password  par défaut d'Elasticsearch des utilisateurs dans `/usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml`. Voir la procédure [change-elastic-pass](https://documentation.wazuh.com/4.0/user-manual/elasticsearch/elastic_tuning.html#change-elastic-pass). Sur ce lien, on peut aussi appliquer certaines options de configuration d'Elasticsearch (dans `/etc/elasticsearch/elasticsearch.yml`)
> - Une fois que Kibana est en marche, il est nécessaire d'assigner à chaque utilisateur le rôle qui convient. Pour cela, voir [Setting up the Wazuh Kibana plugin](https://documentation.wazuh.com/4.0/user-manual/kibana-app/connect-kibana-app.html#connect-kibana-app)
> - Le fichier `/var/ossec/etc/internal_options.conf` contient les paramètres internes (manager, agent). Il n'est pas conseiller de modifier ce fichier. Si nécessaire, ajouter l'option de configuration souhaitée dans un autre fichier (ex : `internal_options.conf`). 
> - Pour plus d'info sur l'administration du manager, voir [Wazuh server administration](https://documentation.wazuh.com/4.0/user-manual/manager/index.html)

> Note :
Pour info, voici comment interagir avec les daemons Elasticsearch, Kibana, Filebeat après les modifications
```
systemctl daemon-reload # reload dameons service après modification d'un service
systemctl enable <service> # activer le service au boot
systemctl start <service>  # démarrer le service
systemctl restart <service>  # redémarrer le service
```

Maintenant, que Wazuh server et tous les composants sont correctement installés, on peut naviguer dans Kibana pour explorer les différents onglets proposés dans l'interface mais voir les premiers logs du server en allant dans `Discovery`. On peut aussi télécharger quesques données d'exemple (sample data) en allant dans `Wazuh > settings > Sample Data`. Ainsi, on peut explorer ces données depuis `Wazuh > modules > nom_module`
Mais, il serait plus intéressant d'installer les agents sur les endpoints (clients) à monitorer.

### Installation de Wazuh agent
L'[agent Wazuh](https://documentation.wazuh.com/4.0/installation-guide/wazuh-agent/index.html#installation-agents) peut être installé sur divers plateformes (Unix, Windows).
Sur les distributions Linux, l'installation de l'agent se fait en suivant les étapes ci-dessous :
- Récupération de la clé GPG du répository
- Récupération du répository (dépôt) d'installation
- Installation du paquet de l'agent.
> Note :
> - L'agent est nativement installé sur le manager (wazuh server)
> - Pour chaque type d'installation de l'agent, il est possible de spécifier des [variables](https://documentation.wazuh.com/4.0/installation-guide/wazuh-agent/deployment_variables/linux/deployment_variables_apt.html#deployment-variables-apt) pour configurer en même temps l'agent comme `WAZUH_MANAGER, WAZUH_AGENT_GROUP, WAZUH_AGENT_NAME, ...`


Dans notre cas, nous allons l'installer sur une machine Ubuntu (comme le serveur). Cela peut se faire depuis l'interface de Kibana (`Wazuh > Agents`) ou en ligne de commande. Nous allons utiliser la deuxième méthode en utilisant des variables.
> Remarque : l'agent doit être en version inférieure ou égale à Wazuh server

### Déploiement en ligne de commande
Pour ce faire, exécuter les commandes ci-dessous :
```
# clé GPG
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
# repository
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
# mise à jour des paquets
apt-get update
# agent
WAZUH_MANAGER="IP_wazuh-manager" apt-get install wazuh-agent
# Démarrer l'agent
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
systemctl status wazuh-agent # voir le status
```
> Ici, on spécifie l'IP de Wazuh server.
> Cela n'est pas obligatoire car on pouvait juste lancer la commande sans les variables pour installer l'agent.
> Remarque : pour que l'agent ne se mette à jour et installe une version supérieure au manager, il est recommendé de désactiver la mise à jour de l'agent. Cela peut se faire via la commande `echo "wazuh-agent hold" | dpkg --set-selections`

Chaque événement collecté par un agent est transmis au manager. On peut visualiser ces informations depuis Kibana.
On peut voir les agents depuis Kibana ou en ligne de commande `/var/ossec/bin/manage_agents -l`.
Mais pour cela, il faut d'abord enregistrer (inscrire) les agents auprès du master puis pousser une configuration (locale ou centrale) (voir les paragraphes suivants).

### Déploiement depuis Kibana
Pour déployer l'agent depuis Kibana, il faut :
- aller `Wazuh > Agent`
- cliquer sur `Deploy a new agent` et choisir renseigner les informations (IP du manager, OS, version, groupe, ...)
- une commande est générée qu'il faudra exécuter sur l'agent pour l'installer et l'inscrire (enregistrer auprès du manager) :
```
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.0.4-1_amd64.deb && sudo WAZUH_MANAGER='192.168.1.4' WAZUH_AGENT_GROUP='linux-servers' dpkg -i ./wazuh-agent.deb
```
- redémarrer l'agent
```
sudo systemctl wazuh-agent start
```

## Configuration des agents
Les agents Wazuh peuvent être configurés de différentes manières :
- via le fichier [ossec.conf](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/index.html). C'est une configuration locale (uniquement pour l'agent)
- via le fichier [agent.conf](https://documentation.wazuh.com/4.0/user-manual/reference/centralized-configuration.html) depuis le manager. C'est une configuration centralisée (déployée pour un groupe d'agents). Ce fichier est localisé dans le répertoire du groupe `/var/ossec/etc/shared/group-name/agent.conf`
> Pour plus de détails sur la configuration centralisée des agents, voir [Agent groups and centralized configuration](https://wazuh.com/blog/agent-groups-and-centralized-configuration/)
> Pour vérifier la configuration en CLI, exécuter la commande : `/var/ossec/bin/verify-agent-conf`

- via l'interface de Kibana, à l'aide du plugin `Kibana app` intégré
> Dans `Wazuh > Management > Configuration`

Ce sont des fichiers au format XML. La syntaxe est la même. Cependant, certaines options ne sont utilisables que soit pour le manager ou soit par l'agent. Dans les configurations, on peut trouver plusieurs sections identifiées par [certaines directives (capabilities)](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/index.html) comme :
- `syscheck` : Monitoring d'intégrité de fichiers
- `rootcheck` :  Detection de Rootkit
- `localfile` : Collecte des logs
- `sca` : Audit de configuration système (Security Configuration Assessment)
- `syscollector` : Inventaire système
- `syslog_output` : Envoi des alertes à un serveur Syslog
- `email_alerts` : Notifications par mail
- `wodle name=”azure-logs”` : Collecte des logs depuis le cloud Azure
- `vulnerability-detector` : Détection des vulnérabilités
- `wodle name=”open-scap”, wodle name=”cis-cat”` :  Monitoring de stratégie de sécurité
- `wodle name=”command”` : Remote commands
- ...

Chacune de ces directives contiennent des sous-directives (options) dont chacune peut avoir à son tour des attributs. Je vous renvoie à la documentation pour voir les [exemples de configuration](https://wazuh.com/blog/agent-groups-and-centralized-configuration/) et dans la section `Monitoring de sécurité`, plus bas.
> Note :
> - Dans ces configurations, les mots entre <!--  --> sont des commentaires

Pour la configuration locale (sur l'agent ou le manager) via le fichier [ossec.conf](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/index.html) , les directives sont contenues dans les sections :
```
<ossec_config>
    ...
</ossec_config>
```

Tandis que, dans le fichier [agent.conf](https://documentation.wazuh.com/4.0/user-manual/reference/centralized-configuration.html), utilisé pour la gestion centralisée (donc sur le manager), toutes les directives sont contenues dans les sections :
```
<agent_config>
    ...
</agent_config>
```
> Note :
> - le fichier peut contenir plusieurs sections `<agent_config>`. Cette direction contient trois options (name, os, profile) qui permettent d'assigner la configuration par affinité. Exemple :
  ```
  <agent_config name=”agent01”>
  ...
  <agent_config os="Linux">
  ...
  <agent_config profile="UnixHost">
  ```
> - Ainsi section s'appliquera une cible précise: agent01, les agents d'OS Linux, les agents ayant le [profile](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/client.html#reference-ossec-client-config-profile) UnixHost. Le profile est défini dans la configuration du client à l'aide de la directive `<config-profile>`. Exemple : `<config-profile>webserver, ubuntu</config-profile>`


> Remarque :
> - Si une configuration centralisée est appliquée (agent.conf), elle prend dessus sur la configuration locale (ossec.conf).
> - les fichiers partagés (exemple: agent.conf, merg.conf) par le manager avec les groupes se trouvent (sur le manager) dans le répertoire du groupe localisé dans [/var/ossec/etc/shared](https://documentation.wazuh.com/4.0/user-manual/reference/centralized-configuration.html)

## Management des agents
### Inscription des agents
Les [agents peuvent s'inscrire auprès du manager](https://documentation.wazuh.com/4.0/user-manual/registering/index.html) de différentes manières (CLI, siple registration, API, registration password,...). Suivant la méthode employée, les actions sur l'agent ou sur le manager ou les deux.
Pour le service de registration, c'est la commande `agent-auth` à utiliser. Et cela se fait depuis l'agent :
```
/var/ossec/bin/agent-auth -m <manager_IP> [-A <agent_name>]
```
> Note : si le nom de l'agent n'est pas spécifié, c'est le hostname qui est utilisé

Ensuite, il faut ajouter l'IP du manager dans le fichier de configuration `/var/ossec/etc/ossec.conf` de l'agent :
```
<client>
  <server>
    <address>MANAGER_IP</address>
    ...
  </server>
</client>
```
Pour finir, il faut relancer l'agent :
```
systemctl restart wazuh-agent
```
> Pour lister les agents, depuis le manager, taper la commande `/var/ossec/bin/manage_agents -l` ou aller dans Kibana `Wazuh > Agents`
> Pour appliquer uniquement les configuration : `/var/ossec/bin/agent_control -R -a`

Pour l'inscription en ligne de commande, ou les autres modes, je vous renvoie à la [documentation](https://documentation.wazuh.com/4.0/user-manual/registering/command-line-registration.html).
En cas de problème lors de l'enregistrement, l'article [Registering Wazuh agents - Troubleshooting](https://documentation.wazuh.com/4.0/user-manual/registering/registering-agents-troubleshooting.html) peut être utile.
> Note : L'enregistrement (enrollement) peut se faire depuis la configuration du client à l'aide de la directive `<enrollment>`


### Création de groupe d'agents
Comme on a vu précédemment qu'on peut déployer une configuration sur un groupe d'agent via le fichier `agent.conf`, il faut alors au préalable créer ces groupes d'agents et ajouter chaque agent dans le/les groupes souhaités. **Remarque**: un groupe `default` est créé par défaut et la création d'un groupe se fait depuis le **manager**.
On peut créer un groupe :
- à l'aide de la commande `agent_groups` (via root)
  ```
  /var/ossec/bin/agent_groups -a -g linux-servers [-q]
  ```
> On peut ajouter `-q` pour ne pas avoir le message de confirmation

  Pour lister les groupes créés en ligne de commande, on utilise l'option `-l` :
  ```
  /var/ossec/bin/agent_groups -l
  ```
  Pour lister les agents d'un groupe, on ajoute l'option `-g` suivie du nom du groupe :
  ```
  /var/ossec/bin/agent_groups -l -g linux-servers
  ```

-  ou depuis Kiban : dans `Wazuh > Management > Groups > Add new group`

### Ajout d'agent à un Groupe
On peut ajouter un agent à un groupe :
- à l'aide de la commande `agent_groups` :
```
/var/ossec/bin/agent_groups -a -i 001 -g linux-servers -q
```
> Note : Chaque agent est identifié par un `ID` (ici 001). Pour voir cela, il faut lister les agents avec la commande `/var/ossec/bin/manage_agents -l`

- depuis Kibana : dans `Wazuh > Management > Groups > Add new group`

## Quelques cas d'usage
Comme vu dans l'introduction, Wazuh permet entre autres le monitoring d'intégrité de fichiers (FIM - File Integrity Monitoring), la détection des intrusions, la détection de vulnérabilités, ...
> Note :
> - Pour plus de détails sur les capacités de cet outil, voir [capabilities](https://documentation.wazuh.com/4.0/user-manual/capabilities/index.html)
> - Pour voir les informations sur chaque directive et ses options, voir le [user manual](https://documentation.wazuh.com/4.0/user-manual/overview.html)
> - Pour la gestion centralisée (via `agent.conf`), il faut accepter au **niveau de l'agent** l'exécution de commande à distance : en mettant `wazuh_command.remote_commands=1` dans `/var/ossec/etc/local_internal_options.conf`

### Monitoring d'intégrité de fichiers
Wazuh est capable de surveiller les systèmes de fichier et de détecter les changements/modifications et déclenche une alerte si un événement survient. C'est ce qu'on appelle [File Integrity Monitoring (FIM)](https://documentation.wazuh.com/4.0/user-manual/capabilities/file-integrity/index.html). Ce FIM est réalisé à l'aide de la directive (module) `syscheck`. Elle peut contenir plusieurs options. Par exemple :
- `frequency` : définit la fréquence des checks (vérifications de changement des fichiers)
- `directory` : définit les répertoires à monitorer
- `ignore` et `registry_ignore`: définissent les fichiers et registres (windows) à ignorer dans ces répertoires. Note : on peut ignorer le monitoring via des règles
- `alert_new_files` : active l'alerte ou non quand un nouveau fichier est créé
- `rule` : permet de créer des règles (rules).

> Remarque : Si la configuration est faite directement dans `agent.conf` sur le manager, vérifier les erreurs avec la commande `/var/ossec/bin/verify-agent-conf`

Exemple :
```
# in agent.conf
<agent_config>
...
  <!-- File Integrity Monitoring -->
  <syscheck>
      <disabled>no</disabled>
      <!-- Execute a scan every 5 minutes -->
      <frequency>300</frequency>

      <scan_on_start>yes</scan_on_start>

      <!-- Generate alert when new file detected -->
      <alert_new_files>yes</alert_new_files>

      <!-- Directories to check (perform all possible verifications) -->
      <directories>/etc,/usr/bin</directories>
      <directories check_all="yes" realtime="yes">/home</directories>
      <directories check_all="yes" realtime="yes" report_changes="yes" recursion_level="3">/test</directories>
      <nodiff>/test/private</nodiff>

      <!-- Directories to ignore on check -->
      <ignore>/etc/httpd/logs</ignore>

      <!-- File types to ignore -->
      <ignore type="sregex">.log$|.swp$</ignore>

      <skip_nfs>yes</skip_nfs>
  </syscheck>
...
</agent_config>
```
> Note :
> - `realtime="yes"` : on active le monitoring en temps réel pour le répertoire `/home`
> - `whodata="yes"` : c'est comme realtime mais ajoute en plus les informations who-data dans l'alerte. A besoin d'Auditd sous Linux.
> - `report_changes="yes"` : l'alerte affichage le contenu qui a changé. A prendre avec précaution car Wazuh copie chaque fichier monitoré dans un "a private location"
> - `recursion_level="3"` : on limite la recursivité à 3 répertoires fils.
> - - `nodiff` : empêche le contenu (sensible) d'être affiché (avec report_changes)
> - `check_all` : on vérifie tous sur le répertoire (file size, permissions, owner, last modification date, inode and all the hash sums (MD5, SHA1 and SHA256))
> - avec `rule` on peut aussi ignorer le monitoring d'un répertoire (`level="0"`)
> - On peut ajouter options comme `scan_time, scan_day` pour spécifier à partir de quel moment (jour, heure), il faut lancer le montoring sur certains fichiers

### Détection des Rootkits
La détection des rootkits se fait grâce à la directive [rootcheck](https://documentation.wazuh.com/4.0/user-manual/capabilities/anomalies-detection/anomaly-configuration.html).
```
# in agent.conf
<agent_config>

<!-- Policy monitoring -->
    <rootcheck>
        <disabled>no</disabled>
        <check_unixaudit>yes</check_unixaudit>
        <check_files>yes</check_files>
        <check_trojans>yes</check_trojans>
        <check_dev>yes</check_dev>
        <check_sys>yes</check_sys>
        <check_pids>yes</check_pids>
        <check_ports>yes</check_ports>
        <check_if>yes</check_if>
        <ignore type="sregex">^/etc/</ignore>

        <!-- Frequency that rootcheck is executed - every 12 hours -->
        <frequency>43200</frequency>

        <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
        <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>

        <skip_nfs>yes</skip_nfs>
    </rootcheck>

</agent_config>
```
> Note :
> - `rootkit_files` : définit le fichier de base de données des fichiers de rootkit. Voir les autres dans `/var/ossec/etc/rootcheck/`
> - `rootkit_trojans` : définit l'emplacement de la base de données des trojans de rootkit
> - `check_unixaudit` : active/désactive unixaudit
> - `check_pids`, `check_if`, `check_ports` : vérifie ou non respectivement les PID, les interfaces réseaux (if), les ports
> - `skip_nfs` : activer ou non le scan des montages NFS (CIFS or NFS)
> - `readall` : autoriser ou non la lecture de tous les filesystem. Si "no", seuls quelques répertoires sont lus

### Collecte des logs
La collecte des logs se fait à l'aide de [localfile](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/localfile.html#reference-ossec-localfile). Cette directive contient des sous-directives comme :
- `log_format` : définit le format du log à collecter. Exemples de format : `syslog, json, eventlog, eventchannel, squid,...`
- `location` : définit le chemin (path) d'accès au log

```
# in agent.conf
<!-- Log Data Collection -->
<agent_config profile="webserver">
  <localfile>
      <log_format>apache</log_format>
      <location>/var/log/apache2/access.log</location>
  </localfile>
</agent_config>

<agent_config os="Linux">
    <localfile>
        <location>/var/log/linux.log</location>
        <log_format>syslog</log_format>
    </localfile>
</agent_config>
```
> Note : ici on note que la collecte se fait par affinité (os et profile)

### Inventaire système
L'agent peut collecter sur la machine des informations du système comme les processus, les paquets installés, les ports, ... Cela se fait à l'aide de la directive [wodle name=”syscollector”](https://documentation.wazuh.com/4.0/user-manual/capabilities/syscollector.html). Pour information, l'inventaire système est activé par défaut. On peut donc le désactiver, modifier,... Voici la configuration par défaut.
```
<!-- System inventory -->
<wodle name="syscollector">
  <disabled>no</disabled>
  <interval>1h</interval>
  <scan_on_start>yes</scan_on_start>
  <hardware>yes</hardware>
  <os>yes</os>
  <network>yes</network>
  <packages>yes</packages>
  <ports all="no">yes</ports>
  <processes>yes</processes>
</wodle>
```
> Note :
> - Ici, on active l'inventaire des informations de l'os, des paquets, du matériel, ...
> - Le résultat de l'invenatire est stocké au niveau du manager dans `/var/ossec/queue/db/`.
> - On peut visualiser les informations collectées en interrogent la base via `sqlite3`, via l'API ou depuis Kibana. Voir la documentation

### Scan de vulnerability
Wazuh peut scanner aussi les vulnérabilités du système grâce à [vulnerability-detector](https://documentation.wazuh.com/4.0/user-manual/capabilities/vulnerability-detection/index.html#vulnerability-detection) (sur le manager uniquement).  Pour cela :
1. configurer l'inventaire système pour collecter au moins les informations de l'os (cf paragraphe dédié à ça).
2. configurer la détection de vulnérabilité sur le manager (`ossec.conf`)
  ```
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>

    <!-- Ubuntu OS vulnerabilities -->
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>bionic</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Aggregate vulnerabilities -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>
  </vulnerability-detector>
  ```
  > Note :
  > - dans la section `provide`, on choisit les bases de données de vulnérabilités canonical (pour ubuntu) et NVD (CVEs from the National Vulnerability Database), on sélectionner les os (bionic, ici) et on détermine les intervalles de scan.
  > - Pour plus de détails, voir la documentation

3. redémarrer le manager `systemctl restart wazuh-manager`

### Audit de conformité des configurations
[SCA (Security Configuration Assessment)](https://documentation.wazuh.com/4.0/user-manual/capabilities/sec-config-assessment/index.html#manual-sec-config-assessment) est un module qui peut-être utilisé pour l'audit de configuration du système avec Wazuh.
Pour un audit, il faut choisir une politique (stratégie), définie à l'aide de `policy`. Chaque politique est décrite dans un fichier `.yml`. Par défaut, le manager est installé avec plusieurs politiques SCA. Par défaut, ces fichiers se trouvenent dans `/var/ossec/ruleset/sca`.
> Note :
> - La plupart de ces politiques sont désactivées par défaut (extension `.disabled`). Il faut les renommer avant de les utiliser en enlevant cette extension.
> - Aussi il faut activer `sca.remote_commands` sur l'agent pour autoriser le manager à pousser ces fichiers : `echo "sca.remote_commands=1" >> /var/ossec/etc/local_internal_options.conf`. Attention : ne pas modifier directement dans `internal_options.conf`

```
# in agent.conf
<agent_config>

 <!-- Security configuration Assessment -->
 <sca>
   <enabled>yes</enabled>
   <scan_on_start>yes</scan_on_start>
   <interval>1h</interval>
   <skip_nfs>yes</skip_nfs>
   <!-- Policies -->
   <policies>
     <policy>sca_unix_audit.yml</policy>
     <policy>web_vulnerabilities.yml</policy>
     <policy>cis_apache_24.yml</policy>
     <policy enabled="no">cis_mysql5-6_community.yml</policy>
   </policies>
 </sca>

</agent_config>
```
Cette configuration peut être idéale pour un serveur web Linux sous Apache avec Mysql56 installé dessus.

> Note :
> - Ces fichiers seront poussés vers l'agent et se trouveront aussi dans `/var/ossec/ruleset/sca`. Par défaut, l'agent exécute chaque fichier `.yml` présent sur ce répertoire.
> - à l'aide de l'attribut `enable`, on peut activer/désactiver une politique (ici, on a désactiver Mysql).
> - Pour créer une politique d'audit personnalisée, voir [Creating custom SCA policies](https://documentation.wazuh.com/4.0/user-manual/capabilities/sec-config-assessment/creating_custom_policies.html).

On peut effectuer l'audit de conformité aussi via [OpenSCAP](https://www.open-scap.org/) grâce au module [OpenSCAP wodle](https://documentation.wazuh.com/4.0/user-manual/capabilities/policy-monitoring/openscap/index.html) (`<wodle name="open-scap">`). Avec `content`, on détermine le type de content (xccdf ou oval) et choisit le content (politique).
```
<wodle name="open-scap">
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>

    <content type="xccdf" path="ssg-centos-7-ds.xml"/>
    <content type="xccdf" path="ssg-centos-6-ds.xml"/>
</wodle>
```

### Monitoring cloud
Wazuh est capable de monitorer les ressources des Cloud comme AWS et Azure grâce à `wodle name=”aws-s3”` et `wodle name=”azure-logs”`.
Ici, nous allons voir comment monitorer les ressources du cloud Azure.
#### Monitoring cloud Azure
Via Wazuh, on peut [monitorer les ressources de Microsoft Azure](https://documentation.wazuh.com/4.0/azure/index.html) : les instances (VM) du cloud Azure, Log analytics, ou encore le stockage.
Pour les instances, il faut installer l'agent sur les instances et collecter les logs, détecter les rootkits, vérifier l'intégrité des fichiers, ... comme on l'a vu plus haut. Pour notre cas, nous allons voir comment interroger [Log Analytics](https://documentation.wazuh.com/4.0/azure/monitoring-activity.html#using-azure-log-analytics) afin de collecter les données d'activity et diagnostique [(Activity, Azure Diagnostics)](https://documentation.wazuh.com/4.0/azure/monitoring-activity.html#using-azure-log-analytics).

1. Pour ces collectes, on peut utiliser l'API REST d'Azure Log Analytics ou Azure Storage accounts. Donc, il faut au préalable disposer des informations d'identification. Voir les détails dans la documentation (lien Log Analytics).
2. Configurer le wodle azure-logs
```
<wodle name="azure-logs">

    <disabled>no</disabled>
    <day>15</day>
    <time>02:00</time>
    <run_on_start>yes</run_on_start>

    <log_analytics>

        <application_id>8b7...c14</application_id>
        <application_key>w22...91x</application_key>
        <tenantdomain>wazuh.onmicrosoft.com</tenantdomain>

        <request>
            <tag>azure-activity</tag>
            <query>AzureActivity | where SubscriptionId == 2d7...61d </query>
            <workspace>d6b...efa</workspace>
            <time_offset>36h</time_offset>
        </request>

    </log_analytics>

</wodle>
```
> Note :
> Dans la section `log_analytics` :
> - on renseigne les ID d'authentication (application_id, application_key)
> - on definit la requête dans `request`, le workspace et autres paramètres. `query` peut prendre n'importe quelle requête comprise par Log Analytics
> les ID d'authentication peuvent être renseignés dans un fichier. On peut appeler ce fichier via `<auth_path> </auth_path>`


### Intégration avec des API tiers
Wazuh peut s'intégrer à d'autres ouils tiers comme [VirusTotal](https://www.virustotal.com/gui/)(outil d'analyse), [PagerDuty](https://www.pagerduty.com/)(outil de réponse à incident), .... Cela se fait à l'aide du module [integration](https://documentation.wazuh.com/4.0/user-manual/manager/manual-integration.html).
Exemple d'intégration à VirusTotal.
```
<integration>
  <name>virustotal</name>
  <api_key>API_KEY</api_key> <!-- Replace with your VirusTotal API key -->
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```



## Liens
- [Getting started](https://documentation.wazuh.com/4.0/getting-started/index.html)
- [User manual](https://documentation.wazuh.com/4.0/user-manual/index.html)
- [Local configuration (ossec.conf)](https://documentation.wazuh.com/4.0/user-manual/reference/ossec-conf/index.html)
