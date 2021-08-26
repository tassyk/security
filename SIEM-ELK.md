---
Title: SIEM ELK
Type: Doc
Nature: Notes
Création: 09/05/2019
Mise à jour : 18/08/2021
---

<div id="globalWrapper">
<div id="column-content">
<div id="content"><a name="top" id="top"></a>

# Déploiement SIEM ELK

<div id="bodyContent">
<table id="toc" class="toc">
<tbody>
<tr>
<td>
<div id="toctitle">

## Sommaire
<span class="toctoggle"></span></div>

*   [<span class="tocnumber">1</span> <span class="toctext">Introduction</span>](#Introduction)
*   [<span class="tocnumber">2</span> <span class="toctext">Prérequis</span>](#Pr.C3.A9requis)
    *   [<span class="tocnumber">2.1</span> <span class="toctext">Mise à jour des paquets</span>](#Mise_.C3.A0_jour_des_paquets)
    *   [<span class="tocnumber">2.2</span> <span class="toctext">Installation de java</span>](#Installation_de_java)
    *   [<span class="tocnumber">2.3</span> <span class="toctext">Dépôt Suite Elastic</span>](#D.C3.A9p.C3.B4t_Suite_Elastic)
*   [<span class="tocnumber">3</span> <span class="toctext">Elasticsearch</span>](#Elasticsearch)
    *   [<span class="tocnumber">3.1</span> <span class="toctext">Brève description d'Elasticsearch</span>](#Br.C3.A8ve_description_d.27Elasticsearch)
    *   [<span class="tocnumber">3.2</span> <span class="toctext">Installation d'Elasticsearch</span>](#Installation_d.27Elasticsearch)
    *   [<span class="tocnumber">3.3</span> <span class="toctext">Configuration d'Elasticsearch</span>](#Configuration_d.27Elasticsearch)
*   [<span class="tocnumber">4</span> <span class="toctext">Logstash</span>](#Logstash)
    *   [<span class="tocnumber">4.1</span> <span class="toctext">Brève description de Logstash</span>](#Br.C3.A8ve_description_de_Logstash)
    *   [<span class="tocnumber">4.2</span> <span class="toctext">Installation de Logstash</span>](#Installation_de_Logstash)
    *   [<span class="tocnumber">4.3</span> <span class="toctext">Configuration de Logstash</span>](#Configuration_de_Logstash)
    *   [<span class="tocnumber">4.4</span> <span class="toctext">Création des pipelines de Logstash</span>](#Cr.C3.A9ation_des_pipelines_de_Logstash)
    *   [<span class="tocnumber">4.5</span> <span class="toctext">Le plugin de filtre Grok</span>](#Le_plugin_de_filtre_Grok)
*   [<span class="tocnumber">5</span> <span class="toctext">Kibana</span>](#Kibana)
    *   [<span class="tocnumber">5.1</span> <span class="toctext">Brève description de Kibana</span>](#Br.C3.A8ve_description_de_Kibana)
    *   [<span class="tocnumber">5.2</span> <span class="toctext">Installation de Kibana</span>](#Installation_de_Kibana)
    *   [<span class="tocnumber">5.3</span> <span class="toctext">Configuration de Kibana</span>](#Configuration_de_Kibana)
    *   [<span class="tocnumber">5.4</span> <span class="toctext">Interface de Kibana</span>](#Interface_de_Kibana)
        *   [<span class="tocnumber">5.4.1</span> <span class="toctext">Création d'index</span>](#Cr.C3.A9ation_d.27index)
        *   [<span class="tocnumber">5.4.2</span> <span class="toctext">Recherche dans les logs</span>](#Recherche_dans_les_logs)
*   [<span class="tocnumber">6</span> <span class="toctext">Beats</span>](#Beats)
    *   [<span class="tocnumber">6.1</span> <span class="toctext">Filebeat</span>](#Filebeat)
        *   [<span class="tocnumber">6.1.1</span> <span class="toctext">Installation de Filebeat</span>](#Installation_de_Filebeat)
        *   [<span class="tocnumber">6.1.2</span> <span class="toctext">Configuration de Filebeat</span>](#Configuration_d'_Auditbeat)
    *   [<span class="tocnumber">6.1</span> <span class="toctext">Auditbeat</span>](#Auditbeat)
        *   [<span class="tocnumber">6.1.1</span> <span class="toctext">Installation d'Auditbeat</span>](#Installation_d'_Auditbeat)
        *   [<span class="tocnumber">6.1.2</span> <span class="toctext">Configuration d'Auditbeat</span>](#Configuration_d'Auditbeat)
    *   [<span class="tocnumber">6.1</span> <span class="toctext">Winlogbeat</span>](#Winlogbeat)
        *   [<span class="tocnumber">6.1.1</span> <span class="toctext">Installation de Sysmon</span>](#Installation_de_Winlogbeat)
        *   [<span class="tocnumber">6.1.2</span> <span class="toctext">Installation de Winlogbeat</span>](#Installation_de_Winlogbeat)
        *   [<span class="tocnumber">6.1.3</span> <span class="toctext">Configuration de Winlogbeat</span>](#Configuration_de_Winlogbeat)
*   [<span class="tocnumber">7</span> <span class="toctext">Informations supplémentaires</span>](#Informations_supplémentaires)
    *   [<span class="tocnumber">7.1</span> <span class="toctext">Security Elastic Stack</span>](#Security_Elastic_Stack)
    *   [<span class="tocnumber">7.2</span> <span class="toctext">Elastic Agent</span>](#Elastic_Agent)
    *   [<span class="tocnumber">7.3</span> <span class="toctext">Troubleshooting</span>](#Troubleshooting)

</td>

</tr>

</tbody>

</table>

<script type="text/javascript">if (window.showTocToggle) { var tocShowText = "afficher"; var tocHideText = "masquer"; showTocToggle(); }</script>

<a name="Introduction"></a>

## Introduction

ELK est la contraction des noms des trois produits phares de la Suite Elastic (**Elasticsearch, Logstash et Kibana**). La combinaison de ces produits permet d'avoir un outil de centralisation des logs performant pour surveiller les logs systèmes et applicatifs afin de signaler des anomalies, des failles de sécurité et de réaliser des diagnostiques. A ceux-là, s'ajoutent d'autres produits de la Suite Elastic, comme les **Beats** (filebeat, metricbeat, heartbeat, auditbeat, winlogbeat, ...) qui étendent les fonctionnalités et les possibilités offertes pas ces trois derniers.  
Dans cette section, nous allons voir comment installer et configurer ces produits manuellement et de les faire communiquer ensemble pour remonter les logs. L'installation se fera sur une distribution **Centos** (Centos 7), en mode standalone (tout sur le même serveur). 
> Note : 
> - Pour tester rapidement la solution, peut-être, il faudrait regarder la version Elastic Cloud ou Docker.
> - Pour d'autres modes d'installations, `localhost` doit être remplacé partout par l'IP ou le fqdn correspondant.
> la machine Centos représentera aussi le client Linux pour la collecte de logs. On utilisera aussi un poste windows 10 pour collecter les événements windows.

<a name="Pr.C3.A9requis"></a>

## Prérequis
> Note : Comme on ne dispose pas d'un serveur DNS, on va renseigner le fqdn de la machine dans `/etc/hosts` comme suit :
    ```
    192.168.56.104 elk-centos7-test
    192.168.56.104 els-centos7-test # elastic
    192.168.56.104 kib-centos7-test # kibana
    192.168.56.104 lgs-centos7-test # logtash
    192.168.56.105 elk-windows-client-test # windows
    ```
> Pour la suite, on utilisera ces fqdn ou cette IP.

<a name="Mise_.C3.A0_jour_des_paquets"></a>

### <ins>Mise à jour des paquets</ins>

Avant de procéder à l'installation d'aucun produit, veuillez mettre à jour les paquets.

```
sudo yum update -y
```

<a name="Installation_de_java"></a>

### <ins>Installation de java</ins>

Ceratins composants de la Suite Elastic comme Elasticsearch et Logstash ont besoin de java (Openjdk >= 1.8) pour fonctionner. Pour installer java 1.8, voici la commande:  

```
sudo yum install -y java-1.8.0-openjdk
```

<a name="D.C3.A9p.C3.B4t_Suite_Elastic"></a>

### <ins>Dépôt Suite Elastic</ins>

Les composants de la Suite Elastic peuvent être installés de différentes manières (archives, paquets deb et rpm, dépôt yum ou deb, docker, ansible, pupet,...), et selon différentes architectures (distribuée, mode standalone). Ici, nous allons utiliser la méthode d'installation via [RPM](https://www.elastic.co/guide/en/elasticsearch/reference/current/rpm.html), c'est-à-dire le dépôt YUM. La Suite Elastic est actuellement à la version 7.x. Nous allons donc installer cette version. Pour ajouter le dépôt yum:  

1.  créer un fichier */etc/yum.repos.d/elastic.repo*
2.  et ajouter ce contenu dedans :
<pre>
[elastic-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=0
enabled=1
autorefresh=1
type=rpm-md
</pre>
3. Importer la clé Elastic PGP
```
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch
```
> C'est facultatif puisque `gpgcheck=0`

Tous les produits de la Suite Elastic peuvent être installés à via ce dépôt. Si ELK est installé sur différentes machines séparément, il faut copier ce dépôt sur chacune d'elles.

<a name="Elasticsearch"></a>

## [Elasticsearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/getting-started.html)

<a name="Br.C3.A8ve_description_d.27Elasticsearch"></a>

### <ins>Brève description d'Elasticsearch</ins>

Elasticsearch est la partie de la Suite Elastic qui stocke les informations dont les logs et les met à la disposition pour la recherche (c'est un moteur de recherche basé sur **[Apache Lucène](https://lucene.apache.org/")**. C'est une base de données **[NoSQL](https://fr.wikipedia.org/wiki/NoSQL )** dont la particularité est de pouvoir indexer des documents fortement orientés textes. Il est développé en **Java** et est doté d'une **[API Resful](https://fr.wikipedia.org/wiki/Representational_state_transfer)** permettant d’interagir avec l'application. Cependant l'API est développée dans d'autres langages aussi comme Python, Java,... Dans Elasticsearch, les informations sont stockées dans ce qu'on appelle les **Index**. Chaque information à stocker dans Elasticsearch doit être au format **JSON**. Elasticsearch peut être installé en mode **Cluster**. Et dans ce cas, chaque machine du cluster est appelé un **noeud**.

<a name="Installation_d.27Elasticsearch"></a>

### <ins>Installation d'Elasticsearch</ins>

Comme le dépôt est prêt, on peut installer Elasticsearch via la commande ci-dessous:  
```
sudo yum install -y elasticsearch --enablerepo=elastic-7.x
```

Pour activer le démarrage du service au boot et démarrer le service elasticsearch, utiliser les commande ci-dessous:

```
# démarrer au boot
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch

# démarrer le service
sudo systemctl start elasticsearch
```
> Regarder le status pour voir que tout se passe bien :
```
sudo systemctl status elasticsearch
```

> On peut aussi interroger l'API pour vérifier que l'installation s'est bien passée, via la commande:

```
curl els-centos7-test:9200
```

Si curl n'est pas installé sur la machine, on peut taper l'url ci-contre dans le navigateur: **[http://els-centos7-test:9200](http://els-centos7-test:9200/)**.  
Si l'installation s'est bien passé, la commande (ou le navigateur) affiche le résultat ci-dessous:

<pre>
{
  "name" : "elk-centos7-test",
  "cluster_name" : "elasticsearch",
  "cluster_uuid" : "PHl7pcwwTqyEyNPD_QPdeQ",
  "version" : {
    "number" : "7.14.0",
    "build_flavor" : "default",
    "build_type" : "rpm",
    "build_hash" : "dd5a0a2acaa2045ff9624f3729fc8a6f40835aa1",
    "build_date" : "2021-07-29T20:49:32.864135063Z",
    "build_snapshot" : false,
    "lucene_version" : "8.9.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
</pre>

Voici d'autres commandes utiles pour vérifier dans les journaux si le produit fonctionne correctement:

```
sudo journalctl -f
sudo journalctl --unit elasticsearch
sudo journalctl --unit elasticsearch --since  "2021-08-18"
sudo less /var/log/elasticsearch/elasticsearch.log
```

> Si le produit ne fonctionne pas, cela peut être dû à plusieurs facteurs:  
<pre>
- java qui n'est pas installé  
- mauvaise configuration  
- Mémoire Ram de la machine trop petite pour supporter elasticsearch (cf JVM heap dans la conf)  
- 'bootstrap.memory_lock' est à 'true' dans '/etc/elasticsearch/elasticsearch.yml' alors que MAX_LOCKED_MEMORY n'est pas 'unlimited' dans '/etc/sysconfig/elasticsearch'  
- blocage du port 9200 par le firewall local  
- Selinux activé or le contexte selinux n'est pas actualisé pour prendre en compte Elasticsearch : `sudo sestatus`
- ...
</pre>

<a name="Configuration_d.27Elasticsearch"></a>

### <ins>Configuration d'Elasticsearch</ins>

Par défaut, les fichiers de configuration d'Elasticsearch se trouvent dans le répertoire **/etc/elasticsearch/**. Le contenu de répertoire peut ressembler à ceci:

<pre>
├── elasticsearch.keystore
├── elasticsearch.yml
├── jvm.options
├── jvm.options.d
├── log4j2.properties
├── role_mapping.yml
├── roles.yml
├── users
└── users_roles
</pre>

Les fichiers les plus importants sont **elasticsearch.yml** qui permet de configurer elasticsearch et **jvm.options** qui permet de modifier la taille du Heap java. Pour un usage basic (installation standalone), ces fichiers n'ont pas besoin d'être édités. Par contre, si on souhaite modifier/adapter la configuration selon le contexte, voici les paramètres les plus importants:  

*   dans **elasticsearch.yml**:  
    <pre>
    - cluster.name : nom du cluster (standalone_elk)
    - node.name: nom du noeud du cluster (els-centos7-test)
    - network.host: interface d'écoute (els-centos7-test, sinon c'est localhost par defaut)
    - discovery.seed_hosts: noms des machines qui adhèrent au cluster (discovery.seed_hosts: ["els-centos7-test"])
    - cluster.initial_master_nodes: les noeuds du cluster qui sont éligibles pour devenir le noeud 'Master' du cluster 
    </pre>
    > Note : ces paramètres sont importants pour une utilisation en mode cluster d'Elasticsearch.
    > Remarque : En  mettant une IP/fqdn à ``network.host``, il faut aussi mêtre au moins un hôte dans `discovery.seed_hosts`.

*   dans **jvm.options**:  
    <pre>
    -Xms et -Xmx qui définissent les tailles de JVM heap. Au maximum, ces valeur ne doivent pas excéder la moitié de la RAM et elles doivent être égales.
    NB: En mode Standalone, il faut s'assurer que la machine dispose de beaucoup de RAM ou il faut réduire considérablement ces valeurs.
    </pre>
> Pour plus de détails dans les paramètres de configurations, voir la [documentation officielle](https://www.elastic.co/guide/en/elasticsearch/reference/current/settings.html)  

Redémarrer le service après ces modifications :
```
sudo systemctl restart elasticsearch
```

<ins>**Remarque**</ins> : 
> A ce stade, on peut créer manuellement des indexes dans Elasticsearch pour stocker des informations au format JSON. Mais on s’appuiera sur Logstash et les beats pour réaliser cela.

<a name="Logstash"></a>

## [Logstash](https://www.elastic.co/fr/products/logstash "https://www.elastic.co/fr/products/logstash")

<a name="Br.C3.A8ve_description_de_Logstash"></a>

### <ins>Brève description de Logstash</ins>

Logstash développé en Java aussi. Il est l’outil de collecte et d’analyse des logs. Il prend les logs en entrée afin de les transformer et les parser pour ensuite les envoyer et stocker dans Elasticsearch (ou dans d'autres outils). Pour réaliser cela, il dispose de trois fonctions:  

* [input {}](https://www.elastic.co/guide/en/logstash/current/input-plugins.html) 

* [filter {}](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html) 

* [output {}](https://www.elastic.co/guide/en/logstash/current/output-plugins.html") 

Ces fonctions sont définies dans un **pipeline** logstash. Le pipeline est un fichier de configuration dans lequel on indique à logstash où trouver les logs (**input**), quelles traitements il faut réaliser sur ces logs (**filter**) et où les envoyer après (ou sans) transformations (**output**). On peut également utiliser des conditions **if** dans un pipeline. On verra l'utilisation de ces trois fonctions plus tard quand on va créer des pipelines.  

<ins>**Remarque**</ins> :
> Parmi les plugins input et output de Logstash, on trouve des brokers de message comme Rabbitmq ou Kafka qui permettent de mettre en file d'attente les logs collectés par Logstash avant de les envoyer vers un output (comme Elasticsearch). Plus bas, nous verrons dans la section dédiée à [**Rabbitmq**](http://exploit1/wikiexploit/index.php/Rabbitmq "http://exploit1/wikiexploit/index.php/Rabbitmq"), comment cela fonctionne.

<a name="Installation_de_Logstash"></a>

### <ins>Installation de Logstash</ins>

Comme Elasticsearch, Logstash aussi besoin de java pour fonctionner. Ne sauter pas cette étape si logstash n'est pas installé sur la même machine que Elasticsearch.  
Logstash s'installe aussi facilement qu'Elasticsearch:

```
sudo yum install -y logstash
````

Le démarrage du service logstash se fait aussi de la même manière qu'Elasticsearch.
```
#démarrage au boot
sudo systemctl daemon-reload
sudo systemctl enable logstash

#démarrer le service
sudo systemctl start logstash
```
<ins>**Remarque**</ins>:  
> A ce stade, il ne faut pas redémarrer le service pour l'instant. Il faut créer un pipeline logstash au préalable pour ingérer les logs (voir plus loin). Sinon la consommation CPU de votre machine va grimper.

Pour tester l'installation de Logstash, tester ce pipeline basic ci-dessous:
```
cd /usr/share/logstash/bin
sudo ./logstash -e 'input { stdin { } } output { stdout {} }' --path.settings /etc/logstash/
```

> Attendez quelques secondes que logstash finisse son traitement. Sur l'écran, dès que vous remarquez ce message `The stdin plugin is now waiting for input:` écrivez un mot (comme 'logstash basic pipeline'). Logstash nous répond avec un message contenant ce qu'on a écrit:

<pre>
{
      "@version" => "1",
          "host" => "elk-centos7-test",
    "@timestamp" => 2021-08-18T15:21:16.653Z,
       "message" => "logstash basic pipeline"
}
</pre>

> Pour arrêter le test, appuyer sur **CTR+C**  
Ainsi logstash est correctement installé, on peut alors créer des pipelines pour collecter les logs sur les machines et les envoyer vers elasticsearch.

<a name="Configuration_de_Logstash"></a>

### <ins>Configuration de Logstash</ins>

Les fichiers de configuration de logstash se trouvent dans le répertoire **/etc/logstash**:

<pre>
├── conf.d
├── jvm.options
├── log4j2.properties
├── logstash-sample.conf
├── logstash.yml
├── pipelines.yml
└── startup.options
</pre>

> Franchement, ces fichiers n'ont pas besoin d'être modifiés sauf si on faire quelques changements comme :  

* changer le répertoire des plugins de logstash (par defaut, /var/lib/logstash), activer le chargement automatique des pipelines (``config.reload.automatic: true``) ou ajouter d'autres options de configuration non fournies avec l'installation dans **logstash.yml**  
* ou modifier les JVM Heap, comme on l'a vu avec Elasticsearch, dans **jvm.options**.  
* ou changer le répertoire des pipelines dans **pipelines.yml**.
C'est le répertoire **conf.d** qui permet de stocker les pipelines qui est le plus utile.  
* ou l'interface d'écoute de l'API HTTP (par défaut c'est `http.host: 127.0.0.1`)

<a name="Cr.C3.A9ation_des_pipelines_de_Logstash"></a>

### <ins>Création des pipelines de Logstash</ins>

Le répertoire **conf.d** permet de stocker les pipelines Logstash. Comme on l'a mentionné plus haut, un pipeline est un fichier comprenant au plus trois sections (fonctions):  

* **input**: correspond à l'ingestion des logs. Il permet de spécifier les sources de log et le plugin qui va collecter ces logs  
* **filter**: réalise des traitements (transformation) sur chaque ligne de log afin l'adapter au format JSON (compréhensible) par Logstash et faire d'autres type de transformation comme le changement du format des dates, la modification des champs, la geolocalisation,...  
* **output**: c'est le stockage vers lequel les logs vont être envoyés.  

> NB: Pour certains plugins input, la section filter (comme les beats) n'est pas obligatoire.  
Logstash dispose d'une multitude de plugins pour chaque fonction ([input](https://www.elastic.co/guide/en/logstash/current/input-plugins.html), [filter](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html), [output](https://www.elastic.co/guide/en/logstash/current/output-plugins.html)) et chaque plugin dispose plusieurs paramètres.  
Pour tester l'utilisation des pipelines, nous allons créer un fichier nommé (par exemple) **test-pipeline.conf** et y ajouter les lignes suivantes:  

```
cd /etc/logstash/conf.d

# in test-pipeline.conf

input { 
    stdin { } 
}
filter {
    grok {
        match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
        match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
}
output {
    elasticsearch { hosts => ["els-centos7-test:9200"] }
    stdout { codec => rubydebug }
}
```

Ce pipeline prend en entrée (**input**) tout ce qui est saisi au clavier, et applique la transformation adaptée au log apache (**filter -> grok**), change le format de la date (**filter -> date**) puis envoie le résultat vers le serveur elasticsearch (**output**).
> Remarque : `stdout { codec => rubydebug }` permet d'afficher le résultat aussi sur la sortie standard. 

Pour exécuter ce pipeline, entrer la commande ci-dessous (on est dans conf.d):
```
sudo /usr/share/logstash/bin/logstash -f test-pipeline.conf --path.settings /etc/logstash/
```
> Remarque : si le service logstash est en cours d'utilisation, il faut l'arrêter pour exécuter cette commande. Après le test, il faut enlever la ligne `stdout { codec => rubydebug }` avant de relancer le service logstash.

Attendre la fine du traitement du pipeline par logstash (apparition de la ligne '`Successfully started Logstash API endpoint {:port=>9600}' ou The stdin plugin is now waiting for input`). Comme la transformation souhaitée est celle d'une ligne de log Apache, nous allons entrer au clavier une ligne de log Apache:

<pre>
127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] "GET /xampp/status.php HTTP/1.1" 200 3891 "http://cadenza/xampp/navi.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0"
</pre>

Logstash nous renvoie alors le résultat ci-dessous (ligne de log précédente en JSON), montrant que le pipeline fonctionne.

<pre>
{
          "agent" => "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"",
       "clientip" => "127.0.0.1",
           "auth" => "-",
        "request" => "/xampp/status.php",
       "@version" => "1",
     "@timestamp" => 2013-12-11T08:01:45.000Z,
          "ident" => "-",
       "response" => "200",
           "host" => "elk-centos7-test",
           "verb" => "GET",
    "httpversion" => "1.1",
       "referrer" => "\"http://cadenza/xampp/navi.php\"",
          "bytes" => "3891",
      "timestamp" => "11/Dec/2013:00:01:45 -0800",
        "message" => "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\""
}
</pre>

> La transformation en JSON a été réalisée grâce au [plugin de filtre Grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html"). Nous allons voir, en peu plus bas, comment ce filtre fonctionne.  

Ce pipeline sert de test. Mais si on dispose d'un serveur web apache sur la machine ou un fichier contenant des logs d'access apache (/tmp/access_log), on peut changer la section **input** de ce pipeline pour mettre un autre plugin d'ingestion de log comme **file** ou **tcp** ou **beats** pour 'choper' les logs du serveur web. Ainsi le pipeline devient (avec le plugin **file** et n'oubliez pas de changer le chemin du fichier de log si besoin):

<pre>
# cat logstash-apache.conf

    input {
        file {
            path => "/tmp/access_log"
            start_position => "beginning"
        }
    }
    filter {
        grok {
            match => { "message" => "%{COMBINEDAPACHELOG}" }
        }
        date {
            match => [ "timestamp" , "dd/MMM/yyyy:HH:mm:ss Z" ]
        }
    }
    output {
        elasticsearch { 
            hosts => ["http://els-centos7-test:9200"]
            index => "logstash-apache-%{+YYYY.MM.dd}"
        }
        stdout { codec => rubydebug }
    }
</pre>

<ins>**Remarques**</ins> :    
> Dans la section **output**, on a ajouté une ligne, **index => "logstash-apache-%{+YYYY.MM.dd}"**, pour nommer notre indexe elasticsearch. En effet, par défaut, tous les logs envoyés via logstash vers Elasticsearch sont indexés "**logstash-date**". Mais on peut préciser un autre nom (n'importe lequel) pour notre indexe si on le souhaite. La chaîne **%{+YYYY.MM.dd}** permet d'ajouter la date au format (année.moi.jour) à notre indexe. Cependant ce n'est pas indispensable, mais fortement recommandé.  
Pour d'autres exemples de configuration d'un pipeline, voir [ici](https://www.elastic.co/guide/en/logstash/current/config-examples.html).  

Après avoir créé ce pipeline fonctionnel, on peut maintenant **démarrer le service logstash** comme on l'a vu plus haut.  
```
sudo systemctl start logstash
sudo systemctl status logstash # voir le status
```
 
> Quand le service logstash tourne déjà, on n'a pas besoin de le redémarrer à chaque fois qu'on crée on pipeline. On peut juste utiliser la commande ci-dessous (depuis **/etc/logstash/conf.d**) pour prendre en compte ce nouveau pipeline par logstash:

```
sudo /usr/share/bin/logstash -f logstash-apache.conf  --path.settings /etc/logstash/
```
> Note : `--debug`, ajouté à la commande permet de débuger.

> Le paramètre "**--path.settings**" permet de préciser le répertoire de configuration de Logstash. En effet, s'il n'est pas précisé, parfois on reçoit un warning comme quoi logstash ne trouve pas le fichier de configuration **logstash.yml**. Mais c'est pas obligatoire. On peut juste se limiter à la commande:

```
sudo /usr/share/bin/logstash -f logstash-apache.conf
```

> Dans la section output, la ligne "**stdout { codec => rubydebug }**" permet juste de voir les résultats sur l'écran pour s'assurer que cela fonctionne. Mais ce n'est pas obligatoire si on compte envoyer les logs vers un stockage comme elasticsearch.  

<a name="Le_plugin_de_filtre_Grok"></a>

### <ins>Le plugin de filtre Grok</ins>

<ins>**Description**</ins> : 
Le rôle du [plugin de filtre Grok](https://www.elastic.co/guide/en/logstash/current/plugins-filters-grok.html) est de permettre à **analyser** un texte arbitraire ( **non structurées**) et de le transformer en données exploitables (**structurées**) et facilement **interrogeables**. Cet outil est adéquat pour tout format de log qui est généralement écrit pour les humains et non pour la consommation d'ordinateur.  
Il permet de à Logstash de transformer les logs au format **JSON**, compréhensible par Elasticsearch.

<ins>**Utilisation**</ins> :  
Grok utilise des patterns qui ne sont rien d'autre qu'un ensemble d'expressions régulières. Il combine ces expressions régulières pour correspondre aux lignes de logs.  
La syntaxe d'un motif du pattern de grok est **%{MOTIF:SEMANTIC}**. Ici _**MOTIF**_ est le motif du pattern de Grok qui correspond à un champ de votre ligne de Log et _**SEMANTIC**_ est la sémantique de ce champ, c'est à dire le nom que vous lui donnez.  
Par exemple, avec cette ligne de log, voici à quoi peut ressembler le pattern de Grok:

<pre>
    # Ligne de log
    55.3.244.1 GET /index.html 15824 0.043

    # Pattern Grok
    %{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}
</pre>

Ainsi, on peut appliquer ce filtre à Logstash comme ceci:

<pre>
    filter {
        grok {
            match => { "message" => "%{IP:client} %{WORD:method} %{URIPATHPARAM:request} %{NUMBER:bytes} %{NUMBER:duration}" }
        }
    }
</pre>

Ce qui produit en sortie sortie, ceci:
<pre> 
    {
        "client": "55.3.244.1"
        "method": "GET"
        "request": "/index.html"
        "bytes": "15824"
        "duration": "0.043" 
    }
</pre>

<ins>**Aide à la construction des patterns**</ins> :
L'équipe Elastic a proposé plusieurs [patterns Grok pour logstash](https://github.com/logstash-plugins/logstash-patterns-core/tree/master/patterns). La communauté également en a proposé d'autres. Ces patterns permettent de transformer quasiment tout type de log.  
Si jamais on ne trouve pas un pattern Grok qu'on veut, on peut en créer un, costumisé, en respectant cette syntaxe : 
```
(?<field_name>the pattern here)
````


Et pour aider à la construction de Grok, le site [Grok Constructor](http://grokconstructor.appspot.com/do/match) ou [Grok Debugger](http://grokdebug.herokuapp.com/) peut faire l'affaire. Mais dans l'interface de Kibana, il y également a un endroit (Onglet **Dev Tools > Grog Debugger**) prévu pour cela.  

<ins>**Remarque**</ins> :
> *Grok n'est pas le seul plugin de filtre proposé par Logstash, il y a également le plugin [Dissect](https://www.elastic.co/guide/en/logstash/current/plugins-filters-dissect.html). Celui-ci est plus facile à utiliser mais il est fait pour les **logs contants**. Il n'utilise pas d'expressions régulières et est très rapide. Il est contruit à l'aide d'un ensemble de sections **%{}**.* 
Par exemple, avec ce texte, voici à quoi peut ressembler la dissection:
<pre>
    # texte
    John Smith,Big Oaks,Wood Lane,Hambledown,Canterbury,CB34RY

    # dissect
    %{name},%{addr1},%{addr2},%{addr3},%{city},%{zip}
</pre>

> *Et à la sortie, on aura ceci :*

<pre>
    {
        "name": "Jane Doe",
        "addr1": "4321 Fifth Avenue",
        "addr2": "",
        "addr3": "",
        "city": "New York"
        "zip": "87432"
    }
</pre>

> *Cependant, si la structure de votre texte **varie d'une ligne à l'autre**, Grok est plus **approprié**.*

Ceci est une brève explication de Grok. Dans la partie concernant les **beats** (plus loin), nous allons créer un pipeline et montrer comment les logs sont envoyés par Logstash vers Elasticsearch.

<a name="Kibana"></a>

## [Kibana](https://www.elastic.co/guide/en/kibana/current/index.html)

<a name="Br.C3.A8ve_description_de_Kibana"></a>

### <ins>Brève description de Kibana</ins>

Kibana est la partie de la Suite Elastic qui permet d'explorer, visualiser et analyser les informations ou logs stockées dans Elasticsearch. Il dispose d'une interface web assez intuitive permettant de manipuler ces données et de créer des tableaux de bord et graphiques et faire des reportings.

> Différents choix de graphiques sont possibles :  
> - Graphique en barre ou en ligne  
> - Nuage de points  
> - Histogrammes  
> - Placés sur une carte  

<a name="Installation_de_Kibana"></a>

### <ins>Installation de Kibana</ins>

L'installation de Kibana se fait avec la commande ci-dessous :

```
sudo yum install -y kibana
```

Ensuite, il faut activer le démarrage du service kibana :

```
#Démarrage au boot
sudo systemctl daemon-reload
sudo systemctl enable kibana

#Démarrage manuel
sudo systemctl start kibana
```

> *Si la machine dispose d'une interface graphique, on peut accéder à Kibana via l'URL: [http://kib-centos7-test:5601](http://kib-centos7-test:5601/"). Sinon (comme c'est mon cas), il faut configurer Kibana (`kibana.yml`) pour qu'il écoute sur un autre fqdn ou une adresse IP (`server.host: kib-centos7-test`) puis pointer le navigateur sur la nouvelle URL [http://kib-centos7-test:5601](http://kib-centos7-test:5601/) ou [http://192.168.56.104:5601](http://192.168.56.104:5601/).  
**NB**: Il faut faut redémarrer le service Kibana pour prendre en compte les modifications dans la configuration.*

**Remarque**:  
> *En accédant à l'interface de kibana, on peut parfois apercevoir ce message d'erreur "**Kibana server is not ready yet**". ceci est souvent lié au problème de communication de kibana avec Elasticsearch (défaut de configuration, services arrêté ou pas démarrage en cours, ...). Vérifier les logs de Kibana et elasticsearch et les status des services.

<a name="Configuration_de_Kibana"></a>

### <ins>Configuration de Kibana</ins>

Le fichier de configuration de kibana, **kibana.yml**, se trouve par défaut dans le répertoire **/etc/kibana/**. Ce fichier contient plusieurs paramètres dont les plus importants sont:
<pre>
- server.port: le port d'écoute de Kibana (5601, par déafut)
- server.host: le fqdn ou l'IP d'écoute de Kibana (kib-centos7-test)
- elasticsearch.hosts: les URLs des instances elasticsearch servant pour les requêtes (["http://els-centos7-test:9200"])
</pre>

D'autres paramètres aussi sont intéressants pour sécuriser l'accès à Kibana via les certificats (server.ssl.enabled, ...) ou sécuriser la communication entre kibana et les instances elasticsearch (elasticsearch.username, elasticsearch.password, ...) ou utiliser kibana derrière un proxy (server.basePath, server.rewriteBasePath, ...). Je vois renvoie pour cela à la documentation sur la [configuration de Kibana](https://www.elastic.co/guide/en/kibana/current/settings.html) pour plus de détails.

<a name="Interface_de_Kibana"></a>

### <ins>Interface de Kibana</ins>

<a name="Cr.C3.A9ation_d.27index"></a>

#### <ins>Création d'index</ins>
Comme on l'a mentionné plus haut, Elasticseach utilise des indexes pour stocker les informations. Dans Kibana, il faut créer chaque indexe d'elasticsearch pour pouvoir visualiser ses contenus. Comme dans les exemples de pipeline qu'on avait créés, on avait spécifié notre instance elasticsearch comme **output**, les index apparaissent dans Kibana. Mais il faut les créer. Pour cela:  
- il faut se rendre dans `Stack Management > Index Patterns` puis cliquer sur `Create index pattern`.  
Le nom de l'indexe accepte des expressions régulières (regex) mais doit correspondre à un des indexes présents dans elasticsearch (exemple : logstash-2021.08.18-000001, ou logstash-*).  
- une fois qu'on est satisfait du nom d'index, il faut cliquer `Next step`, puis choisir timestamp dans `Time Filter field name` et enfin sur "Create index pattern" pour créer l'index. 
- Une fois l'index créé, on peut visualiser les logs l'onglet "**Discover**".
> Note : Pour gérere les indexes existants, aller dans `Stack Management > Index Management.`

<a name="Recherche_dans_les_logs"></a>

#### <ins>Recherche dans les logs</ins>

Dans l'interface de Kibana, on peut faire des recherches dans les logs en utilisant:

*   soit la syntaxe [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html).
*   ou soit l'ancienne syntaxe [Lucene Query Syntax](https://www.elastic.co/guide/en/kibana/current/lucene-query.html), mais toujours disponible.

Dans toutes les deux syntaxes, on utilise des clés et des valeurs (**key:value**) et éventuellement couplées à des mots clés **or**, **and**,... Je vous laisse le soin de vous familiariser avec ça.

<a name="Beats"></a>

## [Beats](https://www.elastic.co/guide/en/beats/libbeat/current/index.html)

Il existe aussi d'autres composants dans la Suite Elastic appelés **Beats** (Filebeat, Metricbeat, Auditbeat, Winlogbeat, ...). Ce sont des agents légers, développés en Go, capables d'envoyer les informations vers l'un des outputs suivants :  Elasticsearch (par défaut), ou logstash. Ils peuvent être installés sur Linux, Windows, MacOS.
> Note : Dans Kibana, avec `Overview > Add data`, on peut voir les étapes à suivre pour ajouter des données à analyser.
> Remarque : S'il n'y a aucun traitement à faire sur les informations, il est inutile de choisir logstash comme output.

Nous allons montrer un exemple d'utilisation d'elasticsearch comme output (pour filebeat). Mais par la suite, nous choisiront logstash comme output pour tous les beats (même si on fait pas de traitement). 

<a name="Filebeat"></a>

### <ins>[Filebeat](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)</ins>

Filebeat est un agent léger qui permet de collecter les fichiers de logs et de les envoyer directement vers elasticsearch (par défaut) ou logstash. Cependant, nous allons choisir logstash comme sortie (output) pour transformer un peu les données avant de les stocker dans elasticsearch.

<a name="Installation_de_Filebeat"></a>

#### <ins>Installation de Filebeat</ins>

Filebeat s'installe avec la commande ci-dessous:
```
sudo yum install -y filebeat
```

Une fois l'installation terminée, on peut démarrer le service comme suit :
```
sudo systemctl enable filebeat
sudo systemctl start filebeat
```

<a name="Configuration_de_Filebeat"></a>

#### <ins>Configuration de Filebeat</ins>

Par défaut, les fichiers de configuration de filebeat se trouvent dans le répertoire **/etc/filebeat**. Le plus important, c'est **filebeat.yml** qui contient les paramètres de configuration de filebeat. Le répertoire **modules.d** contient les différents modules présents filebeat. C'est juste des fichiers de configuration de filbeat pour une application donnée(apache, logstash, kibana,...). 

Chaque module peut être activé soit :  
- En ligne de commande :
    ```
    sudo filebeat enable module nom_module
    # ex:
    sudo filebeat enable module apache
    ```
- Ou directment via le fichier de configuration de filebeat "**filebeat.yml**".  
    > L'intérêt d'utiliser ce fichier de configuration est qu'on peut configurer filebeat pour qu'il collecte les logs de n'importe quel service ou application depuis n'importe quel fichier de logs.

Dans ce qui suit, nous allons configurer filebeat pour collecter les logs en choisissant elasticsearch comme output dans un premier temps, puis logstash. 
- **Elasticsearch comme output** : 
1. Configurer la partie `input` sous la section `- type: log` comme suit dans `filebeat.yml`:
    <pre>
    filebeat.inputs:
    - type: log
    enabled: true
    paths:
        - /var/log/*.log
        - /var/log/secure
        - /var/log/httpd/*_log

    ...
    </pre>

2. S'assurer  elasticsearch est bien sélectionné pour la partie `output` :
    <pre>
    output.elasticsearch:
        hosts: ["els-centos7-test:9200"]
    </pre>

    > Note : Redémarer filebeat et vérifier dans Kibana que les logs arrives bien dans l'index `filebeat-*`. S'il n'existe pas encore, il faut le créer.
    > Si l'index ne contient aucun log, il faut générer des logs en testant des connexions SSH vers la machine (par exemple) ou installant un paquet via yum ou générer du trafic web.
    > Une petite recherche (KQL) : `log.file.path : "/var/log/httpd/access_log"  or log.file.path : "/var/log/secure" `

3. (Obtionnel) Pour visualiser les tableaux de board de filebeat, il faut les charger via la commande ci-dessous :
    ```
    sudo filebeat setup --dashboards
    ```
    > Note : On peut le faire aussi via `filebeat.yml` avec cette ligne :
    ```
    setup.template.enabled : true
    setup.dashboards.enabled: true
    setup.dashboards.index: "filebeat-*"
    ```
    > Note : Par défaut, setup.dashboards.index est "filebeat-*" déjà pour filebeat. Mais ce paramètre est intéressant si le nom de l'index est autre chose. Cette remarque est aussi valable pour tous les autres beat.

- **Logstash comme output** :<br>
La partie `input` (ci-dessus) restera inchangée.
1. Désactiver Elasticsearch output et activer Logstash output dans filebeat.yml
    <pre>
    #output.elasticsearch:
        #hosts: ["els-centos7-test:9200"]

    output.logstash:
        hosts: ["lgs-centos7-test:5044"]
    </pre>

    > Note : pour tester la configuration de filebeat `sudo filebeat test config -e`. *"Config OK"* montre que tout va bien.

2. Créer un pipeline logstash pour cette collecte. Par exemple ceci :
    <pre>
    # cat /etc/logstash/conf.d/beats.conf

    input {
    beats {
        port => 5044
    }
    }

    output {
        elasticsearch {
            hosts => [ "lgs-centos7-test:9200" ]
            index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
        }
        stdout { codec => rubydebug }
    }
    </pre>
    > Note : 
    > Les Beat communiquent avec Logtash par défaut via le port `5044`.
    > Ici, nous effectuons aucun traitement sur les logs. Mais, comme dit plus haut, le choix de Logtash comme output n'est pertinent que s'il y a un traitement des logs à faire.
    > `%{[@metadata][beat]}` récupère le nom du beat (ici filebeat)

3. Charger le template de l'index Elasticsearch manuellement pour logstash
    ```
    sudo filebeat setup --template -E output.logstash.enabled=false \ 
    -E 'output.elasticsearch.hosts=["els-centos7-test:9200"]'
    ```
    > Note : 
    > En effet, par défaut filebeat charge le template des index pour la sortie Elasticsearch.
    > Pour obtenir de l'aide pour la commande : `filebeat help setup`
    > Pour utiliser logstash, il faut charger cependant le template et le dashboard manuellement.*.

4. Tester la configuration du pipeline
    ```
    sudo systemctl stop logstash
    sudo /usr/share/logstash/bin/logstash -f  /etc/logstash/conf.d/apache_log.conf   
    ```
    > *Si aucune erreur n'apparaît, alors générer du trafic (web ou ssh) et constater que la sortie standard affiche les résultats (à cause de la présence de la ligne `stdout`).

5. (Optionnel) Vérifier dans les index Elasticsearch si notre index apparît bien:
    <pre>curl els-centos7-test:9200/_cat/indices
    </pre>

    > *Si tout est Ok, cette ligne doit apparaître*

    <pre>
    yellow open apache_logs-2019.05.10     w4DsqwGWSZSqkK2DFmS1ZA 1 1 12 0 40.5kb 40.5kb
    </pre>

6. (Optionnel) Recharger les dashboard pour une meilleure visualisation via cette commande :
    ```
    sudo filebeat setup -e \
    -E output.logstash.enabled=false \
    -E output.elasticsearch.hosts=['els-centos7-test:9200'] \
    -E setup.kibana.host=kib-centos7-test:5601 \
    -E setup.dashboards.index: "filebeat-*"
    ```
    > Note : cette commande désactive temporairement logstash comme output. Pour plus de détails sur le chargement des assets, voir section ["Set up assets"](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-installation-configuration.html), notamment le "TIP", concernant Logstash. A remplacer "localhost" par les IP/fqdn appropriés si besoin.

6. Redémarrer le service logstash après les tests. 
    > Remarque : Ne pas oublier d'enlver la ligne `stdout` dans le pipeline. avant cette le redémarrage.

> *Dans Kibana, on pourra créer alors un nouveau index "logtash-filbeat-*" ou laisser tout simplement celui déjà existant (`logtash-*`) pour visualiser visualiser ses contenus.*


<a name="AuditBeat"></a>

### <ins>[AuditBeat](https://www.elastic.co/guide/en/beats/auditbeat/current/index.html)</ins>
Les systèmes Linux disposent généralement l'outil `Auditd` qui permet d'auditer le système en surveillant l'activité des processus et des utilisateurs, l'intégrité des fichiers, ... Auditbeat permet de recuillir les mêmes données que ce dernier.

<a name="Installation_d'_Auditbeat"></a>

#### <ins>Installation d'Auditbeat</ins>

Audibeat peut s'installer avec la commande ci-dessous:
```
sudo yum install -y auditbeat
```

<a name="Configuration_d'_Auditbeat"></a>

#### <ins>Configuration d'Auditbeat</ins>
Auditbeat utilise des modules pour collecter les logs d'udit. Actuellement il y en a trois : 
- ``Auditd`` : pour configurer Auditd et le monitorer. Par défaut, les règles de module sont désactivées (commentées)
- ``File Integreity``: pour monitorer l'intégrité des systèmes de fichiers. Par défaut, certains répertoires sont surveillés (ex: /etc, /usr/bin, ...)
- et ``System`` : pour tracer les activités systèmes (installation de paquets, login, process, ...). Par défaut, ce module est activé aussi. 
Auditbeat peut être entièrement configuré à l'aide du fichier `/etc/auditbeat/auditbeat.yml`. 

Pour notre part, nous allons activer aussi les règles du module d'`Auditd`. Nous laisseront la configuration des autres modules comme telle :
<pre>
...
## Identity changes.
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity

    ## Unauthorized access attempts.
    -a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EACCES -k access
    -a always,exit -F arch=b64 -S open,creat,truncate,ftruncate,openat,open_by_handle_at -F exit=-EPERM -k access
...
</pre>
> Note : on ainsi monitore avec ces lignes les changements dans ces fichiers et les différentes tentaives d'accès à la machine.

> Remarque : Comme évoqué plus haut, nous utiliserons logsash comme output.

Charger les assets ([dashboard] et index templates) d'auditbeat pour logtash via la commande :
```
sudo auditbeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["els-centos7-test:9200"]'
sudo auditbeat setup -e \
  -E output.logstash.enabled=false \
  -E output.elasticsearch.hosts=['els-centos7-test:9200'] \
  -E output.elasticsearch.username=auditbeat_internal \
  -E setup.kibana.host=kib-centos7-test:5601 \
  -E setup.dashboards.index: "auditbeat-*"
```
> Remarque : Pour plus de détails, voir section ["Set up assets](https://www.elastic.co/guide/en/beats/auditbeat/current/auditbeat-installation-configuration.html), notamment le "TIP" conernant Logstash.
> A remplacer "localhost" par les IP/fqdn adéquats s'il le faut. Les dashboards seront visibles dans Kibana > dashboard.

Une fois toutes ces étapes passées, on peut démarrer le service comme suit :
```
sudo systemctl enable auditbeat
sudo systemctl start auditbeat
```
> Remarque : On restera sur le même pipeline de logstash précédemment créé pour filebeat.

Pour tester la collecte de logs, on peut :
- créer un utilisateur (test) et lui définir un mot de passe : `sudo adduser test` puis `sudo passwd test`
- ou modifier le mot de passe d'un utilisateur ou ajouter un contenu dans /etc/passwd
- ou tenter un accès avec échec
> Pour visualiser ces événements :
> utiliser la commande `ausearch` ou `aureport` pour voir consulter les logs d'audit : 
> 
```
sudo ausearch -k identity # voir les events relatifs aux modifications des fichiers surveillés
sudo ausearch --failed # voir les events relatifs aux échecs
...
```
> dans kibana, rechercher les logs relatifs à auditbeat. Exemple:  `_index : logstash-auditbeat-*`

<a name="Winlogbeat"></a>

### <ins>[Winlogbeat](https://www.elastic.co/guide/en/beats/winlogbeat/current/index.html)</ins>
C'est un agent leger qui collecte les logs des événements windows (application, hardware, security, system events).
Nous allons donc l'installer sur la machine windows 10. Nous allons aussi installer un autre outil, [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) afin d'amélorer les capacités de journalisation de Windows.
> Remarque : L'installation de Sysmon n'est pas obligatoire pour pouvoir utiliser Winlogbeat.

**** :
<a name="Installation_de_Sysmon"></a>

#### <ins>Installation de Sysmon</ins>
Sysmon collecte les event ID allant de 1 (Process creation) à 26 (File Delete logged) et l'event ID 255 (Error). Il permet ainsi une méilleure visibilité des événements liés aux processus, aux connexions réseaux, et aux comportements suspects. 
Pour l'installer :

1. Télécharger [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) puis décompresser l'archive
2. Récupérer une configuration de Sysmon (ex: [sysmon config de SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config) 
3. Dans le dossier de Sysmon, exécuter la commande ci-dessous (en admin) pour l'installer avec la configuration :
```
sysmon64.exe -accepteula -i /path/sysmonconfig-export.xml
```
> Ou `sysmon.exe` pour une archi 32 bits.
> Note : Les logs de Sysmon sont accessibles depuis l'observateur d'événement de Windows, dans `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`.

Maintenant que Sysmon est correctement installé, nous allons lancer l'intallation de Winlogeat.

<a name="Installation_de_Winlogbeat"></a>

#### <ins>Installation de Winlogbeat</ins>
Pour installer Winlogbeat :
1. Télécharger le paquet d'installation dépuis la [page de téléchargement](https://www.elastic.co/downloads/beats/winlogbeat)
2. décompresser le fichier dans `C:\Program Files`
3. Renommer le dossier `winlogbeat-<version>` à `winlogbeat` tout court.
4. Taper cette commande via powershell en admin :
```
cd 'C:\Program Files\Winlogbeat'
 .\install-service-winlogbeat.ps1
```
> Note : si le lancement du script est bloqué, il faut modifier le policy d'exéctuion : `PowerShell.exe -ExecutionPolicy UnRestricted -File .\install-service-winlogbeat.ps1.`
> si tout se passe bien, la commande d'installation devrait renvoyer quelque chose comme ceci :
    <pre>
    Status   Name               DisplayName
    ------   ----               -----------
    Stopped  winlogbeat         winlogbeat
    </pre>

<a name="Configuration_de_Winlogbeat"></a>

#### <ins>Configuration de Winlogbeat</ins>
La configuration peut se faire à l'aide du fichier `winlogbeat.yml`. 
C'est via le paramètre `winlogbeat.event_logs` qu'on définit les logs windows à monitorer. Les logs relatifs aux événements windows et sysmon, et même powershell sont configurés par défaut pour être monitorés.

Nous allons rester sur notre logique en choisissant `logstash` comme output:
```
# ------------------------------ Logstash Output -------------------------------
output.logstash:
  # The Logstash hosts
  hosts: ["lgs-centos7-test:5044"]
```
> Note : N'oubliez pas de commenter l'output elasticsearch, et de bien spécifier l'IP ou le fqdn du serveur logtash cette fois-ci.

Il faut charger ensuite les assets (templates, dashboards) de winlogbeat manuellement pour logatsh :
```
# index templates
.\winlogbeat.exe setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["els-centos7-test:9200"]'
# dashboards
 .\winlogbeat.exe setup -e `
  -E output.logstash.enabled=false `
  -E output.elasticsearch.hosts=['els-centos7-test:9200'] `
  -E setup.kibana.host=kib-centos7-test:5601
```
> Note : 
> Pour changer le nom de l'index, ajouter cette ligne `-E setup.dashboards.index: "winlogbeat-*"`
> Sur la machine Windows, renseigner le fichier `C:\Windows\System32\drivers\etc\hosts` avec les fqdn (cf prerequis)
> Aller dans ``kibana > dashboard ``et remarquer bien qu'on a les dashboards pour winlogbeat, et attendre quelques minutes pour voir les logs dans l'index `winlogbeat-*`



<a name="Informations supplémentaires"></a>

## Informations supplémentaires

<a name="Security_Elastic_Stack"></a>

### Security Elastic Stack

Sécuriser la suite Elastic pouvait être une véritable casse-tête étant donné que l'outil (X-Pack)) qui fournit les fonctionnalités de sécurité était payant. Alors pour pallier à ce manquement, on pouvait utiliser des produits tiers comme Apache ou Nginx pour protéger l'accès à Kibana, ou encore [SearchGuard](https://search-guard.com/?lang=fr) ou [ReadonlyRest](https://readonlyrest.com/) qui sont des produits spécialisés dans la sécurité de la suite Elastic.  

Cepandant, à partir la version 6.8 et 7.1, la Team Elastic a mis à disposition une [licence](https://www.elastic.co/subscriptions) **free and open source** de X-Pack. Elle est certes limitée, mais apporte quand même des fonctionnalités intéressantes pour apporter les bases de sécurité (chiffrement TLS, contrôle d'accès basé sur les rôles, alerting, ...).  

Dans cet article, nous n'allons pas voir comment utiliser X-Pack en pratique. Pour plus de détails, référez-vous au [blog de la Team Elastic](https://www.elastic.co/fr/blog/getting-started-with-elasticsearch-security) ou la [documentation officielle](https://www.elastic.co/guide/en/elasticsearch/reference/current/setup-xpack.html). 
Nous allons donner quelques pistes pour mieux sécuriser le déploiement :
1. Donner la propriété des fichiers de chaque produit à l'utilisateur correspondant (elasticsearch, logstash, kibana). Exemple : 
    ```
    sudo chown <produit>:<produit> -R /usr/share/<produit>
    sudo chown <produit>:<produit> -R /var/log/<produit>
    sudo chown <produit>:<produit> -R /var/lib/<produit>
    sudo chown <produit>:<produit> -R /etc/<produit>
    sudo chown <produit>:<produit> -R /etc/sysconfig/<produit> # kibana et elasticsearch
    ```
    > Il faut redémarrer le service après cela.
2. Protéger les communications entre les noeuds du cluster elasticsearch par un mot de passe et TLS (https), et l'API par TLS
3. Protéger les communications entre les noeuds elasticsearch et Kibana (et beats, et logstash) par un mot de passe et TLS (https)
4. Protéger l'accès par les utilisateurs par un mot de passe
5. Appliquer le contrôle d'accès sur les données de kibana.


<a name="Elastic_Agent"></a>

### Elastic Agent

[Elastic Agent](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation-configuration.html) un agent unique qu'on peut déployer sur les hôtes or conteneurs pour collecter les données (logs) et les envoyer à Elastic stack. Pas besoin des beats, ils sont tous réunis sur ce même et unique agent.


<a name="Troubleshooting"></a>

### Troubleshooting

Les problèmes de dysfonctionnement des produits ELK peuvent résulter de plusieurs facteurs. Pour diagnostiquer ces problèmes, on peut creuser les pistes suivantes:  

*   Analyser les logs de chaque produit  
*   Analyser les journaux avec `journalctl -xe`  
*   Analyser le contenu de /var/log/messages  
*   Vérifier le status des services avec `systemctl status -l`  
*   Vérifier les processus avec `ps aux` et `grep`  
*   Vérifier les ports qui écoutent avec `netstat -antup`  
*   Utiliser `**telnet**` pour tester l'accès à un port  
*   Utiliser les commandes `tcpdump` et `netcat` pour diagnostiquer l'envoi des flux  
*   Vérifier les configurations  
*   Vérifier les permissions sur les fichiers des différents produits, notamment ceux de logstash
*   ...

<a name="Temporisation de logs "></a>

### Temporisation de logs 

Dans les sections précédentes, tous les logs collectés par Logstash ou les beats sont directement envoyés vers une sortie (sortie standard ou Elasticsearch). Mais pour apporter de la résilience dans l'architecture de centralisation des logs, il est possible de collecter des logs puis de les temporiser dans un Broker de message comme **[Rabbitmq](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-rabbitmq.html)** ou **[Kafka](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-kafka.html)**. Ainsi, ceci permet d'éviter les pertes de données quand un composant ne fonctionne pas correctement. Nous allons voir comment cela fonctionne grâce à Rabbitmq dans un article dédié.
