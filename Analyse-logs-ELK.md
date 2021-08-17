---
Title: Déploiement ELK
Type: Doc
Nature: Notes
Création: 20/07/2019
---

<div id="globalWrapper">
<div id="column-content">
<div id="content"><a name="top" id="top"></a>

# Déploiement ELK

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
        *   [<span class="tocnumber">6.1.2</span> <span class="toctext">Configuration de Filebeat</span>](#Configuration_de_Filebeat)
*   [<span class="tocnumber">7</span> <span class="toctext">Security Elastic Stack</span>](#Security_Elastic_Stack)
*   [<span class="tocnumber">8</span> <span class="toctext">Troubleshooting</span>](#Troubleshooting)

</td>

</tr>

</tbody>

</table>

<script type="text/javascript">if (window.showTocToggle) { var tocShowText = "afficher"; var tocHideText = "masquer"; showTocToggle(); }</script>

<a name="Introduction"></a>

## Introduction

ELK est la contraction des noms des trois produits phares de la Suite Elastic (**Elasticsearch, Logstash et Kibana**). La combinaison de ces produits permet d'avoir un outil de centralisation des logs performant pour surveiller les logs systèmes et applicatifs afin de signaler des anomalies, des failles de sécurité et de réaliser des diagnostiques. A ceux-là, s'ajoutent d'autres produits de la Suite Elastic, comme les **Beats** (filebeat, metricbeat, heartbeat, auditbeat, winlogbeat, ...) qui étendent les fonctionnalités et les possibilités offertes pas ces trois derniers.  
Dans cette section, nous allons voir comment installer et configurer ces produits manuellement et de les faire communiquer ensemble pour remonter les logs. L'installation se fera sur une distribution **Redhat**. Mais pour **Centos** aussi, ce sont les mêmes commandes à utiliser.

<a name="Pr.C3.A9requis"></a>

## Prérequis

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

Les composants de la Suite Elastic peuvent être installés de différentes manières (archives, paquets deb et rpm, dépôt yum ou deb, docker, ansible, pupet,...), et selon différentes architectures (distribuée, mode standalone). Ici, nous allons utiliser la méthode d'installation via le dépôt yum. La Suite Elastic est actuellement à la version 7.x. Nous allons donc installer cette version. Pour ajouter le dépôt yum:  

1.  créer un fichier *elastic.repo* dans */etc/yum.repos.d/* 
2.  et ajouter ce contenu dedans
<pre>
[elastic-7.x]
name=Elasticsearch repository for 7.x packages
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=0
enabled=1
autorefresh=1
type=rpm-md
</pre>

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
sudo yum install -y elasticsearch
```

Pour activer le démarrage du service au boot et démarrer le service elasticsearch, utiliser les commande ci-dessous:

```
# démarrer au boot
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch

# démarrer le service
sudo systemctl start elasticsearch
```

On peut interroger l'API pour tester si l'installation s'est bien passée, via la commande:

```
curl localhost:9200
```

Si curl n'est pas installé sur la machine, on peut taper l'url ci-contre dans le navigateur: **[http://localhost:9200](http://localhost:9200/)**.  
Si l'installation s'est bien passé, la commande (ou le navigateur) affiche le résultat ci-dessous:

<pre>
    {
        "name" : "elk-redhat-test",
        "cluster_name" : "elasticsearch",
        "cluster_uuid" : "XqfdlLDkSVKLMsANIr_lxA",
        "version" : {
            "number" : "7.0.1",
            "build_flavor" : "default",
            "build_type" : "rpm",
            "build_hash" : "e4efcb5",
            "build_date" : "2019-04-29T12:56:03.145736Z",
            "build_snapshot" : false,
            "lucene_version" : "8.0.0",
            "minimum_wire_compatibility_version" : "6.7.0",
            "minimum_index_compatibility_version" : "6.0.0-beta1"
        },
        "tagline" : "You Know, for Search"
    }
</pre>

Voici d'autres commandes utiles pour vérifier dans les journaux si le produit fonctionne correctement:

```
    sudo journalctl -f
    sudo journalctl --unit elasticsearch
    sudo journalctl --unit elasticsearch --since  "2019-05-09 13:50:02"
    sudo less /var/log/elasticsearch/elasticsearch.log
```

Si le produit ne fonctionne pas, cela peut être dû à plusieurs facteurs:  
<pre>
- java qui n'est pas installé  
- mauvaise configuration  
- Mémoire Ram de la machine trop petite pour supporter elasticsearch (cf JVM heap dans la conf)  
- 'bootstrap.memory_lock' est à 'true' dans '/etc/elasticsearch/elasticsearch.yml' alors que MAX_LOCKED_MEMORY n'est pas 'unlimited' dans '/etc/sysconfig/elasticsearch'  
- blocage du port 9200 par le firewall local  
- Selinux activé or le contexte selinux n'est pas actualisé pour prendre en compte Elasticsearch.  
- ...
</pre>

<a name="Configuration_d.27Elasticsearch"></a>

### <ins>Configuration d'Elasticsearch</ins>

Par défaut, les fichiers de configuration d'Elasticsearch se trouvent dans le répertoire **/etc/elasticsearch/**. Le contenu de répertoire peut ressembler à ceci:

<pre>
    elasticsearch.keystore
    elasticsearch.yml
    jvm.options
    log4j2.properties
    role_mapping.yml
    roles.yml
    users
    users_roles
</pre>

Les fichiers les plus importants sont **elasticsearch.yml** qui permet de configurer elasticsearch et **jvm.options** qui permet de modifier la taille du Heap java. Pour un usage basic (installation standalone), ces fichiers n'ont pas besoin d'être édités. Par contre, si on souhaite modifier/adapter la configuration selon le contexte, voici les paramètres les plus importants:  

*   dans **elasticsearch.yml**:  

<pre>
- cluster.name : nom du cluster (cluster_elk par exemple)
- node.name: nom du noeud du cluster (nom de la machine éventuellement)
- discovery.seed_hosts: noms des machines qui adhèrent au cluster
- cluster.initial_master_nodes: les noeuds du cluster qui sont éligibles pour devenir le noeud 'Master' du cluster 
</pre>

*   dans **jvm.options**:  

<pre>
-Xms et -Xmx qui définissent les tailles de JVM heap et qui sont à 1g par défaut. Au maximum, ces valeur ne doivent pas excéder la moitié de la RAM.
NB: En mode Standalone, il faut s'assurer que la machine dispose de beaucoup de RAM ou il faut réduire considérablement ces valeurs.
</pre>

Pour plus de détails dans les paramètres de configurations, voir la [documentation officielle](https://www.elastic.co/guide/en/elasticsearch/reference/current/settings.html)  

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

> Attendez quelques secondes que logstash finisse son traitement. Sur l'écran, dès que vous remarquez ce message 'Successfully started Logstash API endpoint {:port=>9600}' (dernière ligne), écrivez un mot (comme 'logstash basic pipeline'). Logstash nous répond avec un message contenant ce qu'on a écrit:

<pre>
    {
        "@timestamp" => 2019-05-09T13:51:18.847Z,
        "@version" => "1",
        "message" => "logstash basic pipeline",
            "host" => "qp-ans-test-lva"
    }
</pre>

> Pour arrêter le test, appuyer sur **CTR+C**  
Ainsi logstash est correctement installé, on peut alors créer des pipelines pour collecter les logs sur les machines et les envoyer vers elasticsearch.

<a name="Configuration_de_Logstash"></a>

### <ins>Configuration de Logstash</ins>

Les fichiers de configuration de logstash se trouvent dans le répertoire **/etc/logstash**:

<pre>
    - conf.d/
    - jvm.options
    - log4j2.properties
    - logstash-sample.conf
    - logstash.yml                   
    - pipelines.yml
    - startup.options
</pre>

Franchement, ces fichiers n'ont pas besoin d'être modifiés sauf si on faire quelques changements comme:  

* changer le répertoire des plugins de logstash (par defaut, /var/lib/logstash), activer le chargement automatique des pipelines (config.reload.automatic: true) ou ajouter d'autres options de configuration non fournies avec l'installation dans **logstash.yml**  
* ou modifier les JVM Heap, comme on l'a vu avec Elasticsearch, dans **jvm.options**.  
* ou changer le répertoire des pipelines dans **pipelines.yml**
C'est le répertoire **conf.d** qui permet de stocker les pipelines qui est le plus utile.  

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
        elasticsearch { hosts => ["localhost:9200"] }
        stdout { codec => rubydebug }
    }
```

Ce pipeline prend en entrée (**input**) tout ce qui est saisi au clavier, et applique la transformation adaptée au log apache (**filter -> grok**), change le format de la date (**filter -> date**) puis envoie le résultat vers le serveur elasticsearch (**output**).

Pour exécuter ce pipeline, entrer la commande ci-dessous (on est dans conf.d):
```
sudo /usr/share/logstash/bin/logstash -f test-pipeline.conf --path.settings /etc/logstash/
```

Attendre la fine du traitement du pipeline par logstash (apparition de la ligne '`Successfully started Logstash API endpoint {:port=>9600}'`). Comme la transformation souhaitée est celle d'une ligne de log Apache, nous allons entrer au clavier une ligne de log Apache:

<pre>
127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] "GET /xampp/status.php HTTP/1.1" 200 3891 "http://cadenza/xampp/navi.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0"
</pre>

Logstash nous renvoie alors le résultat ci-dessous (ligne de log précédente en JSON), montrant que le pipeline fonctionne.

<pre>
{
       "referrer" => "\"http://cadenza/xampp/navi.php\"",
     "@timestamp" => 2013-12-11T08:01:45.000Z,
       "clientip" => "127.0.0.1",
    "httpversion" => "1.1",
       "@version" => "1",
      "timestamp" => "11/Dec/2013:00:01:45 -0800",
          "ident" => "-",
        "request" => "/xampp/status.php",
       "response" => "200",
          "bytes" => "3891",
           "host" => "qp-ans-test-lva",
          "agent" => "\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"",
           "auth" => "-",
        "message" => "127.0.0.1 - - [11/Dec/2013:00:01:45 -0800] \"GET /xampp/status.php HTTP/1.1\" 200 3891 \"http://cadenza/xampp/navi.php\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0\"",
           "verb" => "GET"
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
            hosts => ["localhost:9200"]
            index => "logstash-apache-%{+YYYY.MM.dd}"
        }
        stdout { codec => rubydebug }
    }
</pre>

<ins>**Remarques**</ins> :    
> Dans la section **output**, on a ajouté une ligne, **index => "logstash-apache-%{+YYYY.MM.dd}"**, pour nommer notre indexe elasticsearch. En effet, par défaut, tous les logs envoyés via logstash vers Elasticsearch sont indexés "**logstash-date**". Mais on peut préciser un autre nom (n'importe lequel) pour notre indexe si on le souhaite. La chaîne **%{+YYYY.MM.dd}** permet d'ajouter la date au format (année.moi.jour) à notre indexe. Cependant ce n'est pas indispensable, mais fortement recommandé.  
Pour d'autres exemples de configuration d'un pipeline, voir [ici](https://www.elastic.co/guide/en/logstash/current/config-examples.html).  

Après avoir créé ce pipeline fonctionnel, on peut maintenant **démarrer le service logstash** comme on l'a vu plus haut.  

 
> Quand le service logstash tourne déjà, on n'a pas besoin de le redémarrer à chaque fois qu'on crée on pipeline. On peut juste utiliser la commande ci-dessous (depuis **/etc/logstash/conf.d**) pour prendre en compte ce nouveau pipeline par logstash:

```
    sudo /usr/share/bin/logstash -f logstash-apache.conf  --path.settings /etc/logstash/
```

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

> *Si la machine dispose d'une interface graphique, on peut accéder à Kibana via l'URL: [http://localhost:5601](http://localhost:5601/"). Sinon (comme c'est mon cas), il faut configurer Kibana pour qu'il écoute sur un autre fqdn ou une adresse IP puis pointer le navigateur sur la nouvelle URL [http://IP_machine:5601](http://ip_machine:5601/) ou [http://fqdn_machine:5601](http://fqdn_machine:5601/).  
**NB**: Il faut faut redémarrer le service Kibana pour prendre en compte les modifications dans la configuration.*

**Remarque**:  
> *En accédant à l'interface de kibana, on peut parfois apercevoir ce message d'erreur "**Kibana server is not ready yet**". ceci est souvent lié au problème de communication de kibana avec Elasticsearch. Cependant, il peut être dû aussi à un autre défaut de configuration de Kibana ou Elasticsearch.*

<a name="Configuration_de_Kibana"></a>

### <ins>Configuration de Kibana</ins>

Le fichier de configuration de kibana, **kibana.yml**, se trouve par défaut dans le répertoire **/etc/kibana/**. Ce fichier contient plusieurs paramètres dont les plus importants sont:
<pre>
    - server.port:             le port d'écoute de Kibana (5601, par déafut)
    - server.host:             le fqdn ou l'IP d'écoute de Kibana ("localhost", par défaut)
    - elasticsearch.hosts:     les URLs des instances elasticsearch servant pour les requêtes (["http://localhost:9200"], par deafut)
</pre>

D'autres paramètres aussi sont intéressants pour sécuriser l'accès à Kibana via les certificats (server.ssl.enabled, ...) ou sécuriser la communication entre kibana et les instances elasticsearch (elasticsearch.username, elasticsearch.password, ...) ou utiliser kibana derrière un proxy (server.basePath, server.rewriteBasePath, ...). Je vois renvoie pour cela à la documentation sur la [configuration de Kibana](https://www.elastic.co/guide/en/kibana/current/settings.html) pour plus de détails.

<a name="Interface_de_Kibana"></a>

### <ins>Interface de Kibana</ins>

<a name="Cr.C3.A9ation_d.27index"></a>

#### <ins>Création d'index</ins>
Comme on l'a mentionné plus haut, Elasticseach utilise des indexes pour stocker les informations. Dans Kibana, il faut créer chaque indexe d'elasticsearch pour pouvoir visualiser ses contenus. Comme dans les exemples de pipeline qu'on avait créés, on avait spécifié notre instance elasticsearch comme **output**, les index apparaissent dans Kibana. Mais il faut les créer. Pour cela:  
- il faut se rendre dans l'onglet "**Management**" puis cliquer sur "**Index Patterns**" puis sur "**Create index pattern**".  
Le nom de l'indexe accepte des expressions régulières (regex) mais doit correspondre à un des indexes présents.  
- une fois qu'on est satisfait du nom d'index, il faut cliquer "**Next step**" pour accéder au "**Step 2**".  
- dans "**Step 2**", choisir une option dans "**Time Filter field name**" puis cliquer sur "Create index pattern" pour créer l'index. - Une l'index créé, cliquer sur son nom dans l'écran qui apparaît ou sur l'onglet "**Discover**" pour explorer les logs! 

<a name="Recherche_dans_les_logs"></a>

#### <ins>Recherche dans les logs</ins>

Dans l'interface de Kibana, on peut faire des recherches dans les logs en utilisant:

*   soit la syntaxe [Kibana Query Language](https://www.elastic.co/guide/en/kibana/current/kuery-query.html).
*   ou soit l'ancienne syntaxe [Lucene Query Syntax](https://www.elastic.co/guide/en/kibana/current/lucene-query.html), mais toujours disponible.

Dans toutes les deux syntaxes, on utilise des clés et des valeurs (**key:value**) et éventuellement couplées à des mots clés **or**, **and**,... Je vous laisse le soin de vous familiariser avec ça.

<a name="Beats"></a>

## [Beats](https://www.elastic.co/fr/products/beats)

Il existe aussi d'autres composants dans la Suite Elastic comme les **Beats**. Il y en a plusieurs:  Filebeat, Metricbeat, Auditbeat, Winlogbeat, ...
Chacun remplit une tâche bien précise comme précisé sur la description du produit sur l'écran. Ce sont des agents légers, développés en Go, capables d'envoyer les informations soit à Elasticsearch (par défaut), soit à logstash. Ils se configurent à peu près de la même manière. Dans notre cas, nous allons nous limiter juste à l'installation et configuration de **filebeat**.

<a name="Filebeat"></a>

### <ins>[Filebeat](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)</ins>

Filebeat est un agent léger qui permet de collecter des fichiers de logs et de les envoyer directement vers elasticsearch (par défaut) ou logstash. Cependant, nous allons choisir logstash comme sortie (output) pour transformer un peu les données avant de les stocker dans elasticsearch.

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

Par défaut, les fichiers de configuration de filebeat se trouvent dans le répertoire **/etc/filebeat**. Le plus important, c'est **filebeat.yml** qui contient les paramètres de configuration de filebeat. Le répertoire **modules.d** contient les différents modules présents filebeat. C'est juste des fichiers de configuration de filbeat pour une application donnée(apache, logstash, kibana,...). Voici le contenu du module apache :
<pre>
- module: apache
  # Access logs
  access:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    #var.paths:

  # Error logs
  error:
    enabled: true

    # Set custom paths for the log files. If left empty,
    # Filebeat will choose the paths depending on your OS.
    #var.paths:
</pre>

Chaque module peut être activé soit :  
- En ligne de commande :
    ```
    sudo filebeat enable module nom_module
    ```
- Ou directment via le fichier de configuration de filebeat "**filebeat.yml**".  
L'intérêt d'utiliser ce fichier de configuration est qu'on peut configurer filebeat pour qu'il collecte les logs de n'importe quel service ou application depuis n'importe quel fichier de logs.

Dans ce qui suit, nous allons configurer filebeat pour qu'il envoie les logs apache **/var/log/httpd/\*log** vers logstash (sans passer par le module apache). Pour cela, ajouter/adapter ces lignes dans "**filebeat.yml**" :

<pre>
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/httpd/*log
</pre>

- Désactiver Elasticsearch output et activer Logstash output dans filebeat.yml

<pre>
#output.elasticsearch:
  #hosts: ["localhost:9200"]

output.logstash:
  hosts: ["127.0.0.1:5044"]
</pre>

- Créer un pipeline logstash pour apache

<pre>
# cat /etc/logstash/conf.d/apache_log.conf

input {
  beats {
    port => 5044
  }
}
filter{
    if [path] =~ "error"
      {
        mutate {
            remove_tag => [ "beats_input_codec_plain_applied" ]
            add_tag => [ "apache_logs" ]
        }
    }
    if [path] =~ "access"
     {
    mutate {
       remove_tag => [ "beats_input_codec_plain_applied" ]
       add_tag => [ "apache_logs" ]
      }
    }
 }
output {
     elasticsearch {
       hosts => ["localhost:9200"]
       index => "apache_logs-%{+YYYY.MM.dd}"
       stdout { codec => rubydebug }
     }
}
</pre>

- Tester la configuration du pipeline
    ```
    sudo /usr/share/logstash/bin/logstash -f  /etc/logstash/conf.d/apache_log.conf   
    ```
    > *Si aucune erreur n'apparaît, alors le pipeline est correct. On doit voir à l'écran :*

<pre>
{
      "@version" => "1",
         "agent" => {
        "ephemeral_id" => "0550eee4-5946-4402-829a-a3e5cdbea9e7",
            "hostname" => "elk-redhat-test",
             "version" => "7.0.1",
                "type" => "filebeat",
                  "id" => "8ab556db-1b8b-4347-9964-014b84035a37"
    },
           "log" => {
          "file" => {
            "path" => "/var/log/httpd/access_log"
        },
 ...
</pre>

- Charger le template de l'index Elasticsearch manuellement pour logstash
    ```
    sudo filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'
    ```

    > *En effet, par défaut filebeat charge le template des index pour la sortie Elasticsearch. Pour utiliser logstash, il faut charger manuellement ce template.*

- Vérifier dans les index Elasticsearch si notre index apparît bien:

<pre>curl localhost:9200/_cat/indices
</pre>

> *Si tout est Ok, cette ligne doit apparaître*

<pre>
    yellow open apache_logs-2019.05.10     w4DsqwGWSZSqkK2DFmS1ZA 1 1 12 0 40.5kb 40.5kb
</pre>

> *Dans Kibana, on pourra créer alors notre index "apache" puis visualiser ses contenus.*

Dans les sections précédentes, tous les logs collectés par Logstash sont directement envoyés vers une sortie (sortie standard ou Elasticsearch). Mais pour apporter de la résilience dans l'architecture de centralisation des logs, il est possible de collecter des logs par logstash puis de les envoyer vers un Broker de message comme **Rabbitmq** pour une mise en file d'attente avant de les envoyer vers la destination finale. Ainsi, ceci permet d'éviter les pertes de données quand un composant ne fonctionne pas correctement. Nous allons voir comment cela fonctionne grâce à Rabbitmq dans un article dédié.

<a name="Security_Elastic_Stack"></a>

## Security Elastic Stack

Sécuriser les composants de la suite Elastic pouvait être une véritable casse-tête étant donné que l'outil qui fournit les fonctionnalités de sécurité était payant. Alors pour pallier à ce manquement, on pouvait utiliser des produits tiers comme Apache ou Nginx pour protéger l'accès à Kibana, ou encore [SearchGuard](https://search-guard.com/?lang=fr) ou [ReadonlyRest](https://readonlyrest.com/) qui sont des produits spécialisés dans la sécurité de la suite Elastic.  

Cepandant, à partir la version 6.8 et 7.1, la Team Elastic a rendu **open source** l'outil qui apporte les couches de sécurité (X-Pack) à Elasticsearch et Kibana. Cela signifie que les utilisateurs peuvent désormais chiffrer le trafic réseau, créer et gérer les utilisateurs, définir les rôles qui protègent l'accès au niveau de l'index et du cluster et sécuriser entièrement Kibana avec Spaces, gratuitement, sans besoin de faire recours à un outil tiers.  

Nous n'allons pas voir la sécurité d'ELK dans cet article, mais pour activer ces fonctionnalités, on peut se référer à au [blog de la Team Elastic](https://www.elastic.co/fr/blog/getting-started-with-elasticsearch-security) ou la documentation officielle.

<a name="Troubleshooting"></a>

## Troubleshooting

Les problèmes de dysfonctionnement des produits ELK peuvent résulter de plusieurs facteurs. Pour diagnostiquer ces problèmes, on peut creuser les pistes suivantes:  

*   Analyser les logs de chaque produit  
*   Analyser les journaux avec `journalctl`  
*   Analyser le contenu de /var/log/messages  
*   Vérifier le status des services avec `systemctl -l`  
*   Vérifier les processus avec `ps -aux` et `grep`  
*   Vérifier les ports qui écoutent avec `netstat -antup`  
*   Utiliser `**telnet**` pour tester l'accès à un port  
*   Utiliser les commandes `tcpdump` et `netcat` pour diagnostiquer l'envoi des flux  
*   Vérifier les configurations  
*   ...