---
Title:  Mise en place de MISP
Nature : Note
Catégorie: Threat analysis
Date: 18/02/2020
Auteur: TK
---


# Mise en place de MISP
---
### Sommaire

- **[Introduction](#Introduction)**
- **[Mise en place de MISP](#Mise-en-place-de-MSIP)**
  - [Prerequis](#Prerequis)
  - [Installation de MISP](#Installation-de-MISP)
- **[Gestion des events MISP](#Gestion-des-events-MISP)**
  - [Ajouter un nouveau event](#Ajouter-un-nouveau-event)
  - [Activer un feed](#Activer-un-feed)
  - [ Activer une source d'enrichissement](#Activer-une-source-d\'enrichissement)
- **[Conclusion](#Conclusion)**
- **[Liens](#Liens)**
---

## Introduction
[MISP](https://www.misp-project.org/)(Malware Information Sharing Platform)
est une plateforme Open source de [Threat Intelligence](https://www.kaspersky.fr/resource-center/definitions/threat-intelligence). Comme son nom l'indique, c'est une solution qui permet de collecter, de stoquer, de corréler et de partager les IoC - indicateurs de compromission (URL, domain, hash, ...) liés à une attaque. Elle est souvent couplée avec [The Hive](https://github.com/TheHive-Project/Cortex)(plateforme de recherche à incident) et [Cortex](https://github.com/TheHive-Project/Cortex)(Outils d'analyse des observables).
Elle peut aussi être couplée à des SIEM (LogPoint, Splunk, ...) comme source d'enrichissement des logs.<br>
Dans cette note, nous allons voir comment mettre en place cette solution sur une machine Linux (Ubuntu 20.04)

## Mise en place de MISP
MISP peut être [installé](https://www.misp-project.org/download/) de plusieurs manières : sur une distribution GNU/Linux standard à partir des scripts d'installation, appliance virtuelle, Vagrant, Docker, Ansible, Pupet ... 
> Note : voir le lien d'installation pour plus d'infos.

Pour notre part, nous allons l'installer via l'image docker [(CoolAcid's MISP Docker images)](https://github.com/coolacid/docker-misp). <br>

### Prerequis
Cette image se basant sur Docker et Docker-compose, nous allons donc installer ces derniers sur notre machine Ubuntu. [Pour ce faire](https://docs.docker.com/compose/install/), exécuter les commandes ci-dessous :

**installation de Docker** : <br>
```
sudo apt-get remove docker docker-engine docker.io containerd runc
sudo apt-get update -y
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release 
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update -y
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
# Ne pas lancer docker via root
sudo groupadd docker
sudo usermod -aG docker $USER
newgrp docker 
```
> Note : le paquet Docker existe (nativement) sur Ubuntu. Mais, nous avons préféré l'installer depuis le repos. Voir : [Installation using the repository](https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository). 
> Il est déconseillé de lancer docker avec root. Voir [Linux post-installation](https://docs.docker.com/engine/install/linux-postinstall/).



**Installation de Docker-compose** : <br>
```
sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
docker-compose --version # tester l'installation
```
> Note: If the command docker-compose fails after installation, check your path. You can also create a symbolic link to /usr/bin or any other directory in your path. For example : `sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose`

Pour la suite, nous aurons aussin besoint de l'outil `Git` pour récupérer le dépot de l'image Docker de MISP. On peut l'installer via la commande : `sudo apt install git -y`.

### Installation de MISP
Une fois Docker-compose et git correctement installés, nous pouvons suivre les étapes ci-dessous pour [installer l'image docker MISP](https://github.com/coolacid/docker-misp) :

1. Cloner le repo : `git clone https://github.com/coolacid/docker-misp.git`
2. Exécuter ensuite `docker-compose up -d`, depuis le répertoire du repos `docker-misp`
3. Ensuite, si tout se passe bien, on peut accéder à l'interface de MISP via `https://localhost`

> Note : User: ``admin@admin.test``, Password: ``admin`` (A changer)
> Remarque : Ceci est une installation adaptée pour le test. Pour une installation en production, lire la documentation (section "Production").

## Gestion des events MISP
### Ajouter un nouveau event
La création d'un [event](https://www.circl.lu/doc/misp/quick-start/) MISP peut être scindé en trois phases : la création de l'event lui-même, l'ajout d'attributs et d'attachments dans l'event et sa publication.
1. Aller dans `Add event`, renseigner le nom, la date, le niveau (level), ainsi du'autres informations.
2. Ensuite, aller `Add attribute`, pour ajouter du contenu dans l'envent : Observables et leurs détails.
> Note : On peut ajouter les attributs à l'aide de l'outil `freetext tool`. Il se trouve parmi les sous-menus, en bas de la page de l'event. Voir tuto video (cf liens)

> Note : Pour notre part, nous avons ajouté les observables trouvées sur cet article de Microsoft [New sophisticated email based attack from nobelium](https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/).<br>
> Pour plus de étails sur les events, voir cet article de [Misp Using the system sur Circl.lu](https://www.circl.lu/doc/misp/using-the-system/)

### Activer un feed
Un [feed](https://www.circl.lu/doc/misp/managing-feeds/) MISP est un flux contenant un ensemble d'indicateurs (IoC) proposé par une organisation. MISP fournit un ensemble de [feeds par defaut](https://www.misp-project.org/feeds/) que l'on peut importer afin de d'enrichir sa base d'events. Un feed peut être structuré au format MISP, CSV ou free-text.
Pour activer un feed :
1. Aller dans le menu **Sync Actions > List feeds**
2. Sélectionner les feeds à activer 
3. Cliquer sur **Enable selected**
4. Ensuite, sélectionner les feeds ainsi activées puis cliquer **Fetch and store all feed data**


### Activer une source d'enrichissement
Les donées des events MISP peuvent être enrichies par d'autres sources de données DNS, VirusTotal, URLhaus, ...). Pour ce faire il faut activer les plugins néessaires :
1. Aller dans **Administration > Server settings & maintenance**
2. Aller dans **Plugins settings**
3. Cliquer sur **Enrichment** 
4. Activer les plugins souhaités : double clic puis mettre sur **true**.
> Note : Ainsi, en ouvrant un event MISP, on verra d'autres informations supplémenatires ajoutées par ces plugins.


# Liens
- Documentations officielles :
  - [MISP Quick start](https://www.circl.lu/doc/misp/quick-start/)
  - [User guide for MISP (Malware Information Sharing Platform)](https://www.circl.lu/doc/misp/)
  - [misp-training](https://github.com/MISP/misp-training/blob/master/README.md)
  - [Download MISP](https://www.misp-project.org/download/)
  - [MISP Data models](https://www.misp-project.org/datamodels/)
  - [MISP default feeds](https://www.misp-project.org/feeds/)
- Tutorial :
    - [Cyber Threat Intelligence Explained and How Install MISP Threat Intelligence Platform with Docker](https://www.youtube.com/watch?v=Oq8thVrNqGw)(Vidéo)
    - [Enhance Security Event Data Using MISP | Demo Using the MISP VM](https://www.youtube.com/watch?v=3sWmm2km9LA)(Vidéo)
- IOC :
  - [Awesome IOCs](https://github.com/sroberts/awesome-iocs)
  - [Malware Indicators of Compromise by ESET](https://github.com/eset/malware-ioc)
  - [IOC Repositories](http://www.covert.io/threat-intelligence/)
