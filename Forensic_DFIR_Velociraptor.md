---
Title: Endpoint monitoring Velociraptor
Type: Doc
Nature: Note
Date de création: 27/04/2021
---


# Endpoint monitoring avec Velociraptor
## Introduction
[Velociraptor](https://www.velocidex.com/) est un outil de monitoring d'endpoints. Il peut-être utilisé dans un cadre de DFIR (Digital Forensics and Incidence Response) afin de collecter les artéfacts de compromission ou de surveiller les comportements suspicious sur les endpoints. Tout ceci se fait soit en temps réel ou en mode hunting (chasse).
Velociraptor est multi plateforme et se base sur une architecture client-server. Mais peut donc être installé en mode standalone (tout sur le même hôte).
Le serveur et le client sont installés par le même paquet ou script.
> note : Pour l'installation, nous allons installer la solution sur les machines ci-dessous :
> - ubuntu 18.04 (Bionic): serveur / client
> - windows 10 : client

## Quelques notions à connaître
Pour mieux utiliser l'outil, quelques notions sont à savoir :
- `artefacts` : désignent les objets/événements à collecter sur les endpoints. Il existe plusieurs types d'artéfacts regroupés en deux catégories : clients artefacts et servers artefacts.
- `VFS - Virtual File System` : représente l'explorateur de fichiers de l'endpoint. Grâce à ça, on peut voir les opérations, les permissions, ...sur les différents répertoires et fichiers de l'endpoint et meême télécharger des fichiers
- `Hunt` : au lieu de collecter les artefacts en temps réel, grâce aux `hunts`, on peut surveiller les endpoints uniquement à des moments précis (ex: lors d'incidents).
- `VQL - Velociraptor Query Language` : est le language de requêtes de Velociraptor.


## Installation
Pour l'installation, il faut télécharger la [dernière release depuis la page Github du projet](https://github.com/velocidex/velociraptor/releases).
Ensuite, suivre les étapes ci-après.
> Note : Pour les distributions, il s'agit d'un script et non un paquet.

### Installation du serveur
Pour [l'installation du serveur (mode standalone)](https://www.velocidex.com/docs/getting-started/stand_alone/), suivre les étapes ci-dessus :
1. Renommer le script en vélociraptor et le rendre exécutable
```
sudo mv velociraptor-v0.5.8-linux-amd64 velociraptor
sudo chmod +x velociraptor
```
> Pour utiliser le script comme une commande, nous allons le déposer dans `/usr/loca/bin`

2. Générer les fichiers de configuration (server et client) en mode interactive (option -i)
```
sudo velociraptor config generate -i
```
> Note : il faut répondre aux questions : OS (Linux), dossier d'installation (défaut: /opt/velociraptor), Certificat (auto signé), le port du frontend (8000), le port du GUI (8889), le username pour GUI, chemin des fichiers de logs (/opt/velociraptor), le chemin de stockage des fichiers de configuration (server.config.yaml et client.config.yaml).
>
> Remarque : A tout moment, on peut ajouter d'autres utilisateurs depuis le GUI ou en CLI : `velociraptor --config server.config.yaml user add MyUserName --role administrator`

3. Lancer le serveur velociraptor
```
sudo velociraptor --config server.config.yaml frontend -v
```
> note : le serveur n'est pas lancé comme un service (daemon) avec cette commande

4. Vérifier que l'interface web (GUI) est accessible en se rendant sur `https://127.0.0.1:8889`

### Déploiement des clients
Maintenant que le serveur est correctement installé, on peut déployer les clients.

#### Déploiement du client sur la machine serveur
Tout d'abord, nous allons utiliser la machine serveur (Ubuntu) comme client aussi. Pour se faire, lancer la commande ci-dessous :
```
sudo velociraptor --config client.config.yaml client -v
```
> Note : `client.config.yaml` a été généré en même temps que le fichier de configuration du serveur.

Après l'exécution de la commande, la machine apparaît dans l'interface en tant que client (cf `Show All`)

#### Déploiement du client sur la machine client
1. Sur la machine client (Windows), télécharger la [dernière release depuis la page Github du projet](https://github.com/velocidex/velociraptor/releases) (msi ou exe).
> Note : C'est le .msi qui est recommandé. Voir [deploying clients](https://www.velocidex.com/docs/getting-started/deploying_clients/)

2. Ensuite lancer l'installation de l'outil
> Par défaut, Velociraptor est installé dans "C:\Program Files\Velociraptor\". ``velociraptor.exe`` se trouve dans ce répertoire.

3. Copier le client `client.config.yaml` vers le client Windows et adapter la ligne concernant l'URL du serveur.
```
Client:
  server_urls:
  - https://192.168.1.4:8000/
  ...
```
4. Lancer le client (en mode service) (depuis powershell)
```
.\Velociraptor.exe --config client.config.yaml service install
```
> Vérifier dans la console que le client est bien remonté (Accueil > Show All ou Rechercher le nom de la machine)

## Collecte d'artefacts
L'objectif principal de l'outil est la collecte [d'artefacts](https://www.velocidex.com/docs/user-interface/artifacts/) (indicateurs). Les artefacts définissent les événements à collecter. Différents types d'artefacts proposés par Velociraptor regroupés en deux grandes catégories:
- client artefacts : qui sont exécutés sur les clients (Linux, Windows)
- server artefacts : qui sont exécutés sur le server
> Note : au déploiement d'un endpoint, seul l'artefact `Generic.Client.Info` existe pour collecter les informations systèmes du client.


Dans cette partie, à titre d'exemple, nous allons utiliser les artefacts suivants pour tracer certaines activités :

- **Linux** :
  - `Linux.Events.ProcessExecutions` : collecter les informations relatives aux processus
  - `Linux.Events.SSHBruteforce` : pour monitorer les événements de brute force SSH
  - `Linux.Sys.LastUserLogin` : pour surveiller les activités de login des utilisateurs.
  - `Linux.Applications.Chrome.Extensions` : collecter les informations relatives aux extentions ajoutées dans Chrome
- **Windows** :
  - `Windows.Sys.Programs` : surveille les programmes installés par windows installer
  - `Windows.Detection.PsexecService` : pour détecter l'excution du service Psexec
  - `Windows.Detection.WMIProcessCreation` : pour détecter le remote acces via WMI
> Note : Un artfefact n'est rien d'autre qu'un fichier contenant une requête VQL. En sélectionnant un artefact, on peut voir son contenu.

Pour ajouter un artfefact,
- il faut se rendre dans l'onglet **Artefact** puis cliquer sur le symbole **+.**
- Sélectionner les artefacts voulus
- Aller dans "Configure Parameters", "Specify Ressources" (s'il le faut)
- A la fin, cliquer sur "Launch" pour les activer.

Si les informations sont collectées, on les retouve dans "**Results**".



## Liens
- [Documentation officielle](https://www.velocidex.com/docs/)
- [Releases](https://github.com/velocidex/velociraptor/releases)
- [Présentations et workshops](https://www.velocidex.com/docs/presentations/)
