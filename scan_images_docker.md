---
Title: Scan images docker
Type: Doc
Nature: Notes
Création: 28/04/2020
---

# Outils de Scan des images docker

---
### Sommaire

- **[Introduction](#Introduction)**
- **[OpenSCAP](#OpenSCAP)**
  - [Installation d'Oscap Docker](#Installation-d'Oscap-Docker)
  - [Utilisation d'Oscap Docker](Utilisation-d'Oscap-Docker)
- **[Trivy](#Trivy)**
  - [Installation de Trivy](#Installation-de-Trivy)
  - [Scan via Trivy](#Scan-via-Trivy)
- **[Dagda](#Dagda)**
  - [Prerequis Dagda](#Prerequis-Dagda)
  - [Installation de Dagda](#Installation-de-Dagda)
  - [Lancement et configuration de Dagda](#Lancement-et-configuration-de-Dagda)
  - [Réalisation de scan via Dagda](Réalisation-de-scan-via-Dagda)
  - [Monitoring d'un conteneur via Dagda](#Monitoring-d'un-conteneur-via-Dagda)
- **[Harbor](#Harbor)**
  - [Installation de Harbor](#Installation-de-Harbor)
  - [Téléchargement Harbor Installer](#Téléchargement-Harbor-Installer)
  - [Configuration de l'accès HTTPS à Harbor et le TLS interne](Configuration-de-l'accès-HTTPS-à-Harbor-et-le-TLS-interne)
  - [Configurer le fichier YML de Harbor](Configurer-le-fichier-YML-de-Harbor)
- **[Anchore](#Anchore)**
- **[Portus](#Portus)**
- **[Atomic](#Atomic)**
---

## Introduction
Dans cette note, nous allons explorer certains outils permettant de scanner des conteneurs [docker](https://docs.docker.com/engine/) afin de détecter des vulnérabilitéss, des virus dans les images.
Les outils seront installés sur une machine Centos 7.

> Note : Docker peut être installé au besoin comme suit :

```
# Installer Docker et ajouter l'utilisateur au groupe Docker
sudo yum install -y docker
sudo groupadd docker
sudo usermod -aG docker $USER
sudo systemctl start docker
sudo systemctl enable docker
```
> Note :
> - `Git` peut être installé au besoin avec la commande `sudo yum install -y git`
> - Au besoin, on peut créer un cluster Kubernetes rapidement via [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)

## OpenSCAP
[OpenSCAP](https://www.open-scap.org/tools/) fournit la commande `oscap-docker` afin de réaliser des scans sur les conteneurs Docker. Le scan est réalisé en mode offline (pas d'altération de l'image docker).

Pour plus détails sur l'outil, je renvoie à ma note sur [OpenSCAP](../Scan-vuln-OpenSCAP-via-workbench-et-scanner.md)

### Installation d'Oscap Docker
Pour disposer de cet outil, il faut :
- installer Openscap-scanner et une politique de sécurité
```
sudo yum -y install openscap-scanner scap-security-guide
```
- installer docker sur la machine (cf plus haut)
- Avoir les images docker à scanner
- Installer Atomic sur la machine. Atomic est une solution de gestion des conteneurs. C'est ce dernier qui permet à oscap-docker d'accéder au conteneur à scanner.
```
sudo yum install -y atomic
```

### Utilisation d'Oscap Docker
Les syntaxes de la commande sont les suivantes :
```
# Compliance scan of Docker image
    Usage: oscap-docker image IMAGE_NAME OSCAP_ARGUMENT [OSCAP_ARGUMENT...]
# Compliance scan of Docker container
    Usage: oscap-docker container CONTAINER_NAME OSCAP_ARGUMENT [OSCAP_ARGUMENT...]
# Vulnerability scan of Docker image
    Usage: oscap-docker image-cve IMAGE_NAME [--results oval-results-file.xml [--report report.html]]
# Vulnerability scap of Docker container
    Usage: oscap-docker container-cve CONTAINER_NAME [--results oval-results-file.xml [--report report.html]]
```
> Note : pour plus de détails, cf `man oscap-docker`

Pour ce scan, nous allons procéder comme suit :
1. Télécharger un conteneur docker rhel7
```
# chercher les images rhel7
docker search rhel7
# télécharger une image
docker pull lionelman45/rhel7
```
2. Scanner l'image via la commande `oscap-docker`
  - Scan de vulnérabilité de l'image via l'option `image-cve`:
```
sudo oscap-docker image-cve lionelman45/rhel7 --report report-docker-rhel7-vuln.html
```
 - Scan de conformité de l'image rhel7 par rapport au profile `ssg-rhel7-ds.xml`
```
# info du profile
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
# lancer le scan
 sudo oscap-docker image lionelman45/rhel7 xccdf eval --report report-docker-rhel7-compliance.html --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
```
> Attention : bien choisir le bon profile


## Trivy
[Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md) est un outil qui permet de scanner une image docker. L'outil peut être installé sur plusieurs plateformes Linux (Centos/Redhat, Debian/Ubuntu, ...).

### Installation de Trivy
Il existe plusieurs manières pour installer l'outil (source, YUM, RPM, Docker, ...) sur Centos. Mais nous allons utiliser la méthode via Yum. Pour cela :
1. Ajouter le dépôt YUM de Trivy dans `/etc/yum.repos.d/trivy.repo`
```
$ cat /etc/yum.repos.d/trivy.repo
[trivy]
name=Trivy repository
baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$releasever/$basearch/
gpgcheck=0
enabled=1
```

### Scan via Trivy
Les scans se font via la commande `trivy`. Voici la syntaxe de cette commande : `trivy YOUR_IMAGE_NAME [options]`.
> Note : `trivy --help`

Ainsi scanner notre image docker rhel7 peut se faire à l'aide de la commande ci-dessous :
```
trivy lionelman45/rhel7
```
> Note : On ne peut scanner qu'une image à la fois

Le résultat du scan est affiché sur la sortie standard, par défaut. Nous pouvons génerer le résultat, cependant dans un fichier, aux formats tables, json ou template.

```
# format json
trivy -o result.json -f json lionelman45/rhel7
# format table (avec options équivalentes)
trivy --output result.json --format table lionelman45/rhel7
```

L'outil a plusieurs autres fonctionnalités. Pour plus d'information, se reporter à la [documentation de Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md#rhelcentos)

## Dagda
[Dagda](https://github.com/eliasgranderubio/dagda) est un outil d'analyse statique des images docker. Il scanne les images/conteneurs dockers afin de détecter des vulnérabilités connues et autres menaces malveillantes. Pour les chevaux de Troie, les virus, des logiciels malveillants, il utilise le moteur d'antivirus [ClamAV](https://github.com/tassyk/security/blob/master/Hardening_Clamav.md). Il s'intégre aussi à [Falco](https://falco.org/#resources) qui un outil d'audit et de détection des comportements anormaux sur un système (linux, conteneur, kubernetes).

### Prerequis Dagda
L'installation de certains est indispensable pour le fonctionnement de Dagda : Python 3.4.X ou plus, MongoDB 2.6 ou plus, Docker, Pip3 et certains modules de pip (cf ``requirements.txt``).

### Installation de Dagda
1. Installation de Dagda
```
git clone https://github.com/eliasgranderubio/dagda.git
```

2. Installation de Python3
```
sudo yum install -y python3
```
3. Installation de docker
Voir plus haut.

4. Installation de MongoDB
MongoDB peut être [installé de différentes manières](https://docs.mongodb.com/manual/administration/install-community/). Mais dans notre cas, nous allons faire simple en installation une image docker de MongoDB à l'aide des commandes ci-dessous.  
```
docker pull mongo
docker run -d -p 27017:27017 mongo
```
5. Installation de pip3 et ses modules
Pour l'installation de Pip3 et les modules, on peut utiliser les commandes ci-dessous :
```
# pip 3
sudo yum install -y python3-pip
# modules
cd dagda
sudo pip3 install -r requirements.txt
```
6. Installer l'entête du kernel
```
sudo yum -y install kernel-devel-$(uname -r)
```

### Lancement et configuration de Dagda

Avant d'utiliser Dagda, il faut lancer d'abord le serveur :
```
cd dagda
python3 dagda.py start
```
> Note :
> - le serveur dagda écoute sur le port `5000` par défaut.
> - on peut aussi lancer cette commande avec des arguments (adresse et port du serveur, adresse de MongoDB, ...). Voir [le wiki: start-sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#start-sub-command)

Une fois le serveur lancé, il faut définir les variables d'environment. Pour cela, dans un autre, entrer les commandes ci-dessous :
```
export DAGDA_HOST='127.0.0.1'
export DAGDA_PORT=5000
```
Ensuite, il faut initialiser la base de données des vulnérabilités :
```
python3 dagda.py vuln --init
```
> Note:
> - cette commande peut durer quelques minutes et c'est elle qui faut utiliser à chaque fois qu'on souhaite mettre à jour la base des vulnérabilités.
> - pour le status : `python3 dagda.py vuln --init_status`
> - Pour plus d'info avec l'argument `vuln`, cf `python3 dagda.py vuln --help` ou voir le wiki [vuln-sub-command](https://github.com/eliasgranderubio/dagda/wiki/CLI-Usage#vuln-sub-command)

### Réalisation de scan via Dagda
Dagda vient avec plusieurs sous-commandes :
- `vuln` : pour initialiser une base, voir les détails d'un CVE, ...
- `check` : pour effectuer un scan local
- `àgent` : pour effectuer un scan distant sur un agent
> Note : pour plus de détails, vor `python3 dagda/dagda.py --help`

Pour lancer un scan local sur une image docker, on utilise la sous-commande `check` avec l'option `--docker_image`. Par exemple, la commande ci-dessous scanne notre image docker rhel7 :
```
python3 dagda.py check --docker_image lionelman45/rhel7
```
Chaque scan est identifié par un identifiant unique comme le montre le résultat de la commande :
```
{
    "id": "5eb6cf4b2d31e111012008fa",
    "msg": "Accepted the analysis of <lionelman45/rhel7>"
}
```
> Note : la commande ne montre pas la fin d'un scan. Il faut vérifier cela manuellement (voir plus bas).

Grâce à la sous-commande `history` couplée avec l'option `--id`, on peut afficher le résultat d'un scan :
```
python3 dagda.py history <DOCKER_IMAGE_NAME_HERE> --id <REPORT_ID_HERE>
```
Pour notre cas, on peut afficher le résultat ainsi :
```
python3 dagda.py history lionelman45/rhel7 --id 5eb6cf4b2d31e111012008fa
```
> Note: le résultat est affiché en JSON.un peut récupérer le résultat dans un fichier en utilisant une redirection `>> dagda-report.json`

### Monitoring d'un conteneur via Dagda
On peut monitorer un conteneur en cours d'exécurition grâce à la sous-commande `monitor`:
```
python3 dagda.py monitor <CONTAINER_ID> --start
```
> Note : pour arrêter le monitoring, on utilise `--stop`. La commande affiche également l'ID du monitoring.

## Harbor
[Harbor](https://goharbor.io/) est un registre open source pour les images des conteneurs. Il permet aussi de scanner les images et de les classer selon en terme de confiance. Il dispose d'une UI intuitive. Il s'appuie sur les outils comme [Clair](https://coreos.com/clair/docs/latest/) et [Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md), [Notary](https://docs.docker.com/notary/getting_started/) pour le scan.

### Installation de Harbor
Harbor peut être [installé](https://goharbor.io/docs/2.0.0/install-config/) de différentes manières : sur une machine, sur kubernetes ou sur Ubuntu via un script d'installation rapide.

Dans ce qui suit, nous allons utiliser la première méthode.

Pour la mise en place de Harbor, il faut suivre les étapes suivantes :
1. s'assurer que l'hôte remplit bien les [caractéristiques](https://goharbor.io/docs/2.0.0/install-config/installation-prereqs/)
2. Télécharger `Harbor Installer`
3. Configurer l'accès HTTPS à Harbor
4. Configurer le fichier YML de Harbor
5. Configurer et activer TLS interne
6. Exécuter le script d'installation

#### Téléchargement de Harbor Installer
Il existe [deux versions](https://github.com/goharbor/harbor/releases) : Online et Offline (s'il n'y pas d'accès internet). Dans notre cas, nous allons installer la version `Online`. Pour cela :
1. Télécharger le paquet de l'installeur
```
sudo wget https://github.com/goharbor/harbor/releases/download/v2.0.0/harbor-online-installer-v2.0.0.tgz
```
2. Décompresser le paquet
```
sudo tar xvf harbor-online-installer-v2.0.0.tgz
```

#### Configuration de l'accès HTTPS à Harbor et le TLS interne
La [configuration de l'accès HTTPS à Harbor](https://goharbor.io/docs/2.0.0/install-config/configure-https/) est fortement recommandé pour les environments de production. De même, [l'activation du TLS interne](https://goharbor.io/docs/2.0.0/install-config/configure-internal-tls/) pour sécuriser les communications internes entre les différents composants de Harbor est aussi important. Mais pour les besoins de cette note, on se contentera de HTTP.

#### Configuration de Harbor
 Harbor est configuré via le fichier `harbor.yml`. La configuration n'est effective qu'après l'exécution du script `install.sh` pour installer ou reconfigurer Harbor.
 > Note : le fichier par défaut est `harbor.yml.tmpl`.

 Le paramètre le plus important à adapter est le `hostname`. Les paramètres relatifs aux mots de passe devront être changés aussi. Les autres dépendent du cadre d'utilisation de l'outil.
 > Note : Etant donné que nous n'utilisons pas https, il faut désactiver les paramètres relatifs à HTTPS (https, internal_tls, ...).

#### Exécution du script d'installation
Après avoir fini de configurer Harbor, on peut maintenant installer et démarrer Harbor en utilisant le script [install.sh](https://goharbor.io/docs/2.0.0/install-config/run-installer-script/). Harbor peut être installé selon différentes configurations :
- Juste Harbor, sans Notary, Clair, ou Chart Repository Service (par défaut)
- Harbor avec Notary
- Harbor avec Clair
- Harbor with Chart Repository Service
- Harbor with two or all three of Notary, Clair, and Chart Repository Service
> Note :
> - Avant l'installation d'Harbor, il faut s'assurer que [Docker](https://docs.docker.com/engine/install/centos/) et [docker-compose](https://docs.docker.com/compose/install/) (v 1.18.0+) sont bien installés et existent en versions acceptables.
> - S'il y a un conteneur nginx sur la machine, il faut le désinstaller
> - Avec Notary, il faut configurer le HTTPS

Dans cette note, nous choisirons installer Harbor avec Clair (scanneur par défaut) :
```
sudo ./install.sh --with-clair
```
> Note :
> - pour les autres méthodes, voici la syntaxe de la commade
```
sudo ./install.sh [--with-notary] [--with-clair] [--with-chartmuseum]
```

### Administration d'Harbor
#### Accès à l'interface d'Harbor
Après l'installation, Harbor est accessible via l'url du serveur : http://IP_fqdn_server:port. Le login par défaut est `admin` et le mot de passe est celui défini dans `harbor.yml` (Harbor12345 par défaut).

Remarques :
- On peut utiliser aussi la commande `Docker` pour se connecter à Harbor, tagger les images, les pousser à Harbor
```
docker login IP_fqdn_server:port
docker push IP_fqdn_server:port/myproject/myrepo:mytag
```
- si http est utilisé au lieu de https, il faut ajouter ce paramètre `--insecure-registry` dans la configuration du dameon du client docker (par défaut `/etc/docker/daemon.json`) puis redémarrer le docker et docker_compose :
```
# --insecure-registry
$ cat /etc/docker/daemon.json
{
"insecure-registries" : ["IP_fqdn_server:5000", "0.0.0.0"]
}
# Démarrage
systemctl restart docker
docker-compose down -v
docker-compose up -d
```

## Anchore
[Anchore](https://anchore.com/) est un outil qui permet de réaliser une inspection approfondie d'une image docker et de scanner ses vulnerabilités. Il existe en deux versions: opensource et commercial.
Dans cette note, nous allons voir comment mettre en place la version [Opensource](https://docs.anchore.com/current/docs/engine/engine_installation/) et réaliser des scans.

### Installation d'Anchore
Anchore est disponible en tant qu'[image Docker](https://hub.docker.com/r/anchore/anchore-engine), mais il peut être installé aussi via [Docker-compose](https://docs.anchore.com/current/docs/installation/docker_compose/). Il peut aussi être installé sous forme de [CLI (Ligne de commande)](https://docs.anchore.com/current/docs/installation/anchore_cli/) à partir des paquets `rpm/deb` ou de la source (github)

## Portus
[Portus](http://port.us.org/features/6_security_scanning.html)

## Atomic
[Atomic](http://www.projectatomic.io/)





## Sources
- Documentations :
  - [Atomic](http://www.projectatomic.io/)
  - [Clair](https://coreos.com/clair/docs/latest/)
  - [OpenSCAP Tools](https://www.open-scap.org/tools/)
  - [Trivy](https://github.com/aquasecurity/trivy/blob/master/README.md)
  - [Dagda](https://github.com/eliasgranderubio/dagda)
  - [Harbor](https://goharbor.io/)
  - [Docker-Clamav](https://hub.docker.com/r/mkodockx/docker-clamav)
  - [Portus](http://port.us.org/features/6_security_scanning.html)
  - [Anchore](https://anchore.com/)
- Tutoriels :
  - [10-top-open-source-tools-docker-security](https://techbeacon.com/security/10-top-open-source-tools-docker-security)
  - [5-tools-container-security](https://opensource.com/article/18/8/tools-container-security)
  - [Harbor & Portus](https://www.objectif-libre.com/fr/blog/2018/08/02/test-registres-docker-open-source-heberges/#lightbox[11632]/0/)
  - [Setup Kubernetes cluster with Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
  - [Clair Tuto](https://nullsweep.com/docker-static-analysis-with-clair/)
