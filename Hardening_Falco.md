---
Title: Audit - Détection via Falco
Type: Doc
Nature: Notes
Création: 10/05/2020
---

# Audit - Détection via Falco
## Introduction
[Falco](https://falco.org/#resources) est un outil opensource pour l'audit et la détection de comportements anormaux sur un sytème (Linux, Conteneurs, kubernetes) en exécution. Il est capable de détecter les appels systèmes, les comportements anormaux dans les flux réseaux, les écritures et modifications sur des fichiers sensibles du système et de ses ressources (conteneurs, applications, filesystem, ...) en se basant sur des [règles](https://falco.org/docs/rules/). Il est le moteur de détection des menaces de prédilection pour Kubernetes. Il peut être installé de différentes manières : sous forme de paquet (deb/rpm) sur une machine linux, sous forme de conteneur Docker, sur un cluster kubernetes, ou à partir de la source, à l'aide des scripts (Linux) ou [Ansible](https://falco.org/docs/installation/#ansible) et [Puppet](https://falco.org/docs/installation/#puppet).

Dans cette note, nous allons mettre en place l'outil sur une machine CentOS 7.

## Installation de Falco
Nous allons montrer deux types d'installation ici : via RPM et à l'aide du script.
### Installation via RPM
L'installation via RPM se fait de manière suivante :
1. Installation du dépôt falcosecurity-rpm.repo
```
sudo rpm --import https://falco.org/repo/falcosecurity-3672BA8F.asc
sudo curl -s -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
```
2. Instalation du dépôt EPEL (si ce n'est pas fait)
```
sudo yum install epel-release
```
> Note : Cette commande est nécessaire pour installer le paquet `DKMS` s'il n'est pas installé. Pour vérifier si le paquet est installé : `yum list dkms`

3. Installation des headers du kernel
```
sudo yum -y install kernel-devel-$(uname -r)
```
> Note : cette commande peut ne pas fonctionner pour tous les kernels. Il faut donc télécharger le paquet adéquat pour chaque kernel.

4. Installation de Falco
```
sudo yum -y install falco
```
5. Démarrage du service falco
```
sudo service falco start
# ou sudo systemctl start falco
```
### L'installation à l'aide du script install_falco
Le script `install_falco` permet d'installer Falco sur une machine Linux de manière plus simple. L'installation se fait comme suit :
1. Téléchargement du script
```
curl -o install_falco -s https://falco.org/script/install
```
2. (Optionnel)Vérification de l'intégrité du script
```
sha256sum install_falco | grep 21e8053c37e32f95d91c9393d961af1c63b5839d795c8cac314d05daadea9779
```
> Note : Actuellement le hash du script est `21e8053c37e32f95d91c9393d961af1c63b5839d795c8cac314d05daadea9779`

3. Insttaltion de Falco
```
sudo bash install_falco
```
> Note :
> - Cette commande fait les actions suivantes:
>   * Detecting operating system
>   * Installing Falco public GPG key
>   * Installing Falco repository
>   * Installing kernel headers
>   * Installing Falco
> - Si l'erreur `Delta RPMs disabled ... not installed.` apparaît, il faut installer le paquet via `sudo yum install deltarpm`

4. Démarrage du service falco
```
sudo service falco start
# ou sudo systemctl start falco
```
> Note : falco peut être lancé aussi manuellement. cf `falco --help`

## Configuration de Falco
Falco peut être configuré à l'aide du fichier `/etc/falco/falco.yaml`. La configuration suit la syntaxe: `key: value ou key: [value list]`. On n'est pas obligé de modifier ce fichier sauf si on souhaite modifier certains [paramètres de configuration](https://falco.org/docs/configuration/). Il en existe plusieurs comme :
- `rules_file`: liste des fichiers où sont définis les règles
- `json_output` : résultat de sortie au format json
- `log_level` : Niveau de log
- `syslog_output` : résulat de sortie vers syslog/rsyslog
- `file_output` : résultat de sortie vers un fichier
- `webserver` : paramètres du serveur web pour les audits de kubernetes
> Note : En l'absence de Kubernetes, il faut désactiver le `webserver`.en mettant `enabled : false`

Je vous laisse explorer tous les autres paramètres au besoin.

## Construction des règles
Falco s'appuie sur les [règles](https://falco.org/docs/rules/) pour effectuer des actions.

### Fichiers des règles
L'installation de Falco génère les fichiers et répertoires de règles ci-dessous :
```
- falco_rules.yaml : contient un ensemble de règles prédéfinies pour couvrir un maximum de situations
- falco_rules.local.yaml : fichier pour définir des règles personnelles ou surcharger celles prédéfines
- k8s_audit_rules.yaml : contient un ensemble de règles prédéfinies pour Kubernetes
- rules.available : contient par défaut un fichier (`application_rules.yaml`) contenant des règles prédéfinies pour certaines applications (Elasticsearch, Zokeeper, Kafka, ...)
  - rules.d : dossier pouvant contenir des fichiers de règles.
```
> Note : Par défaut, `falco_rules.yaml` est toujours lu en premier avant `falco_rules.local.yaml` et il n'est pas recommandé de le modifier. Mais il est possible de changer l'ordre dans le fichier de configuration.

### Eléments des règles
Chaque fichier de règle est un fichier `YAML` qui contient trois types d'éléments :
#### Rules
 Les  rules définissent les conditions et paramètres de la règle. Ils peuvent contenir plusieurs keys dont les plus plus indispensables sont :
 - `rule` : nom court de la règle
 - `condition` : condition de la règle. Ces conditions utilisent les [filtres](http://www.sysdig.com/wiki/sysdig-user-guide/#filtering) au format [Sysdig](https://github.com/draios/sysdig/wiki) (ex: `container.id != host and proc.name = bash`)
 - `desc` : description complète de la règle
 - `output` : l'endroit où envoyer le résultat de sortie de la règle
 - `priority` : la sévérité de l'événement détecté (`emergency, alert, critical, error, warning, notice, informational, debug`)

 Par exemple, la règle ci-dessous permet de détecter l'exécution d'un shell dans un conteneur qui tourne sur la machine :
```
- rule: shell_in_container
  desc: notice shell activity within a container
  condition: container.id != host and proc.name = bash
  output: shell in a container (user=%user.name container_id=%container.id container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)
  priority: WARNING
```
#### Macro
Les macros sont des bouts de conditions qui peuvent être utilisées dans une règle. Exemple :
```
- macro: in_container
  condition: container.id != host
```
On peut utiliser ce macro dans notre exemple de règle `shell_in_container `précédent en réécrivant la condition comme suit :
```
condition: in_container and proc.name = bash
```
#### List
Les `list` sont des liste d'objets ou groupe de listes d'objets. Ils possèdent deux mmots clés :
- `list` : nom de la liste
- `items` : les éléments constituant la liste.

Les listes sont utilisées soit :
- dans un macro :

```
- list: sudo_procs
  items: [sudo, su]
- macro: privileges_procs
  condition: proc.name in (sudo_procs)
```

- ou dans un règle (rule) :

```
- rule: The program "sudo" is run in a container
  desc: An event will trigger every time you run sudo in a container
  condition: evt.type = execve and evt.dir=< and container.id != host and proc.name in (sudo_procs)
  output: "Sudo run in container (user=%user.name %container.info parent=%proc.pname cmdline=%proc.cmdline)"
  priority: ERROR
```
> Note: Pour cet exemple, dans condition, on pouvait mettre aussi directement le macro `privileges_procs` à la place de `proc.name in (sudo_procs)`

### Exemples de règles
Le fichier `falco_rules.yaml` contient plusieurs exemples de règles. Mais en trouve aussi dans [la documentation](https://falco.org/docs/examples/) :

- Exemple 1 : détécter les événements d'exécution de shell dans un conteneur

```
- macro: container
  condition: container.id != host

- macro: spawned_process
  condition: evt.type = execve and evt.dir=<

- rule: run_shell_in_container
  desc: a shell was spawned by a non-shell program in a container. Container entrypoints are excluded.
  condition: evt.type = execve and evt.dir=< and container and proc.name = bash and spawned_process and proc.pname exists and not proc.pname in (bash, docker)
  output: "Shell spawned in a container other than entrypoint (user=%user.name container_id=%container.id container_name=%container.name shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)"
  priority: WARNING
```
- Exemple 2 : Surveillance du fichier sshd_config
```
- rule: sshd_config_open
  desc: sshd_config is opened
  condition: (evt.type=open or evt.type=openat) and evt.is_open_read=true and fd.filename="sshd_config"
  output: "SSH is open by (user=%user.name pid=%proc.pid prog=%proc.cmdline)"
  priority: INFO

- rule: hosts_file_write
  desc: sshd is writting
  condition: (evt.type=open or evt.type=openat) and evt.is_open_write=true and fd.filename="sshd_config" and fd.num>=0
  output: "SSH is writen by (user=%user.name pid=%proc.pid prog=%proc.cmdline)"
  priority: INFO
```
> Note : pour les besoins de performance, `evt.type` est requis pour chaque règle. Sinon Falco affiche un message d'avertissemnt.

## Utilisation de Falco
La commande `falco` permet d'analyser entre autres les résultats. Pour plus de détails sur l'utilisation de la commande , cf `sudo falco --help`.
On peut faire quelques tests afin de voir si les règles détectent les événements surveillé. Pour cela :
- Ajouter la règles des deux exemples ci-dessus dans un fichier de règles (`falco_rules.local.yaml`) :
- taper la commande `sudo falco -r /etc/falco/falco_rules.local.yaml` pour utiliser les règles de ce fichier.
- Test docker :
  - sur un autre terminal, exécuter `bash` sur un conteneur (ex: nginx) à l'aide de la commande :
  ```
  docker exec -ti nginx /bin/bash
  ```
  - sur l'autre terminal, vous devriez voir le message ci-dessous :
  ```
  17:27:54.642576524: Notice A shell was spawned in a container with an attached terminal (user=root nginx (id=ee20039ffc1b) shell=bash parent=docker-runc-cur cmdline=bash terminal=34818 container_id=ee20039ffc1b image=nginx)
  ```
- Test sshd_config
  - éditer/afficher le contenu du fichier `/etc/ssh/sshd_config`
  ```
   sudo vi /etc/ssh/sshd_config
   # ou
   sudo cat /etc/ssh/sshd_config
  ```
  - sur l'autre terminal, on aura le message
  ```
   17:29:21.467238411: Notice SSH is open by (user=root pid=2815 prog=cat /etc/ssh/sshd_config)
  ```
  - Et si on modifie le contenu, on aura le message ci-dessous :
  ```
  17:38:31.516379794: Notice SSH is writen by (user=root pid=2841 prog=vi /etc/ssh/sshd_config)
  ```


## Liens
- Documentations :
  - [Falco](https://falco.org/#resource)
  - [Github Falco](https://github.com/falcosecurity/falco)
  - [Documentation Falco](https://falco.org/docs/)
- Tutoriels :
  - [Installation Falco](https://falco.org/docs/installation/)
  - [Audit kubernetes with Falco](https://kubernetes.io/docs/tasks/debug-application-cluster/falco/)
  - [Introduction to sysdig falco](https://blog.rapid7.com/2016/06/06/introduction-to-sysdig-falco/)
