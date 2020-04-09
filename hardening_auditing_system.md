---
Title: Audit du système
Catégorie: Hardening system
Date: 02/02/2020
Auteur: TK
---

# Introduction
L'outil `auditd` permet de réaliser un audit sur système de fichier, les appels systèmes et contrôles sur un système linux. Il existe nativement sur Linux. Mais dans le cas contraire, on peut l'installer également.
Auditd s'appuie sur des règles pour réaliser les actions.

# Installation et configuration d'Auditd
Audit existe par défaut sur les sysèmes. Vérifier le à l'aide de:

```
sudo yum list audit audit-libs
```
Dans le cas échéant, on peut l'installer via la commande

```
sudo yum install audit audit-libs
```
La configuration se fait via le fichier `/etc/audit/auditd.conf` (cf `man auditd.conf` pour plus de détails)

Exemple de configuration:
```
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
max_log_file = 12
max_log_file_action = ROTATE
```

Démarrer le service après la configuration

```
sudo service auditd restart
# Si erreur, utiliser
sudo service auditd restart
```


# Définition des règles
On peut définir les règles d'auditd de différentes manières:
- à l'aide de la commande `auditctl`
- dans le fichier `/etc/audit/audit.rules`
- dans un fichier avec l'extention `rules` dans le répertoire `/etc/audit/rules.d`. Ces règles sont automatiquement chargées dans `/etc/audit/audit.rules`.

Les deux syntaxes restent les mêmes (mis à part l'ajout de auditctl devant). La première méthode n'est pas persistente. Cependant la troisième méthode est plus recommandées.

# Syntaxe des règles
## Règles pour système de fichier
Pour définir une règle pour auditer les systèmes de fichier, la syntaxe est:
```
-w path_to_file -p permissions -k hosts_file_change
```
Où:
- `-w` permet de spécifier le fichier ou dossier à surveiller
- `-p` définit les actions (Permissions Linux) à surveiller:
  - écriture: `w`
  - lecture: `r`
  - changement d'attribut: `a`
  - exécution: `x`
- `-k` définit la clé de la règle (un nom pour identifier la règle)
Exemple: Pour surveiller les changgements et écriture du fichier hosts

```
-w /etc/hosts -p wa -k hosts_file_change
```
## Règles pour les appels systèmes
### Règles pour les appels systèmes différents des fichiers exécutables
La sysntaxe des règles pour les appels systèmes est la suivante:

```
-a action,filter -S system_call -F field=value -k key_name
```
Où:
- `action` et `filter` spécifient quand un évement est logué:
  - action: prend deux valeur possibles: `always` ou `never`
  - filter: spécifie quel filtre correpondant aux règles du noyau est appliqué à l'événement. Il prend les valeurs suivantes: `task`, `exit`, `user`, et `exclude`
- `system_call`: spécifie l'appel système par son nom (cf fichier `/usr/include/asm/unistd_64.h` pour les noms des appels systèmes). L'option `-S` permet de spécifier plusieurs appels systèmes dans une même règle.
- `field=value` spécifie des options supplémentaires qui modifient encore la règle pour faire correspondre des événements basés sur une architecture, un ID de groupe, un ID de processus et autres spécifiés (cf, page manuel `auditctl(8)`)
- `key_name`: est un nom pour identifier la règle.

**Exemples :**
- Logger les modifications du fichier shadow

```
-a always,exit -F path=/etc/shadow -F perm=wa
```

- Logger la suppression ou le renommage de fichier par l'utilisateur dont l'UID est plus grand que 1000.

```
-a always,exit -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
```
**Remarque:** `-F auid!=4294967295` exclue les utilisateurs n'ayant pas encore d'UID.

### Règles pour les fichiers exécutables
Pour auditer les fichiers exécutables, la syntaxe de la règle est:

```
-a action,filter [ -F arch=cpu -S system_call] -F exe=path_to_executable_file -k key_name
```
Où:
- `path_to_executable_file`: est la path du fichier exécutable.
- les autres paramètres sont comme pour les appels systèmes.
**Exemeple :** Logger l'emploi de la commande `id`

```
-a always,exit -F exe=/bin/id -F arch=b64 -S execve -k execution_bin_id
```
## Règles de contrôle
Les règles de contrôle modifient le comportement du système d'audit. Elles prennent les valeurs suivantes: `-b, -D, -e, -f, -r, --loginuid-immutable, and --backlog_wait_time`
Où:
- `-D`: permer de purger toutes les règles précédentes
- `b`: définit la taille du buffer (mettre une grande valeur, pour éviter les mauvaises surprises)
- `-e`: donne une configuration immutable (le reboot est nécessaire dans ce cas)
- `-f`: Mode panic quand un echec apparaît
- `-r`: indique le nombre de message par seconde à généer
- `--loginuid-immutable`: rend l'UID du login immutable

## Utilisation des règles
Comme évoqué plus, la commande `auditctl` permet de définir les règles. Mais elles ne sont pas persistentes. Pour les rendre permanentes, on définit plutôt les règles dans le fichier `/etc/audit/audit.rules` ou dans le répertoire `/etc/audit/rules.d`. Mais la syntaxe reste la même que `auditctl` (sans le mot `auditctl` bien sûr).
Pour plus d'info sur les règles, voir `man audit.rules`
- Comme cas d'utilisation, éditer le fichier `/etc/audit/audit.rules` ou créer un fichier dans le répertoire `/etc/audit/rules.d`et ajouter les règles suivantes:

```
# Modification du fichier passwd
-w /etc/passwd -p wa -k passwd_changes

# Modification du fichier passwd
-w /etc/shadow -p wa -k shadow_changes

# Modification du dossier selinux
-w /etc/selinux/ -p wa -k selinux_changes

# Modification du fichier hosts
-w /etc/hosts -p wa -k hosts_file_changes

# Modification des fichiers d'auditd
-w /etc/audit/ -p wa -k audit_changes

# Modification du fichier dns
-w /etc/resolv.conf -p wa -k dns_changes

# Modification des repositories yum
-w /etc/yum.repos/ -p wa -k repos_changes

# Modification sshd
-w /etc/ssh/sshd_config -p warx -k sshd_config

# Suppression par un utilisateur non confiance
-a always,exit -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete_bad_uid
```
- Redémarrer le service

```
sudo systemctl restart auditd
```

**NB:** Exemple de règles auditd recommandées par l'ANSSI: https://www.ssi.gouv.fr/uploads/2019/03/linux_configuration-en-v1.2.pdf

## Commandes fournies par auditd
Auditd fournit un ensemble d'outils permettant d'interagir les résultats d'audit:
- `ausearch`: permet d'effectuer des recherches dans les logs d'auditd
-
```
# Rechercher les info concernant l'utilisateur dont l'UID est 100
sudo ausearch -ua 1000 -i
#Evenement sur la clé hosts_file_changes
sudo ausearch -k  hosts_file_changes | less
```

- `aureport`: permet de créer un rapport d'audit

```
# Exemple: résumé des événements sur les fichiers exécutables
aureport -x --summary
# Evénements échoués
sudo aureport -u --failed
```
- `auditctl`: permet de créer des règles d'audit en CLI (règles non persistentes)

```
# Modification du fichier dns
auditctl -w /etc/resolv.conf -p wa -k dns_changes
```

## Comprendre les logs générés par auditd
Auditd génère les logs dans le fichier `/var/log/audit/audit.log`. Pour comprendre ces logs, je vous renvoie à la [documentation de Redhat](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files), dans la section `6.6. Understanding Audit Log Files`


# Sources
- [Redhat auditd documentation](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-starting_the_audit_service)
- tuto:
  - [Auditd digitalocean](https://www.digitalocean.com/community/tutorials/how-to-write-custom-system-audit-rules-on-centos-7)
  - [Auditd Tecmint](https://www.tecmint.com/linux-system-auditing-with-auditd-tool-on-centos-rhel/)
- [Documentation du projet](https://github.com/linux-audit/audit-documentation/wiki)
