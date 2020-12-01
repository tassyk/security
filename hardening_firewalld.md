---
Title: Sécurisation via Firewalld
Catégorie: Hardening system
Date: 06/02/2020
Auteur: TK
---

# Sécurisation d'un serveur via Firewalld
## Introduction
Le firewall (parfeu) est moyen permettant de protéger les machines contre tout trafic indésirable provenant de l'extérieur à l'aide règles de filtrage.
**Firewalld** est le firewall par défaut sur les distributions de la famille Redhat (Redhat, Centos, Fedora). Il a été produit pour rendre plus simple l'utilisation de son prédécesseur, **Iptables** (qui est toujours très très utilisé)

## Installation de Firewalld
Sur les distributions de la famille Redhat, Firewalld est installé nativement. Cependant, au besoin, on peut l'installer via les commandes ci-dessous:
```
# Installation
sudo yum install -y firewalld
# Démarrage du service
systemctl unmask firewalld
sudo systemctl start firewalld
sudo systemctl enable firewalld
# Arrêt complet du service
sudo systemctl stop firewalld
sudo systemctl disable firewalld
sudo systemctl mask firewalld
```
## Fonctionnement de firewalld
Firewalld utilise le concept de zones pour indiquer le niveau de confiance du réseau. Les zones peuvent être affichées via la commande: `sudo firewall-cmd --get-zones`
```
block dmz drop external home internal public trusted work
```
Chaque zone a ses spécificités:
- **drop**: le niveau le plus bas de confiance. Toutes les connexions entrantes sont supprimées sans notifications.
- **block**: même principe que "drop" à quelques différences près. Ici, les connexions entrantes sont supprimées avec notifications (icmp-host-prohibited ou icmp6-adm-prohibited pour IPv6)
- **public**: réseaux public. On n'accorde pas une confiance aveugle aux autres ordianteurs du réseau; les connexions entrantes sont gérées au cas par cas.

Je vous laisse le soin d'explorer les autres zones. Les noms sont assez parlants.

Dans chaque zone, on peut définir des règles pour autoriser ou interdire des services ou des ports en fonction des trafics.

## Gestion des services
### Services prédéfinis
Plusieurs services sont prédéfinis avec Firewalld comme ssh, http, https, ... On peut les voir:
- à l'aide de la commande `firewall-cmd --get-services`
```
RH-Satellite-6 amanda-client amanda-k5-client bacula bacula-client bitcoin bitcoin-rpc bitcoin-testnet bitcoin-testnet-rpc ceph ceph-mon cfengine condor-collector ctdb dhcp dhcpv6 dhcpv6-client dns docker-registry ...
```
- ou en regardant le contenu du répertoire **/usr/lib/firewalld/services/**, répertoire des templates des services. Les services sont des fichiers de configuration au format XML où sont renseignés les paramètres d'un protocole donné.

On peut apercevoir les services activés:
- à l'aide de la commande `sudo firewall-cmd --list-services`
-  ou regarder le répertoire **/etc/firewalld/services/**.

### Ajout de nouveaux services
Comme mentionné plus haut, les services sont des fichiers au XML. POur créer un nouveau service:
- on peut copier le template d'un service dans le répertoire **/etc/firewalld/services/** et l'adapter:

```
cp /usr/lib/firewalld/services/service-name.xml /etc/firewalld/services/service-name.xml
```
- ou le créer à l'aide de la commande `firewall-cmd --new-service-from-file=service-name.xml`. Cette commande génère le fichier xml du nouveau service dans **/etc/firewalld/services/** où on peut le modifier.

### Contrôler les services
Pour lister l'ensemble des services disponibles, taper la commande `sudo firewall-cmd --get-services`. Et pour lister ceux déjà activé, taper la commande `firewall-cmd --list-services`.
Ensuite, autoriser le service à l'aide de la commande `sudo firewall-cmd --add-service=<service-name>`. Puis appliquer ces modifications :
```
# Rendre la règle persistente
sudo firewall-cmd --runtime-to-permanent
# Recharger le firewalld
sudo firewall-cmd --reload
```
Pour interdire un service donnée :
```
sudo firewall-cmd --remove-service=<service-name>
```
### Contrôler le protocole ICMP
Le protocole ICMP permet d'effectuer des pings à une machine. Il existe plusieurs paquets ICMP. Mais seuls quelques paquets sont indispensables pour efectuer un ping (echo-reply echo-request). Donc il est recommandé d'en autoriser que ceux qui sont indispensables.
Les commandes ci-dessous montrent quelques exemples du contrôle de ICMP via Firewalld:
- Voir les paquets ICMP disponibles : `sudo firewall-cmd --get-icmptypes`
```
address-unreachable bad-header communication-prohibited destination-unreachable echo-reply echo-request fragmentation-needed host-precedence-violation host-prohibited host-redirect host-unknown host-unreachable ...
```
- Bloquer tous les paquets ICMP :
```
sudo firewall-cmd --add-icmp-block-inversion
```

- Autoriser uniquement quelques paquets pour le ping :
```
sudo firewall-cmd --add-icmp-block=echo-reply
sudo firewall-cmd --add-icmp-block=echo-request
sudo firewall-cmd --add-icmp-block=host-unreachable
# rendre les règles persistentes
sudo firewall-cmd --runtime-to-permanent
```

## Contrôle des ports
Pour afficher la liste des ports, taper la commande `sudo firewall-cmd --list-ports`.
### Autoriser un port via le firewalld
Pour atoriser un port via le firewall:
1. Taper la commande `sudo firewall-cmd --add-port=port-number/port-type`. Ajouter l'option **--permanent** pour rendre la règle persistente. Le port-type prend les valeurs: **tcp, udp, sctp, ou dccp.**
**Exemple :** `sudo firewall-cmd --add-port=22/tcp --permanent`. **Remarque :** Comme, on l'a vu pour les services, on peut autoriser le port à l'aide de la commande ci-dessus sans l'option `--permanent` puis la rendre persistente à l'aide de `sudo firewall-cmd --runtime-to-permanent`
2. Relancer le firewalld via la commande `sudo firewall-cmd --reload`

Comme firawalld fonctionne sur des zones, si on ne précise pas une zone dans la commande `firewall-cmd`, les règles s'applique pour la zone active (par défaut, public). On peut changer ce fonctionnement.

## Contrôle des adresses IP
### Contrôle d'une seule adresse IP
On peut autoriser ou bloquer des IP via Firewalld.
- Pour bloquer une adresse (83.97.20.34):
```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="83.97.20.34" reject’                                                          
```
- Pour débloquer une IP source :
```
firewall-cmd --remove-rich-rule='rule family="ipv4" source address="83.97.20.34" reject’
```

### Contrôle d'un groupe d'adresses IP
On peut aussi créer un groupe d'IP (avec ipset) pour les contrôles par la suite. On peut ajouter une IP à ce groupe, ou une liste d'IP à partir d'un fichier.
- Créer un groupe d'IP (à bloquer)
```
sudo firewall-cmd --permanent --new-ipset=IP_drop --type=hash:net
```
> Pour supprimer l'ipset IP_drop : `sudo firewall-cmd --permanent --delete-ipset=IP_bloc --type=hash:net`

- Ajouter une IP à ce groupe
```
sudo firewall-cmd --permanent --ipset=IP_drop --add-entry=83.97.20.34
```
- Ajouter une liste d'IP (à partir d'un fichier) :

```
# contenu du fichier
cat > iplist.txt <<EOL
52.89.78.251
83.97.20.34
178.62.41.77
192.168.1.0/24
192.168.2.254
EOL
sudo firewall-cmd --permanent --ipset=IP_drop --add-entries-from-file=iplist.txt
```

- Voir le contenu de ce groupe
```
sudo firewall-cmd --permanent --ipset=IP_drop --get-entries
```

- Bloquer ces IP
```
sudo firewall-cmd --permanent --zone=drop --add-source=ipset:IP_drop
```

## Définition des règles plus complexes avec Rich Rule
Grâce au langage Rich, Firewalld permet de définir des règles plus complexes. La syntaxe de cette règle est:

```
rule [family="rule family"]
    [ source [NOT] [address="address"] [mac="mac-address"] [ipset="ipset"] ]
    [ destination [NOT] address="address" ]
    [ element ]
    [ log [prefix="prefix text"] [level="log level"] [limit value="rate/duration"] ]
    [ audit ]
    [ action ]
```

Où :
- **family** : spécifie le type d'IP IPv4 ou IPv6
- **source** : spécifie l'adresse source
- **destinantion** : spécifie l'adresse de destination
- **action** : spécifie l'action à effectuer (drop, accept, reject, ...)
Je vous laisse le soin de regarder la signication et les valeurs de chaque paramètre. Les noms sont assez évocateurs.

Voici quelques exemples d'utilisation de cette règle :
- Accepter une IP source
```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="192.168.2.2" accept'
```
- Pour bloquer une adresse (83.97.20.34):
```
firewall-cmd --add-rich-rule='rule family="ipv4" source address="83.97.20.34" reject’                                                          
```
- Pour débloquer une IP source :
```
firewall-cmd --remove-rich-rule='rule family="ipv4" source address="83.97.20.34" reject’
```

## Gestion des zones
- Afficher la zone par courante :
```
sudo firewall-cmd --get-default-zone
```
- Modifier la zone par défault :
```
sudo firewall-cmd --set-default-zone zone-name
```
- Lister les zones actives ainsi que les interfaces associées :
```
sudo firewall-cmd --get-active-zones
```
- Assigner une zone à une interface :
```
sudo firewall-cmd --zone=zone-name --change-interface=<interface-name>
```
Remarque: On peut assigner une zone à une interface en ajoutant `Zone=zone-name` dans le fichier de configuration de l'interface (`/etc/sysconfig/network-scripts/ifcfg-connection-name`)
- Définir l'action cible par défaut (DROP, REJECT, ACCEPT, ...) d'une zone
```
sudo firewall-cmd --zone=zone-name --set-target=<default|ACCEPT|REJECT|DROP> --permanent
```
- Créer sa propre zone : cela se fait en créeant le fichier xml de la zone dans le répertoire `/usr/lib/firewalld/zones/` ou `/etc/firewalld/zones/`. Voici un exemple:
```
<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>My zone</short>
  <description>Here you can describe the characteristic features of the zone.</description>
  <service name="ssh"/>
  <port port="2222" protocol="tcp"/>
  <port port="6553" protocol="udp"/>
</zone>
```

## Résumé
- La commande `firewall-cmd` est l'utilitaire qui permet de gérer le `firewalld` en ligne de commande.
- `firewall-cmd` vient avec plusieurs options: les paramètres avec `add` permet d'autoriser un service, un port, ... `remove` fait l'inverse. Les paramètres `get` et `set` permettent respectivement d'obtenir et de modifier.
- On peut créer ses propres services, zones en ligne de commande ou en créant des fichiers XML.
- `Rich Rule` permet de définir des règles plus complexes.


## Sources
- [Doc Firewalld Redhat](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using_firewalls)
- [Site officiel Firewalld](http://www.firewalld.org/)
- Tutorials:
  - [Fédora: Parefeu_-_firewall_-_FirewallD](https://doc.fedora-fr.org/wiki/Parefeu_-_firewall_-_FirewallD)
  - [digitalocean: how-to-set-up-a-firewall-using-firewalld-on-centos-7](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7)
  - [it-connect: centos-7-utilisation-et-configuration-de-firewalld](https://www.it-connect.fr/centos-7-utilisation-et-configuration-de-firewalld/)
  - [thegeekdiary: 5-useful-examples-of-firewall-cmd-command](https://www.thegeekdiary.com/5-useful-examples-of-firewall-cmd-command/)
