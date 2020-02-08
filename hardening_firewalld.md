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

# Contrôle du trafic
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

## Contrôler les ports
Pour afficher la liste des ports, taper la commande `sudo firewall-cmd --list-ports`.
### Autoriser un port via le firewalld
Pour atoriser un port via le firewall:
1. Taper la commande `sudo firewall-cmd --add-port=port-number/port-type`. Ajouter l'option **--permanent** pour rendre la règle persistente. Le port-type prend les valeurs: **tcp, udp, sctp, ou dccp.**
**Exemple :** `sudo firewall-cmd --add-port=22/tcp --permanent`. **Remarque :** Comme, on l'a vu pour les services, on peut autoriser le port à l'aide de la commande ci-dessus sans l'option `--permanent` puis la rendre persistente à l'aide de `sudo firewall-cmd --runtime-to-permanent`
2. Relancer le firewalld via la commande `sudo firewall-cmd --reload`

Comme firawalld fonctionne sur des zones, si on ne précise pas une zone dans la commande `firewall-cmd`, les règles s'applique pour la zone active (par défaut, public). On peut changer ce fonctionnement.

## Gestion des zones





## Sources
- Doc officiel: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using_firewalls

- Tutorials:
  - Fédora: https://doc.fedora-fr.org/wiki/Parefeu_-_firewall_-_FirewallD
  - digitalocean: https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7
  - it-connect: https://www.it-connect.fr/centos-7-utilisation-et-configuration-de-firewalld/
  - thegeekdiary: https://www.thegeekdiary.com/5-useful-examples-of-firewall-cmd-command/
