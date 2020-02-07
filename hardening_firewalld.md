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
sudo systemctl enable firewalld
sudo systemctl start firewalld
```
## Fonctionnement de firewalld
Firewalld fonctionne en zones comme le montre la commande suivante: ``
```
sudo firewall-cmd --get-zones
---
block dmz drop external home internal public trusted work
```
Chaque zone a ses spécificités:
- **drop**: le niveau le plus bas de confiance. Toutes les connexions entrantes sont supprimées sans notifications.
- **block**: même principe que "drop" à quelques différences près. Ici, les connexions entrantes sont supprimées avec notifications (icmp-host-prohibited ou icmp6-adm-prohibited pour IPv6)
- **public**: réseaux public. On n'accorde pas une confiance aveugle aux autres ordianteurs du réseau; les connexions entrantes sont gérées au cas par cas.
Je vous laisse le soin d'explorer les autres zones. Les noms sont assez parlants.




## Sources
- Doc officiel: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-using_firewalls

- Tutorials:
  - Fédora: https://doc.fedora-fr.org/wiki/Parefeu_-_firewall_-_FirewallD
  - digitalocean: https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7
  - it-connect: https://www.it-connect.fr/centos-7-utilisation-et-configuration-de-firewalld/
  - thegeekdiary: https://www.thegeekdiary.com/5-useful-examples-of-firewall-cmd-command/
