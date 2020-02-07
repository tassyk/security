---
Title: Sécurisation SSH
Catégorie: Hardening system
Date: 02/02/2020
Auteur: TK
---

# Sécurisation SSH

## Introduction
Le protocol SSH permet de réaliser des connexions disatntes sécurisées sur les systèmes. Dans cet article, nous allons voir comment on peut sécuriser son utilisation.
Les modifications se font dans le fichier de configuration `/etc/ssh/sshd_config`

## Changement du port par défaut et l'adresse d'écoute
Ce changement se fait via les directives Port et ListenAddress
```
Port PORT_NUMBER
ListenAddress IP_ADRESS
```


**Remarques :**

Si SElinux est activé, il faut redefinir le contexte via a commande:
```
sudo semanage port -a -t ssh_port_t -p tcp 2235
```
ou le mettre en Permissive ou le déactivé, pour que le changement de port soit autorisé.

Si le firewall est activé sur la machine, il faut autoriser le port avant de redémarrer le service sshd.
```
sudo firewall-cmd --add-port=2235/tcp --permanent
sudo firewall-cmd --reload
sudo systemctl restart sshd

```

## Les options d'authentification
Certaines directives sont utilisées pour renforcer la méthode d'autentification

- Temps d'innactivité autorisé: `LoginGraceTime 2m`
- Ne pas autoriser le login via root: `PermitRootLogin no`
- Nombre de tentatives de connexion permis:
`MaxAuthTries 4`
- Authentification via clé ssh : `PubkeyAuthentication yes`
- Authentification via un password mais non vide :
```
PermitEmptyPasswords no
PasswordAuthentication yes
```
- Authentification via un challenge (dans le cas d'un 2FA):
```
ChallengeResponseAuthentication yes
```
- Interdire l'agent forwarding si le serveur n'est pas utilisé pour un rebond ssh et les X11 et TCP forwarding si le serveur X n'est pas autorisé:
```
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
```

## Activation de l'authentification multi facteurs
L'authentification via une clé est plus sécurisée qu'un mot de passe. Cependant, une authentification avec plusieurs facteurs (au moins deux) est encore mieux.
Dans ce qui suit, nous allons montrer comment activer une double authentification à l'aide de l'outil opensource `google-authenticator` (ou à la place, on peut utiliser aussi d'autres outils comme [duo unix](https://duo.com/docs/duounix))

### Installer google-authenticator
Installer google-authenticator à l'aide des commandes ci-dessous:
```
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
sudo yum install google-authenticator
```
Lancer la commande `google-authenticator` et répondre aux questions et noter les clés qui sont données.

### Configuration de PAM pour activer la double authentification
Maintenant que le token est généré, nous allons configurer PAM pour activer cette authentification
- Editer le fichier /etc/pam.d/sshd
```
sudo nano /etc/pam.d/sshd
```
- Ajouter cette ligne tout en bas
```
auth required pam_google_authenticator.so nullok
```
- Rmq: En commentant la
`auth       substack     password-auth`, on désactive l'emploi d'un mot de passe dans les MFA.

### Configuration de sshd pour appliquer la double authentication
- Editer le fichier /etc/ssh/sshd_config
- Activer la directive `ChallengeResponseAuthentication` en mettant `yes`
- Modifier la méthode d'autentification en ajoutant cette ligne à la fin du fichier
```
AuthenticationMethods publickey,password publickey,password keyboard-interactive
```
Cette ligne autorise l'authentication par clé, ou password et clé, ou password et token TOTP de google_authenticator


## Sources
- 2FA SSH: https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-centos-7
- Génération de clé ssh: https://adamdehaven.com/blog/how-to-generate-an-ssh-key-and-add-your-public-key-to-the-server-for-authentication/
