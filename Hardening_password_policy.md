---
Title: Password policy
Catégorie: Hardening system
Date: 02/02/2020
Auteur: TK
---

# Introduction
Dans cet article de "Hardening System", nous allons nous intéresser à la politique de mot de passe systèmes. La complexification de mot de passe peut augmenter le niveau de sécurité d'un système.

# Complexification de la politique de mot de passe
A partir de Redhat 7, cette politique est gérée via le module PAM (Pluggable Authentication Modules) `pam_pwquality` (qui remplace `pam_cracklib`).

**Remarque :**
- Avant toute modification d'un fichier de configuration, veuillez effectuer une copie du fichier d'abord.

### Configuration de /etc/pam.d/passwd
L'activation de  `pam_quality` se fait dans le fichier `/etc/pam.d/passwd`.
Ajouter la ligne ci-dessous dans ce fichier.
```
password    required    pam_pwquality.so retry=3 authtok_type=enforce_for_root
```
**NB :** `authtok_type=enforce_for_root` exige cette politique même pour le compte root.

### Configuration de /etc/security/pwquality.conf
La politique de mot de passe est définie dans `/etc/security/pwquality.conf`.
Ajouter les lignes ci-dessous dans ce fichier.
```
minlen = 12
minclass = 4
lcredit=-1
ucredit=-1
dcredit=-1
ocredit=-1
maxsequence = 2
maxrepeat = 2
difok = 5
```
Où:
- **minlen**: longueur minimale du mot de passe
- **minclass**: famille de caractère minimale
- **lcredit**: nombre caractère miniscule
- **ucredit**: nombre caractère majuscule
- **dcredit**: nombre caractère décimale
- **ocredit**: nombre caractères spéciaux (@, #, ..;)
- **maxsequence**: nombre de séquence de caractères qui se suivent (ex: 123, abc)
- **maxrepeat**: nombre de répétition d'un même caractère (ex: aa, cc)
- **difok**: nombre de caractère dans l'ancien mot de passe autorisé

Pour plus de détails sur les paramètres de ce fichier, cf `man pwquality.conf`

**NB :** On peut modifier également ce fichier à l'aide de l'outil `authconfig`.

### Tester la complexité du mot de passe
Pour tester cette politique, créer un utilisateur et essayer de lui définir un mot de passe.
Si le mot de passe ne respecte pas la politique, une erreur de ce genre apparaît:
```
MOT DE PASSE INCORRECT : Le mot de passe contient moins de 1 chiffres
```

### Définir une durée de validité d'un mot de passe.
La commande `chage` permet de définir une durée de validité d'un mot de passe. Utilisée seule, elle demande au prompt à l'utilisateur de saisir les informations. Cependant, elle peut être utilisée aussi avec des options:
- `-M`: spécifie le nombre de jour maximun de validité
- `-W`: spécifie le nombre de jour pour avertir l'utilisateur à changer son password.
- `-l`: liste les paramètres du mot de passe de l'utilisateur.

Pour les autres options voir le lien Redhat ci-dessous ou `man chage`.

**Exemple :** Pour définir une durée de validité de 120 jours et lui prévenir de l'expiration du mot de passe quand il reste 10 jours:
```
sudo chage user -M 120 -W 10
```
Pour vérifier l'age du password:
```
sudo chage user -l
```
### Désactivation d'un compte
Après un certain nombre de tentatives échouées, on peut bloquer le compte de l'utilisateur pendant un certain temps grâce au module `pam_faillock `

# Source
- Hardening Redhat: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/chap-hardening_your_system_with_tools_and_services#sec-Password_Security

- Enforce password: https://kifarunix.com/enforce-password-complexity-policy-on-centos-7-rhel-derivatives/
