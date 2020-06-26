---
Title: Windows Forensics tips
Type: Doc
Nature: Notes
Création: 20/05/2020
---

# Investigation numérique (Forensics) sous Windows

## Etapes de l'Investigation numérique
- Identification du contexte et récupération des informations
- Collecte des supports numériques à analyser
- Analyse des données collectées
- Corrélation et reporting

## Investigation numérique Offline
Les investigations dans ce cas peuvent être réalisées via des outils comme `FTK, Volatility, ...`

### Dumps mémoires, disk, logs, mail
- `FTK imager` permet de dumper (réaliser une copie) une mémoire RAM, un disk, des registres, partition NTFS (MTF - Master File Table).... Il permet aussi d'extraire des logs
- calcul de condensat ou hash des dumps (intégrité) : `[sha512sum | sha256sum | md5sum ] memdump.mem`
> Note :
> - Les formats peuvent être RAW, MEM, DMP, les formats Forensic (AFF, SMART, EWF), ...

- `Dumpit` : est outil qui permet aussi de dumper une mémoire

### Analyse mémoires
- Informations à analyser : connexions réseaux, des clés de registre, des mots de passe ou encore des processus en cours d’exécution, ...

- Identification de l'image de la machine (profile) : `imageinfo, kdbgscan, kpcrscan`
```
# identifier les profiles potentiels de l'image : imageinfo
volatility -f memdump.mem imageinfo
# identifier les détails du profile exact : kdbgscan
 volatility -f memdump.mem --profile=Win2003SP2x64 kdbgscan
# scanner les potentielles structures KPCR (details des processeurs) : kpcrscan
volatility -f memdump.mem --profile=Win7SP1x64 kpcrscan
```
> note:
> - le profile ressemble à ceci `Win7SP1x86`
> - dépendant de la méthode d'installation de volatility, on peut utiliser : `python vol.py`

- Analyse des processus et DLL : : `pslist, pstree, psxview, psscan,psdispscan, procdump, dlllist,dlldump`
```
# liste des processus
volatility -f memdump.mem –-profile=Win7SP1x86 pslist [-P] # list
volatility -f memdump.mem –-profile=Win7SP1x86 pstree # arborescence
volatility -f memdump.mem –-profile=Win7SP1x86 psxview # cachés
# Enumérer les proocessus : psscan
volatility --profile=Win7SP0x86 -f memdump.mem psscan
# Liste DLL d'un processus : dlllist
volatility -f memdump.mem –-profile=Win7SP1x86 dlllist  -p $PID
# Dumper un DLL pour analyse détaillée :
volatility -f memdump.mem  --profile=Win7SP0x64 dlldump -D $DLL_DIR/
# Dump d'un processus
volatility -f memdump.mem –-profile=Win7SP1x86 procdump -D $DIR/ -p $PID
```

- Analyse des registres
```
# Extraction des informations des registres : hivelist
volatility -f memdump.mem –-profile=Win7SP1x86 hivelist
# dump des hash des mots de passe : hashdump
volatility -f memdump.mem --profile=Win7SP1x86 hashdump -y 0x8981c008 -s 0x8a6579c8
```

- Analyse des connexions réseaux
```
# Liste des connexions réseaux actives : netscan, connexions, sockscan, socket
volatility -f memdump.mem --profile=Win7SP1x86 netscan
```

- Analyse des fichiers de mémoire : `Hiberfil.sys, Pagefile.sys`
```
# décompression du fichier hiberfil.sys (pour l'analyse via Volatility)
volatility -f hiberfil.sys -–profile=Win7SP1x64 imagecopy -O hiberfil.dmp
# Extration des informations de pagefile.sys (strings)
strings pagefile.sys | grep “http://”
```

- Détection de l'injection de code : `malfind`
```
# détecter de l’injection de code malveillant
volatility -f memdump.mem –-profile=Win7SP1x86 malfind
```
- Lecture des mutex : `mutantscan`
```
volatility -f memdump.mem –-profile=Win7SP1x86 mutantscan
```

- Scan et Extraction d'autres informations : `svcscan, cmdscan, yarascan`
```
# Lister les services : svcscan
volatility -f memdump.mem –-profile=Win7SP1x86 svcscan
# extraire l’historique des commandes : cmdscan
volatility -f memdump.mem –-profile=Win7SP1x86 cmdscan
# scanener via yara rules : yarascan
```
### Analyse de la copie de disque
- via `Autopsy`
> Autopsy est une interface graphique de l’outil open source The Sleuth Kit. Il permet d'analyser, de parser les données du disque, de générer une timeline et un rapport, ...

### Analyse des mails
> Avec Outlook, les emails de chaque utilisateur sont stockés dans un fichier `.PST(Personal Storage Table)` en activité, ou `.OST ` hors connexion. Cf `C:\users\username\AppData\Local\Microsoft\Outlook`. On peut extraire ces fichiers de mail avec `FTK Imager`.

- Visualisation du mail (.OST/.PST) via un `viewer` : `Free OST Viewer Tool,` `pff-tools (Sous Linux)`
> On peut visualiser ces fichiers via `Free OST Viewer Tool`, extraire le mail au format `.MSG`. Sous Linux, on peut aussi utiliser l'outil `pff-tools`

- Analyse de l'entête et extraction des pièces jointes :
> - Pour obtenir les informations de l'entête, il faudra d’abord convertir le .`MSG` en fichier `.EML` via un outil comme `msgconvert (Linux)`
> - Pour l'installer : `sudo apt install libemail-outlook-message-perl libemail-sender-perl`
> - Pour convertir en `.EML`: `msgconvert your_mail.msg``
> - Ainsi on peut ouvrir `msgconvert your_mail.eml` avec un éditeur de texte.
> - La pièce jointe est codée en `base64`. On peut copier/coller cette chaîne dans un fichier (ex: pj.b64) puis le décoder pour récupérer la pièce jointe : `base64 -d pj.b64 >> pj.decoded`

## Investigation numérique Online
Les investigations dans ce cas peuvent être réalisées via des outils comme `les commandes systèmes, la suite sysinternals, la suite NirSoft, wireshark, ...`

### Analyse des processus et DLL
- via `ProcessExplorer` (sysinternals)
> Note : disposé d'une interface graphique, il analyse à la fois les processus, les info de réseau, CPU, Disk, DLL, ... Il a également plusieurs fonctionnalités telles que l'affichage des signatures, scan via virustotal, Kill Process Tree, ...(cf `click droit`). Il peut être utiliser pour les opération de diagnostique et de troubleshooting

- via `ProcessMonitor`  (sysinternals)
> Disposé d'une interface graphique, il capture les opérations I/O (Input / Output) qu'il soit au niveau du file system, registry, ou le réseau network. Il peut être utiliser pour les opération de diagnostique et de troubleshooting

- via `Handle` (sysinternals)
> Ligne de commande fonctionnant comme Process Explorer
- via `ListDlls` (sysinternals)
> Liste les DLL appelés par un programme

- via `tasklist` (cmd Windows)
> Commande Windows pour lister les processus

### Analyse des disques
- via `Diskmon` (sysinternals)
> Affiche l'activité des disque durs.

- via `DiskView` (sysinternals)

- via `Mft2Csv`
> Outil qui permet convertir la MFT (Master File Table) de la partition du disque NTFS en CSV (exploitablse). la MFT enregistre toutes les informations relatives à un fichier. On peut extraire la MFT via `FTK imager`

- via `scandisk` (cmd windows)
> Commande interne Windows pour vérifier les volumes pour détecter des erreurs

- via `diskcomp` (cmd Windows)
> Compare le contenu de deux disques

### Analyse des fichiers, répertoires
- via `RootkitRevealer` (sysinternals)
> Détecte les virus dans le registre.

- via `AccessEnum` (sysinternals)
> Indique qui (administrateur, utilisateur) a accès aux répertoires et contenu du registre. Graphique.

- via `AccessChk` (sysinternals)
> Montre quels genre d'accès sont réalisés sur les ressources (fichiers etc.).

- via `SDelete` (sysinternals)
> Secured delete efface les fichiers de telle sorte qu'on ne puisse ni les récupérer ni voir leur contenu en analysant le disque dur.

- via `DU` (sysinternals)
> Affiche pour un répertoire donné, le nombre de fichiers et l'espace occupé

- via `Strings` (sysinternals)
> Convertit les fichiers contenant des codes unicode illisibles pour les éditeurs de texte.

- via `Streams` (sysinternals)
> Analyse et affiche les fichiers cachés NTFS

- via `SigCheck` (sysinternals)
> Analyse les fichiers non signés numériquement

- via `findlinks` (sysinternals)
> Affiche les liens symboliques vers un fichier

### Analyse des registres
> notamment, les registres users (Ntuser.dat), base sam, softwares

- via `Regedit` (Windows)
> Editeur de registre windows

- via `RegRipper`
> Cet outil permet d'analyser un dump de redistre

### Analyse des informations réseaux
- via `ShareEnum` (sysinternals)
> Détecte les domaines utilisateurs pour les fichiers partagés.

- via `TcpView` (sysinternals)
> Montre les connexions en cours et permet de les fermer.

- via `WhoIs` (sysinternals)
> Résoud les noms de domaines

- via `SmartSniff` (NirSoft)
> Sniffeur de paquets TCP dans un réseau

### Analyse des services
- via `Autoruns` (sysinternals)
> Permet d'afficher et des gérer les services qui sont lancés automatiquement.

- via `services.msc` (Windows)
> Gestionnaire de service windows

### Analyse des logs
- via `Event Viewer` (Windows)
> Outil windows permettant d'analyser les logs d'événements windows. [www.eventid.net](www.eventid.net): ce site permet d'obtenir plus d’informations sur un évènement donné. [Event Log Explorer](https://eventlogxp.com/download.php) est un logiciel payant (version d'essai disponible) qui permet aussi d'explorer les logs

### Analyse des secrets
- via `Password-Recovery tools` (Nirsoft)
> suite d'outils permettant de retrouver un password perdu sur un ensemble d'application (Systèmes, navigateurs, Mail, Wifi)

### Analyse des mails
- via `Outlook, Exchange, ...`
> En mode Online, on peut analyser aussi l'entête d'un mail via l'outil de messagerie `Outlook, Exchange` (dans les options).

- via `mxtoolbox, Email Dossier, MailXaminer`
> On peut obtenir des informations sur un mail via d'autres outils comme [mxtoolbox](https://mxtoolbox.com/), [Email Dossier](https://centralops.net/co/EmailDossier.aspx), [MailXaminer](https://www.mailxaminer.com/)

- Analyse des pièces jointes : `pdfid, pdf-parser, oledump`
> Après avoir récupérer les pj du mail, on peut les analyser via des outils comme : [pdfid](https://github.com/Rafiot/pdfid), `pdf-parser`, [oledump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py)
>
```
# fichiers pdf
pdfid.py invoice.pdf # via pdfid
pdfparser.py invoice.pdf # via pdf-parser
# fichiers Office
oledump.py invoice.docm # afficher les éléments du fichier
oledump.py -s A3 -v invoice.docm # afficher le contenu d'un macro
```

## Liens
- Usefull Tools
  - Dump: FTK, Dumpit
  - Analyse: [Volatility](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference), [Sysinternals](https://docs.microsoft.com/fr-fr/sysinternals/downloads/), [Encase](https://www.guidancesoftware.com/encase-forensic), [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/), [NirSoft utilities](https://www.nirsoft.net/), [Mft2Csv](https://github.com/jschicht/Mft2Csv), ADS Spy (lads), QuickStego (stégano), snow, pdf-parser, [RegRipper](https://github.com/keydet89/RegRipper2.8), [pdfid](https://github.com/Rafiot/pdfid), [oledump](https://github.com/DidierStevens/DidierStevensSuite/blob/master/oledump.py), [mxtoolbox](https://mxtoolbox.com/), [Email Dossier](https://centralops.net/co/EmailDossier.aspx), [MailXaminer](https://www.mailxaminer.com/), [www.eventid.net](www.eventid.net), [Event Log Explorer](https://eventlogxp.com)
- Forensics resources
  - [Menez une investigation numérique Forensic | Openclassroom](https://openclassrooms.com/fr/courses/1750151-menez-une-investigation-d-incident-numerique-forensic)
  - [Windows Internals Book 7th Edition Tools](https://github.com/zodiacon/WindowsInternals)
  - [Sysinternals Learning Resources | video and podcast](https://docs.microsoft.com/en-us/sysinternals/learn/)
  - [Volatility](https://www.volatilityfoundation.org/)
  - [NirSoft utilities](https://www.nirsoft.net/)
  - [SANS windows forensic analysis Poster](https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download)
  - [Commandes Windows](https://docs.microsoft.com/fr-fr/windows-server/administration/windows-commands/windows-commands)
  - [PowerForensics](https://powerforensics.readthedocs.io/en/latest/)
- Forensics tutorials :
  - [howtogeek | sysinternals lessons](https://www.howtogeek.com/school/sysinternals-pro/)
  - [Systol | Sysinternals, outils mal connus pour Windows](https://www.scriptol.fr/logiciel/sysinternals.php)
  - [tech2tech | Nirsoft](https://www.tech2tech.fr/tag/nirsoft/)
  - [Blog Nirsoft | nirsoft tips](https://blog.nirsoft.net/category/nirsoft-tips/)
  - [How to hide files](https://www.bleepingcomputer.com/tutorials/windows-alternate-data-streams/)
  - [ionos : commandes windows](https://www.ionos.fr/digitalguide/serveur/know-how/commande-cmd/)
- Rapport Forensics :
  - [ATT&CK Matrix](https://attack.mitre.org/)
