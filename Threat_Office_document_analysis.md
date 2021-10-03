---
Title: MS office files analysis
Type: Doc
Nature: Notes
Création: 02/08/2021
---

# Microsoft office files analysis

---
### Sommaire

- **[Introduction](#Introduction)**
- **[Prequis](#Prequis)**
  - [Formats documents Office](#Formats_documents_Office)
  - [Outils d'analyse](#Outils_d\'_analyse)
- **[Analyse du document Office](#Analyse_du_document_Office)**
  - [Analyse via des outils](#Analyse_via_des_outils)
  - [Analyse manuelle](#Analyse_manuelle)
- **[Conclusion](#Conclusion)**
- **[Liens](#Liens)**
---

## Introduction
Dans cette note, nous allons voir comment analyser un fichier de Microsoft office.
Pour l'environnement d'analyse, nous travaillerons sur une machine Kali Linux.
Pour le fichier à analyser, nous allons créer notre propre fichier excel contenant un macro (donc non malveillant).


## Prerequis
### Formats documents Office
Il existe une douzaine d'extension de fichiers pour les documents de Microsoft office. Ce sont tous des formats de fichiers binaires structurés et composés qui peuvent contenir des liens ou des objets embarqués. Et ils peuvent contenir des Macro.
On en distinque deux grands formats :
- **OLE (Object Linking and Embedding)** formats : comme RTF, DOC, XLS, PPT. C'est l'ancien (legacy) format, mais ils sont toujours maintenus par Microsfot.
- et **OOXML (Office Open XML)** formats : comme DOCX, XLSX, PPTX. C'est le nouveau format introduit par microsoft depuis Office 2007 et ce sont des fichiers ZIP, donc on peut bien les analyser manuellement.
> Note :
> - Les extensions avec "m" contiennent des macros (.docm, pptm, dotm, etc. etc.)
> - Macro functions like AutoOpen, AutoExec, Workbook_Open  or Document_Open will be automatically executed.

### Outils d'analyse
Pour l'analyse, nous allons utiliser les outils ci-dessous :
- ``File`` : commande Linux pour trouver le type d'un fichier
- `Strings` : commande pour extraire les strings d'un fichier
- [exiftool](https://exiftool.org/) : afficher les métadonnées d'un fichier
  > NB : Voir les [instructions d'installation](https://exiftool.org/install.html#Unix)

- [Oletools](https://github.com/decalage2/oletools) (oleid, olevba, ...) : suite d'outils pour l'analyse des documents de Microsoft office
> Installation : `sudo -H pip install -U oletools`

- [oledump](https://github.com/DidierStevens/DidierStevensSuite) : fait partie de DidierStevensSuite et il est intéressant pour l'analyse des documents de Microsoft office

## Analyse du document Office
On peut analyser le fichier soit manuellement, soit à l'aide des outils.
Comme cité plus haut, nous utiliserons un fichier excel (analyse_ole_file.xlsm)  contenant ce code vba ci-dessous :
```
Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" _
    Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, _
    ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long

Private Sub Auto_Open()

  download_HK_picture
  infected

End Sub

Sub infected()
    MsgBox "This is a Macro. Your laptop has been hacked!"
End Sub


Sub download_HK_picture()
imgsrc = "https://upload.wikimedia.org/wikipedia/commons/thumb/7/75/Hong_Kong_at_night.jpg/2400px-Hong_Kong_at_night.jpg"
dlpath = "C:\Users\user\Downloads\"
URLDownloadToFile 0, imgsrc, dlpath & "HK Skyline.jpg", 0, 0
End Sub
```
> Source : [Download Files with VBA URLDownloadToFile](https://wellsr.com/vba/2018/excel/download-files-with-vba-urldownloadtofile/)

Ce code n'est pas malveillant. Il permet juste de télécharger une image jpeg dans le répertoire Donwloads puis d'afficher un messagebox à l'ouverture du fichier Excel (Auto_Open).

> Note : Il existe cependant plusieurs manières d'obtenir un fichier "malveillant" : <br>
> 1) Générer un code VBA (reverse_https) via Metasploit puis de l'intégrer dans un macro.
> 2) Récupérer un document de Microsoft Office depuis des plateformes comme [Hybrid-Analysis](https://www.hybrid-analysis.com/) ou [Any.Run](https://any.run/)

> **Attention** : si le fichier est avéré malveillant, il faut penser à bien isoler la plateforme d'analyse avant de procéder à son analyse.

### Analyse via des outils
- **Vérifier le type du fichier** <br>

Parfois les développers de malware cachent bien le type du fichier. Ainsi, la commande `file` permet d'afficher le type véritable d'un fichier.
```
$ file analyse_ole_file.xlsm
analyse_ole_file.xlsm: Microsoft Excel 2007+
```
> File montre bien qu'il s'agit d'un fichier Excel

- **Afficher les métadonnées du fichier** <br>

Les métadonnées (date de création, de modification, type, ...) permettent aussi de mieux identifier le fichier. Elles peuvent être obtenues grâce à l'outil `Exiftool` :
```
└─$ exiftool analyse_ole_file.xlsm
ExifTool Version Number         : 12.32
File Name                       : analyse_ole_file.xlsm
Directory                       : .
File Size                       : 15 KiB
File Modification Date/Time     : 2021:10:03 09:25:27-04:00
File Access Date/Time           : 2021:10:03 09:26:11-04:00
File Inode Change Date/Time     : 2021:10:03 09:25:45-04:00
File Permissions                : -rw-rw-rw-
Warning                         : Install Archive::Zip to decode compressed ZIP information
File Type                       : ZIP
File Type Extension             : zip
MIME Type                       : application/zip
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x513599ac
Zip Compressed Size             : 367
Zip Uncompressed Size           : 1087
Zip File Name                   : [Content_Types].xml
```
> Ajouter l'opton `-v` pour affcher plus de détails sur les métadonnées.

- **Afficher les strings** <br>

Parfois les chaines de caractères (strings) contenues dans un fichier peuvent donner des indcations sur la nature malveillante ou non d'un fichier. Elles peuvent être obtenues grâce à la commande `strings` ou `rabin2` :
```
$ strings --encoding=l   analyse_ole_file.xlsm
$ rabin2 -zz analyse_ole_file.xlsm
```
> Note : les strings obtenus ne sont pas très identifiabes.

- **Examiner le fichier pour déterminer sa nature** <br>

Les documents d'office malveillants contiennent le plus suouvent des macro. Donc, il faut donc explorer le document pour identifier les éléments suspicieux. Cela peut se faire à l'aide de `oleid` (de oletools) ou `oledump`(de DidierStevensSuite):
```
  $ oleid analyse_ole_file.xlsm                                                                                 1 ⨯
  ...
  --------------------+--------------------+----------+--------------------------
  Indicator           |Value               |Risk      |Description               
  --------------------+--------------------+----------+--------------------------
  File format         |MS Excel 2007+      |info      |                          
                      |Macro-Enabled       |          |                          
                      |Workbook (.xlsm)    |          |                          
  --------------------+--------------------+----------+--------------------------
  Container format    |OpenXML             |info      |Container type            
  --------------------+--------------------+----------+--------------------------
  Encrypted           |False               |none      |The file is not encrypted
  --------------------+--------------------+----------+--------------------------
  VBA Macros          |Yes, suspicious     |HIGH      |This file contains VBA    
                      |                    |          |macros. Suspicious        
                      |                    |          |keywords were found. Use  
                      |                    |          |olevba and mraptor for    
                      |                    |          |more info.                
  --------------------+--------------------+----------+--------------------------
  XLM Macros          |No                  |none      |This file does not contain
                      |                    |          |Excel 4/XLM macros.       
  --------------------+--------------------+----------+--------------------------
  External            |0                   |none      |External relationships    
  Relationships       |                    |          |such as remote templates,
                      |                    |          |remote OLE objects, etc   
  --------------------+--------------------+----------+--------------------------
```
> Ici, on note bien la présence d'un macro grâce à la ligne `VBA Macros` qui est qui est considéré comme très risqué (Yes, suspicious et HIGH).

> Remarque: On peut obtenir le même résultat grâce à `oledump` :
```
$ python3 DidierStevensSuite/oledump.py analyse_ole_file.xlsm
A: xl/vbaProject.bin
 A1:       475 'PROJECT'
 A2:       107 'PROJECTwm'
 A3: m    1009 'VBA/Feuil1'
 A4: m    1017 'VBA/ThisWorkbook'
 A5:      3441 'VBA/_VBA_PROJECT'
 A6:      1778 'VBA/__SRP_0'
 A7:       152 'VBA/__SRP_1'
 A8:       544 'VBA/__SRP_2'
 A9:       259 'VBA/__SRP_3'
A10: M    3700 'VBA/analysis_macro'
A11:       590 'VBA/dir'
```
> `M` marque la présence d'un macro. Donc, on remarque ainsi que le stream (flux) 10 contienne un code VBA.


- **Examiner les macros du fichier** <br>

Une fois qu'on identifie un macro dans le fichier, on peut l'extraire grâce à l'outil `olevba`.
On peut analyser les éléments supsects du macro grâce à l'option `-a` :
```
olevba -a analyse_ole_file.xlsm
...
  +----------+--------------------+---------------------------------------------+
  |Type      |Keyword             |Description                                  |
  +----------+--------------------+---------------------------------------------+
  |AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
  |Suspicious|Lib                 |May run code from a DLL                      |
  |Suspicious|URLDownloadToFileA  |May download files from the Internet         |
  |Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
  |          |                    |used to obfuscate strings (option --decode to|
  |          |                    |see all)                                     |
  |IOC       |https://upload.wikim|URL                                          |
  |          |edia.org/wikipedia/c|                                             |
  |          |ommons/thumb/7/75/Ho|                                             |
  |          |ng_Kong_at_night.jpg|                                             |
  |          |/2400px-Hong_Kong_at|                                             |
  |          |_night.jpg          |                                             |
  +----------+--------------------+---------------------------------------------+
```
> On découvre les mots-clés (keyword) présents dans le macro ainsi que leur valeur et leur type. Un des mots-clés (Auto_Open) déclenche une action automatique. Les autres sont considérés comme suspicieux (Lib, URLDownloadToFile, Hex Strings). On note même la présence d'une URL considérée comme IOC (Indicateur de compromission).

L'option `-c` nous permettra d'afficher le code VBA du macro :
```
olevba -c analyse_ole_file.xlsm
...
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" _
   Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, _
   ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long

Private Sub Auto_Open()

 download_HK_picture
 infected

End Sub

Sub infected()
   MsgBox "This is a Macro. Your laptop has been hacked!"
End Sub


Sub download_HK_picture()
imgsrc = "https://upload.wikimedia.org/wikipedia/commons/thumb/7/75/Hong_Kong_at_night.jpg/2400px-Hong_Kong_at_night.jpg"                                                                                                               
dlpath = "C:\Users\user\Downloads\"
URLDownloadToFile 0, imgsrc, dlpath & "HK Skyline.jpg", 0, 0
End Sub
```
> Ici, le code apparaît en clair. Mais, la plupart du tout les développeurs de malware obfusquent le code ou y ajoutent des commentaires/fonctions inutiles afin de rendre sa compréhension plus difficile pour l'analyste.
> Dans le cas dd'une obfuscation, les options `--decode` et `--deobf` pourraient être très utiles pour déobfusquer le code.

> Note : `olevba nom_fichier` donne un résultat plus complet. Help: `olevba -h`

> Remarque : On peut extraire ou dumper aussi le code VBA contenu dans ce fichier grâce à `oledump` à l'aide des options `-s` et `-v`. Ainsi pour extraire le macro contenu dans le stream 10 :

```
$ python3 DidierStevensSuite/oledump.py -s 10 -v analyse_ole_file.xlsm                                        2 ⨯
  Attribute VB_Name = "analysis_macro"
  Private Declare PtrSafe Function URLDownloadToFile Lib "urlmon" _
      Alias "URLDownloadToFileA" (ByVal pCaller As Long, ByVal szURL As String, _
      ByVal szFileName As String, ByVal dwReserved As Long, ByVal lpfnCB As Long) As Long

  Private Sub Auto_Open()

    download_HK_picture
    infected

  End Sub

  Sub infected()
      MsgBox "This is a Macro. Your laptop has been hacked!"
  End Sub

  Sub download_HK_picture()
  imgsrc = "https://upload.wikimedia.org/wikipedia/commons/thumb/7/75/Hong_Kong_at_night.jpg/2400px-Hong_Kong_at_night.jpg"
  dlpath = "C:\Users\user\Downloads\"
  URLDownloadToFile 0, imgsrc, dlpath & "HK Skyline.jpg", 0, 0
  End Sub
```

### Analyse manuelle
Un document Office est en quelque sorte une arcg=hive Zip, ce qui fait qu'il peut être analysé manuellement.
> Note : Cette procédure est bien décrite sur le Blog VadeSecure dans l'arcticle dédié à l'[Analyse d'un email malveillant](https://www.vadesecure.com/fr/blog/analyse-dun-email-malveillant).

Pour analyser le fichier, commençons d'abord par le décompresser :
```
$ unzip analyse_ole_file.xlsm        
```
> On obtient ainsi des fichiers XML que l'on peut ouvir à l'aide d'un éditeur de texte. La commande `tree` nous permet de mieux appréhender la structure :
```
$ tree
.
├── analyse_ole_file.xlsm
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   └── core.xml
├── _rels
└── xl
    ├── _rels
    │   └── workbook.xml.rels
    ├── styles.xml
    ├── theme
    │   └── theme1.xml
    ├── vbaProject.bin
    ├── workbook.xml
    └── worksheets
        └── sheet1.xml
```

Ainsi, nous remarquons bien la présence d'un binaire vba (vbaProject.bin) qui peut être suspect.
L'analyse du fichier `workbook.xml` montre cette ligne ci-dessous qui peut prêter à croire à une action de téléchargement.
```
<x15ac:absPath url="C:\Users\user\Downloads\"
```
Le fichier `workbook.xml.rels` montre une relation entre le binaire et e fichier `sheet1.xml` :
```
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
	<Relationship Id="rId4" Type="http://schemas.microsoft.com/office/2006/relationships/vbaProject" Target="vbaProject.bin"/>
```
Mai ce fichier `sheet1.xml` est bien vide. Ce qui rend encore plus suspect le binaire VBA qu'il contient.
Ce binaire peut être examiné à l'aide des outils présentés précédemment ou soumis sur des plateforme comme VirusTotal, AnyRun ou Hybrid-analysis.

## Conclusion
Les documents d'Office sont souvents vecteurs d'infection par les malwares. Ils peuvent contenir des macros pour réaliser des actions malveillantes.
L'analyse d'un tel document peut être fait manuellement (car c'est un fichier zip) ou à l'aide des outils. Par ces derniers, `oletools` ou `oledump`(de Didier Stevens) sont très complets et l'un ou l'autre peut suffire pour l'analyse dans bien des cas. Cependant, rien n'empêche de les utiliser à la fois.


## Liens
- *Documentations* : <br>
    - [Micosoft Office File Formats](https://docs.microsoft.com/en-us/deployoffice/compat/office-file-format-reference)
    - [Lenny Zeltser / Analyzing Malicious Documents Cheat Sheet](https://zeltser.com/analyzing-malicious-documents/)
    - [HackTrick / Office File analysis](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis)
    - [Blog VadeSecure / Analyse d'un email malveillant](https://www.vadesecure.com/fr/blog/analyse-dun-email-malveillant)
    - [Malicious Document Crash Course Part 1: Microsoft Office Documents and Macros](https://joshstepp.com/post/maliciousdoc_part1/)
    - [Hackingarticles / Multiple Ways to Exploit Windows Systems using Macros](https://www.hackingarticles.in/multiple-ways-to-exploit-windows-systems-using-macros/)

- *Tools* :<br>
    - [decalage2/oletools](https://github.com/decalage2/oletools)
    - [Didier Stevens Suite](https://github.com/DidierStevens/DidierStevensSuite)
    - [REMnux MS office tools](https://docs.remnux.org/discover-the-tools/analyze+documents/microsoft+office)
    - [OfficeDissector](https://www.officedissector.com/)
    - [exiftool](https://exiftool.org/)
