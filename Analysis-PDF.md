---
Title: PDF analysis
Type: Doc
Nature: Notes
Création: 02/08/2021
---

# Analyse d'un fichier PDF

---
### Sommaire

- **[Introduction](#Introduction)**
- **[Prequis](#Prequis)**
  - [Approche générale pour l'analyse d'un document](#Approche-générale-pour-l\'-analyse-d'un-document)
  - [Objets PDF à risque](#Objets-PDF-à-risque)
  - [Environnement d'analyse](#Environnement-d'analyse)
- **[Analyse du pdf à l'aide des outils](#Analyse-du-pdf-à-l\'-aide-des-outils)**
  - [Installation des outils](#Installation-des-outils)
  - [Analyse via PDFid](#Analyse-via-PDFid)
  - [Analyse via PDF-parser](#Analyse-via-PDF-parser)
  - [Analyse via Peepdf](#Analyse-via-Peepdf)
  - [Analyse via PDF Stream Dumper](#Analyse-via-PDF-Stream-Dumper)
- **[Analyse manuelle du pdf](#Analyse-manuelle-du-pdf)**
- **[Conclusion](#Conclusion)**
- **[Liens](#Liens)**
---

## Introduction
Dans cette note, nous allons voir comment analyser un fichier PDF malveillant. L'analyse peut être fait à l'aide des outils. Elle peut aussi être faite manuellement car PDF est en quelque sorte un format à balises comme HTML ou autre.

## Prequis
### Approche générale pour l'analyse d'un document

1. Rechercher ds anomalies dans le document telles que les objets/tags à risque, les scripts, les URLs, ou autres artefacts embarqués
2. Localiser les codes embarqués tels que les shellcode, macros, JavaScript, or autres objets suspicieux.
3. Extraire les codes suspicieux ou objets du fichier
4. Si pertinent, deobfusquer et examiner les macros, JavaScript, ou autres objets embarqués dans le code
5. Si pertinent, emuler, desassembler et/ou debugger le shellcode extrait du document.
> source : "[Lenny Zlttser / Analyzing Malicious Documents Cheat Sheet](https://zeltser.com/analyzing-malicious-documents/)"

### Objets PDF à risque
- /OpenAction et /AA : specifient les scripts ou actions à exécuter automatiquement
- /JavaScript, /JS, /AcroForm, et /XFA : peuvent spécifier le code JavaScript à lancer.
- /URI accesses a resource by its URL, perhaps for phishing.
- /SubmitForm et /GoToR : peuvent spécifier l'envoi des données vers une URL
- /RichMedia : peut être utilisé pour embarquer un Flash dans un pdf
- /ObjStm : peut cacher des objets à l'intérieur d'un flux d'objets.
- /XObject : peut embarqer une image (pour phising)
> source : "[Lenny Zlttser / Analyzing Malicious Documents Cheat Sheet](https://zeltser.com/analyzing-malicious-documents/)"

### Environnement d'analyse
Il faut disposer d'une machine Linux ou Windows ayant les outils nécessaires pour cette analyse et un échantillon de fichier PDF "malveillant".<br>

Pour notre part, nous travaillerons sur Windows 10.<br> Et concernant l'échantillon de PDF "malicieux", nous allons le créer par nous-même à l'aide de l'outil [make-pdf-javascript](https://github.com/DidierStevens/DidierStevensSuite) de Didier Stevens.
```
python make-pdf-javascript [option] pdf-file
# exemple : python make-pdf-javascript malware-analysis-cheat-sheet.pdf
```
> Par défaut, ceci emabarque un code javascript (calling app.alert) dans le pdf. On sppeut écifier son propore code à l'aide des options --javascript (-j) ou –javascriptfile (-f)

> Note sur l'environnement:
> - Kali Linux, ou des platefromes dédiées à l'analyse de malware comme [REMnux](https://docs.remnux.org/) ou [FlareVM](https://github.com/fireeye/flare-vm) peuvent bien convenir aussi.
> - On peut créer un pdf "malicieux" à l'aide de Metasploit également, ou en télécharger à partir des plateformes de sandbox en ligne comme [Any.run](https://app.any.run/submissions) ou [Hybrid Analysis](https://www.hybrid-analysis.com/), ou le générer à l'aide des outils générateurs comme [Bad-PDF](https://github.com/deepzec/Bad-Pdf), [Malicious PDF Generator](https://github.com/jonaslejon/malicious-pdf), ...
> **Attention Attention** : Il faut bien isoler la machine d'analyse si le pdf est vraiment malicieux.


## Analyse du pdf à l'aide des outils
On examinera notre pdf "malicieux" précédemment généré à l'aide de :
- [PDFid (Didier Stevens)](https://blog.didierstevens.com/programs/pdf-tools/): examine un fichier pdf et affiche les mots clés (les objets)
- [PDF-parser (Didier Stevens)](https://blog.didierstevens.com/programs/pdf-tools/) : parse un fichier pdf
- [Peepdf](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool) : examine le fichier et indique les éléments suspicieux
- [PDF Stream Dumper](http://sandsprite.com/blogs/index.php?uid=7&pid=57) : disposant d'une GUI, il examine, parse, scan un fichier pdf, extrait des objets, déobfusque, ...

### Installation des outils
 Note : Ignorer cette partie si les outils sont déjà installés sur la distribution (Kali, REMnux, FlareVM, ...) que vous utilisez pour l'analyse. Mais "PDF Stream Dumper" s'installe sur un Windows.

**PDFid et PDF-parser** : <br>
  - Télécharger l'archive [DidierStevens suite](https://blog.didierstevens.com/didier-stevens-suite/) puis le décompresser.

**Peepdf** :
  - Télécharger et décompresser le [paquet](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool) ou Installer le via [pip](https://pypi.org/project/peepdf/): `pip install peepdf`
  - Installer ensuite les modules PyV8, pylibemu, pour pouvoir utiliser certaines fonctionnalités (js_analyse, ...)
  ```
  pip install wheel # dépendance pour pylibemu
  pip install pylibemu
  ```
  > sinon, voir le [README](https://github.com/jesparza/peepdf/blob/master/README) sur le Github pour voir les instructions d'installation. Mais semble être fait pour une distribution Linux.

**PDF Stream Dumper**
- Télécharger [l'exécutable](http://sandsprite.com/blogs/index.php?uid=7&pid=57) et l'installer.


### Analyse via PDFid
PDFid donne un aperçu sur les éléments à risque du pdf.

On éxecute la commande suivante :
```
pdfid.py ..\malware-analysis-cheat-sheet.pdf -n
```
> Note : l'option `-n` affiche uniquement les mots clés à risque. `-aefv` affiche les objets et la structure des action

La commande nous renvoie le résultat ci-dessous :
```
PDFiD 0.2.8 ..\malware-analysis-cheat-sheet.pdf
 PDF Header: %PDF-1.1
 obj                    7
endobj                 7
stream                 1
endstream              1
xref                   1
trailer                1
startxref              1
/Page                  1
/JS                    1
/JavaScript            1
/OpenAction            1
```
On remarque ainsi que le pdf contient une page (`/Page`), 7 objets (`obj`), du code javascript (`/JS et /JavaScript`). Ce dernier peut s'exécuter à l'ouverture du fichier (`/OpenAction`).

Maintenant, examinons le fichier avec le parser.


### Analyse via PDF-parser
Après avoir afficher les éléments à risque du fichier, PDF parser peut nous aider à mieux explorer ces objets et à approfondir notre analyse.

Explorons les éléments du pdf plus en détail :
```
pdf-parser.py ..\malware-analysis-cheat-sheet.pdf -v
```
La commande nous renvoie beaucoup de résultats. L'objet 1 (`obj 1 0`), nous montre que `/OpenAction` se passe à l'objet 7.
```
PDF Comment '%PDF-1.1\r\n'

obj 1 0
 Type: /Catalog
 Referencing: 2 0 R, 3 0 R, 7 0 R

  <<
    /Type /Catalog
    /Outlines 2 0 R
    /Pages 3 0 R
    /OpenAction 7 0 R
  >>
```
En regardant l'objet 7, on voit l'action en question. Il s'agit d'un code javascript :
```
obj 7 0
 Type: /Action
 Referencing:

  <<
    /Type /Action
    /S /JavaScript
    /JS "(app.alert({cMsg: 'Hello from PDF JavaScript', cTitle: 'Testing PDF JavaScript', nIcon: 3});)"
  >>
```
> Note : On peut afficher l'objet 7 à l'aide de cette commande aussi
```
pdf-parser.py ..\malware-analysis-cheat-sheet.pdf  -o 7
```
> Pour effectuer une recharche dans le fichier, on utilise l'option `--search (ou -s)`. Exemple :
```
pdf-parser.py --search javascript ..\malware-analysis-cheat-sheet.pdf
pdf-parser.py --search Flash ..\malware-analysis-cheat-sheet.pdf
```

 > Note : On peut obtenir les mêmes résultats avec [Peepdf](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool).

### Analyse via Peepdf
[Peepdf](https://eternal-todo.com/tools/peepdf-pdf-analysis-tool) est un outil assez complet. En effet, l'objectif de l'outil est de pouvoir de réaliser toute l'analyse sans faire recours à un autre outl. Il peut même être lancé de manière interactive à l'aide de la commande `peepdf -i`). En mode interactif, taper `help` pour voir toutes les sous-commandes.

Examinons le fichier en mode interactif via la commande ci-dessous :
```
peepdf.py -i ..\malware-analysis-cheat-sheet.pdf
```
Celle-ci nous renvoie ce résultat ci-dessous. Et on remarque bien les éléments suspicieux
```
Objects with JS code (1): [7]
        Suspicious elements:
                /OpenAction (1): [1]
                /JS (1): [7]
                /JavaScript (1): [7
```
- Afficher l'objet 7 : `PPDF> object 7`
```
<< /Type /Action
/S /JavaScript
/JS app.alert({cMsg: 'Hello from PDF JavaScript', cTitle: 'Testing PDF JavaScript', nIcon: 3});
 >>
```
- Afficher le code javascript de objet 7 : `PPDF> js_code 7`
```
app.alert({
    cMsg: 'Hello from PDF JavaScript',
    cTitle: 'Testing PDF JavaScript',
    nIcon: 3
});
```
> Note : Afficher le code plus joliment avec `js_beautify object 7`

### Analyse via PDF Stream Dumper
[PDF Stream Dumper](http://sandsprite.com/blogs/index.php?uid=7&pid=57) dispose d'une interface graphique. C'est un outil complet pour l'analyse d'un PDF. Il permet de d'analyser, de parser, d'extraire les objets, ...

Pour charger le fichier, Lancer le logiciel, puis aller dans `Load > PDF file` et parcourir le fichier
> Note : le glisser-déposer aussi fonctionne

- A gauche de la fenêtre, l'outil nous indique que le fichier est composé de 8 objets. Dans l'object 7 (Hlen : 0x8b), le code javascript apparaît. Un clic-droit sur l'objet fait afficher un menu contextuel.

- L'onglet `jascript_ui`, un 'éditeur' javascript, permet d'ouvrir le code javascript.
- L'onglet `Goto_Objects` permet d'afficher le contenu d'un objet (exemple : 7)
- L'onglet `Search_For` permet d'effectuer une recherche (String, JavaScript, Flash objects, ...).
> note : Le résultat s'affiche dans l'encadré en bas.

- L'onglet `Tools` présente différents outils pour décompresser, décoder, décompiler, ...un élément.

Grâce à cet outil, nous obtenons les mêmes résultats que les autres outils. Cependant, nous allons nous limiter à cette brève présentation de l'outil. Pour plus de détails, voir cet article Lenny Zeltser [Analyzing Suspicious PDF Files With PDF Stream Dumper](https://zeltser.com/pdf-stream-dumper-malicious-file-analysis/)

## Analyse manuelle du pdf
Bien que l'analyse d'un fichier PDF est plus simple avec les outils, nous pouvons aussi le faire manuellement.
En effet le format PDF est en quelque sorte un format à balise comme HTML, XML, ... En ce sens, on peut donc l'ouvrir via un éditeur de text.
En ouvrant le fichier, nous obtenons ceci :
```
%PDF-1.1

1 0 obj
<<
 /Type /Catalog
 /Outlines 2 0 R
 /Pages 3 0 R
 /OpenAction 7 0 R
>>
endobj

2 0 obj
<<
 /Type /Outlines
 /Count 0
>>
endobj

...


7 0 obj
<<
 /Type /Action
 /S /JavaScript
 /JS (app.alert({cMsg: 'Hello from PDF JavaScript', cTitle: 'Testing PDF JavaScript', nIcon: 3});)
>>
endobj

xref
0 8
0000000000 65535 f
0000000012 00000 n
0000000109 00000 n
0000000165 00000 n
0000000234 00000 n
0000000439 00000 n
0000000553 00000 n
0000000677 00000 n
trailer
<<
 /Size 8
 /Root 1 0 R
>>
startxref
837
%%EOF
```
Dans les premères lignes, on remarque bien dans l'objet 1 qu'une action se passera dans l'objet 7 : `/OpenAction 7 0 R`
Et vérifiant cet objet, on voit bien qu'il s'agit d'un code javascript :
```
/JS (app.alert({cMsg: 'Hello from PDF JavaScript', cTitle: 'Testing PDF JavaScript', nIcon: 3});)
```

## Conclusion
L'analyse d'un fichier pdf peut se faire soit manuellement soit à l'aide des outils spécialisés (pdfid/pdf-parser, peepdf, pdf stream dumper, ...).
Dans cette note, on a souhaité explorer les différents outils, mais il est vrai qu'on pouvait bel et bien réaliser notre analyse à l'aide d'un seul outil (peepdf ou pdf stream dumper, pdfid/pdf-parser). Car même l'analyse manuelle révèle bien le code javascript qui est embarqué dans le fichier. Il s'agit d'une analyse simple, mais l'analyse de certains fichiers peut être beaucoup plus complexe car peut nécessite d'autres actions supplémentaires (déobfuscation, décodage, décompression, ...)


## Liens
- *Documentations* : <br>
    - [Blog Didier Stevens/Physical and Logical Structure of PDF Files](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)
    - [Lenny Zeltser/Analyzing Malicious Documents Cheat Sheet](https://zeltser.com/analyzing-malicious-documents/)
    - [zbetcheckin/PDF_analysis](https://github.com/zbetcheckin/PDF_analysis)
    - [HackTrick/PDF File analysis](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/specific-software-file-type-tricks/pdf-file-analysis)
    - [hackercoolmagazine/PDF forensics with Kali Linux : pdfid and pdfparser](https://www.hackercoolmagazine.com/pdf-forensics-kali-linux-pdfid-pdfparser/)
    - [Lenny Zeltser/Analyzing Suspicious PDF Files With PDF Stream Dumper](https://zeltser.com/pdf-stream-dumper-malicious-file-analysis/)
    - [Lenny Zeltser/How to Extract Flash Objects from Malicious PDF Files](https://www.sans.org/blog/how-to-extract-flash-objects-from-malicious-pdf-files/)
    - [fareedfauzi/Create malicious PDF - Metasploit](https://fareedfauzi.github.io/blog-post/Create-malicious-pdf/#)
    - [Blog VadeSecure/analyse d'un email malveillant](https://www.vadesecure.com/fr/blog/analyse-dun-email-malveillant)

- *Tools* :<br>
    - [Didier Stevens PDF Tools](https://blog.didierstevens.com/programs/pdf-tools/)
    - [PDF Stream Dumper](http://sandsprite.com/blogs/index.php?uid=7&pid=57)
    - [Peepdf](https://github.com/jesparza/peepdf)
    - [REMnux PDF tools](https://docs.remnux.org/discover-the-tools/analyze+documents/pdf)
    - [zbetcheckin/PDF_analysis Tools list](https://github.com/zbetcheckin/PDF_analysis)
