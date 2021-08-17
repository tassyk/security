---
Title: Memory Forensic Volatility
Type: Doc
Nature: Notes
Création: 11/08/2021
---

#  Memory Forensic Volatility
---
**Sommaire**

- **[Introduction](#Introduction)**
- **[Préparation de l'environnement ](#Préparation-de-l'environnement)**
  - [Installation de volatility](#Installation-de-volatility)
  - [Acquisition d'un dump mémoire](#Acquisition-d'un-dump-mémoire )
- **[Analyse forensique mémoire](#Analyse-forensique-mémoire)**
  - [Obtention du profil de l'image](#Obtention-du-profil-de-l'image)
  - [Analyse des processus](#Analyse-des-processus)
  - [Analyse des connexions](#Analyse-des-connexions)
  - [Analyse des commandes lancées](#Analyse-des-commandes-lancées)
  - [Analyse des registres](#Analyse-des-registres)
  - [Analyse des DLLs](#Analyse-des-DLLs)
  - [Analyse du timeline des événements](#Analyse-du-timeline-des-événements)
  - [Dumper les éléments](#Dumper-les-éléments)
- **[Lever les suspicions](#Lever-les-suspicions)**
- **[Conclusion](#Conclusion)**
- **[Liens](#Liens)**
---

## Introduction
Dans cette note, nous allons voir comment réaliser une analyse forensique de mémoire (RAM) à l'aide du framework Volatility. C'est une suite de commandes permettant d'inspecter une RAM. Mais il existe aussi maintenant en version GUI, [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html). C'est un framework qui fonctionne sous différentes plateformes (Linux, Windows, Mac) et peut analyser les dumps mémoires de ces dernières.
> NB : Vous pouvez récupérer un échantillon de dump de mémoire sur le Github de Volatility, section [Memory-Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) ou sur le de Volatility Workbench ci-dessus, dans la section **Sample Memory Dumps**. 

Pour notre cas, nous allons installer volatility2 sur une machine Windows et analyser un dump mémoire de Windows XP correspondant au [Malware - Cridex] (https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples).

## Préparation de l'environnement 
### Installation de volatility
- Télécharger une version de volatility2 depuis [le site de l'éditeur](https://www.volatilityfoundation.org/releases)
- Décompresser l'archive dans un répertoire (ici forensics)
> Note : Ne pas exécuter le .exe, mais il sera utilisé en ligne de commande.

### Acquisition d'un dump mémoire 
Pour l'analyse mémoire, il faut d'abord disposer d'un dump mémoire. Pour notre cas, nous avons récupéré le dump mémoire [Malware - Cridex] (https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples).
> Note :
> On peut créer son propre dump mémoire aussi. **Attention attention à bien isoler la machine!** Pour cela : 
> - Il suffit de créer une [VM windows]. On peut récupérer VM windows le [Centre de developpement Windows](https://developer.microsoft.com/fr-fr/windows/downloads/virtual-machines/) ou depuis la page  [Microsoft Edge Developer](https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/) 
> - Ensuite, infecter la VM par un malware (par exemple). Il existe des [plateformes](https://cyberlab.pacific.edu/resources/malware-samples-for-students) qui fournissent des échantillons
> - Enfin, créer un dump mémoire à l'aide des outils comme [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) ou [FTK Imager](https://www.exterro.com/ftk-imager). Avec VirtualBox ou Vmware, on peut aussi créer un dump mémoire à partir de la VM (cf articles [Dump Virtual Box Memory](https://www.ired.team/miscellaneous-reversing-forensics/dump-virtual-box-memory) et [Converting a snapshot file to memory dump using the vmss2core tool](https://kb.vmware.com/s/article/2003941)).

Voici les formats de dump acceptés :
- Raw format
- Hibernation File
- VM snapshot
- Microsoft crash dump

## Analyse forensique mémoire
Volatility s'utilise en [ligne de commande](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference). Voici la syntaxe :
```
volatility.exe [plugin] -f [/path/to/image] --profile=[profile]
```
> NB : Si l'installation est faite partir du dépôt Github, on peut lancer avec : 
```
python vol.py [plugin] -f [image] --profile=[profile] 
```
> Note : Pour obtenir de l'aide : `volatility.exe -h`.

> Note : On peut aussi stoquer le résultat des commandes dans un fichier à l'aide de l'option `--output-file=OUTPUT_FILE`. Syntaxe :
```
volatility.exe [plugin] -f [/path/to/image] --profile=[profile] --output-file=OUTPUT_FILE
```

### Obtention du profil de l'image
Le profil d'une VM est très important. Il permet de connaître le type de l'OS du dump mémoire. Donc c'est la première chose à chercher sur le dump mémoire. Il est obtenu grâce au plugin `imageinfo` ou `kdbgscan`:
```
volatility.exe -f cridex.vmem imageinfo
```
> La commande retourne ces profils : `Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)`. Nous prendrons le premier de la list (`WinXPSP2x86`). 

Le plugin `kdbgscan` peut aussi permet aussi d'obtenir le profil (à partir du Kernel). Il est plus précis généralement. 
```
volatility.exe -f cridex.vmem kdbgscan
```
> Note : Cependant, il faut prendre le profil avec l'offset valide, c'est-à-dire dont la valuer *processes* et *modules* n'est pas 0 (zero).
```
Instantiating KDBG using: Kernel AS WinXPSP2x86 (5.1.0 32bit)
Offset (V)                    : 0x80545ae0
Offset (P)                    : 0x545ae0
...
PsActiveProcessHead           : 0x8055a158 (17 processes)
PsLoadedModuleList            : 0x80553fc0 (109 modules)
```
> Remarque : parfois pour certaines images, il arrive que `pslist` n'affice pas les processus pour le profil. Pour résoudre ce genre de problème, on peut préciser le bon offset (0x80545ae0, ici) pour le profil à l'aide de l'option `--kdbg`. Exemple :
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 --kdbg=0x80545ae0 pslist
```

### Analyse des processus
On peut interagir avec les processus à l'aide des plugins comme `pslist, psscan, pstree, psxview`.
- Afficher la liste des processus `pslist`:
```
volatility.exe -f cridex.vmem --profile=Win10x64 pslist -P
```
> Parmi la liste des processus trouvés, on identifie quelques uns qui semblent suspects :
```
...
0x0207bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000
0x022e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000
```
> Note : D'autres processus sont "safe" comme :
> - spoolsv.exe : service d'impression de windows
> - wuauclt.exe : service lié à WSUS

- Afficher l'arborescence des processus à l'aide de `pstree`:
```
volatility.exe -f cridex.vmem --profile=Win10x64 pstree
```

> Note : on remarque que `reader_sl.exe` est un processus fils d'explorer.exe. 
```
...
 0x821dea70:explorer.exe                             1484   1464     17    415 2012-07-22 02:42:36 UTC+0000
. 0x81e7bda0:reader_sl.exe                           1640   1484      5     39 2012-07-22 02:42:36 UTC+0000
```

- Afficher les processus cachés à l'aide de `psxview` et `psscan` :
```
volatility.exe -f cridex.vmem --profile=Win10x64 psxview [--output-file=psxview.txt]
```
> Note : `False` dans une colonne signifie que le processus en question ne peut être affiché par le plugin. D'après le résultat, ces processus ne sont pas cachés (à ``pslist``, ni ``psscan``)
```
Offset(P)  Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
---------- -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
...
0x022e8da0 alg.exe                 788 True   True   True     True   True  True    True
0x0207bda0 reader_sl.exe          1640 True   True   True     True   True  True    True
```

### Analyse des connexions
Pour voir les connexions (réseaux, sockets), on peut utiliser des plugins comme `netscan, connscan, sockets, sockscan, connexions ...`.
- Analyser les connexions TCP (actives ou inactives) : `connscan`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 connscan [--output-file=connscan.txt]
```
> Note : Le résultat indique des connexions sortantes vers deux IP distantes (41.168.5.140 et 125.19.103.198). Le PID 1484 correspond au processus `explorer.exe`
```
Offset(P)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x02087620 172.16.112.128:1038       41.168.5.140:8080         1484
0x023a8008 172.16.112.128:1037       125.19.103.198:8080       1484
```
- Afficher les sockets ouverts pour tous protocols (TCP, UDP, RAW, etc) : `sockets`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 sockets
```
> Note : Le résultat montre des sockets ouverts sur l'IP 172.16.112.128.

> Remarque : `netscan` fournit plus d'informations sur les connexions (TCP et Sockets). Mais il ne peut-être utilisé sur windows XP. `connections` affiche les flux TCP actifs au moment de la prise du dump mémoire. Ici, i s'agit de :
```
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x81e87620 172.16.112.128:1038       41.168.5.140:8080         1484
```

### Analyse des commandes lancées 
On peut visualiser les commandes lancées à l'aide des plugins comme `cmdscan, consoles, cmdline, ...`.
- Afficher les lignes de commandes : `cmdline`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 cmdline
```
> On remarque que le processus suspect a été lancé depuis Adope reader. Il semblerait donc que ce soi un exécutable contenu dans un fichier PDF.
```
...
reader_sl.exe pid:   1640
Command line : "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe"
***********************************************************************
```
> Note : le plugin `cmdscan` affiche l'historique des commandes lancées par l'attaquant depuis le shell (cmd.exe). Il s'appuie sur l'objet *COMMAND_HISTORY*.   `consoles` a les mêmes actions que `cmdscan` mais à quelques différences près. Il cherche les informations depuis l'objet *_CONSOLE_INFORMATION* et peut afficher les commandes lancées via un **backdoor**. Il peut afficher inputs et outputs, c'est-à-dire les commandes saisies ainsi que leurs résultats de sortie! 
>
> Mais ces plugins ne renvoient aucun résultat pour notre cas. L'attaquant a t-il effacer les traces ?
> A partir de là, `Reader_sl.exe` semble de plus en plus suspect. Mettons de côté les informations (pid, IP, port) d'ici là trouvées. Nous nous en servirons plus tard.

### Analyse des registres
- Lister les registres : `hivelist`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 hivelist
```
> On voit des registres légitimes mais remarque aussi deux autres sans nom (adresses : 0xe13ba008 et 0xe102e008) qui semblent suspects.
```
Virtual    Physical   Name
---------- ---------- ----
...
0xe13ba008 0x02e4b008 [no name]
0xe102e008 0x02a7d008 [no name]
```
- Lister les sous-clés d'un registre : `printkey` ou `hivedump`
> Note : On eput afficher la valeur d'une clé de registre à l'aide du plugin `printkey` et l'option `-K "registry_key"` ou `-o "virtual_address"` :
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 printkey -o 0xe102e008
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 printkey -o 0xe13ba008
```
> D'après leurs sous-clés, on remarque ainsi que les registres sans nom sont en fait légitimes
```
Subkeys:
  (S) MACHINE
  (S) USER
```
`hivedump`, affiche les sous-clés de manière récursives.
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 hivedump -o 0xe102e008
...
2012-07-22 02:42:24 UTC+0000 \REGISTRY
2012-07-22 02:42:32 UTC+0000 \REGISTRY\MACHINE
2012-07-22 02:42:35 UTC+0000 \REGISTRY\USER
2012-07-22 02:42:32 UTC+0000 \REGISTRY\USER\S-1-5-18
```

### Analyse des DLLs
Un processus peut charger des librairies (DLLs) sur le système.
- Afficher les DLLs : `dlllist` (l'option `p` spécifie le/les pid)
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 dlllist  -p 1640 # process parent
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 dlllist  -p 1484
```
> Note : On remarque que notre processus suspect a interagi avec certains DLLsS
```
Base             Size  LoadCount Path
---------- ---------- ---------- ----
0x01000000    0xff000     0xffff C:\WINDOWS\Explorer.EXE
0x7c900000    0xaf000     0xffff C:\WINDOWS\system32\ntdll.dll
...
0x01100000   0x2c5000        0x3 C:\WINDOWS\system32\xpsp2res.dll
0x71d40000    0x1b000        0x1 C:\WINDOWS\system32\actxprxy.dll
...
```

### Analyse du timeline des événements 
Le plugin `timeliner` peut afficher le timeline des différents artéfacts.
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 timeliner [--output-file=timeliner.txt]
```
> Note : On peut voir ainsi certains événements liés à notre processus suspect
```
2012-07-22 02:42:36 UTC+0000|[PROCESS]| reader_sl.exe| PID: 1640/PPID: 1484/POffset: 0x0207bda0
2012-07-22 02:42:36 UTC+0000|[PROCESS LastTrimTime]| reader_sl.exe| PID: 1640/PPID: 1484/POffset: 0x0207bda0
2012-07-22 02:42:32 UTC+0000|[Handle (Key)]| MACHINE| reader_sl.exe PID: 1640/PPID: 1484/POffset: 0x0207bda0
...
2012-07-22 02:42:37 UTC+0000|[Handle (Key)]| USER\S-1-5-21-789336058-261478967-1417001333-1003| reader_sl.exe PID: 1640/PPID: 1484/
2008-06-12 09:37:53 UTC+0000|[PE HEADER (dll)]| Reader_sl.exe| Process: reader_sl.exe/PID: 1640/PPID: 1484/Process POffset: 0x0207bda0/DLL Base: 0x00400000
```

### Dumper les éléments 
A ce stade de l'analyse, on a identifié un process suspect **reader_sl.exe (PID: 1484)** lancé par **explorer.exe (PID: 1640)**.
On peut "dumper" ces processus ainsi que les DLLs qu'ils ont chargés dans la mémoire. On peut soumettre ces dumps à analyse plus poussées.
- Dumper le processus : `procdump`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 procdump -p 1640 -D /dump/dir
```
> Note : on obtient le fichier executable.1640.exe dans /dump/dir. 
> Ce dernier peut être un point (.) pour le répertoire courant. On peut remplacer `-D /dump/dir` par `--dump-dir=/dump/dir`.
> Attention:
> - Déconnecter la carte réseau avant ces manipulations (sous virtualbox : périphériques > réseau > décocher la carte) 
> - Aussi renommer le fihcier pour ne pas l'exécuter par inadvertance : `mv executable.1640.exe executable.1640.exe.dump`

- Dumper la mémoire du processus : `memdump`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 memdump -p 1640 -D /dump/dir
```
> Note : on obtient le fichier **1640.dmp** dans /dump/dir

- Dumper les DLLs : `dlldump`
```
volatility.exe -f cridex.vmem --profile=WinXPSP2x86 dlldump -p 1640 -D /dump/dir/DLLs
```
> Note : On obtient les DLLs dans le répertoire /dump/dir/DLLs

Il existe d'autres commandes intéressantes comme `hashdump, lsadump` pour dump les crédentials ou encore `handles` pour liste les handles ouverts, ... Mais nous allons arrêter la recherche et analyser les résultats obtenus.

## Lever les suspicions
Grâce à nos analyses, nous avons pu identifier le processus suspect **reader_sl.exe (PID: 1484)** lancé par **explorer.exe (PID: 1640)**, et récupérer certains artefacts (IoC) liés à ce dernier : les IP et ports (41.168.5.140:8080 , 125.19.103.198:8080), les dumps de processus et mémoire, le timeline. Maintenant, on peut analyser ces données via des plateforme en ligne comme [VirusTotal](https://www.virustotal.com/), [Hybrid analysis](https://www.hybrid-analysis.com/), ou encore pour obtenir plus d'informations.
> L'analyse de l'IP **41.168.5.140** montre qu'elle a été signalée par 5/86 antivirus comme malveillante.
> Tandis que **125.19.103.198** a été signalée par 3/87 antivirus.
> En renvance, l'analyse du dump du processus **executable.1640.exe.dump** montre incontestablement qu'il s'agit d'un malware. Il a été détecté par 28/68 antivirus.
> L'analyse du dump de la mémoire (**1640.dmp**) via l'outil `strings` de la suite sysinternals révèle aussi d'autres artefacts comme des domaines et urls.

## Conclusion
A trvaers cette note, nous avons essayé de réaliser une analyse forensique d'une mémoire d'un Windows XP infecté par le malware Cridex. 
La recherche de preuve (artéfacts) a été 'longue' car notre objectif était d'explorer aussi les commandes de Volatility. On pouvait bel et bien raccourcir l'analyse au moment où nous avons trouvé le processus suspicieux, les connexions réseaux et soumettre ces éléments sur des plateformes comme virusTotal pour lever le doute.

## Liens
- Documentation 
    - [Volatility Foundation Wiki](https://github.com/volatilityfoundation/volatility/wiki)
    - [Volatility Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference)
- Tools
    - [Volatility](https://www.volatilityfoundation.org/releases)
    - [Volatility Workbench](https://www.osforensics.com/tools/volatility-workbench.html)
    - [FTK Imager](https://www.exterro.com/ftk-imager)
    - [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer)
- Tutorials :
    - [Memory Forensics: Using Volatility Framework](https://www.hackingarticles.in/memory-forensics-using-volatility-framework/)
    - [Memory Forensics using Volatility Workbench](https://www.hackingarticles.in/memory-forensics-using-volatility-workbench/)
    - [Volatility 2/3 - CheatSheet | Hacktrick](https://book.hacktricks.xyz/forensics/basic-forensic-methodology/memory-dump-analysis/volatility-examples)
    - [Investigating Malware Using Memory Forensics - A Practical Approach (video)](https://www.youtube.com/watch?v=BMFCdAGxVN4)
    - [Cridex malware analysis](https://medium.com/@zemelusa/first-steps-to-volatile-memory-analysis-dcbd4d2d56a1)
    - [Dump Virtual Box Memory](https://www.ired.team/miscellaneous-reversing-forensics/dump-virtual-box-memory)
    - [Converting a snapshot file to memory dump using the vmss2core tool](https://kb.vmware.com/s/article/2003941)
- Malware samples 
    - [Malware samples for students](https://cyberlab.pacific.edu/resources/malware-samples-for-students)
    - [Malware samples sources](https://zeltser.com/malware-sample-sources/)