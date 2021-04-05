---
Title: Collecte artéfacts via DFIR-ORC
Type: Doc
Nature: Notes
Création: 03/04/2021
---

# Collecte artéfacts via DFIR-ORC
## Introduction
[DFIR ORC](https://dfir-orc.github.io/) est un outil de recherche de compromission (ORC). Il est utilisé dans le cadre de digital forensic et réponse à incident (DFIR).
Il est open source, dévéloppé et mis à disposition par l'ANSSI. C'est une collection d'outils (commandes) intégrés (FastInfo, GetThis, NTFSInfo, RegInfo, ...) dédiés à la collecte des éléments de compromission (artéfacts) sur une machine windows. Il peut s'agir des métadonnées NTFS(MFT, USN) ou FAT, des fichiers (même cachés) ou encore des éléments de la base de registre. L'outil est modulaire et peut intégrer d'autres outils externes.
Il peut-être utilisé selon deux grands modes :
1. En ligne de commande (ou mode non configuré)
2. En mode configuré

> Note : L'outil est très bien documenté, et il existe même un tutoriel pour faicilter la compréhension.

## Installation de DFIR ORC
Les binaires de DFIR ORC (32 et 64 bits) peuvent être récupérés à partir des [releases fournis par l'ANSSI](https://github.com/DFIR-ORC/dfir-orc/releases) ou compilés avec Visual Studio en suivant les instructions [README](https://github.com/dfir-orc/dfir-orc) ou
> Both 32-bit and 64-bit versions should be built for maximum compatiliby before deployment

## Commandes intégrées à DFIR ORC
DFIR ORC fournit une [suite d'une dizaine de commandes](https://dfir-orc.github.io/embedded_tool_suite.html) intégrées :
- FastInfo : collecte les métadonnées d'un système de fichiers FAT;
- FastFind : recherche les indicateurs de compromission (IoC) systèmes
- GetThis : collecte les fichiers sur systèmes de fichiers NTFS en s'appuyant sur une recherche avancée (regex, hash, ADS, [Yara](https://support.virustotal.com/hc/en-us/articles/115002178945-YARA), ...);
- GetSamples : automatise la collecte d'artéfacts;
- GetSectors : collecte les secteurs (MBR, VBR) du disque et des partitions;
- NTFSInfo : collecte les métadonnées NTFS (fichiers, timestamps, hashes, empreinte, etc.);
- NTFSUtil : outil (bas niveau) permettant l'inspection de la MFT;
- ObjInfo : collecte les objets nommés de Windows (canaux, mutex, etc.);
- RegInfo : collecte les éléments de la base de registre;
- USNInfo : collecte le journal USN (qui permet de suivre les changements qui sont apportés sur votre disque dur)


## DFIR ORC en ligne de commande
Dans ce premier mode, chaque commande de DFIR-ORC peut être utilisée de manière unitaire. C'est-à-dire, les arguments (options) peuvent être passés directement en ligne de commande, ou spécifiés à l'aide d'un fichier de configuration (au format XML).
DFIR-ORC s'exécute selon la syntaxe suivante :
```
C:\> DFIR-Orc_x64.exe <commande> <paramètres>
```
> Note : En utilisant la version 64bit

Exemples :
```
# avec arguments
DFIR-Orc.exe GetThis /sample=git.exe /out=git.7z "C:\Program Files\git\bin" /nolimits
# avec un fichier de configuration
DFIR-Orc.exe GetThis /config=GetThisConfig.xml
```
> Note :
> Pour obtenir de l'aide sur une commande : `DFIR-ORC_x64.exe <commande> /?`
> Lancer la commande en mode Admin

Chaque commande assure plusieurs fonctions et mériterait un chapitre entier. Mais, nous allons en choisir quelques unes dans cette note.
> Note : en ligne de commande, ``FastFind`` est utilisé uniquement avec un fichier de configuration.


### Usage de GetThis
[GetThis](https://dfir-orc.github.io/GetThis.html) collecte les fichiers sur systèmes de fichiers NTFS. L'utilisation de cette commande peut ressembler à ceci :
- A l'aide des arguments
```
DFIR-Orc_x64.exe GetThis /sample=iexplore.exe /out=iexplore.exe.7z "C:\Program Files\internet explorer" /nolimits
```
> Note :
> `sample` : spécifie l'objet (outil, fichier) de la collecte (ici iexplore.exe)
> `out` (optionnel) : spécfie le résultat en sortie (archive)
> `"C:\Program Files\internet explorer"` : spécifie le path (location) de l'objet (iexplore.exe)
> `nolimits` (optionnel) : pas de limitation (taille, nombre d'éléments) sur la collecte

> Remarque :
> - on peut spécifier  plusieurs path (location) séparés par ",". Exemple : `DFIR-Orc_x64.exe GetThis /sample=iexplore.exe <Location1>, <Location2>`
> - l'archive i contient deux fichier : GetThis.csv contenant le résultat de la commande et GetThis.log contenant les journaux. Si l'output n'est précisé, le résultat est dans l'archive <commande.7z> (Gethis.7z, ici)

- A l'aide d'un fichier de configuration
```
# in Config\getThis-ieexplorer.xml
<getthis>
    <location>%SystemDrive%\</location>
    <yara block="20M" overlap="2M" timeout="20" source="GetThisSample.yara" />
    <samples MaxPerSampleBytes="50MB" MaxSampleCount="15000" MaxTotalBytes="1024MB" >
        <sample name="iexplore" MaxPerSampleBytes="50MB" MaxSampleCount="150" MaxTotalBytes="150MB">
            <ntfs_find path="C:\Program Files\internet explorer\iexplore.exe" />
        </sample>
        <sample name="WSTCODEC" MaxPerSampleBytes="50MB" MaxSampleCount="150" MaxTotalBytes="150MB">
            <ntfs_find path="\Windows\System32\DRIVERS\WSTCODEC.SYS" />
        </sample>
        <sample name="notdll" MaxPerSampleBytes="80MB">
            <ntfs_find name_match="\*.dll"  yara_rule="is_not_dll" />
        </sample>
    </samples>
</getthis>
#
# execution
DFIR-Orc_x64.exe GetThis /config=Config\getThis-ieexplorer.xml
```
> note :
> Toute la configuration est entre les balises `<getthis>...</getthis>`
> Dans schaque ection `<sample> ...</sample>`, on spécifie l'objet de la collecte (iexplore, WSTCODEC, notdll) en déterminant son nom, les limites (MaxPerSample*), le path dans `<ntfs_find ...>`
> `notdll` est ici collecté via Yara.

> Remarque : dans cette configuration, on n'a pas spécifié d'output (sortie). Donc, les résultats seront dans `GetThis.7z`

Pour plus de détails sur cette commande ou les autres ainsi que leurs attributs et les informations collectées, voir la documentation.

### Usage de NTFSInfo
[NTFSInfo](https://dfir-orc.github.io/NTFSInfo.html) est destiné à collecter des données sur des systèmes de fichiers NTFS. Il énummère les fichiers en utilisant soit le parsing MTF (par défaut) ou USN. Il peut collecter 5 différents types d'informations (FileInfo, AttrInfo, I30Info, TimeLine et SecDescr). Chacun de ces types contient des informations précises.
> Note : Le parsing USN est déprécié.

La commande  peut être utilisé comme suit :
- A l'aide des arguments
```
DFIR-Orc_x64.exe NTFSInfo "%SystemDrive%\Program Files" /fileinfo=%TEMP%\test.csv /logfile=%TEMP%\NTFSInfo.log /Dates,File,ParentName,USN,FRN,LastAttrChangeDate,ADS,SizeInBytes
```
> Note :
> - Dans cette commande, on fait appel au type d'information `fileinfo` pour collecter les métadonnées des fichiers du répertoire `"%SystemDrive%\Program Files"`. Le résultat est enregistré dans `test.csv`
> - Avec ``logfile``, on spécifie le fichier qui va contenir les traces (journaux) de la commande
> - Ensuite, avec` Dates,File,ParentName,USN,FRN,LastAttrChangeDate,ADS,SizeInBytes`, on spécifie les attributs (éléments) du fichier (types de métadonnées) à collecter.

> Remarque :
> - L'utilisation basique de la commande est : `DFIR-Orc_x64.exe NTFSInfo <Location1> <Location2>`
> - If no output option is specified, only the FileInfo information is collected in a file called NTFSInfo.csv

- On peut collecter les mêmes informations via un fichier de configuration
```
# in Config\NTFSInfoConfig.xml
<ntfsinfo walker="MFT">
    <fileinfo>%TEMP%\test.csv</fileinfo>
    <logging file="%TEMP%\NTFSInfo.log" />
    <location>%SystemDrive%\Program files</location>
    <columns>
        <default>Dates</default>
        <default>File</default>
        <default>ParentName</default>
        <default>USN,FRN</default>
        <default>LastAttrChangeDate</default>
        <default>ADS</default>
        <default>SizeInBytes</default>
    </columns>
</ntfsinfo>
#
# Exécution
DFIR-Orc_x64.exe NTFSInfo /config=%TEMP%\NTFSInfoConfig.xml
```
> Note :
> - Toute la configuration est contenue dans les balises `<ntfsinfo ...> ...</ntfsinfo>`. `ntfsinfo` peut prendre des options. Ici l'option `wlaker` permet de spécifier le type de parsing (MFT, ici).
> - Dans les sections `<columns> ...</columns>`, on indique les attributs à collecter.

### Usage de FastFind
L'objectif de [FastFind](https://dfir-orc.github.io/FastFind.html) est de faciliter la collecte et la recherche des indicateurs de compromission (IoC) systèmes. Il peut collecter les montages de systèmes de fichiers, les registres, les objets windows, ...
> Note : Il est préférable d'utiliser cette commande à l'aide de XML.

- Exemple de commande d'usage
```
DFIR-Orc_x64.exe FastFind /config=Config\FastFindConfig.xml [/out=Results\fastfind_output.xml]
```
- Le XML de FastFind peut ressembler à ceci :
```
# dans Config\FastFindConfig.xml
<fastfind version="Test 2.0">
    <filesystem>
        <location shadows="yes">%SystemDrive%</location>
        <yara source="yara.rules" block="2M" timeout="120" overlap="8192" scan_method="filemapping" />
        <ntfs_find size="694160" md5="1CECAFE147F1CC3E2B9804B8CDA593C9"/>
        <ntfs_find name="ntdll.dll" yara_rule="is_dll"/>
        <ntfs_find name_match="gdi*.dll"/>
        <ntfs_exclude sha1="c766364efd9c9b5aa3a7140a69f0cf5b147bc476"/>
    </filesystem>
    <registry>
        <location>%SystemDrive%\</location>
        <hive name="SOFTWARE">
            <ntfs_find name="SOFTWARE"/>
            <registry_find key_path="\Microsoft\Windows\CurrentVersion\Run" value="SecurityHealth"/>
        </hive>
    </registry>
    <object>
        <object_find type="Mutant" name="foobar"/>
    </object>
</fastfind>
```
> Note :
> - Le fichier XML est séparé en 3 sections :  filesystem, registry et object
> - A l'intérieur de `<filesystem>...</filesystem>`, on indique les indicateurs filesystem à inclure (`ntfs_find`) ou exclure (`ntfs_exclude`) dans la recherche.
> - Avec les blocs `registry`, on détermine les indicateurs liés au registre
> - Avec les blocs `object`, on spécifie chaque objet à rechercher.

> Les outputs de FastFind sont stockés dans un fichier XML. Mais ils peuvent être stockés dans 2 fichiers CSV (pour filesystem et object)
> Pour plus de détails, voir la documentation


### Usage de GetSamples
[GetSamples](https://dfir-orc.github.io/GetSamples.html) est conçu dans le but d'automatiser la collecte d'artéfacts. Il peut énumérer les binaires, à l'aide de ``autorunsc.exe`` de la suite SysInternals, les binaires et les drivers chargés, générer une configuration de `GetThis` et exécuter la commande.
> Note : On peut lui indiquer aussi un fichier XML GetThis à prendre à l'aide du paramètre ``GetThisConfig``.

- Example d'usage en ligne de commande :
```
DFIR-Orc_x64.exe GetSamples /MaxPerSampleBytes=16MB /MaxTotalBytes=512MB /MaxSampleCount=200000 /out=Results\GetSamples.7z
```
> Note :
> `out` spécifie l'output. Il est obligatoire.
> `MaxPerSampleBytes, MaxSampleCount, MaxTotalBytes ` (optionnels) déterminent la limite de la collecte.

- Exemple d'usage via XML
```
# dans Config\GetSamples.xml
<GetSamples>
    <Output>Results\GetSamples.7z</Output>
    <Samples MaxPerSampleBytes="16MB" MaxTotalBytes="512MB" MaxSampleCount="200000" />
</GetSamples>
#
# en exécution
DFIR-Orc_x64.exe GetSamples /config=Config\GetSamples.xml
```
> Note : GetSamples peut prendre d'autres paramètres (en ligne de commande ou XML) comme `sampleinfo, timeline,Autoruns, GetThisConfig` (voir la documentation)


Bien qu'on peut utiliser DFIR ORC en ligne de commande pour collecter des artefacts, ou encore automatiser un peut ce processus à l'aide `GetSamples`, l'objectif principal de l'outil est de configuré/préparé un binaire de collecte afin de rendre beaucoup plus simple cette tâche (d'où le mode configuré).

## DFIR ORC en mode configuré
En mode configuré, DFIR-ORC nous permet de générer notre propre binaire de collecte personnalié et personnalisable. Dans ce cas, les commandes sont définies et exécutées à l'aide d'un orchestrateur (WolfLauncher). Le binaire est ensuite généré à l'aide de la commande [ToolEmbed](https://dfir-orc.github.io/ToolEmbed.html) qui exécute toutes les commandes définies dans [WolfLauncher](https://dfir-orc.github.io/wolf_config.html).
> Note : ANSSI décrit bien la généraion du binaire configuré dans son [tutoriel](https://dfir-orc.github.io/tuto.html)

### Les éléments du binaire
Dans le mode configuré, deux éléments contribuent à la génération du binaire : WolfLauncher et ToolEmbed.

[WolfLauncher](https://dfir-orc.github.io/wolf_config.html) est l'orchestrateur de commandes de DFIR-ORC. Il permet de définir et de configurer toutes les commandes de DFIR ORC ou externes qui seront exécutées par le binaire, ainsi que leur ordre d'exécution, leurs limitations, le chiffrement des archives, etc. Ceci ce fait à l'aide du fichier ``WolfLauncher.xml``. Le squelette de ce fichier est :
```
<wolf attributes=”…” >
  <log attributes=”…” > value </log>
  <outline attributes=”…” > > value </outline>
  <recipient attributes=”…”> value </recipient>
  <archive attributes=”…”>
    <restrictions attributes=”…” />
    <command attributes=”…” >
    <execute attributes=”…” />
    <input attributes=”…” />
    <output attributes=”…” />
    <argument attributes=”…” />
    </command>
  </archive>
</wolf>
```

[ToolEmbed](https://dfir-orc.github.io/ToolEmbed.html) est l'outil en charge de la génération du binaire. Il prépare et définit les fichiers de configurations nécessaires à l'exécution des commandes définies dans `WolfLauncher.xml`. Cette préparation se fait à l'aide du fichier `ToolEmbed.xml`. Le squelette de ce fichier peut ressembler à ceci :
```
<toolembed attributes=”…” >
  <input > value </input>
  <output > value </output>
  <run attributes=”…”></run>
  <run32 attributes=”…”></run32>
  <run64 attributes=”…”></run64>
  <file attributes=”…” />
  <pair attributes=”…” />
  <archive attributes=”…” >
    <file attributes=”…” />
  </archive>
</toolembed>
```

Une fois ce fichier bien configuré, on génère le binaire à l'aide de la commande `ToolEmbed` :
```
DFIR-ORC_x64.exe ToolEmbed /config=ToolEmbed.xml
```
> Note : On peut définir un autre nom pour ToolEmbed.xml ou WolfLauncher.xml.

### Exemple d'usage du mode binaire
Pour exemple, nous allons préparer un binaire de collecte en utilisant la [configuration fournie par l'ANSSI](https://github.com/DFIR-ORC/dfir-orc-config). On y opérera quelques petites modifications :
- les fichier `DFIR-ORC_config.xml` et `DFIR-ORC_embed.xml` seront remplacés respectivement par `WolfLauncher.xml` et `ToolEmbed.xml` pour plus de compréhension;

#### Préparation de l'environnement
L'ANSSI a propose ce modèle de projet pour DFIR ORC constitué de 3 répertoires :
```
├───config : stocke les différents fichiers de configuration
├───output : stocke les différents résultats
└───tools : regroupe les différents outils qui seront utilisés
```

1. Cloner le projet dfir-orc-config de l'ANSSI.
```
git clone "https://github.com/dfir-orc/dfir-orc-config.git"
cd dfir-orc-config
```
> Note : Il faut installer [Git](https://git-scm.com/downloads) au préalable.

2. Télécharger les binaires (non configurés) de DFIR ORC depuis [releases de l'ANSSI](https://github.com/DFIR-ORC/dfir-orc/releases) (si ce n'est pas déjà fait). Et copier les binaires dans le répertoire `tools` dans `dfir-orc-config`;
```
Copy-Item <Path dfir-orc>\DFIR-Orc_x86.exe .\tools
Copy-Item <Path dfir-orc>\DFIR-Orc_x64.exe .\tools
```
3. Télécharger le binaire `autorunsc.exe`
```
Invoke-WebRequest "https://live.sysinternals.com/autorunsc.exe" -OutFile .\tools\autorunsc.exe
```

Si tout se passe bien, le contenu du répertoire `dfir-orc-config` ressemblera à ceci :
```
C:.
│   Configure.cmd
|   ...
│
├───config
│       WolfLauncher.xml
│       ToolEmbed.xml
│       FatInfoHashPE_config.xml
│       FatInfo_config.xml
│       GetArtefacts_config.xml
│       GetEvents_config.xml
│       ...
│
├───output
└───tools
|       autorunsc.exe
|       DFIR-Orc_x64.exe
|       DFIR-Orc_x86.exe
```
> Note : les fichiers `WolfLauncher.xml` et `ToolEmbed.xml` remplacent respectivement `DFIR-ORC_config.xml` et `DFIR-ORC_embed.xml`.


#### Contenus des fichiers de configuration
Les fichiers de configuration de chaque outil, de l'orchestrateur (WolfLauncher) et du générateur du binaire (ToolEmbed) sont dans le répertoire `config`. Ils peuvent être modifiés et adaptés selon les besoins.
Je vous laisse le soin de les regarder.


#### Génération du binaire configuré
Le binaire configuré (TEST_ORC.exe) peut être généré à l'aide :
- du script `Configure.cmd`
```
.\Configure.cmd
```
> Note :
> Par défaut, le nom du bianire généré (configuré) est DFIR-ORC.exe (dans output)

- ou tout simplement via la commande ci-dessous :
```
.\DFIR-Orc_x64.exe ToolEmbed /Config=.\config\ToolEmbed.xml
```

#### Test du binaire
Avant de lancer le binaire ainsi configuré, on peut énumérer la liste des commandes qui seront exécutées avec le switch `/keys` :
```
cd output
.\DFIR_ORC.exe /keys
```
> Note :
> Les cases cochées indiquent la commande (ou l'archive) qui sera exécutée par défaut. Elles représentes les clés (key).
> On peut séléctionner ou déssélectionner certaines clés à l'aide de `/key+= ou /key-=`. Exemple : `.\DFIR-Orc.exe /key+=GetSamHive /key-=Yara  /keys`. Ainsi, lors d'une collecte, on peut choisir les commandes à exécuter!
> On peut aussi tout simplement sortir les résultats d'une commande (clé) : `.\DFIR-Orc.exe /key=SystemInfo [/out=\Temp\test]`

- Extraire les métadonnées NTFS du disque C :
```
.\DFIR-Orc.exe NTFSInfo /out=C_drive.csv "C:\"
```
- Extraire les informations sur les fichiers ntdll.dll contenus dans C :
```
.\DFIR-Orc.exe GetThis /nolimits /sample=ntdll.dll /out=ntdll.7z "C:\"
```
- Obtenir les informations systemes
```
.\DFIR-Orc.exe /key=SystemInfo /out=\Temp\testing
```

On voit qu'on peut utiliser le binaire en ligne de commande en spéciant des options (comme pour les commandes non configurées).
On peut aussi définir ces paramètres à l'aide d'un [fichier de configuration local](https://dfir-orc.github.io/orc_local_config.html). Pour cette dernière commande, par exemple, on peut utiliser ce fichier de configuration local correspondant :
```
# in \Temp\testing\DFIR-Orc.xml
<dfir-orc priority="low" powerstate="SystemRequired,AwayMode">
   <output>\Temp\testing</output>
   <key>SystemInfo</key>
</dfir-orc>
```
> Note : avec l'option `recipient`, on peut chiffrer les archives avec une clé publique (voir la documentation)

Puis l'exécuter comme suit :
```
.\DFIR-Orc.exe /local=\Temp\testing\DFIR-Orc.xml
```







## Ressources
- [DFIR ORC Documentation](https://dfir-orc.github.io/)
- [DFIR ORC Tutorial](https://dfir-orc.github.io/tuto.html)
- MISC HORS-SERIE N°23 / Investigation
- [DFIR ORC Config](https://github.com/DFIR-ORC/dfir-orc-config)
