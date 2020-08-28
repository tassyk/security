---
Title: Yara
Type: Doc
Nature: Notes
Création: 24/05/2020
---

# Détection des malwares via Yara

---
### Sommaire

- **[Introduction](#Introduction)**
- **[Installation de yara](#Installation-de-yara)**
- **[Règles yara](#Règles-yara)**
  - [Identifiant de règle](#Identifiant-de-règle)
  - [Section Strings](#Section-Strings)
  - [Section condition](#Section-condition)
- **[Utilisation de Yara](#Utilisation-de-Yara)**
---

## Introduction
[Yara](https://virustotal.github.io/yara/) est un outil Open Source de détection des malwares. Il permet de détecter les Indices de Compromission (IoC) des malwares sur un système. Pour cela, il faut créer des règles Yara dans lesquelles définir les IoC.


## Installation de yara
Yara peut être [installé](https://yara.readthedocs.io/en/stable/gettingstarted.html) de différentes manières et sur plusieurs plateformes (Linux, Windows, Mac OS X) : à partir de la source, via [vcpkg](https://github.com/Microsoft/vcpkg/), via [Homebrew](https://brew.sh/). Il peut être incorporé dans un script Python aussi en installant le paquet [yara-python](https://github.com/VirusTotal/yara-python).

Par ailleurs, il existe un outil générateur des règles Yara : [Yara-Rules](https://github.com/Yara-Rules/rules )

Dans ce qui suit, nous installerons Yara à partir de la source. Pour cela :
1. Installer les dépendances
```
sudo yum -y install epel-release
sudo yum update -y
sudo yum  -y install autoconf libtool
sudo yum -y install openssl-devel
sudo yum -y install python3 python3-devel
# pour les modules cuckoo et magic
sudo yum -y install file-devel
sudo yum -y install jansson jansson-devel
```
2. Installer yara
```
sudo wget https://github.com/VirusTotal/yara/archive/v4.0.1.tar.gz
sudo tar xzvf v4.0.1.tar.gz
sudo cd yara-4.0.1/
sudo ./bootstrap.sh
#pour activer les modules cuckoo et magic
sudo ./configure --enable-cuckoo --enable-magic
sudo make
sudo make install
```

3. Vérifier l'installation
```
sudo make check
```
Si l'installation s'est bien passée, on aura dans le résultat de sortie `FAIL:  0 et ERROR: 0` :

4. Premier test : écrire une règle simple dans un fichier puis le tester
````
echo rule dummy { condition: true } > my_first_rule.txt
yara my_first_rule.txt my_first_rule
````
La commande nous renverra le résulat suivant :
```
dummy my_first_rule
```

## Règles Yara
La syntaxe des [règles Yara](https://yara.readthedocs.io/en/stable/writingrules.html) ressemble à celle du langage C. Exemple :

```
rule ExampleRule
{
    strings:
        $my_text_string = "text here"
        $hex_string1 = { E2 34 A1 C8 23 FB }
        $hex_string2 = { F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45 }

    condition:
        $my_text_string or $hex_string1 or $hex_string2
}
```

### Identifiant de règle
Chaque règle est identifiée par son `nom` (ExampleRule) et comprend principalement deux parties : `strings` et `condition`. Le nom respecte les mêmes conventions de nommage que C. Il ne doit pas correspondre à l'un des mots réservés (`all, and, any,	ascii, 	at, ...`).
> Note :
> - La section `strings` n'est pas obligatoire, si aucune chaîne n'est à définir, contrairement à `condition`.
> - on peut ajouter aussi une section `meta` pour ajouter des informations supplémentaires sur les règles (ex: auteur, malware, ...)

### Section Strings
La section `strings` sert à indiquer les chaînes de caractère suspects à rechercher (ex: IOC des malwares). Chaque chaine est précédée de `$`.

Il y a trois types de `string` : héxadécimal, text et expressions régulières.

- Un string `héxadécimal` peut comprendre aussi tous les quantifiants des expressions régulières (ex: ?, |, [], ...)
- String de type `Text` est chaîne de caractère normale (ascii) sensible à la casse. Il peut contenir des caractères d'échappent comme `\", \\, \t, \n, \xdd`. Il peut comprendre aussi d'autres mots clés (modificateurs) comme :
  - `nocase` : pour tenir de compte de la casse (ex: `$text_string = "foobar" nocase`)
  - `wide` : pour chercher des chaînes codées avec deux octets par caractère (ex: `B\x00o\x00r\x00l\x00a\x00n\x00d\x00 pour Borland`)
  - `fullword` : pour une chaîne précise (ex: `$a = "myweb.com" fullword` correspondra à www.myweb.com mais pas à www.my-web.com)
  - d'autres mots aussi : `xor, base64, base64wide, ascii,`
- Un string de type `Expression régulière` contient des des expressions régulières (ex: `$re1 = /md5: [0-9a-fA-F]{32}/`).

> Note :
- on peut combiner plusieurs modificateurs, `xor wide, wide ascii, xor wide ascii, ...` (ex: `$xor_string = "This program cannot" xor wide`)
- mais un string de type `expression régulière` ne peut être suivi que de `nocase, ascii, wide, et fullword`
- Pour plus de détails, cf la documentation sur les règles.

### Section condition
La section `condition` est obligatoire. Elle n'est rien d'autre qu'une combinaison d'expressions logiques (boléennes) que l'on trouve dans les lagages de programmation (`or, and, >, =, |, &, ...`). C'est dans cette section que la condition de recherche des strings est indiquée. Exemple :
```
rule Example
{
    strings:
        $a = "text1"
        $b = "text2"
        $c = "text3"
        $d = "text4"

    condition:
        ($a or $b) and ($c or $d)
}
```
Une condition peut contenir aussi des expressions de
- comptage (ex: `#a == 6 and #b > 10`)
- d'offset : (ex: `$a at 100 and $b in (0..100)`)
- de position comme `int8, uint16, ...`
- des variables spéciales `filesize, entrypoint` (ex: `filesize > 200KB`, `$a in (entrypoint..entrypoint + 10)`)
- des éléments pour spécifier un groupe comme :
```
all of them       // all strings in the rule
any of them       // any string in the rule
all of ($a*)      // all strings whose identifier starts by $a
any of ($a,$b,$c) // any of $a, $b or $c
1 of ($*)         // same that "any of them"
```
- ...

## Utilisation de Yara
Après avoir construit les règles, on peut effectuer la recherche avec yara en utilisant l'une des syntaxes ci-dessous :
```
yara [OPTIONS] RULES_FILE TARGET
# règle compilée
yara [OPTIONS] -C RULES_FILE TARGET
# fichiers de règles multiples
yara [OPTIONS] RULES_FILE_1 RULES_FILE_2 RULES_FILE_3 TARGET
```
`TARGET` peut être un fichier, un répertoire ou processus.

Pour le test :
- ajouter une liste d'IoC dans un fichier (ex: tmp/malwares) :
```
$ cat tmp/malware.txt
novayagazeta.spb.ru
hostname        www.aica.co.jp
hostname        www.fontanka.ru
hostname        www.grupovo.bg
FileHash-SHA1   afeee8b4acff87bc469a6f0364a81ae5d60a2add
FileHash-SHA1   de5c8d858e6e41da715dca1c019df0bfb92d32c0
IPv4    185.149.120.3
```
- créer le fichier de règles

```
$ cat malwareSearch.yar
rule malwareSearch
{
    strings:
        $domain = "caforssztxqzf2nm.onion" nocase ascii
        $hash = "16605a4a29a101208457c47ebfde788487be788d"
        $ip = "185.149.120.3"

    condition:
        1 of them
}
```
- exécuter la règle sur le répertoire ou sur le fichier
```
yara malwareSearch.yar tmp/
```
> Note : la commande affichera `malwareSearch tmp/malware.txt` montrant que le fichier "compromis"


## Liens
- Documentation
  - [Yara](https://virustotal.github.io/yara/)
  - [Yara-Rules](https://github.com/Yara-Rules/rules)
- Tutoriels
  - [Get Started](https://yara.readthedocs.io/en/stable/gettingstarted.html)
  - [Installing yara from source code | securitasdato](http://securitasdato.blogspot.com/2018/04/installing-yara-from-source-code-on.html)
  - [Yara rule for Webshell-shell](https://github.com/DarkenCode/yara-rules/blob/master/malware/Webshell-shell.yar)
