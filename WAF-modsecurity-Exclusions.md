---
Title: ModSecurity Exclusions
Nature : Note
Catégorie: Web security
Date: 21/12/2020
Auteur: TK
---

# ModSecurity Exclusions
---
**Sommaire**

- **[Introduction](#Introduction)**
- **[Structure de logs d'Audit](#Structure-de-logs-d'Audit)**
- **[Structure d'une règle](#Structure-d'une-règle)**
  - [Variables](#Variables)
  - [Opérateurs](#Opérateurs)
  - [Transformations](#Transformations)
  - [Actions](#Actions)
- **[Exclusions](#Exclusions)**
  - [Exceptions](#Exceptions)
  - [Whitelistes](#Whitelistes)
- **[Liens](#Liens)**
---
## Introduction
Dans cette note, nous allons voir comment définir des exclusions (exceptions, whiteliste) avec le WAF [ModSecurity](https://github.com/tassyk/security/blob/master/WAF-modsecurity.md). Ceci peut-être intéressant pour résoudre les faux-positifs.

## Structure de logs d'Audit
Avant de toute chose, il est important de comprendre la structure des logs de ModSecurity afin de mieux identifier quelles exclusions à créer.

Un [log d'Audit](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats#Audit_Log) de ModSecurity est composé de plusieurs sections marquées par des lettres (A-K et Z) :
```
    A - audit log header
    B - request headers
    C - request body
    D - intended response headers (NOT IMPLEMENTED)
    E - intended response body
    F - response headers
    G - response body (NOT IMPLEMENTED)
    H - audit log trailer
    I - reduced multipart request body
    J - multipart files information (NOT IMPLEMENTED)
    K - matched rules information
    Z - audit log footer
```
La section **A (audit log header)** contient l'entête du log. Elle contient le timestamp, l'unique ID de la transaction, l'IP et le port source, l'IP et le port de destination. Exemple :
```
--f59d1467-A--
[20/Dec/2020:21:51:09 +0100] X9@5PV7k4QBCm23Dn3IXKgAAAAA 127.0.0.1 53896 127.0.0.1 80
```
> Ici, on a :
- Timestamp : [20/Dec/2020:21:51:09 +0100]
- Unique transaction ID : X9@5PV7k4QBCm23Dn3IXKgAAAAA
- Source IP address (IPv4 or IPv6) : 127.0.0.1
- Source port : 53896
- Destination IP address (IPv4 or IPv6) : 127.0.0.1
- Destination port : 80

Les sections **B** et **C** contiennent respectivement l'entête et la réponse de la requête.

La section **H (audit log trailer)** est très importante car elle donne les détails de la transaction. Exemple :
```
--f59d1467-H--
Message: Warning. detected XSS using libinjection. [file "/usr/share/modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf"] [line "60"] [id "941100"] [msg "XSS Attack Detected via libinjection"] [data "Matched Data: XSS data found within ARGS:website: <script>alert(\x22xss\x22)</script>"] [severity "CRITICAL"] [ver "OWASP_CRS/3.2.0"] [tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-xss"] [tag "paranoia-level/1"] [tag "OWASP_CRS"] [tag "OWASP_CRS/WEB_ATTACK/XSS"] [tag "WASCTC/WASC-8"] [tag "WASCTC/WASC-22"] [tag "OWASP_TOP_10/A3"] [tag "OWASP_AppSensor/IE1"] [tag "CAPEC-242"]
...
```
> Ici, on remarque que ModSecurity a identifié une attaque XSS avec la règle `941100`. C'est le champs `website` du formulaire qui a été la cible comme le montre cette ligne `ARGS:website: <script>alert(\x22xss\x22)</script>"`

## Structure d'une règle
Avant d'aborder les exclusions, il est aussi important de comprendre comment créer une règle (`rule`) dans ModSecurity grâce à l'aide de la directive `SecRule`. Voici sa syntaxe :
```
SecRule VARIABLES OPERATOR [TRANSFORMATION,ACTIONS]
```
Ainsi on remarque qu'une `rule` est composée de quatre différentes parties :
- **VARIABLES** : Instructs ModSecurity where to look (sometimes called Targets)
- **OPERATOR** : Instructs ModSecurity when to trigger a match
- **TRANSFORMATIONS** : Instructs ModSecurity how it should normalize variable data
- **ACTIONS** : Instructs ModSecurity what to do if a rule matches

Considérons la règle ci-dessous :
```
SecRule ARGS_GET "@contains test" "id:1,phase:1,t:lowercase,deny"
```
On a :
- variable : ARGS_GET
- opérateur : @contains
- transformation : t:lowercase
- action : "id:1,phase:1,t:lowercase,deny"

### Variables
Les [variables](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Variables), aussi appelées `Target (cible)`, constituent l'élément (l'objet) à inspecter dans une rule. Il existe plusieurs variables : `ARG, ARG_NAMES, FILE, QUERY_STRING, REMOTE_ADDR, REQUEST_COOKIES, REQUEST_HEADERS, REQUEST_URI, SESSION, ...`
> NB : On peut utiliser plusieurs variables dans une même règle en les séparant par un `pipe (|)`. Exemple: `SecRule ARGS_GET|ARGS_POST|REQUEST_COOKIES ...`

### Opérateurs
Les [opérateurs](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Operators) indiquent l'opération à effectuer sur une variable. Parmi les opérateurs, on peut citer : `beginsWith, endWith, contains, detectXSS, ipMatch, pmFromFile, le, lt, ge, rx, ...`. Dans l'utilisation, un opérateur est précédé du caractère `@`. Exemple : `@contains, @streq`

### Transformations
Les [transformations](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Transformation_functions) précisent le pre-traitement (transformation) qu'une la valeur d'une variable doit subir. Il existent plusieurs fonctions de transformation : `base64Decode, lowercase, uppercase, none, normalizePath, removeNulls, urlDecode, ... `

### Actions
Les [actions](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Actions) indiquent à ModSecurity quoi faire quand il y a une correspondance (c'est à dire la transaction correspond à ce que l'on recherche). Il existe plusieurs actions : `block, allow, deny, drop, pass, pause, phase, id, append, chain, msg, tag, severity, status, xmlns, skip, ...`
> Note : Il existe 5 catégories :
- **Disruptive actions** - Cause ModSecurity to do something. In many cases something means block transaction, but not in all. Example: `allow, block, deny, pass, pause, redirect,  ...`
- **Non-disruptive actions** - Do something, but that something does not and cannot affect the rule processing flow. Setting a variable, or changing its value is an example of a non-disruptive action. Non-disruptive action can appear in any rule, including each rule belonging to a chain. Example : `append, accuracy, ctl, exec, msg, tag, ver, ...`
- **Flow actions** - These actions affect the rule flow. Example : `skip, skipAfter, chain`
- **Meta-data actions** - Meta-data actions are used to provide more information about rules. Examples : `id, rev, severity, msg`.
- **Data actions** - Not really actions, these are mere containers that hold data used by other actions. Example : `status, xmlns`

> Note : l'action [ctl](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#ctl) change un élément de configuration de ModSecurity (désactiver ruleEngine, une regle identifiée par son ID, ...).
Exemple : `ctl:ruleRemoveTargetById=981260;ARGS:user pour ignorer le champs `user` pour la règle 981260`
Plusieurs options de configuration sont acceptées pour cette action dont : `auditEngine, ruleRemoveById[ByMsg, ByTag], ruleEngine, ruleRemoveTargetById[ByTag, ByMsg], ...`

> **Remarque** : On peut combiner les actions, mais on ne peut utiliser deux actions disruptives dans une même règle (seule la dernière prend effet, dans le cas contraire)

### Exemples de règles
Voici quelques exemples de règles :
```
# Allow unrestricted access from 192.168.1.100
SecRule REMOTE_ADDR "^192\.168\.1\.100$" phase:1,id:95,nolog,allow

# Parse requests with Content-Type "text/xml" as XML
SecRule REQUEST_CONTENT_TYPE ^text/xml "nolog,pass,id:106,ctl:requestBodyProcessor=XML"

# white-list the user parameter for rule #981260 when the REQUEST_URI is /index.php
SecRule REQUEST_URI "@beginsWith /index.php" "phase:1,t:none,pass, \
  nolog,ctl:ruleRemoveTargetById=981260;ARGS:user

# Allow Nikto scanner
SecRule REQUEST_HEADERS:User-Agent "nikto" "log,allow,id:107,msg:'Allow Nikto Scanners'"
```

## Exclusions
Après avoir compris un peu la structure d'un log d'Audit de ModSecurity et d'une règle, on pourra maintenant voir comment créer les exclusions.
Il existe deux types d'exclusions : [exceptions et whitelistes](https://coreruleset.org/docs/exceptions.html).
> NB : ModSecurity maintient deux catégories de context : startup (démarrage) et par transaction.
  - Les règles de type `Exception` sont exécutées au startup, donc elles doivent être placées **après** les règles qu'elles suppriment (cf fichier `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example`).
  - Quand aux règles de type `Whiteliste`, elles sont executées dans un contexte de transaction. Elles doivent donc être placées avant les règles qu'elles modifient (cf fichier `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example`)

### Exceptions
Une exception désactive complètement une règle (Remove) ou modifie son comportement (Update). Elle est créé à partir de ces [directives](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#Configuration_Directives) ci-dessous :
```
- SecRuleRemoveById (Syntax: SecRuleRemoveById ID ID RANGE ...)
- SecRuleRemoveByMsg (Syntax: SecRuleRemoveByMsg REGEX)
- SecRuleRemoveByTag (Syntax: SecRuleRemoveByTag REGEX)
- SecRuleUpdateActionById (Syntax: SecRuleUpdateActionById RULEID[:offset] ACTIONLIST
- SecRuleUpdateTargetById (Syntax: SecRuleUpdateTargetById RULEID TARGET1[,TARGET2,TARGET3] REPLACED_TARGET )
- SecRuleUpdateTargetByMsg (Syntax: SecRuleUpdateTargetByMsg TEXT TARGET1[,TARGET2,TARGET3] REPLACED_TARGET)
- SecRuleUpdateTargetByTag (Syntax: SecRuleUpdateTargetByTag TEXT TARGET1[,TARGET2,TARGET3] REPLACED_TARGET )
```
Comme le laisse voir le nom de ces directives, on peut supprimer ou une regèle à partir de son ID (*ById), de son message (*ByMsg) ou de son tag (*ByTag)
> NB : Une règle peut-être identifiée soit par son ID (ex: `941100`), par son message (ex : `"XSS Attack Detected via libinjection"`) ou par son Tag (ex : `"WEB_ATTACK/XSS"`)

Exemples d'exceptions :
```
# Désactiver la règle identifiée par l'ID 941100
SecRuleRemoveById 941100
# Désactiver toutes les règles dont le tag est "WEB_ATTACK/XSS"
SecRuleRemoveByTag "WEB_ATTACK/XSS"
# Désactiver les règles identifiées par le message "FAIL"
SecRuleRemoveByMsg "FAIL"
# Ignorer l'argument email pour la règle 941100
SecRuleUpdateTargetById 941100 !ARGS:email
# Ignorer l'argument email pour les règles marquées par le message "XSS Attack"
SecRuleUpdateTargetByMsg "XSS Attack" "!ARGS:email"
```
> Remarque : Ces exceptions doivent être placées après les règles SecRules qu'elles modifient (ex: dans un fihcier `RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf`)

### Whitelistes
Une whiteliste permet de créer une exception pour un objet donné (IP, URL, Arguments). Elle est construite via la directive **SecRule**.
```
Syntax: SecRule VARIABLES OPERATOR [ACTIONS]
```
Elle est généralement utilisée avec l'action `ctl` afin de changer le comportement de ModSecurity vis-à-vis d'un object.
Par exemple :
```
#Désactiver Modsecurity pour une IP
SecRule REMOTE_ADDR "@IPMatch 127.0.0.1" "id:1,ctl:ruleEngine=Off"

# Désactiver la règle 941100 pour la plage d'IP 129.21.0.0/24
SecRule REMOTE_ADDR "@IPMatch 129.21.0.0/24" "id:3,ctl:ruleRemoveById=941100"

# Ignorer la variable REQUEST_COOKIES pour la règle SQL 942450
SecRuleUpdateTargetById 942450 "!REQUEST_COOKIES"

# Ignorer le chams ids[] pour les règles 942130 et 942431 pour l'URI commençant par /drupal/index.php
SecRule REQUEST_URI "@beginsWith /drupal/index.php" \
    "phase:2,nolog,pass,id:10006,ctl:ruleRemoveTargetById=942130;ARGS:ids[],\
                                 ctl:ruleRemoveTargetById=942431;ARGS:ids[]"
```
> On trouvera plusieurs exemples de whiteliste sur l'article [Handling False Positives with the OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/#step_8_summarizing_all_rule_exclusions)

## Liens
Docummentation :
- [The OWASP Core Rule Set Documentation](https://coreruleset.org/documentation/)
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual-%28v2.x%29#SecRule)
- [ModSecurity ModSecurity-2-Data-Formats](https://github.com/SpiderLabs/ModSecurity/wiki/ModSecurity-2-Data-Formats)
- [Handling False Positives with the OWASP ModSecurity Core Rule Set](https://www.netnea.com/cms/apache-tutorial-8_handling-false-positives-modsecurity-core-rule-set/#step_8_summarizing_all_rule_exclusions)
- [Adding Exceptions and Tuning CRS](https://coreruleset.org/docs/exceptions.html)

Tools :
- [Framework for Testing WAFs (FTW)](https://github.com/coreruleset/ftw)
- [WAF Bench (WB) Tool Suits](https://microsoft.github.io/WAFBench/)
- [ModeSecurity Audit Log Analyzer](http://reconity.com/)
