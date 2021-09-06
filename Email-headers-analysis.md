---
Title: Analyse des entêtes des mails
Type: Doc
Nature: Notes
Création: 18/09/2020
---

# Analyse des entêtes des mails

## Introduction
Dans cette note, nous allons découvrir comment extraire l'entête d'un mail.
Ceci permet de voir des informations sur la provenance du mail comme les adresses IP,
les serveurs de relay, ...

## Afficher l'entête d'un mail
Depuis votre mail, effectuez un clic droit ou accédez aux options pour choisir **Afficher la source**.
Par exemple, pour outlook (version web) :
- Ouvrez le mail
- cliquez sur l'icône **Autres actions (les trois points)**
- Cliquez sur **Afficher** puis sur **Afficher la source du message**
- Vous accédez ainsi à l'entête du mail qui ressemble à ceci :

```
Received: from VI1EUR05HT197.eop-eur05.prod.protection.outlook.com
 (2603:10a6:102::24) by PR3PR02MB6457.eurprd02.prod.outlook.com with HTTPS via
 PR1PR01CA0011.EURPRD01.PROD.EXCHANGELABS.COM; Fri, 18 Sep 2020 17:47:09 +0000
Received: from VI1EUR05FT062.eop-eur05.prod.protection.outlook.com
 (2a01:111:e400:fc12::53) by
 VI1EUR05HT197.eop-eur05.prod.protection.outlook.com (2a01:111:e400:fc12::385)
 with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.3391.15; Fri, 18 Sep
 2020 17:47:09 +0000
Authentication-Results: spf=pass (sender IP is 167.89.30.32)
 smtp.mailfrom=mail.n.convertkit.com; outlook.fr; dkim=pass (signature was
 verified) header.d=n.convertkit.com;outlook.fr; dmarc=none action=none
 header.from=feltsecure.com;
Received-SPF: Pass (protection.outlook.com: domain of mail.n.convertkit.com
 designates 167.89.30.32 as permitted sender) receiver=protection.outlook.com;
 client-ip=167.89.30.32; helo=o15.ck.n.convertkit.com;
...

```
> Note entêtes :
> - Pour Outlook (version client lourd) :
  1. Double click sur le mail pour l'ouvrir > Aller dans fichiers > puis dans Propriétés > En-têtes Internet
 - Pour les autres solutions de messagerie, voir [How to Get Email Headers](https://mxtoolbox.com/Public/Content/EmailHeaders/)

## Analyser les informations de l'entête
Dans une entête, on peut voir des IP, des serveurs par où est passé le mail jusqu'à arriver à destination.
Il existe cependant des outils qui facilitent le traçace du mail.
### Localisation des IP
On peut localiser chaque IP contenue dans une entête sur de nombreux sites spécialisés comme [CISCO TALOS](https://talosintelligence.com/), [www.iplocation.net](www.iplocation.net), ou [www.hostip.fr](https://www.hostip.fr/), ou [www.whatismyip.com](www.whatismyip.com).
On peut aussi passer ces IP sur des sites comme [VirusTotal](https://www.virustotal.com/gui/home/search) ou [AbuseIPDB](https://www.abuseipdb.com/) pour vérifier si elles ne sont pas malveillantes ou blacklistées.

### Extraction des informations de l'entête
Pour trouver analyser une entête efficacement, il existe des sites qui simplifient cette tâche pour nous comme [mxtoolbox.com](https://mxtoolbox.com/EmailHeaders.aspx) ou [Email HEADER](https://emailheaders.net/), [Boîte à outils G Suite | En-tête message](https://toolbox.googleapps.com/apps/messageheader/). Il suffit juste de copier / coller l'entête du mail dans le champ.
Sinon, il existe aussi des plugins pour analyser les entêtes comme [EmailHeader](https://packagecontrol.io/packages/Email%20Header), un plugin pour Sublime Text.


## Liens
- [How to Get Email Headers](https://mxtoolbox.com/Public/Content/EmailHeaders/)
- [Email Headers | Forensic Email Search](https://emailheaders.net/forensic-email-search.html)
- [Video | Email Header Analysis and Forensic Investigation](https://www.youtube.com/watch?v=nK5QpGSBR8c)
- [Video | 12 Days of Defense - Day 4: How to Analyze Email Headers and How Spoofed Email Works](https://www.youtube.com/watch?v=reRzWHUwI80)

