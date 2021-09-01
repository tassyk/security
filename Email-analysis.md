---
Title: Email Analysis
Type: Doc
Nature: Notes
Création: 01/10/2020
---

# Analyse de mails
## Introduction
L'analyse d'un mail permet de déterminer sa nature. Cela permet de reconnaître un mail de [Phising](https://www.vadesecure.com/fr/phishing)(Hameçonnage), de [Spear Phising](https://www.vadesecure.com/fr/spear-phishing), de [Spam](https://fr.wikipedia.org/wiki/Spam) ou de tout courriel indésirable.

## Termes à savoir
- **SPF (Sender Policy Framework)** : Defines a mechanism by which an organization can specify server(s) that are allowed to send email on behalf of that domain. If an email fails an SPF check, it can be an easy mechanism we can use to detect spam
- **DKM (DomainKeys Identified Mail)** : Provides a cryptographic method of verifying a received email actually originated from the sending domain. We can use this to detect forged senders and spam
- **DMARC (Domain-based Message Authentication Reporting & Conformance)** : improves your email security and protection. It´s an email authentication, a set of policies and rules that uses SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail) to detect and prevent fraud.
- **Return-Path**: See if the email address in this entry matches the email address in the From: entry. They typically will not match for mass emailers like advertisers or spammers. The Return-Path: email address is used when an email cannot be delivered to its recipients, and it “bounces back”. Spammers don’t want all the undelivered email to end up in their inboxes!
- **Reply-To**: See if the email address in this entry matches the email address in the From: entry. When you hit reply to an email, the Reply-To entry is used to populate the recipients’ email. If it is different, you may accidentally send your reply to someone else
- **X-Distribution**: if this field’s value is bulk. This indicates bulk/spam email
- **X-Mailer**: field indicates the email client. If it includes weird names, be suspicious
- **Bcc: or X-UIDL**: entries exist. This is a sign of poorly crafted header. They are never in normal emails!
- **X-Spam score, X-Spam flag and X-Spam status** entries help determine “spamminess”. But the scores are not standardized across servers so these have to examine on a case by case basis.

## Ce qu'il faut analyser 
Dans un mail, plusieurs éléments peuvent être vérifiés afin de déterminer sa nature (malveillant ou non) :
- Le nom et l'adresse mail de l'expéditeur
> NB : bien vérifier le lien entre le nom et l'adresse. Dans un mail de [spear phising](https://www.vadesecure.com/en/spear-phishing), le nom de l'expéditeur fait penser à un mail légitime alors que l'adresse est complètement fausse. <br>
> Parfois, c'est le nom de domaine de l'adresse qui est usurpé (domain spoofing).

- analyser bien le contenu du message: l'ortographe, le ton, le caractère urgent du message, les actions demandées, ...
- vérifier bien les liens contenus dans le message.
> Attention : Ne pas cliquer, mais poser juste la souris dessus pour afficher le lien exacte. Puis copier le lien pour l'analyser via des outils comme : [VirusToTal](https://www.virustotal.com/gui/home/search), ou [IsitPhising de VadeSecure](https://www.isitphishing.ai)

- vérifier les différentes pièces jointes
> Remarque : On peut ouvrir un fichier PDF avec un éditeur de text pour l'analyser car c'est en quelque sorte un format à balises. Quand aux fichiers OOXML (docx, xlsx, pptx), ce sont des archives ZIP contenant des fichiers XML. Pour plus de détails, voir cet article [[Analyse d'un email malveillant](https://www.vadesecure.com/fr/blog/analyse-dun-email-malveillant)]<br>
> NB : On peut aussi analyser les pièces jointes via des outils comme [Hybrid Analysis](https://www.hybrid-analysis.com/) (ou d'autres sandbox), ou VirusTotal...

- vérifier l'entête du mail
> NB : ceci peut se faire à l'aide des outils comme [Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)(de MXtoolbox.com)

## Ressources
### Documents
- [How to Get Email Headers](https://mxtoolbox.com/Public/Content/EmailHeaders/)
- [EmailHeaders.net | Forensic Email Search](https://emailheaders.net/forensic-email-search.html)
-[Detailed Study On Thunderbird Header Analysis](https://emailheaders.net/thunderbird.html)
- [Phishing - Email Header Analysis](https://mlhale.github.io/nebraska-gencyber-modules/phishing/email-headeranalysis/)
- [Analyse d'un email malveillant](https://www.vadesecure.com/fr/blog/analyse-dun-email-malveillant)
- [What is SPF (Sender Policy Framework)?](https://gatefy.com/blog/what-dmarc/)

### Vidéos
- [Email Header Analysis and Forensic Investigation](https://www.youtube.com/watch?v=nK5QpGSBR8c)
- [EMail Spoofing / SPF / DKIM](https://www.youtube.com/watch?v=5WekUz5cSAY)
- [How to analyze headers using MXtoolbox com](https://www.youtube.com/watch?v=rKDuX4QIxps)

## Tools
**Analyseurs d'une entête de mail** : <br>
- [MXtoolbox.com | Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Plugin Email Header](https://packagecontrol.io/packages/Email%20Header) : This plugin will parse .eml or .msg files for email message headers
- [Boîte à outils G Suite | En-tête message](https://toolbox.googleapps.com/apps/messageheader/)

**Analyseurs de liens ou fichiers** :<br>
- [VirusToTal](https://www.virustotal.com/gui/home/search)
- [IsitPhising de VadeSecure](https://www.isitphishing.ai) : détecter un lien de phising
- [Any.Run](https://any.run/) : Sandbox
- [Hybrid Analysis](https://www.hybrid-analysis.com/) : Sandbox

**Commandes utiles** : <br>
- dig : interroger le DNS
- nslookup : interroger le DNS
- file : déterminer le type d'un fichier (l'extension)
- strings : afficher les chaines de caractère d'un fichier
