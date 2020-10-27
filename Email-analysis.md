---
Title: Email Analysis
Type: Doc
Nature: Notes
Création: 01/10/2020
---

# Analyse de mails

## Termes à savoir
- **SPF (Sender Policy Framework)** : Defines a mechanism by which an organization can specify server(s) that are allowed to send email on behalf of that domain. If an email fails an SPF check, it can be an easy mechanism we can use to detect spam
- **DKM (DomainKeys Identified Mail)** : Provides a cryptographic method of verifying a received email actually originated from the sending domain. We can use this to detect forged senders and spam
- **DMARC (Domain-based Message Authentication Reporting & Conformance)** : improves your email security and protection. It´s an email authentication, a set of policies and rules that uses SPF (Sender Policy Framework) and DKIM (DomainKeys Identified Mail) to detect and prevent fraud.
- **Return-Path**: See if the email address in this entry matches the email address in the From: entry. They typically will not match for mass emailers like advertisers or spammers. The Return-Path: email address is used when an email cannot be delivered to its recipients, and it “bounces back”. Spammers don’t want all the undelivered email to end up in their inboxes!
- **Reply-To**: See if the email address in this entry matches the email address in the From: entry. When you hit reply to an email, the Reply-To entry is used to populate the recipients’ email. If it is different, you may accidentally send your reply to someone else
- **X-Distribution**: if this field’s value is bulk. This indicates bulk/spam email
- **X-Mailer**: field indicates the email client. If it includes weird names, be suspicious
- **Bcc: or X-UIDL**: entries exist. This is a sign of poorly crafted header. They are never in normal emails!
- **X-Spam score, X-Spam flag and X-Spam status** entries help determine “spamminess”. But the scores are not standardized across servers so these have to examine on a case by case basis

## Ressources
### Documents
- [How to Get Email Headers](https://mxtoolbox.com/Public/Content/EmailHeaders/)
- [EmailHeaders.net | Forensic Email Search](https://emailheaders.net/forensic-email-search.html)
-[Detailed Study On Thunderbird Header Analysis](https://emailheaders.net/thunderbird.html)
- [Phishing - Email Header Analysis](https://mlhale.github.io/nebraska-gencyber-modules/phishing/email-headeranalysis/)
- [What is SPF (Sender Policy Framework)?](https://gatefy.com/blog/what-dmarc/)

### Vidéos
- [Email Header Analysis and Forensic Investigation](https://www.youtube.com/watch?v=nK5QpGSBR8c)
- [EMail Spoofing / SPF / DKIM](https://www.youtube.com/watch?v=5WekUz5cSAY)
- [How to analyze headers using MXtoolbox com](https://www.youtube.com/watch?v=rKDuX4QIxps)

## Email header anlysis tools
- [MXtoolbox.com | Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Plugin Email Header](https://packagecontrol.io/packages/Email%20Header) : This plugin will parse .eml or .msg files for email message headers, including x-headers, and will also color IPv4 and IPv6 addresses for ease of readability. Note: requires Sublime Text build 3092 or higher.
- [Boîte à outils G Suite | En-tête message](https://toolbox.googleapps.com/apps/messageheader/)

## Commandes utiles
- dig
- nslookup
