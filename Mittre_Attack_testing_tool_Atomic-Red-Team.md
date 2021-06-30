---
Title: Mitre Attack test with Atomic Red Team
Type: Doc
Nature: Notes
Création: 10/05/2021
---

# Mitre Attack test with Atomic Red Team

## Introduction

> Atomic Red Team allows every security team to test their controls by executing simple "atomic tests" that exercise the same techniques used by adversaries (all mapped to [Mitre's](https://attack.mitre.org/)[ ](https://attack.mitre.org/)[ATT&CK](https://attack.mitre.org/)).

## Prerequis
Disposer de powershell sur les machines : voir comment installer [Powershell Core](https://docs.microsoft.com/en-us/powershell/scripting/install/installing-powershell?view=powershell-7.1&viewFallbackFrom=powershell-7)

Activer / configurer [Powershell Over SSH](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell-core?view=powershell-7)[ ](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell-core?view=powershell-7) si les machines locale et distante ne sont pas Windows. Pour cela :
- Installer openssh-client et openssh-server (si ssh n'est pas installé sur la machine)
- Ajouter ces configurations dans /etc/ssh/sshd_config :
```
PasswordAuthentication yes
#et/ou
PubkeyAuthentication yes
#Add a PowerShell subsystem entry
Subsystem powershell /usr/bin/pwsh -sshs -NoLogo
```
- Redémarrer le service sshd

## Installation
Installation (sur Kali): framework and folder
```
└─$ pwsh

PS /home/kali> IEX (IWR '<https://raw.githubusercontent.com/redcanaryco/invoke->

[atomicredteam/master/install-atomicredteam.ps1](atomicredteam/master/install-atomicredteam.ps1)' -UseBasicParsing);

PS /home/kali> Install-AtomicRedTeam -getAtomics
```

## Usages
### Exécution de test : command Invoke-AtomicTest
- Voir les info sur les tactiques :
```
#Toutes :
PS /home/kali> Invoke-AtomicTest All -ShowDetailsBrief
#Spécifique (T1003) :
PS /home/kali> Invoke-AtomicTest T1003 -ShowDetails
```
- Voir les prérequis systèmes relatifs à une tactique
```
PS /home/kali> Invoke-AtomicTest T1003 -CheckPrereqs
PS /home/kali> Invoke-AtomicTest T1003 -TestName "Windows Credential Editor" -CheckPrereqs
```
- Remote test : test à distance (il faut activer d'abord le remote powershell sur la machine, [cf wiki](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Execute-Atomic-Tests-\(Remote\))ou prerequis)
  - Créer une session powershell sur la machine attaquante/locale (Kali)
```
/home/kali> $sess = New-PSSession -HostName 192.168.1.4 -Username my_user
```
  - Lancer des tests :
```
# Install any required prerequisites on the remote machine before test
execution
/home/kali> Invoke-AtomicTest T1218.010 -Session $sess -GetPrereqs
# execute all atomic tests in technique T1218.010 on a remote machinePS
/home/kali> Invoke-AtomicTest T1218.010 -Session $sess
```

    > NB : pour exécuter tous les tests sur la machine
    >
```
#Execute All Attacks
/home/kali> Invoke-AtomicTest All
```

# Documentation
- Github atomic Red Team : <https://github.com/redcanaryco/atomic-red-team>
- Official website : <https://atomicredteam.io/>
- Wiki installation atomic red team : <https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing->
