---
Title: Linux Forensics tips
Type: Doc
Nature: Notes
Création: 20/05/2020
---

# Linux Forensics Tips

## Artifacts (what to search?) :
- Filesystem
  - Logs (secure, messages, HTTP logs, syslog, ...)
  - Malware persistence (if any) (/bin, /tmp, ...)
- Memory
  - Process memory and state
  - Kernel memory
- Network
  - Configuration
  - Packet capture (in-band and out-of-band)

## For Offline forensics
- Take a Capture
```
dd if=/dev/sda3 of=$IMAGE_FILE # capture
mount -o loop,ro$IMAGE_FILE /mnt # Browse
```

## Files and directories analysis
- Files and directories checking
```
# lister les derniers fichiers modifiés
ls -alt | head
# lister les fichiers d'un répertoire
ls -alRtFp --full-time -h $PATH
# voir les attributs des fichiers (fichiers immutables)
lsattr -a /bin
# specific files on the system
sudo find /donnees/web/* -name "*saltedpassword*" -print
# Find files that were modified after October 28th
sudo find / -newermt2019-10-28
# Suspicious Files Hidden Binaries
sudo find / -name ".*" -exec file -p '{}' \; | grep ELF
# Suspicious FilesNamed Pipes
sudo find / -type p
# Full file details
sudo stat $FILE
# Identify file type
sudo file $FILE
```
- Packages Integrity
```
# Display a package's contents
sudo dpkg-query -L php  # debian
# malicious or not ?
sudo rpm --verify keyutils-libs # redhat family
sudo rpm -qi keyutils-libs
# checks every file on your system against the stock md5sum files
sudo debsums --all
sudo debsums --config # check only the configuration files
```
- Log files analysis
```
# Search some audit logs (using ausearch, aureport)
ausearch -m EXECVE
# apache logs : bad method
sudo grep -E -R "GET|PUT|DELETE"  /var/log/apache2/*log |  more
# apache logs : ioc
sudo grep -E "172.67.183.186|104.24.107.161|104.24.106.161|104.27.160.184|104.27.161.184" /var/log/apache2/*.log
# apaches http reponse not 200
sudo egrep -v "HTTP/1.1\" 200" /var/log/apache2/website_access.log >> /logs/error.log
```

## Process analysis
- with **netstat -> ss** :
```
#  show all process
sudo netstat -nalp | more
sudo ss -alt | more
sudo ss -alp sport eq 38255 # specific port
```
- with **ps** :
```
# Top memory consuming process
sudo ps -auxf | sort -nr -k 4 | head -10
# see all process launched by a user
sudo ps --forst --user $USER
```
- with **lsoft** :
```
# List open files and network streams
sudo lsof-p $PID
```
- with **procfs (provides a lot of useful details)** :
```
# list out Process ID under to see what is going on
sudo ls -al /proc/$PID/
# see its statut
sudo cat /proc/$PID/status
# procfsexemagic link
sudo ls -l /proc/$PID/exe # Find the path of the executed file
sudo cp /proc/$PID/exe malware.elf # Retrieve the executable file even if it was deleted
# Malwares open files descriptors
sudo ls -al /proc/<PID>/fd
# malware process
cat /proc/<PID>/maps # process maps
cat /proc/<PID>/stack # process stack
# procfs environ
tr '\0' '   \n' < /proc/$PID/environ
# Process stalling
sudo kill -SIGSTOP $PID # Stop a process without destroying its resources
sudo kill -SIGCONT $PID # Resume a process previously stopped with SIGSTOP
```

## Network packages analysis
- with **tcpdump** :
```
# packets going one way using src or dst
sudo tcpdump -i eth0 dst 10.10.1.20
# Write a capture file
sudo tcpdump -i eth0 -s0 -w capture.pcap
tshark -r capture.pcap # analysis or with wireshark
# Extract HTTP Request URL's
sudo tcpdump -s 0 -v -n -l | egrep -i "POST /|GET /|Host:"
# Extract HTTP Passwords in POST Requests
sudo tcpdump -s 0 -A -n -l | egrep -i "POST /|pwd=|passwd=|password=|Host:"
```

- with **Netcat** :
```
# syntaxe : nc [options] host port
# Ecouter un port sur une interface
nc -l 192.168.0.2 10222
#  verify what data a server is sending in response
printf "GET / HTTP/1.0\r\n\r\n" | nc 192.168.0.2  80
```
- with **Sysdig** :
```
# connexions établies sur les ports
sudo sysdig -c fdcount_by fd.sport "evt.type=accept"
# See all the GET HTTP requests made by the machine
sudo sysdig -s 2000 -A -c echo_fds fd.port=80 and evt.buffer contains GET
# See queries made with apache to an external MySQL server happening in real time
sysdig -s 2000 -A -c echo_fds fd.sip=192.168.30.5 and proc.name=apache2 and evt.buffer contains SELECT
```

## Ports scan
- with **NMAP**
```
# single host or an IP address scan
nmap -v 192.168.1.1
# network scan with exclusion
nmap 192.168.1.0/24 --exclude 192.168.1.5,192.168.1.254
# scan furtif sur un ensemble de ports et hosts
nmap -sV -p 22,53,110,143,4564 198.116.0-255.1-127
# vuln scan
nmap -Pn --script vuln 192.168.1.105
# list website ciphers suit
nmap -Pn --script ssl-enum-ciphers -p 443 192.168.1.254
# all non intruisive scripts scan
nmap --script "not intrusive"
```

- with **Netcat**
```
#scan a single port
nc -v -w 2 -z 192.168.56.1 22  
#scan range of ports
nc -v -w 2 -z 192.168.56.1 20-25   
```

## Users activities
- with **Sysdig**
```
# répertoires consultés par un utilisateur (root)
sudo sysdig -p"%evt.arg.path" "evt.type=chdir and user.name=root"
# Show the ID of all the login shells that have launched the "tar" command
sysdig -r file.scap -c list_login_shells tar
# Monitoring Users activities
sysdig -c spy_users
# Show all the commands executed by the login shell with the given ID
sysdig -r trace.scap.gz -c spy_users proc.loginshellid=5459
```
- with **Acct**
```
# Display Time Totals for each User
ac -p
# Print All Account Activity Information
sa
# Print Individual User Information
sa -u
# Summary for each user
sa --user-summary
# List Last Executed Commands of User
lastcomm user
# Search Logs for Commands
lastcomm ls
```
- with **who, w and utmpdump**
```
# who or w to parse login records
who -a
w
# dump UTMP and WTMP files in raw format
sudo utmpdump -r < wtmp.fix > /var/log/wtmp
```
- with **Crontab**
```
# Users Scheduled tasks
sudo crontab -l
```
## Scripts analysis
### Script based malwares
- remove whitespace from obfuscated codes
```
# Tidying codes with :
- Perl -> perltidy
– Python -> PythonTidy
– PHP -> php-cs-fixer
```
- Rename variables with search and replace
- Use interactive prompts to evaluate parts of the code
```
- Perl -> perl-de1
- Python -> ipython
- PHP -> php -a
```
### Compiled malwares
- Reverse engineering
```
- strace
- ltrace : for dynamically linked binaries
- gdb : or any other debugger you like–gcore
```

## Liens
- Tools & commands :
  - Files analysis : `ls -alt, lsattr, find, stat, file, grep, debsums, rpm -qi, rpm -Va, dpkg-query, strings`
  - Process analysis : `ps, netstat, ss, lsoft, procfs (/proc)`
  - Networks trafic : `tcpdump, sysdig, wireshark, netcat`
  - Users activities : `sysdig, w, who, utmpdump, lastcomm, sa, ac, last, lastb`
  - Ports scan : `nmap, netcat`
  - Codes analysis : `perltidy, PythonTidy,php-cs-fixer,perl-de1,ipython, php -a, strace, ltrace, gdb`
- Forensics demonstration
  - [Security Linux Forensics](https://www.sandflysecurity.com/wp-content/uploads/2018/04/sandfly.security.linux_.forensics.chc2017.pdf)
  - [Compromised Linux Cheat Sheet](https://www.sandflysecurity.com/blog/compromised-linux-cheat-sheet/)
  - [how to basic linux malware process forensics for incident responders](https://blog.apnic.net/2019/10/14/how-to-basic-linux-malware-process-forensics-for-incident-responders/)
  - [Hunting Linux Malware for Fun and Flags](https://www.rsaconference.com/usa/agenda/hunting-linux-malware-for-fun-and-flags)
  - [sysdig workshop forensics](https://github.com/draios/sysdig-workshop-forensics)
- Usefull tools with examples
  - [hackertarget | tcpdump examples](https://hackertarget.com/tcpdump-examples/)
  - [50 Ways to Isolate Traffic with tcpdump](https://danielmiessler.com/study/tcpdump/)
  - [tecmint | netcat exampes](https://www.tecmint.com/netcat-nc-command-examples/)
  - [NMAP Tuto](https://www.cyberciti.biz/security/nmap-command-examples-tutorials/)
  - [Sysdig Examples](https://github.com/draios/sysdig/wiki/Sysdig-Examples)
  - [how to monitor user activity with psacct or acct tools](https://www.tecmint.com/how-to-monitor-user-activity-with-psacct-or-acct-tools/)
  - [10 ways to analyze binary files on Linux](https://opensource.com/article/20/4/linux-binary-analysis)
  - [30 Useful ‘ps Command’ Examples for Linux Process Monitoring](https://www.tecmint.com/ps-command-examples-for-linux-process-monitoring/)
  - [check verify md5sum packages files in linux](https://www.tecmint.com/check-verify-md5sum-packages-files-in-linux/)
- Rapport Forensics :
  - [ATT&CK Matrix](https://attack.mitre.org/)
