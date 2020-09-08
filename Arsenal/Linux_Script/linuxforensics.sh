#!/bin/bash

# This is written by @securitySura for AFI tool at BlackHat Hachathon
# need root access 
# ssh linux1@172.16.44.156 sudo sh < /home/master/linuxforensics.sh
 


echo "create folder to save files \n "
if [ -d "/tmp/fartifact" ]; then rm -Rf /tmp/fartifact; fi
mkdir /tmp/fartifact

echo "dumping password file \n"
cat /etc/passwd | cut -d ":" -f1 | sort -u > /tmp/fartifact/userlist.log

echo "list all the root users \n"
grep -v -E "^#" /etc/passwd 2>/dev/null| awk  -F: '$3 == 0 { print $1}' > /tmp/fartifact/rootusers.log

echo "dumping network statistic \n"
netstat -panut | grep -v "udp6\|tcp6" | awk '{print $1, $4, $5, $6}'  | sort -u > /tmp/fartifact/externalIPs.log

echo "dumping hidden files belongs to other users \n"
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; | grep -v "Permission denied" | grep -v "root root" | awk '{print $3, $9}' > /tmp/fartifact/hiddenfilesforotherusers.log

echo "dumping process statistic \n"
ps -a | awk '{print $1, $4}' > /tmp/fartifact/pidpsname.log

echo "dumping users crontab details \n"
cat /etc/passwd | cut -d ":" -f1 | while read users; do crontab -u $users -l;done > /tmp/fartifact/userscrontab.log

echo "dumping auto start services \n"
ls -all /etc/init.d/ /lib/systemd/system/ /etc/systemd/system/ >> /tmp/fartifact/autostartservices.log

echo "dumping bad logins"
lastb > /tmp/fartifact/badlogins.log

echo "Collecting log files ....!!! \n"
cp /var/log/auth.log /tmp/fartifact/sshaccess.log
cp /var/log/apache2/error.log /tmp/fartifact/webservererror.log
cp /var/log/apache2/access.log /tmp/fartifact/webserveraccess.log

echo "creating upload folder \n "
if [ -d "/tmp/fartifactupload" ]; then rm -Rf /tmp/fartifactupload; fi
mkdir /tmp/fartifactupload

echo "add files to zip file"
name=$(hostname)_
time=$(date +"%Y.%m.%d.%H.%M").zip
 
filename=$name$time
echo  "file created at /tmp/fartifactupload/: "$filename 
zip -r "/tmp/fartifactupload/$filename" /tmp/fartifact/
echo "ls folder /tmp/fartifactupload/"
 

echo '\n \n sending files to server \n'
 
#sshpass -p 'password' scp -o StrictHostKeyChecking=no  /tmp/fartifactupload/* server@172.16.124.212:/home/admin/Dropbox/hacksmith/Arsenal/splunk/
 
echo "Done...!!!"
