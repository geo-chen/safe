#!/bin/bash

# This is written by @securitySura
# this is an acquisition tool for linux forensic artifacts
# need root access 
# ssh linux1@172.16.44.156 sudo sh < /home/master/fscript-final.sh


echo "create folder to save files \n "
if [ -d "/tmp/fartifact" ]; then rm -Rf /tmp/fartifact; fi
mkdir /tmp/fartifact

echo "dumping password file \n"
cat /etc/passwd | cut -d ":" -f1 | sort -u > /tmp/fartifact/userlist.log
echo "done..!!! \n"

echo "list all the root users \n"
grep -v -E "^#" /etc/passwd 2>/dev/null| awk -F: '$3 == 0 { print $1}' > /tmp/fartifact/rootusers.log
echo "done..!!! \n"

echo "dumping network statistic \n"
# netstat -pant  | awk '{print $5}' | grep -v "0.0.0.0" | cut -d ":" -f1 | grep -v "and" | grep -v "Address" | sort -u > /tmp/fartifact/externalIPs.log

netstat -panut | grep -v "udp6\|tcp6" | awk '{print $1, $4, $5, $6}'  | sort -u > /tmp/fartifact/externalIPs.log
echo "done..!!! \n"

echo "dumping hidden files belongs to other users \n"
find / -name ".*" -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; | grep -v "Permission denied" | grep -v "root root" | awk '{print $3, $9}' > /tmp/fartifact/hiddenfilesforotherusers.log
echo "done..!!! \n"

echo "dumping process statistic \n"
ps -a | awk '{print $1, $4}' > /tmp/fartifact/pidpsname.log
echo "done..!!! \n"

echo "dumping users crontab details \n"
cat /etc/passwd | cut -d ":" -f1 | while read users; do crontab -u $users -l;done > /tmp/fartifact/userscrontab.log
echo "done..!!! \n"

echo "dumping auto start services \n"
ls -all /etc/init.d/ /lib/systemd/system/ /etc/systemd/system/ >> /tmp/fartifact/autostartservices.log
echo "done..!!! \n"

echo "dumping bad logins"

lastb > /tmp/fartifact/badlogins.log


echo "coping log files ....!!! \n"
cp /var/log/auth.log /tmp/fartifact/sshaccess.log
cp /var/log/apache2/error.log /tmp/fartifact/webservererror.log
cp /var/log/apache2/access.log /tmp/fartifact/webserveraccess.log
echo "log dump done..!!! \n"

echo "create folder to upload \n "
if [ -d "/tmp/fartifactupload" ]; then rm -Rf /tmp/fartifactupload; fi
mkdir /tmp/fartifactupload
echo "send files to master server \n"

echo "add files to zip file"
name=$(hostname)
time=$(date +"%Y-%m-%d").zip
echo $name
echo $time
filename=$name.$time
#zip -r "/tmp/fartifactupload/archive-$(hostname)-$(date +"%Y-%m-%d").zip" /tmp/fartifact/
zip -r "/tmp/fartifactupload/$filename" /tmp/fartifact/

echo '\n \n sending files to server \n'

###sshpass -p '123' scp -r /tmp/fartifactupload/archive-ubuntu-2019-12-05.zip master@172.20.10.4:/home/master/Dropbox/hacksmith/test/evidence.zip

sshpass -p '123' scp -r /tmp/fartifactupload/$filename master@172.20.10.4:/home/master/Dropbox/hacksmith/test/$filename
