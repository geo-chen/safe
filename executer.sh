#!/bin/bash

echo " If you are use this for the first time make sure to change evidence upload location on your host machine. "

echo "Example: change this </home/master/Dropbox/hacksmith/test/> to your destination folder "
echo 'if you want to do automated forensic investigation on random machines, press "r" '
echo 'if you want to do automated forensic investigation on selected machine, press "u" '

read instructions

if [ $instructions = "r" ]
then 

echo "please enter number of random machines you need to check : " 

read numberofmachines
#if [ ! -z "$numberofmachies" ]; then echo "number of machines count cannot be empty";
#exit 1
#fi
if [ $numberofmachines = "1" ]
   then
#sshpass -p '123' scp -r /tmp/fartifactupload/archive-ubuntu-2019-12-05.zip master@172.20.10.4:/home/master/Dropbox/hacksmith/test/evidence.zip
   sshpass -p '123'  ssh linux1@172.20.10.6 sudo sh < fscript-final.sh
exit 1

elif [ $numberofmachines = "2" ]
 then 
ssh linux1@172.16.44.156 sudo sh < fscript-final.sh
  exit 1

else
    echo "please check your input"
    exit 1
fi


elif [ $instructions = "u" ]
then
echo "please run the following command"
echo "(1). ssh <UserName>@<IP> sudo sh < /home/master/fscript-final.sh"
echo "(2). make sure to change <UserName> field with administrator/root previlege user and <IP> fiel with remote machine IP"
echo "(3). enter password for User"
exit 1

fi
