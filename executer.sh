#!/bin/bash

echo " If you are use this for the first time make sure to change evidence upload location on your host machine. "

echo "Example: change this </home/master/Dropbox/hacksmith/test/> to your destination folder "
echo 'if you want to do automated forensic investigation on sampled machines, press "r" '
echo 'if you want to do automated forensic investigation on selected machine, press "u" '

read instructions

if [ $instructions = "r" ]
then 
echo 'For a pool of 10 servers, with a 95% confidence level and confidence interval of 45, the sample size would be 3.'
echo 'For a pool of 100 servers, with a 95% confidence level and confidence interval of 45, the sample size would be 5.'
echo 'Current pool of servers:'
echo '1. hslxpdwbwm01'
echo '2. hslxpdwbwm02'
echo '3. hslxpdwbwm03'
echo '4. hslxpdwbwm04'
echo '5. hswnpdwbwm05'
echo '6. hswnpdwbwm06'
echo '7. hswnpdwbwm07'
echo '8. hswnpdwbwm08'
echo '9. hswnpdwbwm09'
echo '10. hswnpdwbwm10'


echo "please enter number of sample size: " 

read numberofmachines
#if [ ! -z "$numberofmachies" ]; then echo "number of machines count cannot be empty";
#exit 1
#fi
if [ $numberofmachines = "1" ]
   then
1. hslxpdwbwm01
#sshpass -p '123' scp -r /tmp/fartifactupload/archive-ubuntu-2019-12-05.zip master@172.20.10.4:/home/master/Dropbox/hacksmith/test/evidence.zip
   sshpass -p '123'  ssh linux1@172.20.10.10 sudo sh < linuxforensics.sh
exit 1

elif [ $numberofmachines = "2" ]
 then 
echo 'Selected servers:'
echo '1. hslxpdwbwm01'
echo '2. hslxpdwbwm03'

sshpass -p '123' ssh linux1@172.20.10.10 sudo sh < linuxforensics.sh
sshpass -p '123' ssh administrator@172.20.10.7 powershell.exe < powershellscript.ps1


  exit 1

elif [ $numberofmachines = "3" ]
 then 
echo 'Selected servers:'
echo '1. hslxpdwbwm01'
echo '2. hslxpdwbwm03'
echo '3. hswnpdwbwm05'

sshpass -p '123' ssh linux1@172.20.10.10 sudo sh < linuxforensics.sh
#sshpass -p '123' ssh administrator@172.20.10.7 powershell.exe < powershellscript.ps1
sshpass -p '123' ssh linux2@172.20.10.8 sudo sh < linuxforensics.sh

  exit 1
else
    echo "please check your input"
    exit 1
fi


elif [ $instructions = "u" ]
then
echo "please run the following command"
echo "(1). ssh <UserName>@<IP> sudo sh < /home/master/fscript-final.sh"
echo "(2). make sure to change <UserName> field with administrator/root privilege user and <IP> field with remote machine IP"
echo "(3). enter password for User"
exit 1

fi
