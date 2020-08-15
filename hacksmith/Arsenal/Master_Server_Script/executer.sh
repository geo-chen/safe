#!/bin/sh
echo ''
echo ''
echo '                                           ,,                                             ,,                   ,,                                '
echo ' .M"""bgd                                `7MM                 db                        `7MM                   db                                '
echo ',MI    "Y                                  MM                ;MM:                         MM                                                     '
echo '`MMb.     ,6"Yb. `7MMpMMMb.pMMMb.`7MMpdMAo.MM .gP"Ya        ,V^MM.   `7MMpMMMb.  ,6"Yb.   MM`7M`   `MF,pP"Ybd`7MM `7MMpMMMb. .P"Ybmmm            '
echo '  `YMMNq.8)   MM   MM    MM    MM  MM   `WbMM,M`   Yb      ,M  `MM     MM    MM 8)   MM   MM  VA   ,V 8I   `"  MM   MM    MM:MI  I8              '
echo '.     `MM ,pm9MM   MM    MM    MM  MM    M8MM8M""""""      AbmmmqMA    MM    MM  ,pm9MM   MM   VA ,V  `YMMMa.  MM   MM    MM WmmmP"              '
echo 'Mb     dM8M   MM   MM    MM    MM  MM   ,APMMYM.    ,     A`     VML   MM    MM 8M   MM   MM    VVV   L.   I8  MM   MM    MM8M                   '
echo 'P"Ybmmd" `Moo9^Yo.JMML  JMML  JMML.MMbmmd.JMML`Mbmmd`   .AMA.   .AMMA.JMML  JMML`Moo9^Yo.JMML.  ,V    M9mmmP`.JMML.JMML  JMMLYMMMMMb             '
echo '                                   MM                                                          ,V                           6`     dP            '
echo '                                 .JMML.                                                     OOb"                            Ybmmmd`              '
echo '                                                                                                                                                 '
echo '                                                 ,,                                                                  ,,                          '
echo '`7MM"""YMM                                       db                  `7MM"""YMM                                      db                          '
echo '  MM    `7                                                             MM    `7                                                                  '
echo '  MM   d ,pW"Wq`7Mb,od8.gP"Ya`7MMpMMMb. ,pP"Ybd`7MM ,p6"bo ,pP"Ybd     MM   d   `7M`   `MF`,6"Yb. `7MMpMMMb.pMMMb. `7MM `7MMpMMMb. .gP"Ya`7Mb,od8'
echo '  MM""MM6W`   `WbMM` ",M`   Yb MM    MM 8I   `"  MM6M`  OO 8I   `"     MMmmMM     `VA ,V` 8)   MM   MM    MM    MM   MM   MM    MM,M`   Yb MM` "`'
echo '  MM   Y8M     M8MM   8M"""""" MM    MM `YMMMa.  MM8M      `YMMMa.     MM   Y  ,    XMX    ,pm9MM   MM    MM    MM   MM   MM    MM8M"""""" MM    '
echo '  MM    YA.   ,A9MM   YM.    , MM    MM L.   I8  MMYM.    ,L.   I8     MM     ,M  ,V` VA. 8M   MM   MM    MM    MM   MM   MM    MMYM.    , MM    '
echo '.JMML.   `Ybmd9.JMML.  `Mbmmd.JMML  JMMLM9mmmP`.JMMLYMbmd` M9mmmP`   .JMMmmmmMMM.AM.   .MA`Moo9^Yo.JMML  JMML  JMML.JMML.JMML  JMML`Mbmmd.JMML.  '
echo ''
echo ''
echo "Please make sure the upload folder is configured correctly. (Hardcoded for now)"
echo "Example: change this </home/master/Dropbox/hacksmith/test/> to your destination folder "
echo 'To run forensics on a sampled pool of servers, press "r" '
echo 'To run forensics on a specified list of server/s, press "u" '
echo 'Press "h" for help ' 

read instructions
if [ $instructions = "r" ]
then 
echo ''
printf "Please enter Master Server HostName : " 
read masterserver
echo ''
echo ''
printf "Please enter the username: " 
read username
echo ''
###echo -n "Please enter the password" 
###read -s password
stty -echo
printf "Password: "
read password
stty echo
printf "\n"
echo ''
echo "Please enter the desired confidence interval (1 to 100):"
echo "( 1 means, I have no confident about the system. 100 means, my system is 100 secured.) " 
read confidenceinterval
echo ''
population=$(wc -l server-list.txt |cut -d " " -f1) 
samplesize=$(python sampling.py $population $confidenceinterval)
echo "Population of "$population" with 95% Confidence Level and "$confidenceinterval" Confidence Interval of requires a sample size of "$samplesize
numberofmachines=$samplesize
echo ''
echo 'Sample size is ' $numberofmachines
echo ''
randomip=$(shuf -i 1-$samplesize -n 1)
echo 'Random Sample possition: ' $randomip
# Run script for each sampled machines
while [ $numberofmachines -gt 0 ]; do
              
randomip=$(shuf -i 1-$samplesize -n 1);

ip=$(awk "NR==$randomip" server-list.txt);
echo 'Random Server IP: ' $ip ; 

# identify IP or hostname based on TTL and extract the TTL to determind remote host OS. 
if [ $(ping -c1 $ip |grep -i "ttl" |cut -d " " -f6 |cut -d "=" -f1) -eq "ttl" ]
then 
ttlvalue=$(ping -c1 $ip |grep -i "ttl" |cut -d " " -f6 |cut -d "=" -f2);
else
ttlvalue=$(ping -c1 $ip |grep -i "ttl" |cut -d " " -f7 |cut -d "=" -f2)

fi
# check for linux machine
if [ $ttlvalue -gt 55 -a $ttlvalue -lt 70 ];
 then
echo $ip ' is a linux machine' ;
  numberofmachines=$((numberofmachines-1))
 # we can improve here to get the linux binary with cp command from the dropbox (but remote machine need to have dropbox)
# copy the forensic script into remote machine
sshpass -p $password scp /home/$username/Dropbox/hacksmith/Arsenal/Linux_Script/linuxforensics.sh  $username@$ip:/tmp/linuxforensics.sh
# run the forensic script inside the remote machine
sshpass -p $password ssh -l $username -o StrictHostKeyChecking=no $ip <<EOFL

echo -e "$password\n"  | sudo -S whoami && sudo su

chmod a+x /tmp/linuxforensics.sh
cd /tmp && sh ./linuxforensics.sh

 
sshpass -p $password scp -o StrictHostKeyChecking=no  /tmp/fartifactupload/* $username@$masterserver:/home/$username/Dropbox/hacksmith/Arsenal/splunk/
rm -rf /tmp/linuxforensics.sh

EOFL
#check for Windows machine
elif [ $ttlvalue -gt 120 -a $ttlvalue -lt 130 ];
then 
echo $ip ' is a windows machine';
  numberofmachines=$((numberofmachines-1));

sshpass -p $password ssh -l $username -o StrictHostKeyChecking=no $ip powershell.exe  < /home/$username/Dropbox/hacksmith/Arsenal/Windows_Script/powershellscript.ps1 &

#sshpass -p $password ssh -l $username -o StrictHostKeyChecking=no $ip powershell.exe <<EOFWEOFW

else
echo 'check the ttl values for: ' $ttlvalue ;
fi
wait

done < server-list.txt
# --------------------------------------------------------------------------
elif [ $instructions = "h" ] 
then

echo "
username = remore server ssh username
password= remote server ssh password
";

elif [ $instructions = "u" ] 
then
echo "please run the following command on selected server/s. 

sshpass -p [password] ssh -l [username] -o StrictHostKeyChecking=no [ip] sudo sh < linuxforensics.sh 
";

fi
