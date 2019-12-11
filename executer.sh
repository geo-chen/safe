#!/bin/bash
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
echo 'To run forensics on a specified list of servers, press "u" '

read instructions

if [ $instructions = "r" ]
then 
echo 'For the current list of 10 servers, a 95% confidence level and confidence interval of 45 would require a sample size of 3.'
#echo 'For a pool of 100 servers, using a 95% confidence level and confidence interval of 45, the sample size would be 5.'
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
