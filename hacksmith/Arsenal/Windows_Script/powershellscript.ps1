
#created by SecuritySura for Telok Blanga Team at Blackhat Asia competition on 2k19-12-07
#ssh user@172.20.10.5 powershell.exe .\ < powershellscript.ps1
$username = ($env:UserName)
$deleteupload = "c:\upload"
If (Test-Path $deleteupload)
{
 Remove-Item -LiteralPath $deleteupload -Force -Recurse
}

$deletetmp = "c:\tmp"
If (Test-Path $deletetmp)
{
 Remove-Item -LiteralPath $deletetmp -Force -Recurse
}

New-Item -ItemType directory -Path C:\tmp
New-Item -ItemType directory -Path C:\upload

#Dumping Logs with  psloglist.exe binary. 

C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  Application > c:\tmp\Application.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  Security > c:\tmp\Security.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  System > c:\tmp\System.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  "Windows PowerShell" > c:\tmp\Windows_PowerShell.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  "Windows Azure" > c:\tmp\Windows_Azure.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  Parameters > c:\tmp\Parameters.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  "Internet Explorer" > c:\tmp\Internet_Explorer.csv
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\.\psloglist.exe /accepteula -s -x  HardwareEvents > c:\tmp\HardwareEvents.csv
# Dumping process tree details with pslist.exe binary
C:\Users\admin\Dropbox\hacksmith\Arsenal\Windows_Binary\pslist.exe /accepteula -t -nobanner pid > c:\tmp\Processtree.log
#Dumping ExternalIPs
netstat -ano  | Where-Object {$_ -NotMatch "Active"}  | Where-Object {$_ -NotMatch "Proto"}  | Where-Object {$_ -NotMatch "\["}  > C:\tmp\externalIPs.log
#Dumping startup process
Get-CimInstance win32_service -Filter "startmode = 'auto'" | Out-File -FilePath "c:\tmp\startupprocess.log" -Encoding ASCII
#Dumping local users
Get-LocalUser | Out-File -FilePath "c:\tmp\localusers.log" -Encoding ASCII
# Dumping process list
Get-Process | Out-File -FilePath "c:\tmp\Processlist.log" -Encoding ASCII

$date =  Get-Date -format "yyyy.MM.dd.hh.mm"
$comname = hostname
$concot = "_"
$filename = $comname + '_' + $date 
$extention = ".zip"
$archive = $filename + $extention
$sourcepath = 'c:\tmp\'
$destpath = 'c:\upload\' + $filename
$uploadpath = 'c:\upload\' + $archive
$ultimatepath = 'C:\Users\' + $username + '\Dropbox\hacksmith\Arsenal\splunk\' 
If(!(test-path $ultimatepath))
{
      New-Item -ItemType Directory -Force -Path $ultimatepath
}
compress-archive -path $sourcepath -destinationpath $uploadpath
Copy-Item $uploadpath $ultimatepath



