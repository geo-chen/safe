
#created by SecuritySura for Telok Blanga Team at Blackhat Asia competition on 2k19-12-07
#ssh user@172.20.10.5 powershell.exe .\ < powershellscript.ps1
$deleteupload = "c:\upload"
If (Test-Path $deleteupload)
{
 #Remove-Item $deleteupload
 Remove-Item -LiteralPath $deleteupload -Force -Recurse
}
$deletetmp = "c:\tmp"
If (Test-Path $deletetmp)
{
 # Remove-Item $deletetmp
 Remove-Item -LiteralPath $deletetmp -Force -Recurse
}
New-Item -ItemType directory -Path C:\tmp
New-Item -ItemType directory -Path C:\upload


netstat -ano  | Where-Object {$_ -NotMatch "Active"}  | Where-Object {$_ -NotMatch "Proto"}  | Where-Object {$_ -NotMatch "\["}  > C:\tmp\externalIPs.log
Get-WinEvent -LogName "Security" | Out-File -FilePath "c:\tmp\Security.log" -Encoding ASCII
#Get-WinEvent -LogName "System" > c:\tmp\System.log
Get-WinEvent -LogName "System" | Out-File -FilePath "c:\tmp\System.log"-Encoding ASCII
#Get-WinEvent -LogName "Application" > c:\tmp\Application.log
Get-WinEvent -LogName "Application" | Out-File -FilePath "c:\tmp\Application.log" -Encoding ASCII
#Get-CimInstance win32_service -Filter "startmode = 'auto'" > c:\tmp\startupprocess.log
Get-CimInstance win32_service -Filter "startmode = 'auto'" | Out-File -FilePath "c:\tmp\startupprocess.log" -Encoding ASCII
#Get-LocalUser > c:\tmp\localusers.log
Get-LocalUser | Out-File -FilePath "c:\tmp\localusers.log" -Encoding ASCII
#Get-Process  > c:\tmp\Processlist.log
Get-Process | Out-File -FilePath "c:\tmp\Processlist.log" -Encoding ASCII


#netstat -ano  | Where-Object {$_ -NotMatch "Active"}  | Where-Object {$_ -NotMatch "Proto"}  | Where-Object {$_ -NotMatch "\["}  > #C:\tmp\externalIPs.log
#Get-WinEvent -LogName "Security" > c:\tmp\Security.log
#Get-WinEvent -LogName "System" > c:\tmp\System.log
#Get-WinEvent -LogName "Application" > c:\tmp\Application.log
#Get-CimInstance win32_service -Filter "startmode = 'auto'" > c:\tmp\startupprocess.log
#Get-LocalUser > c:\tmp\localusers.log
#Get-Process  > c:\tmp\Processlist.log

$date =  Get-Date -format "yyyy.MM.dd.hh.mm"
$comname = hostname
$concot = "_"
$filename = $comname + '_' + $date 
$extention = ".zip"
$archive = $filename + $extention
$sourcepath = 'c:\tmp\'
$destpath = 'c:\upload\' + $filename
$uploadpath = 'c:\upload\' + $archive
$ultimatepath = 'C:\Users\User\Dropbox\hacksmith\test\'
compress-archive -path $sourcepath -destinationpath $destpath
Copy-Item $uploadpath $ultimatepath



