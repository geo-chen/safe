# Sample Analysing Forensics Examiner (SAFE)

Security incidents are usually created by alerts or events, which are based on a small set of forwarded logs. When a server is suspected to be compromised, we go back to the host machine to perform forensics on the rest of the logs to investigate the network traffic and endpoint.

Sample Analysing Forensics Examiner (SAFE) enables security administrators/engineers to run automated forensics investigations effortlessly on a selected set of machines, either specified or via sampling, to get individual baseline threat scores on the likelihood of a server compromise. A number of logs, including web server, syslog, system, network logs are surveyed for this analysis. With SAFE, security engineers can easily survey a selected pool of servers to hunt for any potential infection or compromise.
<details>
  <summary>Details</summary>
  
  #### Problems
  1. [accuracy] Misses (FNs) on security threat detections (reactive) are common, many of which are only discovered during in-depth forensics investigation.
  2. [cost] While forensics investigation is accurate (richer logs), it’s expensive, and is usually only conducted when machine is suspected to be compromised.
  3. [time] We (incident response team) spend a lot of time manually reviewing forensics artefacts for various incidents
  4. [scalability] It’s virtually impossible to conduct forensics investigations over many servers in a scalable manner.

  #### Proposed Solution – Finding evil in an automated, scalable manner
Using a proactive and sampling approach, our tool automatically conducts a basic forensics investigations on an identified healthy (we would like to assume compromised) pool of servers to get threat scores, flagging out suspected compromised machines for further investigations.

  #### Target Users
  1. Security Incident Responders
  2. L3 SOC
  3. Server Owners
</details>

There are four main features in SAFE:
 1. Sampling based on 95% confidence level and stipulated confidence interval
 2. Acquisition of forensics artefacts on host machines
 3. Automatic remote orchestration and log ingestion
 4. Analysis to churn out a threat score that is indicative of the likelihood of server compromise

## 1. Sampling
Sampling is used on larger pools of servers where we either want confirmation on the security health of target pool, or perform threat hunting (in this case, potentially undetected compromised servers).

Sampling is based on 95% Confidence Level, a chosen Confidence Interval between 1 to 100, and the population size. 

In our demonstration, our naming convention for host "hslxpdwbvm01" is as follows:
  + hs - hacksmith (or whichever workgroup naming you have)
  + lx - linux
  + pd - production environment
  + wb - web server
  + vm - VM as the type of server
  + 01 - index number 1

![safe-6](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-6-2.png)

## 2. Forensics Acquisition Scripts
Current forensics scripts come in two flavours - Linux and Windows. These scripts:
 1. Collect filtered log entries for the purpose of threat scoring
 2. Collect all other useful logs for manual investigations
 
## 3. Remote Orchestration & Log Ingestion
Remote orchestration on target machines can be configured using any one of the following options:
 1. SSH Keys
 2. Role-based user with administrative privileges
 3. Service account with administrative privileges
 4. If SSH service is exposed, using SSH credentials
 
Without sudo/admin rights, log collection would be limited. 

The current setup provides two options for log ingestion:
 1. Splunk forwarder - installing Splunk forwarder on the master server where the forensics scripts are run.
 2. Dropbox - setting up syncing Dropbox folders on master server and Splunk server.
 
In our tests over mobile network, the time taken for syncing and ingesting was within ten seconds.

## 4. Analysis and Threat Scoring
3 Levels of rules are performed. First level is the "Base" rules where forensics log statistics are filtered according to predefined criteria and thresholds to highlight notable events. The second level, "Baseline" rules compares the current statistics with the previous capture that is at least 48 hours ago to highlight changes from the previous benchmark. The third level, "Notable Scoring", picks up the notable events created by the first two levels of rules, and applies individual points to calculate an eventual threat score for the various hosts.

### i. Base (Condition) Rules - > Summary/Notable Events

| Log  | Criteria | Points |
| ------------- | ------------- | ------ | 
| netstat  | for non-internet routed hosts, and for each foreign address that is external and not whitelisted or trusted |    +5 |
| netstat | for each ephemeral (or in watchlist) port, from foreign address that is external | +3 |
| lastb | bad login ratio for past 24 hours | + (ratio * 100) |
| /var/log/auth.log | for each user that has at least 1 failed login within past week | +2 |
| webserver | for each unique IP that is associated with bad activity (based on Intel) | +3 |
| webserver | for each unique URI path that contains a malicious payload (based on OWASP 10, payloads) that’s not http 200 | +3 | 
| ls -lap /tmp | new /tmp/* files (by create date) + other world-writable directories | +1 |
| crontab | for each modified cronjob | +5 | 
| /etc/passwd | new root user | +20 | 
| ... | ... | ... | 


<details>
  <summary>Base Rules</summary>

`Base - Bad IP`
```
index=safe source="*webserveraccess.log" earliest=-1d
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host
| rename src_ip as ip
| eval points = 3
| eval concat = host . ip
| search NOT [search index=summary source="Base - Bad IP" earliest=-1d | table ip,orig_host | eval concat = orig_host . ip | table concat]
| fields host, ip, points
| collect index=summary sourcetype=stash source="Base - Bad IP" marker="tier=base"
```

`Base - Bad Logins`
```
index="safe" source="*badlogins.log" earliest=-1d
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex "(?<user>[a-zA-Z0-9]+)\ .+" max_match=0
| stats count by user, host
| eval points = 3
| eval concat = user . host
| search NOT user = "btmp"
| search NOT [search index=summary source="Base - Bad Logins" earliest=-1d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Base - Bad Logins" marker="tier=base"
```

`Base - New Root Users`
```
index=safe source="*rootusers.log" earliest=-1d
| rex "(?<user>.+)" max_match=0
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by user, host
| search NOT user IN ("root") `comment("whitelist")`
| eval points = 20
| eval concat = user . host
| search NOT [search index=summary source="Base - New Root Users" earliest=-1d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Base - New Root Users" marker="tier=base"
```

`Base - OWASP Payloads`
```
index=safe source=*webserveraccess.log earliest=-1d
| rex "[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?<status>\d\d\d)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?<uri>[^ ]+)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^=]+\=(?<query>[^ ]+)\ .+" 
| eval uri_query=replace(coalesce(query,uri),"\"","")
| rex "^(?<src_ip>[^ ]+)\ .+" 
| where status!=200 `comment("general assumption made is that 200 means well handled. not fully accurate of course")` 
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host, uri_query
| rename uri_query as payload
| lookup payloads.csv payload
| where isnotnull(attack)
| eval points = 3
| eval concat = host . payload
| search NOT [search index=summary source="Base - OWASP Payloads" earliest=-1d | table payload,orig_host | eval concat = orig_host . payload | table concat]
| fields host, payload, points
| collect index=summary sourcetype=stash source="Base - OWASP Payloads" marker="tier=base"
```

`Base - RDP Connections Bypassing Bastion`
```
index=safe source="*RemoteConnectionManager_Operational.xml" earliest=-1d 
| spath
| rename Event.UserData.EventXML.Param3 as src
| rename Event.System.Computer as host
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+" 
| search NOT src IN ("172.16.124.5","172.16.124.135","172.16.124.133") `comment("Bastion IPs")` 
| stats count by src, host 
| eval points = 5 
| eval concat = host . src  
| search NOT 
    [ search index=summary source="Base - RDP Connections Bypassing Bastion" earliest=-1d 
    | table status,src 
    | eval concat = orig_host . src  
    | table concat]
| collect index=summary sourcetype=stash source="Base - RDP Connections Bypassing Bastion" marker="tier=base"
```

`Base - SSH Connections Bypassing Bastion`
```
index=safe source=*sshaccess.log "Accepted password for" earliest=-1d 
| rex "(?<src>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})" 
| rex "Accepted\ password\ for\ (?<user>[^ ]+)\ .+" 
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+" 
| search NOT src IN ("172.16.124.5","172.16.124.135","172.16.124.133") `comment("Bastion IPs")` 
| stats count by src, user, host 
| eval points = 5 
| eval concat = host . src . user 
| search NOT 
    [ search index=summary source="Base - SSH Connections Bypassing Bastion" earliest=-1d 
    | table status,src,user 
    | eval concat = orig_host . src . user 
    | table concat] 
| collect index=summary sourcetype=stash source="Base - SSH Connections Bypassing Bastion" marker="tier=base"
```

`Base - Suspicious Windows Processes`
```
index=safe source="*/Security.xml" earliest=-1d
| spath
| search "Event.EventData.Data{@Name}"=ProcessName 
| rex field=_raw max_match=20 "ProcessName\'\>(?<process_name>[^\<]+)\<" 
| rex field=process_name max_match=20 ".+[\\\](?<process_name>[^\\\]+)$" 
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| search process_name IN ("*whois64.exe","*whois.exe","*vmmap.exe","*sync64.exe","*sync.exe","*strings64.exe","*strings.exe","*streams64.exe","*streams.exe","*sigcheck64.exe","*sigcheck.exe","*sdelete64.exe","*sdelete.exe","*ru64.exe","*ru.exe","*regjump.exe","*pssuspend64.exe","*pssuspend.exe","*psshutdown.exe","*psping64.exe","*psping.exe","*pspasswd64.exe","*pspasswd.exe","*psloglist64.exe","*psloglist.exe","*pslist64.exe","*pslist.exe","*pskill64.exe","*pskill.exe","*psfile64.exe","*psfile.exe","*procexp64.exe","*procexp.exe","*procdump64.exe","*procdump.exe","*portmon.exe","*pipelist64.exe","*pipelist.exe","*pendmoves64.exe","*pendmoves.exe","*pagedfrg.exe","*ntfsinfo64.exe","*ntfsinfo.exe","*notmyfaultc64.exe","*notmyfaultc.exe","*notmyfault64.exe","*notmyfault.exe","*movefile64.exe","*movefile.exe","*logonsessions64.exe","*logonsessions.exe","*livekd64.exe","*livekd.exe","*ldmdump.exe","*junction64.exe","*junction.exe","*hex2dec64.exe","*hex2dec.exe","*handle64.exe","*handle.exe","*efsdump.exe","*du64.exe","*du.exe","*diskext64.exe","*diskext.exe","*disk2vhd.exe","*ctrl2cap.exe","*autorunsc64.exe","*autorunsc.exe","*adrestore.exe","*accesschk64.exe","*accesschk.exe","*ZoomIt.exe","*Winobj.exe","*Volumeid64.exe","*Volumeid.exe","*Testlimit64.exe","*Testlimit.exe","*Tcpview.exe","*Tcpvcon.exe","*Sysmon64.exe","*Sysmon.exe","*ShellRunas.exe","*ShareEnum.exe","*RegDelNull64.exe","*RegDelNull.exe","*RAMMap.exe","*PsService64.exe","*PsService.exe","*PsLoggedon64.exe","*PsLoggedon.exe","*PsInfo64.exe","*PsInfo.exe","*PsGetsid64.exe","*PsGetsid.exe","*PsExec64.exe","*PsExec.exe","*Procmon64.exe","*Procmon.exe","*LoadOrdC64.exe","*LoadOrdC.exe","*LoadOrd64.exe","*LoadOrd.exe","*Listdlls64.exe","*Listdlls.exe","*FindLinks64.exe","*FindLinks.exe","*Diskmon.exe","*DiskView.exe","*Desktops.exe","*Dbgview.exe","*Coreinfo64.exe","*Coreinfo.exe","*Contig64.exe","*Contig.exe","*Clockres64.exe","*Clockres.exe","*Cacheset.exe","*CPUSTRES64.EXE","*CPUSTRES.EXE","*Bginfo64.exe","*Bginfo.exe","*Autoruns64.exe","*Autoruns.exe","*Autologon.exe","*AccessEnum.exe","*ADInsight.exe","*ADExplorer.exe")
| eval points = 20
| eval concat = host . process_name
| search NOT [search index=summary source="Base - Suspicious Windows Processes" earliest=-1d | table orig_host,process_name | eval concat = orig_host . process_name | table concat]
| fields host, payload, points
| collect index=summary sourcetype=stash source="Base - Suspicious Windows Processes" marker="tier=base"
```

`Base - Vulnerability Scanning On Web Server`
```
index=safe source=*webserveraccess.log earliest=-1d
| rex "[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?<status>\d\d\d)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?<uri>[^ ]+)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^=]+\=(?<query>[^ ]+)\ .+" 
| eval uri_query=replace(coalesce(query,uri),"\"","")
| rex "^(?<src_ip>[^ ]+)\ .+" 
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats dc(uri_query) as dc_uri_query count by src_ip, host
| where dc_uri_query > 500 AND count > 1000
| eval points = 3
| eval concat = host . src_ip
| search NOT [search index=summary source="Base - Vulnerability Scanning On Web Server" earliest=-1d | table src_ip,orig_host | eval concat = orig_host . src_ip | table concat]
| fields host, src_ip, points
| collect index=summary sourcetype=stash source="Base - Vulnerability Scanning On Web Server" marker="tier=base"
```

`Base - Web Server Errors`
```
index=safe source=*webserveraccess.log earliest=-1d
| rex "[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?<status>\d\d\d)\ .+"
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats first(_time) as time count by host, status
| where status > 499
| eval points = 3
| eval concat = host . status . time
| search NOT [search index=summary source="Base - Server Errors" earliest=-1d | table status,orig_host,time | eval concat = orig_host . status . time | table concat]
| fields host, status, points, time
| collect index=summary sourcetype=stash source="Base - Web Server Errors" marker="tier=base"
```

`Base - Suspicious Cron Jobs`
```
index=safe source="*/userscrontab.log" TERM(nc) OR TERM(wget) OR TERM(curl) OR TERM(ncat) OR TERM(fping) OR "/dev/null" earliest=-1d
| rex "(?m)^(?<cron>[^#\r\n]+)" max_match=500
| eval cron=rtrim(cron," ")
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by cron, host
| eval points = 10
| eval concat = host . cron
| search NOT [search index=summary source="Base - Suspicious Cron Jobs" earliest=-1d | table cron,orig_host | eval concat = orig_host . cron | table concat]
| fields host, cron, points
| collect index=summary sourcetype=stash source="Base - Suspicious Cron Jobs" marker="tier=base"
```

`Base - Web Shells`
```
index=safe source="*/webserveraccess.log" earliest=-1d "cmd=*nc" OR "cmd=*/bash" OR "cmd=*ncat" OR "cmd=*netcat"
| rex "\?(?<uri_query>[^ ]+)"
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by host, uri_query
| eval points = 10
| eval concat = host . uri_query
| search NOT [search index=summary source="Base - Web Shells" earliest=-1d | table uri_query,orig_host | eval concat = orig_host . uri_query | table concat]
| fields host, uri_query, points
| collect index=summary sourcetype=stash source="Base - Web Shells" marker="tier=base"
```

</details>

### ii. Baseline (Comparison) Rules - > Summary/Notable Events

| Log  | Criteria | Points |
| ------------- | ------------- | ------ | 
| ps -aux | for each newly identified process that is not whitelisted | +5 |
| ps -aux | for each newly identified user based on process | +1 |
| ~/.ssh/authorized_keys | for each newly added SSH key | +20 |
| ~/.ssh/known_hosts | for each newly added known host | +10 |
| /etc/passwd | for each newly added user | +5 |
| ... | ... | ... | 


<details>
  <summary>Baseline Rules</summary>

`Baseline - New Autostart Services`
```
index=safe source="*/autostartservices.log" earliest=-1d
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex ".+\ (?<service>[^ ]+)[\r\n.]" max_match=0
| stats count by service, host
| where len(service)>3
| search NOT service IN ("") `comment("whitelist")`
| eval points = 5
| eval concat = service . host
| search NOT [search index=summary source="Baseline - New Autostart Services" earliest=-7d | table service,orig_host | eval concat = service . orig_host | table concat]
| fields service, host, points
| collect index=summary sourcetype=stash source="Baseline - New Autostart Services" marker="tier=baseline"
```

`Baseline - New Cron Jobs`
```
index=safe source="*/userscrontab.log" earliest=-1d
| rex "(?m)^(?<cron>[^#\r\n]+)" max_match=0
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by cron, host
| eval points = 5
| eval concat = host . cron
| search NOT [search index=summary source="Baseline - New Cron Jobs" earliest=-7d | table orig_host,cron | eval concat = orig_host.cron | table concat]
| fields cron, host, points
| collect index=summary source="Baseline - New Cron Jobs" marker="tier=baseline"
```

`Baseline - New Hidden Files`
```
index=safe source=*/hiddenfilesforotherusers.log earliest=-1d
| rex field=_raw "(?m)^(?<user>[^ ]+)\ (?m)(?<hidden_files>[^ ]+)$" max_match=400
| rex field=source ".+\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex mode=sed field=user "s/\n/ /g"
| rex mode=sed field=hidden_files "s/\n/ /g"
| eval user = ltrim(user," ")
| stats count by user, hidden_files, host
| eval points = 3
| eval concat = user . hidden_files . host
| search NOT [search index=summary source="Baseline - New Hidden Files" earliest=-7d | table user,hidden_files,orig_host | eval concat = user . hidden_files . orig_host | table concat]
| fields user, hidden_files, host, points
| collect index=summary sourcetype=stash source="Baseline - New Hidden Files" marker="tier=baseline"
```

`Baseline - New Identified Windows Processes`
```
index=safe source="*/Processlist.log" earliest=-1d
| rex field=_raw max_match=300 "\ \d\ (?<process_name>[^ ]+)" 
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| eval points = 4
| eval concat = host . process_name
| search NOT [search index=summary source="Baseline - New Identified Windows Processes" earliest=-7d | table orig_host,process_name | eval concat = orig_host.process_name | table concat]
| fields process_name, host, points 
| collect index=summary source="Baseline - New Identified Windows Processes" marker="tier=baseline"
```

`Baseline - New Processes`
```
index=safe source=*pidpsname.log earliest=-1d
| rex "(?<pid>\d+)\ (?<cmd>\w+)" max_match=0
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| eval time = max(_time)
| eval points = 5
| stats count by time, cmd, host, points
| eval concat = cmd . host
| search NOT [search index=summary source="Baseline - New Processes" earliest=-7d | table cmd,orig_host | eval concat = cmd . orig_host | table concat]
| fields time, cmd, host, points
| collect index=summary sourcetype=stash source="Baseline - New Processes" marker="tier=baseline"
```

`Baseline - New SSH Users`
```
index=safe source="*sshaccess.log" user earliest=-1d
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex "New\ session\ /d+ of\ user\ (?<user>[a-zA-Z0-9])"
| rex "session\ opened\ for\ user\ (?<user>[a-zA-Z0-9])\ by"
| eval time = max(_time) `comment("I know this line should go below")`
| stats count by user, host
| eval points = 10
| search NOT user IN ("sshd","mysql","gdm") `comment("whitelist")`
| eval concat = user . host
| search NOT [search index=summary source="Baseline - New Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Baseline - New Users" marker="tier=baseline"
```

`Baseline - New Startup Processes`
```
index=safe source=*startupprocess.log earliest=-1d
| rex field=_raw max_match=500 "\d+\ +(?<startup_process>[^ ]+)\ .+"
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by startup_process, host
| eval points = 5
| eval concat = host.startup_process
| search NOT [search index=summary source="Baseline - New Startup Processes" earliest=-7d | table startup_process,orig_host | eval concat = orig_host.startup_process | table concat]
| fields startup_process, host, points
| collect index=summary sourcetype=stash source="Baseline - New Startup Processes" marker="tier=baseline"
```

`Baseline - New Users`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*sshaccess.log" user earliest=-1d
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex "New\ session\ /d+ of\ user\ (?<user>[a-zA-Z0-9])"
| rex "session\ opened\ for\ user\ (?<user>[a-zA-Z0-9])\ by"
| eval time = max(_time) `comment("I know this line should go below")`
| stats count by user, host
| eval points = 10
| search NOT user IN ("sshd","mysql","gdm") `comment("whitelist")`
| eval concat = user . host
| search NOT [search index=notable search_name="Baseline - New Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
```

`Baseline - New Windows Processes`
```
index=safe source="*/Security.xml" earliest=-1d
| spath 
| search "Event.EventData.Data{@Name}"=ProcessName 
| rex field=_raw max_match=20 "ProcessName\'\>(?<process>[^\<]+)\<" 
| rex field=process max_match=20 ".+[\\\](?<process_name>[^\\\]+)$" 
| rex field=source ".+splunk\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| eval points = 4
| eval concat = host . process_name
| search NOT [search index=summary source="Baseline - New Windows Processes" earliest=-7d | table orig_host,process_name | eval concat = orig_host.process_name | table concat]
| fields process_name, host, points 
| collect index=summary source="Baseline - New Windows Processes" marker="tier=baseline"
```

</details>

### iii. Summary/Notable Scoring - > Dashboard
This is managed by our Threat Scoring Dashboard.

<details>
  <summary>Sample Analysing Forensics Examiner</summary>

```
index=summary orig_host = $server1$ | stats sum(points) as points count by orig_host, source  | eval points = min(points,100) | stats sum(points) as points count by orig_host | fields points
```
```
index=summary orig_host="$server1$" | timechart count by source
```
```
index=summary orig_host="$server1$" | stats values(*) as * count, sum(points) as points by source | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - search_name, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos - time - search_now - cmd| convert ctime(time)
```

```
<form>
  <label>Sample Analysing Forensics Examiner</label>
  <fieldset submitButton="false" autoRun="true">
    <input type="text" token="server1">
      <label>server1</label>
    </input>
    <input type="text" token="server2">
      <label>server2</label>
    </input>
    <input type="text" token="server3">
      <label>server3</label>
    </input>
    <input type="time" token="field1">
      <label></label>
      <default>
        <earliest>-24h@h</earliest>
        <latest>now</latest>
      </default>
    </input>
  </fieldset>
  <row>
    <panel>
      <single>
        <title>$server1$</title>
        <search>
          <query>index=summary orig_host = $server1$  | stats sum(points) as points count by orig_host, source  | eval points = min(points,100) | stats sum(points) as points count by orig_host | fields points</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="rangeValues">[60,100,200]</option>
        <option name="refresh.display">progressbar</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>$server2$</title>
        <search>
          <query>index=summary orig_host = $server2$  | stats sum(points) as points count by orig_host, source  | eval points = min(points,100) | stats sum(points) as points count by orig_host | fields points</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="rangeValues">[60,100,200]</option>
        <option name="refresh.display">progressbar</option>
        <option name="useColors">1</option>
      </single>
    </panel>
    <panel>
      <single>
        <title>$server3$</title>
        <search>
          <query>index=summary orig_host = $server3$  | stats sum(points) as points count by orig_host, source  | eval points = min(points,100) | stats sum(points) as points count by orig_host | fields points</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="colorMode">block</option>
        <option name="drilldown">none</option>
        <option name="rangeColors">["0x53a051","0xf8be34","0xf1813f","0xdc4e41"]</option>
        <option name="rangeValues">[60,100,180]</option>
        <option name="refresh.display">progressbar</option>
        <option name="useColors">1</option>
      </single>
    </panel>
  </row>
  <row>
    <panel>
      <chart>
        <search>
          <query>index=summary orig_host="$server1$" NOT time IN ("1598629964") earliest=-7d | timechart count by source</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <search>
          <query>index=summary orig_host="$server2$" NOT time IN ("1598629964") earliest=-7d | timechart count by source</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
    <panel>
      <chart>
        <search>
          <query>index=summary orig_host="$server3$" NOT time IN ("1598629964") earliest=-7d | timechart count by source</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="charting.chart">line</option>
        <option name="charting.drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <search>
          <query>index=summary orig_host="$server1$" | stats values(*) as * count, sum(points) as points by source | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - search_name, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos - time - search_now - cmd| convert ctime(time)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="count">10</option>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>table</title>
        <search>
          <query>index=summary orig_host="$server2$" | stats values(*) as * count, sum(points) as points by source | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - search_name, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos - time - search_now - cmd| convert ctime(time)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
    <panel>
      <table>
        <search>
          <query>index=summary orig_host="$server3$" | stats values(*) as * count, sum(points) as points by source | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - search_name, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos - time - search_now - cmd | convert ctime(time)</query>
          <earliest>$field1.earliest$</earliest>
          <latest>$field1.latest$</latest>
        </search>
        <option name="drilldown">none</option>
        <option name="refresh.display">progressbar</option>
      </table>
    </panel>
  </row>
</form>
```
</details>

<details>
  
  <summary>Sample Analysing Forensics Examiner</summary>
  
```
<form theme="dark">
  <label>SAFE - Scoring Logs</label>
  <description>Scoring ingested forensics artefacts, and generating the dashboard link to the top threats. Run " | script safe" to invoke forensics script before loading this dashboard.</description>
  <fieldset submitButton="false"></fieldset>
  <row>
    <panel>
      <input type="dropdown" token="sample">
        <label>Top N Results</label>
        <choice value="2">2</choice>
        <choice value="3">3</choice>
        <choice value="4">4</choice>
        <choice value="5">5</choice>
        <choice value="6">6</choice>
        <choice value="7">7</choice>
        <choice value="8">8</choice>
        <choice value="9">9</choice>
        <choice value="10">10</choice>
      </input>
      <table>
        <search>
          <query>index=summary 
| stats sum(points) as points count by orig_host, source 
| eval points = min(points,50) 
| stats sum(points) as points by orig_host 
| sort $sample$ -points 
| eval counter=1 
| accum counter as LineNumber 
| eval param = "form.server".LineNumber."=".orig_host 
| stats values(*) as * by counter 
| eval dashboard="http://192.168.50.75:8000/en-GB/app/search/safe?".mvjoin(param,"&amp;") 
| fields dashboard</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <refresh>5s</refresh>
          <refreshType>delay</refreshType>
        </search>
        <option name="drilldown">cell</option>
        <option name="refresh.display">progressbar</option>
        <drilldown>
          <link target="_blank">http://localhost:8000/en-GB/app/search/safe?form.server1=hslxpdfsvm01&amp;form.server2=hslxpdwbvm01&amp;form.server3=hswnpdadvm01</link>
        </drilldown>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Base - Bad IP</title>
        <search>
          <query>index=safe source="*webserveraccess.log" earliest=-1d
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host
| rename src_ip as ip
| eval points = 3
| eval concat = host . ip
| search NOT [search index=summary source="Base - Bad IP" earliest=-1d | table ip,orig_host | eval concat = orig_host . ip | table concat]
| fields host, ip, points
| collect index=summary sourcetype=stash source="Base - Bad IP" marker="tier=base"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Bad Logins</title>
        <search>
          <query>index="safe" source="*badlogins.log" earliest=-1d
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| rex "(?&lt;user&gt;[a-zA-Z0-9]+)\ .+" max_match=0
| stats count by user, host
| eval points = 3
| eval concat = user . host
| search NOT user = "btmp"
| search NOT [search index=summary source="Base - Bad Logins" earliest=-1d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Base - Bad Logins" marker="tier=base"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - New Root Users</title>
        <search>
          <query>index=safe source="*rootusers.log" earliest=-1d
| rex "(?&lt;user&gt;.+)" max_match=0
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by user, host
| search NOT user IN ("root") `comment("whitelist")`
| eval points = 20
| eval concat = user . host
| search NOT [search index=summary source="Base - New Root Users" earliest=-1d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Base - New Root Users" marker="tier=base"</query>
          <earliest>-1w</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - OWASP Payloads</title>
        <search>
          <query>index=safe source=*webserveraccess.log earliest=-1d
| rex "[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?&lt;status&gt;\d\d\d)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ (?&lt;uri&gt;[^ ]+)\ .+" 
| rex "^[^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^ ]+\ [^=]+\=(?&lt;query&gt;[^ ]+)\ .+" 
| eval uri_query=replace(coalesce(query,uri),"\"","")
| rex "^(?&lt;src_ip&gt;[^ ]+)\ .+" 
| where status!=200 `comment("general assumption made is that 200 means well handled. not fully accurate of course")` 
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host, uri_query
| rename uri_query as payload
| lookup payloads.csv payload
| where isnotnull(attack)
| eval points = 3
| eval concat = host . payload
| search NOT [search index=summary source="Base - OWASP Payloads" earliest=-1d | table payload,orig_host | eval concat = orig_host . payload | table concat]
| fields host, payload, points
| collect index=summary sourcetype=stash source="Base - OWASP Payloads" marker="tier=base"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - SSH Connections Bypassing Bastion</title>
        <search ref="Base - SSH Connections Bypassing Bastion"></search>
        <option name="count">5</option>
        <option name="drilldown">none</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Suspicious Windows Processes</title>
        <search>
          <query>index=safe source="*/Security.xml" earliest=-1d
| spath
| search "Event.EventData.Data{@Name}"=ProcessName 
| rex field=_raw max_match=20 "ProcessName\'\&gt;(?&lt;process_name&gt;[^\&lt;]+)\&lt;" 
| rex field=process_name max_match=20 ".+[\\\](?&lt;process_name&gt;[^\\\]+)$$" 
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| search process_name IN ("*whois64.exe","*whois.exe","*vmmap.exe","*sync64.exe","*sync.exe","*strings64.exe","*strings.exe","*streams64.exe","*streams.exe","*sigcheck64.exe","*sigcheck.exe","*sdelete64.exe","*sdelete.exe","*ru64.exe","*ru.exe","*regjump.exe","*pssuspend64.exe","*pssuspend.exe","*psshutdown.exe","*psping64.exe","*psping.exe","*pspasswd64.exe","*pspasswd.exe","*psloglist64.exe","*psloglist.exe","*pslist64.exe","*pslist.exe","*pskill64.exe","*pskill.exe","*psfile64.exe","*psfile.exe","*procexp64.exe","*procexp.exe","*procdump64.exe","*procdump.exe","*portmon.exe","*pipelist64.exe","*pipelist.exe","*pendmoves64.exe","*pendmoves.exe","*pagedfrg.exe","*ntfsinfo64.exe","*ntfsinfo.exe","*notmyfaultc64.exe","*notmyfaultc.exe","*notmyfault64.exe","*notmyfault.exe","*movefile64.exe","*movefile.exe","*logonsessions64.exe","*logonsessions.exe","*livekd64.exe","*livekd.exe","*ldmdump.exe","*junction64.exe","*junction.exe","*hex2dec64.exe","*hex2dec.exe","*handle64.exe","*handle.exe","*efsdump.exe","*du64.exe","*du.exe","*diskext64.exe","*diskext.exe","*disk2vhd.exe","*ctrl2cap.exe","*autorunsc64.exe","*autorunsc.exe","*adrestore.exe","*accesschk64.exe","*accesschk.exe","*ZoomIt.exe","*Winobj.exe","*Volumeid64.exe","*Volumeid.exe","*Testlimit64.exe","*Testlimit.exe","*Tcpview.exe","*Tcpvcon.exe","*Sysmon64.exe","*Sysmon.exe","*ShellRunas.exe","*ShareEnum.exe","*RegDelNull64.exe","*RegDelNull.exe","*RAMMap.exe","*PsService64.exe","*PsService.exe","*PsLoggedon64.exe","*PsLoggedon.exe","*PsInfo64.exe","*PsInfo.exe","*PsGetsid64.exe","*PsGetsid.exe","*PsExec64.exe","*PsExec.exe","*Procmon64.exe","*Procmon.exe","*LoadOrdC64.exe","*LoadOrdC.exe","*LoadOrd64.exe","*LoadOrd.exe","*Listdlls64.exe","*Listdlls.exe","*FindLinks64.exe","*FindLinks.exe","*Diskmon.exe","*DiskView.exe","*Desktops.exe","*Dbgview.exe","*Coreinfo64.exe","*Coreinfo.exe","*Contig64.exe","*Contig.exe","*Clockres64.exe","*Clockres.exe","*Cacheset.exe","*CPUSTRES64.EXE","*CPUSTRES.EXE","*Bginfo64.exe","*Bginfo.exe","*Autoruns64.exe","*Autoruns.exe","*Autologon.exe","*AccessEnum.exe","*ADInsight.exe","*ADExplorer.exe")
| eval points = 20
| eval concat = host . process_name
| search NOT [search index=summary source="Base - Suspicious Windows Processes" earliest=-1d | table orig_host,process_name | eval concat = orig_host . process_name | table concat]
| fields host, payload, points
| collect index=summary sourcetype=stash source="Base - Suspicious Windows Processes" marker="tier=base"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Vulnerability Scanning On Web Server</title>
        <search ref="Base - Vulnerability Scanning On Web Server"></search>
        <option name="count">5</option>
        <option name="drilldown">none</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Web Server Errors</title>
        <search ref="Base - Web Server Errors"></search>
        <option name="count">5</option>
        <option name="drilldown">none</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - RDP Connections Bypassing Bastion</title>
        <search ref="Base - RDP Connections Bypassing Bastion"></search>
        <option name="count">5</option>
        <option name="drilldown">none</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Suspicious Cron Jobs</title>
        <search>
          <query>index=safe source="*/userscrontab.log" TERM(nc) OR TERM(wget) OR TERM(curl) OR TERM(ncat) OR TERM(fping) OR "/dev/null" earliest=-1d
| rex "(?m)^(?&lt;cron&gt;[^#\r\n]+)" max_match=500
| eval cron=rtrim(cron," ")
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by cron, host
| eval points = 10
| eval concat = host . cron
| search NOT [search index=summary source="Base - Suspicious Cron Jobs" earliest=-1d | table cron,orig_host | eval concat = orig_host . cron | table concat]
| fields host, cron, points
| collect index=summary sourcetype=stash source="Base - Suspicious Cron Jobs" marker="tier=base"</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Base - Web Shells</title>
        <search>
          <query>index=safe source="*/webserveraccess.log" earliest=-1d "cmd=*nc" OR "cmd=*/bash" OR "cmd=*ncat" OR "cmd=*netcat"
| rex "\?(?&lt;uri_query&gt;[^ ]+)"
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by host, uri_query
| eval points = 10
| eval concat = host . uri_query
| search NOT [search index=summary source="Base - Web Shells" earliest=-1d | table uri_query,orig_host | eval concat = orig_host . uri_query | table concat]
| fields host, uri_query, points
| collect index=summary sourcetype=stash source="Base - Web Shells" marker="tier=base"</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
  <row>
    <panel>
      <table>
        <title>Baseline - New Processes</title>
        <search>
          <query>index=safe source=*pidpsname.log earliest=-1d
| rex "(?&lt;pid&gt;\d+)\ (?&lt;cmd&gt;\w+)" max_match=0
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| eval time = max(_time)
| eval points = 5
| stats count by time, cmd, host, points
| eval concat = cmd . host
| search NOT [search index=summary source="Baseline - New Processes" earliest=-7d | table cmd,orig_host | eval concat = cmd . orig_host | table concat]
| fields time, cmd, host, points
| collect index=summary sourcetype=stash source="Baseline - New Processes" marker="tier=baseline"</query>
          <earliest>-1h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">cell</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Autostart Services</title>
        <search>
          <query>index=safe source="*/autostartservices.log" earliest=-1d
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| rex ".+\ (?&lt;service&gt;[^ ]+)[\r\n.]" max_match=0
| stats count by service, host
| where len(service)&gt;3
| search NOT service IN ("") `comment("whitelist")`
| eval points = 5
| eval concat = service . host
| search NOT [search index=summary source="Baseline - New Autostart Services" earliest=-7d | table service,orig_host | eval concat = service . orig_host | table concat]
| fields service, host, points
| collect index=summary sourcetype=stash source="Baseline - New Autostart Services" marker="tier=baseline"</query>
          <earliest>-1mon</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New SSH Users</title>
        <search>
          <query>index=safe source=*userlist.log earliest=-1d
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| rex "(?&lt;user&gt;.+)" max_match=0
| stats count by user, host
| search NOT user IN ("sshd","mysql","_apt","avahi","avahi-autoipd","backup","bin","colord","cups-pk-helper","daemon","dnsmasq","games","gdm","geoclue","gnats","gnome-initial-setup","hplip","irc","kernoops","list","lp","mail","man","messagebus","news","nobody","proxy","pulse","root","rtkit","saned","speech-dispatcher","sync","sys","syslog","systemd-network","systemd-resolve","usbmux","uucp","uuidd","whoopsie") `comment("whitelist")`
| eval points = 5
| eval concat = user . host
| search NOT [search index=summary source="Baseline - New SSH Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Baseline - New SSH Users" marker="tier=baseline"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Startup Processes</title>
        <search>
          <query>index=safe source=*startupprocess.log earliest=-1d
| rex field=_raw max_match=500 "\d+\ +(?&lt;startup_process&gt;[^ ]+)\ .+"
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by startup_process, host
| eval points = 5
| eval concat = host.startup_process
| search NOT [search index=summary source="Baseline - New Startup Processes" earliest=-7d | table startup_process,orig_host | eval concat = orig_host.startup_process | table concat]
| fields startup_process, host, points
| collect index=summary sourcetype=stash source="Baseline - New Startup Processes" marker="tier=baseline"</query>
          <earliest>-24h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Users</title>
        <search>
          <query>index=safe source="*sshaccess.log" user earliest=-1d
| rex field=source ".+artefacts\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| rex "New\ session\ /d+ of\ user\ (?&lt;user&gt;[a-zA-Z0-9])"
| rex "session\ opened\ for\ user\ (?&lt;user&gt;[a-zA-Z0-9])\ by"
| eval time = max(_time) `comment("I know this line should go below")`
| stats count by user, host
| eval points = 10
| search NOT user IN ("sshd","mysql","gdm") `comment("whitelist")`
| eval concat = user . host
| search NOT [search index=summary source="Baseline - New Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
| collect index=summary sourcetype=stash source="Baseline - New Users" marker="tier=baseline"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Windows Processes</title>
        <search>
          <query>index=safe source="*/Security.xml" earliest=-1d
| spath 
| search "Event.EventData.Data{@Name}"=ProcessName 
| rex field=_raw max_match=20 "ProcessName\'\&gt;(?&lt;process&gt;[^\&lt;]+)\&lt;" 
| rex field=process max_match=20 ".+[\\\](?&lt;process_name&gt;[^\\\]+)$$" 
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| eval points = 4
| eval concat = host . process_name
| search NOT [search index=summary source="Baseline - New Windows Processes" earliest=-7d | table orig_host,process_name | eval concat = orig_host.process_name | table concat]
| fields process_name, host, points 
| collect index=summary source="Baseline - New Windows Processes" marker="tier=baseline"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">false</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Cron Jobs</title>
        <search>
          <query>index=safe source="*/userscrontab.log" earliest=-1d
| rex "(?m)^(?&lt;cron&gt;[^#\r\n]+)" max_match=0
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by cron, host
| eval cron = rtrim(cron," ")
| eval points = 5
| eval concat = host . cron
| search NOT [search index=summary source="Baseline - New Cron Jobs" earliest=-7d | table orig_host,cron | eval concat = orig_host.cron | table concat]
| fields cron, host, points
| collect index=summary source="Baseline - New Cron Jobs" marker="tier=baseline"</query>
          <earliest>-1d</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="refresh.display">progressbar</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Identified Windows Processes</title>
        <search>
          <query>index=safe source="*/Processlist.log" earliest=-1d
| rex field=_raw max_match=300 "\ \d\ (?&lt;process_name&gt;[^ ]+)" 
| rex field=source ".+splunk\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| stats count by process_name, host
| eval points = 4
| eval concat = host . process_name
| search NOT [search index=summary source="Baseline - New Identified Windows Processes" earliest=-7d | table orig_host,process_name | eval concat = orig_host.process_name | table concat]
| fields process_name, host, points 
| collect index=summary source="Baseline - New Identified Windows Processes" marker="tier=baseline"</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
    <panel>
      <table>
        <title>Baseline - New Hidden Files</title>
        <search>
          <query>index=safe source=*/hiddenfilesforotherusers.log earliest=-1d
| rex field=_raw "(?m)^(?&lt;user&gt;[^ ]+)\ (?m)(?&lt;hidden_files&gt;[^ ]+)$$" max_match=400
| rex field=source ".+\/(?&lt;host&gt;[a-zA-Z0-9]+)\_.+"
| rex mode=sed field=user "s/\n/ /g"
| rex mode=sed field=hidden_files "s/\n/ /g"
| eval user = ltrim(user," ")
| stats count by user, hidden_files, host
| eval points = 3
| eval concat = user . hidden_files . host
| search NOT [search index=summary source="Baseline - New Hidden Files" earliest=-7d | table user,hidden_files,orig_host | eval concat = user . hidden_files . orig_host | table concat]
| fields user, hidden_files, host, points
| collect index=summary sourcetype=stash source="Baseline - New Hidden Files" marker="tier=baseline"</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
          <sampleRatio>1</sampleRatio>
        </search>
        <option name="count">5</option>
        <option name="dataOverlayMode">none</option>
        <option name="drilldown">none</option>
        <option name="percentagesRow">false</option>
        <option name="rowNumbers">false</option>
        <option name="totalsRow">false</option>
        <option name="wrap">true</option>
      </table>
    </panel>
  </row>
</form>
```
</details>


<details>
  <summary>Simulated Thread Feed</summary>

### Simulated Thread Feed
```
| makeresults `comment("Intel Feed")`
| eval ip="4.4.4.4"
| eval threat_list_name = "c2 traffic"
| append [|makeresults
| eval ip="5.5.5.5"
| eval threat_list_name = "tor node"]
| append [|makeresults
| eval ip="172.20.10.6"
| eval threat_list_name = "hacker ip"]
| outputlookup threatintel.csv
```
</details>

## Demo

We run a command injection exploit on a WordPress instance on hslxpdwbvm01 (HackSmith - Linux - Production - Web - VM - #01):

![safe-1](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-1.png)

Running the forensics scripts show us that hslxpdwbvm01 is now at "warning" (orange) level (for demonstration sake):

![safe-3](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-3.png)

We now run a simulated dirty cow exploit where the uid of a malicious user is changed to 0:

![safe-7](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-7.png)

Then we run the forensics script:

![safe-2](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-2.png)

Checking on the dashboard, we now see the increase in severity to "critical" (red) level, which flags for manual intervention:

![safe-4](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-4.png)


## Architecture & Design 
![safe-5](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-5.png)

## Setting up
If you are using Splunk as your SIEM, please set up your Enterprise Security instance, and install a Splunk Forwarder on your master/bastion server. Instructions on setting that up can be found here: https://www.splunk.com/en_us/download/splunk-enterprise.html

Once Splunk is set up, make sure your account on bastion can access the remote target servers. 

Splunk rules can be set up by running the above rules in your Splunk search, and then saving them as alerts. The Splunk dashboard is available in this repository as a .xml file which can be imported.

## Running SAFE
On the master server, run
```
bash ./safe.sh
```
