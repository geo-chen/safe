# Automated Forensics Investigator (AFI)

Security incidents are triggered based on matches on alerts, and these alerts are based on a small selected set of aggregated logs. Whenever a server is suspected to be compromised, we go back to the source for the rest of the logs to investigate on traffic and endpoint.

The AFI enables teams to run automated forensics investigations on a selected set of machines, either specified or sampled, on both Windows and Linux, to get a baseline threat score on the likelyhood of a server compromise. A number of logs, including web server, syslog, system, network logs are surveyed for this analysis.

## Forensics Scripts

Current forensics scripts come in two flavours - Linux and Windows.

## Splunk Rules

Get started on free Splunk here: https://www.splunk.com/en_us/download/splunk-enterprise.html
You may also use the more suited Splunk Enterprise Security module instead: https://www.splunk.com/getsplunk/es_sandbox

### 1. Base Rules

`Base - Bad IP`
```index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*webserveraccess.log" earliest=-1d
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host
| rename src_ip as ip
| lookup threatintel.csv ip
| where isnotnull(threat_list_name)
| eval points = 3
| eval concat = host . ip
| search NOT [search index=notable search_name="Base - Bad IP" earliest=-1d | table ip,orig_host | eval concat = orig_host . ip | table concat]
| fields host, ip, points
```

`Base - Bad Logins`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*badlogins.log" 
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex "(?<user>[a-zA-Z0-9]+)\ .+" max_match=0
| stats count by user, host
| eval points = 3
| eval concat = user . host
| search NOT user = "btmp"
| search NOT [search index=notable search_name="Base - Bad Logins" earliest=-1d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
```

`Base - New Root Users`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*rootusers.log" earliest=-1d
| rex "(?<user>.+)" max_match=0
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by user, host
| search NOT user IN ("root") `comment("whitelist")`
| eval points = 20
| eval concat = user . host
| search NOT [search index=notable search_name="Base - New Root Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
```

`Base - OWASP Payloads`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*webserveraccess.log" status!=200 `comment("general assumption made is that 200 means well handled. not fully accurate of course")` earliest=-1d
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| stats count by src_ip, host, uri_query
| rename uri_query as payload
| lookup payloads.csv payload
| where isnotnull(attack)
| eval points = 3
| eval concat = host . payload
| search NOT [search index=notable search_name="Base - OWASP Payloads" earliest=-1d | table payload,orig_host | eval concat = orig_host . payload | table concat]
| fields host, payload, points
```

### 2. Baseline Rules

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

`Baseline - New SSH Users`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*userlist.log" earliest=-1d
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| rex "(?<user>.+)" max_match=0
| stats count by user, host
| search NOT user IN ("sshd","mysql","_apt","avahi","avahi-autoipd","backup","bin","colord","cups-pk-helper","daemon","dnsmasq","games","gdm","geoclue","gnats","gnome-initial-setup","hplip","irc","kernoops","list","lp","mail","man","messagebus","news","nobody","proxy","pulse","root","rtkit","saned","speech-dispatcher","sync","sys","syslog","systemd-network","systemd-resolve","usbmux","uucp","uuidd","whoopsie") `comment("whitelist")`
| eval points = 5
| eval concat = user . host
| search NOT [search index=notable search_name="Baseline - New SSH Users" earliest=-7d | table user,orig_host | eval concat = user . orig_host | table concat]
| fields user, host, points
```

`Baseline - New Processes`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*pidpsname.log" earliest=-1h
| rex "(?<pid>\d+)\ (?<cmd>\w+)" max_match=0
| rex field=source ".+artefacts\/(?<host>[a-zA-Z0-9]+)\_.+"
| eval time = max(_time)
| eval points = 5
| stats count by time, cmd, host, points
| eval concat = cmd . host
| search NOT [search index=notable search_name="Baseline - New Processes" earliest=-7d | table cmd,orig_host | eval concat = cmd . orig_host | table concat]
| fields time, cmd, host, points
```

### 3. Notable Miner Rule
```
index=notable | stats sum(points) as points count by orig_host | search orig_host = $server1$ | fields points
```
```
index=notable orig_host="$server1$" | stats values(*) as * count, sum(points) as points by search_name | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - source, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos | convert ctime(time)
```

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
