# Sample Analysing Forensics Examiner (SAFE)

Security incidents are usually created by alerts or events, which are based on a small set of forwarded logs. When a server is suspected to be compromised, we go back to the source for the rest of the logs to investigate on traffic and endpoint.

SAFE enables security administrators to run automated forensics investigations on a selected set of machines, either specified or via sampling, to get a baseline threat score on the likelyhood of a server compromise. A number of logs, including web server, syslog, system, network logs are surveyed for this analysis.
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
 2. Acqusition of forensics artefacts on host machines
 3. Automatic remote orchestration and log ingestion
 4. Analysis to churn out a threat score that is indicative of the likelyhood of server compromise

## 1. Sampling
There are two modes on choosing target servers - Sampling and Specified.
Sampling is used on larger pools of servers where we either want confirmation on the security health of target pool, or perform threat hunting (in this case, potentially undetected compromised servers).

Sampling is based on 95% Confidence Level, a chosen Confidence Interval between 0.1 and 50, and the population size. 

![safe-6](https://github.com/spigeo/automatedforensicsinvestigator/blob/master/hacksmith/safe-6.png)

## 2. Forensics Acqusition Scripts
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
 1. Splunk forwarder - installing splunk forwarder on the master server where the forensics scripts are run.
 2. Dropbox - setting up syncing Dropbox folders on master server and Splunk server.
 
In our tests over mobile network, the time taken for syncing and ingesting was within ten seconds.

## 4. Analysis and Threat Scoring
3 Levels of rules are performed. First level is the "Base" rules where forensics log statistics are filtered according to predefined criteria and thresholds to highlight notable events. The second level, "Baseline" rules compares the current statistics with the previous capture that is at least 48 hours ago to highlight changes from the previous benchmark. The third level, "Notable Scoring", picks up the notable events created by the first two levels of rules, and applies individual points to calculate an eventual threat score for the various hosts.

Here's what we have currently from HackSmith v3.0

### i. Base (Condition) Rules - > Notable Events

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

<details>
  <summary>Base Rules</summary>

`Base - Bad IP`
```
index="hacksmith" source="/home/master/Dropbox/hacksmith/artefacts/*webserveraccess.log" earliest=-1d
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
</details>

### ii. Baseline (Comparison) Rules - > Notable Events

| Log  | Criteria | Points |
| ------------- | ------------- | ------ | 
| ps -aux | for each newly identified process that is not whitelisted | +5 |
| ps -aux | for each newly identified user based on process | +1 |
| ~/.ssh/authorized_keys | for each newly added SSH key | +20 |
| ~/.ssh/known_hosts | for each newly added known host | +10 |
| /etc/passwd | for each newly added user | +5 |

<details>
  <summary>Baseline Rules</summary>

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
</details>

### iii. Notable Scoring - > Dashboard
This is managed by our Threat Scoring Dashboard.

<details>
  <summary>Notable Scoring</summary>

```
index=notable | stats sum(points) as points count by orig_host | search orig_host = $server1$ | fields points
```
```
index=notable orig_host="$server1$" | stats values(*) as * count, sum(points) as points by search_name | fields - date_*, - eventtype, - host, - index, - info_*, - linecount, - orig_action_name, - orig_rid, - orig_sid, - source, - sourcetype, - splunk_server, - tag*, - timeendpos, - timestartpos | convert ctime(time)
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
bash ./executer.sh
```

## Roadmap to Arsenal: TODO
 1. Error handling in forensics scripts
 2. Bundling with ELK
 3. Adding more rules for calculation of threat score
 4. Making log ingestion more robust
 5. Beefing up on powershell script
 6. Data enrichment
 7. Randomising and Sampling algorithm
 8. Access management
 9. Remove hardcoded configurations
