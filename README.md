# Sample Analysing Forensics Examiner (SAFE)

Security incidents are usually created by alerts or events, which are based on a small set of forwarded logs. When a server is suspected to be compromised, we go back to the source for the rest of the logs to investigate on traffic and endpoint.

SAFE enables security administrators to run automated forensics investigations on a selected set of machines, either specified or via sampling, to get a baseline threat score on the likelyhood of a server compromise. A number of logs, including web server, syslog, system, network logs are surveyed for this analysis.

There are four main features in SAFE:
 1. Sampling based on 95% confidence level and stipulated confidence interval
 2. Acqusition of forensics artefacts on host machines
 3. Automatic remote orchestration and log ingestion
 4. Analysis to churn out a threat score that is indicative of the likelyhood of server compromise

## 1. Sampling

## 2. Forensics Acqusition Scripts
Current forensics scripts come in two flavours - Linux and Windows.

## 3. Remote Orchestration & Log Ingestion

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

### ii. Baseline (Comparison) Rules - > Notable Events

| Log  | Criteria | Points |
| ------------- | ------------- | ------ | 
| ps -aux | for each newly identified process that is not whitelisted | +5 |
| ps -aux | for each newly identified user based on process | +1 |
| ~/.ssh/authorized_keys | for each newly added SSH key | +20 |
| ~/.ssh/known_hosts | for each newly added known host | +10 |
| /etc/passwd | for each newly added user | +5 |

### iii. Notable Scoring - > Dashboard
This is managed by our Threat Scoring Dashboard.


## Demo



## Roadmap to Arsenal: TODO
 1. Error handling in forensics scripts
 2. Bundling with ELK
 3. Adding more rules for calculation of threat score
 4. Making log ingestion more robust
 5. Beefing up on powershell script
 6. Data enrichment
