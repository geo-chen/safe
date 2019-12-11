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


## Demo

## Roadmap to Arsenal: TODO
 1. Error handling in forensics scripts
 2. Bundling with ELK
 3. Adding more rules for calculation of threat score
 4. Making log ingestion more robust
 5. Beefing up on powershell script
