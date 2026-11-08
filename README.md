
# Threat Hunting in Microsoft Sentinel: Investigating Suspicious Authentication Activity

## Scenario

A security operations investigation was initiated after Microsoft Sentinel generated an incident involving an IP address attempting to authenticate against disabled accounts. The objective was to determine whether the source IP had successfully authenticated as an active user, identify the potential account compromise, and investigate additional threat activity within the Sentinel environment.

The investigation used Microsoft's pre-recorded Sentinel Training Lab dataset to simulate a SOC analyst's incident triage and threat-hunting workflow.

## Environment

- **Platform:** Microsoft Azure
- **Security platform:** Microsoft Sentinel
- **Environment:** Live multi-user Azure training tenant
- **Dataset:** Microsoft's Sentinel Training Lab dataset
- **Log Analytics workspace:** `law-madhat-labs-sentinel-cus`
- **Data sources:** Custom training tables, including `SigninLogs_CL`, `SecurityEvent_CL`, `OfficeActivity_CL`, `AzureActivity_CL`, and `Cisco_Umbrella_dns_CL`
- **Query language:** Kusto Query Language (KQL)
- **Access level:** Microsoft Sentinel Reader and Azure Reader
- **Investigation tools:** Sentinel Incidents, incident entities, Logs, and Hunting

## Investigation

### 1. Identifying suspicious authentication activity

I started in the Microsoft Sentinel incident queue, where I located an incident titled:

`Sign-ins from IPs that attempt sign-ins to disabled accounts`

I opened the incident and reviewed its associated entities to identify the source IP responsible for the authentication attempts.

The incident contained multiple alerts associated with the same detection. The source IP entity provided the initial indicator for further investigation.

This established the starting point for pivoting into the underlying sign-in telemetry.

**Evidence — Sentinel incident and suspicious IP entity**

<img width="882" height="620" alt="image" src="https://github.com/user-attachments/assets/f5adb112-820b-4d86-be7c-4d079300c3ce" />


*Before publishing, redact the source IP, account information, and other tenant-specific identifiers.*

### 2. Correlating the suspicious IP with user accounts

After identifying the suspicious source IP, I pivoted into the `SigninLogs_CL` table to determine whether the activity resulted in successful authentication.

I used KQL to group authentication results by user principal name and count successful and failed sign-ins.

```kql
SigninLogs_CL
| where IPAddress == "<REDACTED_IP>"
| summarize
    Successes = countif(ResultType == 0),
    Failures = countif(ResultType != 0)
    by UserPrincipalName_s
| sort by Successes desc
```

The query returned two user accounts:

| Authentication results | Successful sign-ins | Failed sign-ins |
|---|---:|---:|
| Account 1 | 53 | 3 |
| Account 2 | 0 | 4 |

The results revealed that the suspicious source IP had successfully authenticated as one account 53 times, while the second account had only failed authentication attempts.

This was a significant finding because the source IP was not simply generating failed authentication attempts against disabled accounts. The telemetry showed repeated successful authentication associated with an account.

**Investigation conclusion:** The account associated with the 53 successful sign-ins required further investigation to determine whether the activity was legitimate or represented unauthorized access.

**Evidence — KQL authentication correlation**

<img width="522" height="402" alt="image" src="https://github.com/user-attachments/assets/787adf0b-688c-4833-b0df-0b928b9c2f3f" />


*Before publishing, redact the IP address and both user principal names. Preserve the query structure and authentication counts.*

### 3. Investigating the Solorigate network beacon

The next stage of the lab involved a separate Sentinel incident titled `Solorigate Network Beacon`.

The objective was to investigate a DNS-based command-and-control detection associated with the SolarWinds supply-chain compromise.

The lab scenario described an analytics rule that detected a host communicating with a known Solorigate command-and-control domain. The detection used DNS telemetry normalized through the Advanced Security Information Model (ASIM).

This demonstrates how normalized security data can allow a detection rule to operate across different DNS data sources.

**Evidence limitation:** I completed this lab objective, but I did not retain a screenshot of the incident entities or the command-and-control domain. Therefore, I am not publishing a specific domain or claiming independent visual verification of the entity.

### 4. Investigating the Solorigate blast radius

The next objective involved determining how many machines were potentially affected by the Solorigate malware.

The lab provided a hunting query named `Solorigate Inventory check`. The query searched for indicators associated with the malicious DLL and the Solorigate named pipe.

The purpose of this investigation was to move beyond the initially identified beaconing host and determine whether additional machines contained indicators of compromise.

This is an important incident-response step because identifying one compromised endpoint does not establish the full scope of an intrusion.

**Evidence limitation:** The lab objective was completed, but I did not retain the query results screenshot. I am therefore not including a specific infected-host count.

### 5. Identifying the DNS telemetry source

The final objective involved examining the raw events associated with the Solorigate alert and identifying the source table containing the DNS telemetry.

The investigation demonstrated the role of ASIM normalization in Sentinel. By normalizing DNS events into a common schema, Sentinel analytics rules can detect suspicious DNS activity without depending on one specific DNS vendor's original log format.

The lab identified a custom DNS source table as the underlying telemetry source.

**Evidence limitation:** I did not retain a screenshot of the raw DNS events or schema details, so I am not publishing a specific source-table result as independently verified evidence.

## What broke / what surprised me

- The first incident appeared to be authentication probing against disabled accounts, but the KQL investigation revealed successful authentication activity associated with the same source IP.
- Investigating the underlying sign-in records provided substantially more context than relying on the incident title alone.
- Grouping authentication results by user principal name made it possible to distinguish the account with successful authentication from the account with only failed attempts.
- The investigation reinforced that an incident's initial detection is only the starting point. Analysts must pivot into raw telemetry to understand what actually happened.
- I would capture screenshots at every stage in a future investigation, particularly the Solorigate incident entities, inventory query results, and raw DNS events.

## Findings and recommendations

### Findings

1. Microsoft Sentinel generated an incident involving an IP attempting to authenticate against disabled accounts.
2. The suspicious IP was associated with two accounts in the sign-in telemetry.
3. One account had 53 successful sign-ins and 3 failed sign-ins from the suspicious IP.
4. The second account had 4 failed sign-ins and no successful sign-ins.
5. The lab also demonstrated a separate Solorigate DNS beacon investigation, malware inventory hunting, and ASIM-normalized DNS detection.

### Recommendations

1. **Investigate the account with successful authentication:** Review authentication timelines, source locations, application access, user-agent information, and other sign-in activity. Determine whether the successful sessions were authorized.
2. **Scope potential compromise:** Correlate the suspicious IP and account with additional endpoint, identity, and cloud telemetry. Review other accounts and devices for related activity.
3. **Improve detection and investigation coverage:** Use KQL hunting queries and normalized data sources to correlate authentication and DNS activity. Validate that analytics rules identify suspicious behavior across the available telemetry sources.

## What I learned

- **Technical:** KQL aggregation functions such as `countif()` can distinguish successful and failed authentication attempts when investigating suspicious source IPs.
- **Incident triage:** Sentinel incidents provide an initial detection, but analysts should pivot into the underlying log records to establish what actually occurred.
- **Threat hunting:** A suspicious IP associated with failed authentication attempts may also have successful authentication activity that requires further investigation.
- **Security architecture:** ASIM normalization allows analytics rules to work with normalized DNS telemetry instead of relying on a specific vendor's log format.
- **What I would do differently:** Capture the raw query results, incident entities, and supporting telemetry throughout the investigation so every conclusion in the final report is backed by documented evidence.

---

**Project classification:** Microsoft Sentinel threat-hunting investigation using Microsoft's pre-recorded training telemetry in a live multi-user Azure training tenant.
