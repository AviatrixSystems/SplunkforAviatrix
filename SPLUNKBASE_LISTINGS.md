# Splunkbase Listing Materials

The text below is what the Splunkbase listings show (Manage app > Metadata >
App description and Media). Keep it in sync when a release changes what the
apps do. Screenshots for the app listing are generated into
`screenshots/splunkbase/` (gitignored) at 1440x1080 and downscaled to 1200x900.

---

## App 1: Aviatrix Security (aviatrix-security, Splunkbase 8515)

### Short description

SOC dashboards for Aviatrix Distributed Cloud Firewall: traffic outcomes (including "would block" monitor-mode denies), ranked notable detections, IDS/IPS threats with MITRE ATT&CK, L7 policy, gateway health, controller audit and User VPN. Built in Dashboard Studio for Splunk 9.0+ and 10.x.

### Summary

Security analytics for Aviatrix Distributed Cloud Firewall (DCF), built for SOC and SIEM teams. Seven Dashboard Studio dashboards turn DCF, IDS, gateway, controller and User VPN logs into triage-ready views.

Highlights:
- Security Overview with a ranked Notable activity table: port scans and host sweeps, internet ingress allowed only by the DCF default rule, egress allowed only by monitor mode, IDS/IPS threats, logging/identity/policy changes on the controller, multi-country VPN logins, large VPN transfers and tunnels down.
- A "Would block" outcome everywhere: denies from monitor-mode rules are shown apart from enforced blocks, so policy rollout gaps are visible before you enforce.
- Threat Detection combining Suricata IDS with DCF L7 inline IPS, pivoted on the affected workload and the external peer, with MITRE ATT&CK tactics.
- Fast over long time ranges: the bundled Aviatrix_Traffic data model serves the firewall panels through tstats (turn on its acceleration).
- Responsive layout that fills the screen on Splunk 9.4 and Splunk 10.

Requires the Aviatrix Add-on for Splunk (TA-aviatrix) 2.2.0 or later.

### Details

```markdown
## Overview

Aviatrix Security turns Aviatrix Distributed Cloud Firewall (DCF) logs into SOC workflows: what was allowed, what was blocked, what *would* be blocked once monitor-mode rules are enforced, which workloads are involved in threats, and which controller changes matter for security.

Version 2.2 is a full rebuild in Dashboard Studio (Splunk 9.0+, tested on 9.4 and 10.6).

## Dashboards

**Security Overview**: posture KPIs with trends, firewall outcomes over time, threat severity, and a ranked **Notable activity** table that pulls detections from every Aviatrix source. Gateway posture shows how much traffic is decided by monitor-mode rules or only by the DCF default rule.

**Traffic Analysis**: hunt across L4 micro-segmentation and L7 flows by source, destination, port, protocol, direction and outcome. Includes a source network → service → outcome flow diagram, top talkers, and scan and sweep suspects (reply traffic is excluded, so busy servers are not flagged).

**Threat Detection**: Suricata IDS alerts plus DCF L7 inline IPS verdicts, with severity, MITRE ATT&CK tactics, affected internal hosts and external peers (with geolocation).

**L7 Firewall Activity**: TLS/SNI policy verdicts by domain and rule, domains that *would be blocked if enforced*, and inspection exceptions (TLS validation failures, IDS engine unavailable, stalled handshakes).

**Gateway Health**: worst-first gateway status (including gateways that stopped reporting), CPU, memory, throughput, tracked connections, AWS ENA allowance-exceeded counters and tunnel up/down history.

**Audit Trail**: who created, modified or deleted what on the Aviatrix Controller, when (off-hours punchcard), from where, whether it worked (grouped by AVXERR error code), and which changes are security-relevant (logging, identity, policy).

**VPN Sessions**: open sessions, users, client platforms and locations, and sessions worth a look (multiple countries, transfers over 1 GB, very long sessions, many client IPs).

## Data

| Sourcetype | Content |
|---|---|
| aviatrix:firewall:l4 | DCF L4 micro-segmentation |
| aviatrix:firewall:l7 | DCF L7 TLS/SNI inspection and inline IDS/IPS |
| aviatrix:ids | Suricata IDS alerts (EVE JSON) |
| aviatrix:gateway:network | Gateway network statistics |
| aviatrix:gateway:system | Gateway CPU, memory and disk |
| aviatrix:tunnel:status | Tunnel up/down changes |
| aviatrix:controller:audit | Controller API audit |
| aviatrix:vpn:session | User VPN sessions |

Legacy FQDN egress logs (aviatrix:firewall:fqdn) are deprecated and not shown by the dashboards.

Logs are sent to Splunk HEC by the Aviatrix SIEM connector. Field extractions and CIM mapping come from the Aviatrix Add-on for Splunk.
```

### Installation

```markdown
## Prerequisites

- Splunk Enterprise or Splunk Cloud 9.0 or later (Dashboard Studio).
- **Aviatrix Add-on for Splunk (TA-aviatrix) 2.2.0+**: install it first, on search heads and indexers.
- Aviatrix logs in Splunk via the Aviatrix SIEM connector (HEC), with the per-type sourcetypes listed on the Details tab.

## Install

1. Install **TA-aviatrix**, then **Aviatrix Security** (Apps > Manage Apps > Install app from file, or from Splunkbase).
2. Restart Splunk when prompted.
3. If your Aviatrix data is not in `index=main`, update the `aviatrix_index` macro (Settings > Advanced search > Search macros).

## Recommended: accelerate the Aviatrix_Traffic data model

The firewall dashboards read the bundled **Aviatrix_Traffic** data model. Results are always complete, but with acceleration on, 90-day and 1-year views load in seconds instead of minutes:

Settings > Data models > **Aviatrix Traffic** > Edit > Edit Acceleration > check **Accelerate** and choose a summary range (for example 3 months or 1 year).

Acceleration ships turned off (a Splunk Cloud requirement). The CIM add-on is optional: the TA's CIM tags work with it, and the dashboards do not need it.
```

### Troubleshooting

```markdown
## Dashboards show no data

- Check the `aviatrix_index` macro points at the index holding Aviatrix data (default `index=main`).
- Confirm data and sourcetypes: `` `aviatrix_index` sourcetype=aviatrix:* | stats count by sourcetype ``. Events must use the per-type sourcetypes (for example aviatrix:firewall:l4), not a single generic HEC sourcetype.
- Make sure TA-aviatrix 2.2.0+ is installed and Splunk was restarted after installing it.

## Long time ranges are slow

Turn on acceleration for the Aviatrix_Traffic data model (see Installation). Until the summary is built, firewall panels fall back to raw events.

## Fields missing or showing %{...}

Upgrade TA-aviatrix: it nulls the connector's unresolved %{field} placeholders and parses several fields from the syslog text.

## FQDN panels are gone

Legacy FQDN egress filter logs are deprecated as of 2.2.0. The add-on still parses them, but the dashboards focus on Distributed Cloud Firewall L4 and L7.
```

---

## App 2: Aviatrix Add-on for Splunk (TA-aviatrix, Splunkbase 8517)

### Short description

Field extractions, lookups and CIM mapping for Aviatrix Distributed Cloud Firewall, IDS, gateway, tunnel, controller audit and User VPN logs sent to Splunk HEC by the Aviatrix SIEM connector.

### Summary

The Aviatrix Add-on for Splunk normalizes Aviatrix logs for search, Enterprise Security and the Aviatrix Security app.

- CIM Network Traffic (DCF L4 and L7), Intrusion Detection (Suricata), Change (controller audit), Performance (gateways), Network Sessions and Authentication (User VPN).
- Traffic outcome normalization, including monitor-mode denies (action=allowed, action_cim=blocked, policy_mode=monitor).
- Suricata EVE support (nested or flattened) with MITRE ATT&CK fields from rule metadata.
- Cleans up connector placeholders and parses fields the connector drops (rates with units, FQDN drop reasons, controller error codes).

Search-time only; install on search heads (and indexers/heavy forwarders in distributed deployments).

### Details

```markdown
## Overview

Search-time field extractions, event types, tags and lookups for Aviatrix logs sent to Splunk HEC by the Aviatrix SIEM connector. Pair it with the **Aviatrix Security** app for SOC dashboards.

## Sourcetypes and CIM

| Sourcetype | Content | CIM |
|---|---|---|
| aviatrix:firewall:l4 | DCF L4 micro-segmentation | Network Traffic |
| aviatrix:firewall:l7 | DCF L7 TLS/SNI inspection, inline IDS/IPS | Network Traffic |
| aviatrix:ids | Suricata IDS alerts (EVE JSON) | Intrusion Detection |
| aviatrix:gateway:network | Gateway network statistics | Performance |
| aviatrix:gateway:system | Gateway CPU, memory, disk | Performance |
| aviatrix:tunnel:status | Tunnel up/down changes | - |
| aviatrix:controller:audit | Controller API audit | Change |
| aviatrix:vpn:session | User VPN sessions | Network Sessions, Authentication |
| aviatrix:firewall:fqdn | Legacy FQDN egress (deprecated, removal planned for 3.0) | Network Traffic, Web |

## Key fields

- **Firewall**: `action` (allowed/blocked; monitor-mode denies are allowed), `action_cim` (policy verdict), `vendor_action`, `policy_mode`, `session_phase`, `l7_event_class`, `src`, `dest`, `dest_port`, `transport`, `rule`.
- **IDS**: `signature`, `signature_id`, `severity` / `severity_id`, `category`, `mitre_tactic`, `mitre_technique`, `app`, `tls_sni`.
- **Audit**: `action` (created/modified/deleted/read), `command`, `object`, `object_category`, `user`, `src`, `status`, `error_code`, `error_message`.
- **VPN**: `user`, `src` (client public IP), `dest_ip` (virtual IP), `dvc`, `duration`, `bytes_in` / `bytes_out`.
```

### Installation

```markdown
1. Install the add-on on search heads (and on indexers or heavy forwarders in distributed deployments).
2. Restart Splunk.
3. Send logs with the Aviatrix SIEM connector's Splunk HEC output, which sets the per-type sourcetypes above.
4. Optional: install the **Aviatrix Security** app for dashboards.
```

---

## Screenshots (aviatrix-security)

Generated from the test Splunk with `hideSplunkBar=true&hideAppBar=true&hideEdit=true`, 1440x1080, downscaled to 1200x900:

1. Security Overview (1 year)
2. Notable activity (1 year)
3. Traffic Analysis (dense week)
4. Threat Detection (1 year)
5. L7 Firewall Activity (1 year)
6. Gateway Health (a 12-hour window with all gateways reporting)
7. Audit Trail (1 year)
8. VPN Sessions (1 year)

## Icons

`tools/brand/build_icons.py` builds every app icon and logo from the official Aviatrix mark (transparent background). Splunk 10 draws the nav `color` behind the app icon, so `nav/default.xml` uses `color="transparent"`.
