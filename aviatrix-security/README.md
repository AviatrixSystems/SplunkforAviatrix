# Aviatrix Security

Security visibility and analytics app for Aviatrix Distributed Cloud Firewall. Provides pre-built dashboards for traffic analysis, threat detection, policy enforcement, gateway health monitoring, and audit trail investigation -- optimized for SIEM and SOC teams.

## Prerequisites

- **Aviatrix Add-on for Splunk** (`TA-aviatrix`) version 2.0.0 or later must be installed.

## Dashboards

### Security Overview
At-a-glance security posture with KPIs for total events, blocked sessions, IDS alerts, and active gateways. Includes a threat timeline, top blocked destinations, IDS signature summary, and gateway block rates.

### Traffic Analysis
Deep-dive into L4/L7/FQDN traffic patterns. Filter by gateway, action (allowed/blocked), and protocol. Analyze traffic volume over time, top sources and destinations, and drill into individual events.

### Threat Detection
IDS alert monitoring with severity breakdown, alert timeline, signature analysis, and source/destination correlation. Filter by severity level and signature to investigate specific threats.

### Policy Enforcement
L7 firewall policy activity with domain analysis. Track policy hit counts, block rates, enforced vs. monitor mode split, and top accessed/blocked domains. Drill down by policy UUID for investigation.

### Gateway Health
Real-time gateway status monitoring with CPU utilization, memory usage, disk capacity, and network throughput. Identify overloaded gateways and capacity trends.

### Audit Trail
Controller API audit log analysis. Track configuration changes, user activity, success/failure rates, and policy/security-related changes over time.

## Installation

1. Install the **Aviatrix Add-on for Splunk** (`TA-aviatrix`) first.
2. Install this app on your Splunk search heads.
3. Ensure Aviatrix logs are flowing into Splunk via HEC with the appropriate sourcetypes (see TA-aviatrix documentation).

## Configuration

### Index

By default, dashboards query `index=main`. To change this, edit the `aviatrix_index` macro:

1. Go to **Settings > Advanced Search > Search Macros**.
2. Select the **Aviatrix Security** app context.
3. Edit the `aviatrix_index` macro definition to match your index (e.g., `index=aviatrix`).

## Compatibility

- Splunk Enterprise 8.0+
- Splunk Cloud
- Requires Aviatrix Add-on for Splunk (TA-aviatrix) >= 2.0.0

## License

Apache License 2.0

## Support

For issues and feature requests, visit the [GitHub repository](https://github.com/AviatrixSystems/SplunkforAviatrix).
