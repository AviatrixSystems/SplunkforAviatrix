# Splunkbase Listing Materials

Use the content below when filling out the Splunkbase submission forms.

---

## App 1: Aviatrix Add-on for Splunk (TA-aviatrix)

### Title
Aviatrix Add-on for Splunk

### Short Description (one line)
Field extractions, CIM compliance, and data normalization for Aviatrix Distributed Cloud Firewall logs.

### Full Description (for Splunkbase listing)

The Aviatrix Add-on for Splunk provides field extractions, lookups, and CIM-compliant data normalization for Aviatrix Distributed Cloud Firewall logs ingested via HEC (HTTP Event Collector).

**Supported Log Types:**
- L4 Firewall (DCF micro-segmentation) — allow/deny with session metadata
- L7 Firewall (TLS/SNI inspection) — domain-level policy enforcement
- FQDN Egress Filtering — hostname-based egress controls
- IDS (Suricata) — intrusion detection alerts in EVE JSON format
- Gateway Health — network throughput, CPU, memory, and disk statistics
- Controller Audit — API audit logs for configuration change tracking

**CIM Data Models:**
- Network Traffic (L4, L7, FQDN)
- Intrusion Detection (IDS/Suricata)
- Change Analysis (Controller Audit)

**Features:**
- Automatic JSON field extraction for all Aviatrix HEC sourcetypes
- Action normalization lookup (PERMIT/Permit/Allow → allowed, DENY/Deny/Block → blocked)
- Severity mapping for IDS alerts
- Protocol and session end reason lookups
- Event types and tags for CIM data model acceleration

Install the companion **Aviatrix Security** app for pre-built dashboards.

### Category
Security, Fraud & Compliance

### Splunk Version Compatibility
- Splunk Enterprise 8.0+
- Splunk Cloud

### CIM Version
4.0+

### License
Apache License 2.0

### Package File
`TA-aviatrix-2.0.0.tar.gz`

---

## App 2: Aviatrix Security (aviatrix-security)

### Title
Aviatrix Security

### Short Description (one line)
Security dashboards and analytics for Aviatrix Distributed Cloud Firewall.

### Full Description (for Splunkbase listing)

Aviatrix Security provides pre-built dashboards for monitoring and investigating Aviatrix Distributed Cloud Firewall activity. Designed for SIEM and SOC teams, it delivers visibility into firewall traffic, threat detection, policy enforcement, gateway health, and configuration changes.

**Dashboards:**
- **Security Overview** — KPIs, threat timeline, top blocked destinations, IDS summary, gateway block rates
- **Traffic Analysis** — L4/L7/FQDN traffic patterns, top sources/destinations, protocol breakdown
- **Threat Detection** — IDS alert severity, signature analysis, source/destination correlation
- **Policy Enforcement** — L7 policy hits, allow/deny ratios, enforced vs. monitor mode, domain analysis
- **Gateway Health** — CPU, memory, disk, network throughput per gateway
- **Audit Trail** — Controller API changes, user activity, success/failure tracking

**Features:**
- Interactive filters (time range, gateway, action, severity)
- Drilldown from overview panels to detailed investigation views
- Color-coded severity and action indicators
- Configurable index macro for enterprise deployments

**Requirements:**
- Aviatrix Add-on for Splunk (TA-aviatrix) version 2.0.0+
- Aviatrix logs flowing via HEC with appropriate sourcetypes

### Category
Security, Fraud & Compliance

### Splunk Version Compatibility
- Splunk Enterprise 8.0+
- Splunk Cloud

### Dependencies
Aviatrix Add-on for Splunk (TA-aviatrix) >= 2.0.0

### License
Apache License 2.0

### Package File
`aviatrix-security-2.0.0.tar.gz`

---

## Screenshots Needed (aviatrix-security only)

Splunkbase recommends 3-5 screenshots. Take these from a Splunk instance with sample data:

1. **Security Overview** — the full overview dashboard showing KPIs and charts
2. **Traffic Analysis** — traffic patterns with the time chart and top sources table
3. **Threat Detection** — IDS alerts with severity breakdown
4. **Policy Enforcement** — L7 domain analysis with allow/block ratios
5. **Gateway Health** — gateway status table with CPU/memory gauges

Recommended screenshot size: 1440x900 or higher. PNG format.

---

## Icons Checklist

Both apps already include:
- [x] `static/appIcon.png` (36x36 PNG)
- [x] `static/appIcon_2x.png` (72x72 PNG)
- [x] `static/appLogo.png` (160x40 PNG)
- [x] `static/appLogo_2x.png` (320x80 PNG)
