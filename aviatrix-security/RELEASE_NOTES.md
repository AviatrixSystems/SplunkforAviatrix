# Aviatrix Security - Release Notes

## Version 2.2.0

- **Focused on Distributed Cloud Firewall.** Legacy FQDN egress events (`aviatrix:firewall:fqdn`) are deprecated and no longer appear in any dashboard. The `aviatrix_firewall` macro (and everything built on it, including the new data model) covers L4 micro-segmentation and L7 only. The `aviatrix_fqdn` macro remains for saved searches but is unused.

Works with Aviatrix Add-on for Splunk 2.0.2 and later (2.2.0 recommended). Requires Splunk Enterprise 9.0+ or Splunk Cloud (Dashboard Studio). Tested on 9.4.7 and 10.6.1.1.

- **All seven dashboards are rebuilt in Dashboard Studio**, with a responsive grid layout that fills the screen at native size, one dark design system, and reserved colors: blue allowed, amber "would block", red blocked, and severity colors with labels.
- **New "Would block" outcome everywhere**: denies from monitor-mode rules are shown separately from enforced blocks, so policy rollout gaps are visible.
- **Security Overview**: KPI tiles with period totals and sparklines, and a new **Notable activity** table that ranks detections across all sources. It covers port scans and host sweeps, internet ingress allowed only by the DCF default rule, egress allowed only by monitor mode, IDS/IPS threats, logging, identity and policy changes, repeated API failures, VPN logins from several countries, large VPN transfers, and tunnels down. Gateway posture adds Monitor % and Default rule %.
- **Traffic Analysis**: Outcome and direction filters; a source network → service → outcome sankey; top sources, destinations and services; and **scan and sweep suspects** that count requests only, so busy servers replying to ephemeral ports are not flagged. Flow counts no longer double count 8.2 session start and end events.
- **Threat Detection**: Combines Suricata alerts with the 8.2 L7 inline IPS verdicts. Adds MITRE ATT&CK tactics, affected internal hosts and external peers (with geolocation), and an "Asset IP (either side)" pivot.
- **L7 Firewall Activity**: "Would be blocked if enforced" domains, rules by hits and mode, and inspection exceptions (TLS validation failures, IDS unavailable, stalled handshakes).
- **Gateway Health**: A worst-first status table that includes Silent gateways and AWS ENA allowance-exceeded counts; top-10 saturation charts; and tunnel state and changes (new data).
- **Audit Trail**: Security-relevance categories (logging, identity, policy change), a when-changes-happen punchcard, and failures grouped by controller error code.
- **VPN Sessions**: A "sessions worth a look" table (several countries, transfers over 1 GB, sessions over 12 h, many client IPs).
- **Performance over long ranges**: A new **Aviatrix_Traffic** data model (one event per flow) feeds the firewall panels through `tstats summariesonly=false`, so results are always complete. **Turn on its acceleration** (Settings > Data models > Aviatrix Traffic > Edit Acceleration) to make 90-day and 1-year views take seconds instead of minutes. It ships turned off, as Splunk Cloud vetting requires.
- New macros: `aviatrix_flows`, `aviatrix_outcome`, `aviatrix_direction`, `aviatrix_service(1)`, `aviatrix_severity_label(1)`, `aviatrix_threats`, `aviatrix_threat_fields`, `aviatrix_audit_risk`, `aviatrix_tunnel`.
- Dashboard token names are unchanged, so existing links such as `traffic_analysis?form.dest=...` still work. The Traffic Analysis `action` token takes `allowed`, `monitor` or `blocked`.

## Version 2.1.0

Works with Aviatrix Add-on for Splunk 2.0.0 and later (2.1.0 recommended).

- **New VPN Sessions dashboard** (Security menu) for Aviatrix User VPN:
  - KPIs: sessions started, still connected, unique users, client public IPs, data transferred and average session length.
  - Open sessions: connects with no disconnect, unless a newer session has since been given the same virtual IP on that gateway.
  - Sessions over time by gateway, data transferred over time, and top users by connected time and data.
  - Client platform and version, a client location map, connections by public IP with geolocation, and the session event log.
  - Filters for user, VPN gateway and client public IP. Clicking a user or IP applies it as a filter.
- New macros: `aviatrix_vpn` (VPN session events) and `aviatrix_vpn_fields` (normalized user, IPs, gateway, duration and bytes). With add-on versions before 2.1.0 the macro derives these from the connector's fields.

## Version 2.0.1

Works with Aviatrix Add-on for Splunk 2.0.0 and later. Required with add-on 2.0.2.

- Dashboards use the CIM traffic outcome instead of raw `PERMIT`/`DENY`/`Permit`/`Deny` comparisons (new `aviatrix_traffic_action` macro). With add-on 2.0.2, Blocked Sessions, Gateway Block Rate and the Traffic Analysis panels count only traffic that was actually dropped: monitor-mode denies show as allowed.
- **L7 Firewall Activity** shows policy verdicts, including monitor-mode denies. The Action filter is now labelled "Policy Verdict" (Permit/Deny); use Enforcement Mode to separate monitor-only denies.
- **Audit Trail rebuilt around CIM Change**: KPIs for Created/Modified/Deleted/Failed and an Operation filter (excludes read-only calls like login checks by default). It adds operations over time and by user, changes by object category, Top Commands (IDs collapsed to `{id}`) and the client source IP. All panels share one base search. Needs add-on 2.0.2 for the operation breakdown; with older add-ons, operations show as `unknown`.
- **Traffic Analysis**: The Action filter (Allowed/Blocked) returned no results on the volume, flow, top talkers and port panels (the comparison was case-sensitive). Fixed.
- **Overview**: "Top Accessed Domains (L7/FQDN)" only included FQDN events because of SPL `OR` precedence. It now includes L7 SNI domains. Its drilldown pointed to a dashboard that doesn't exist (`egress_monitoring`) and now opens L7 Firewall Activity filtered to the domain. "Top IDS Signatures" no longer plots severity as a second bar series.
- **L7 Firewall Activity**: Clicking a domain in "Top Accessed Domains" set the filter to the literal text "Domain". The Enforced/Monitor pie drilldown did nothing. Domain filter values are now quoted. All three fixed.
- **Threat Detection**: The severity filter uses `severity_id`. Signature filter values are quoted, so signatures with spaces or parentheses match exactly.
- **Audit Trail**: Successful REST API calls (`200 OK`, `201 CREATED`, `204 NO CONTENT`) were counted as failures. They now count as successes. Selecting the "unknown" user (from the Activity by User drilldown) now matches events.
- **Gateway Health**: RX/TX throughput charts showed values up to 1000x too small (units were lost upstream). They now read the real rate and unit.
- **L7 Firewall Activity**: The default domain filter dropped L7 events without an SNI hostname (for example SYN-timeout denies), so Total Blocks was undercounted. Fixed.
- **Audit Trail**: The Action Types pie dropped every REST API (`/v2.5/...`) event. REST actions are now grouped by path. User and signature filter values are escaped.
- **Traffic Analysis**: Table drilldowns now apply immediately instead of waiting for Submit.
- Gateway dropdowns follow the selected time range instead of a fixed 24 hours. On Overview and Traffic Analysis they now list L7 and FQDN gateways too.
- The L7 Traffic Direction panel and the `aviatrix_private_ip` macro treat all of 100.64.0.0/10 as private (previously only 100.64.0.0/16).
- Macros: `aviatrix_network_traffic` uses the CIM action, and `aviatrix_duration_format` handles durations over 24h and doesn't shift by timezone.


## Version 2.0.0

Initial release with security-focused dashboards for Aviatrix Distributed Cloud Firewall:

- **Security Overview**: At-a-glance security posture with KPIs and threat timeline
- **Traffic Analysis**: Deep-dive into allowed/blocked traffic patterns with source/destination analysis
- **Threat Detection**: IDS alert monitoring with severity breakdown and signature analysis
- **Policy Enforcement**: Firewall rule hit analysis with allow/deny ratio tracking
- **Gateway Health**: Gateway performance monitoring (CPU, memory, disk, network throughput)
- **Audit Trail**: Controller API audit log analysis with change tracking

Requires the Aviatrix Add-on for Splunk (TA-aviatrix) version 2.0.0 or later.
