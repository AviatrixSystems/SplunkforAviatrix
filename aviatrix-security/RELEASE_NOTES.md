# Aviatrix Security - Release Notes

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
