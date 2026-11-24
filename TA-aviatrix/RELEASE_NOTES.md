# Aviatrix Add-on for Splunk - Release Notes

## Version 2.2.1

- New app icon and logo built from the official Aviatrix mark on a transparent background (`tools/brand/build_icons.py`). Icons are sharper at small sizes in Splunk 10's side navigation.

## Version 2.2.0

- **Deprecated: legacy FQDN egress filter logs (`aviatrix:firewall:fqdn`).** Aviatrix security analytics now focus on the Distributed Cloud Firewall (L4 micro-segmentation + L7). The TA still parses the sourcetype, and its `aviatrix_fqdn` event type keeps its CIM tags, so existing searches and Enterprise Security data models work. It is no longer part of `aviatrix_firewall_traffic`, `aviatrix_traffic_allowed` or `aviatrix_traffic_blocked`. Removal is planned for 3.0; move egress controls to DCF L7 (SNI) policies.
- **New sourcetype support: `aviatrix:tunnel:status`** (tunnel up/down changes). Fields: `dvc`/`src_gw_name`, `dest`/`dst_gw_name`, `src_cloud`/`src_region`, `dst_cloud`/`dst_region`, `tunnel`, `status` (`up`/`down`). New event types `aviatrix_tunnel_status` and `aviatrix_tunnel_down`.
- **L4**: New `policy_mode` (`enforced`/`monitor`) and `session_phase` (`start`/`end`/`none`) so searches can count each 8.2+ flow once (start and end are separate events). `session_end_reason` is looked up into `session_end_description`. Unresolved `%{session_*}` placeholders are nulled.
- **L7**: `transport` is lowercase (gateways send both `TCP` and `tcp`). New `policy_mode`, `signature_id` (from the 8.2 inline-IPS `sid`), and `l7_event_class`, which separates policy verdicts from inline IPS drops, IDS alerts, IDS-unavailable timeouts, TLS inspection checks and SYN-only timeouts. New event type `aviatrix_l7_threat`.
- **IDS**: MITRE ATT&CK fields from ET rule metadata: `mitre_tactic`, `mitre_tactic_id`, `mitre_technique`, `mitre_technique_id`, plus `signature_severity`. `app` (from `app_proto`) and `tls_sni`.
- **FQDN**: A hostname that matched a deny (blacklist) rule logs `state=MATCHED` with `drop_reason=BLACKLISTED` and was reported as `action=allowed`. `action` now uses `drop_reason`, which is parsed from the syslog text with `fqdn_rule`; `vendor_action` holds the drop reason or state.
- **Gateway stats**: `%{alias}`, `%{public_ip}` and `%{conntrack_*}` placeholders (controller events, FireNet interfaces) are nulled. `dvc_ip` no longer carries the placeholder. New `cpu_core_count` and `cpu_busy_max`.
- **Controller audit**: Some connector releases send `host` as a literal `%{gw_hostname}`. `dvc`/`dest` now come from the controller name in the syslog text. New `error_code` and `error_message` from failed V2.5 API calls (for example `AVXERR-DFW-0043`).

## Version 2.1.0

- **New sourcetype `aviatrix:vpn:session`** (Aviatrix User VPN connect/disconnect events from the SIEM connector).
  - CIM **Network Sessions**: every event is tagged `network`, `session`, `vpn`, plus `start` on connect and `end` on disconnect.
  - CIM **Authentication**: connect events are tagged `authentication` with `action=success`.
  - `action` is `success` on connect and `deleted` on disconnect. The raw status (`active`/`disconnected`) is in `vendor_action`.
  - Fields: `user`, `src` (client public IP), `dest_ip` (VPN virtual IP), `dvc`/`dest` (gateway), `dvc_ip`, `app`, `signature`. Disconnects also carry `duration` (seconds, from `D:H:M:S`) and `bytes_in`/`bytes_out`/`bytes` (from values like `8.7KB` or `2.1 MB`).
  - Fields are parsed from the `AviatrixVPNSession:` text, not the connector's pre-parsed fields (an empty gateway IP arrives as a `%{vpn_gateway_ip}` placeholder). The plain syslog line works with this sourcetype too.
- New event types: `aviatrix_vpn_session`, `aviatrix_vpn_session_start`, `aviatrix_vpn_session_end`.

## Version 2.0.2

**CIM fixes. Upgrade the Aviatrix Security app to 2.0.1 at the same time:** app 2.0.0 compares `action` to the raw vendor values and shows wrong counts with this add-on.

- **L4/L7 firewall**: `action` now holds the CIM Network_Traffic outcome (`allowed`/`blocked`). Before this, it kept the raw `PERMIT`/`DENY`/`Permit`/`Deny`, so CIM and Enterprise Security searches on `action=blocked` missed L4/L7 traffic.
  - A deny from a rule in monitor mode (`enforced=false`) is logged but not dropped, so its `action` is `allowed`.
  - The raw value is in the new `vendor_action` field.
  - `action_cim` is now the normalized policy verdict: `blocked` for every deny, enforced or not.
- **L4**: Added `dest_port` (CIM). `transport` is lowercase (`tcp`/`udp`/`icmp`). `bytes` and `packets` are numeric, or null when the connector sends unresolved `%{...}` placeholders. Removed a no-op `src_mac` alias.
- **L7**: Removed the incorrect `stage AS http_content_type` alias and two no-op evals.
- **IDS**: `severity` is now the CIM string (`critical`/`high`/`medium`/`low`/`informational`). The numeric Suricata priority is in `severity_id`. The `aviatrix_ids_critical`/`aviatrix_ids_high` event types now use `severity_id`.
- **Controller audit (CIM Change)**:
  - `action` is now the CIM verb (`created`/`modified`/`deleted`/`read`). It comes from the HTTP method for REST calls, and from the command name and its argv sub-operation for legacy commands. For example, `USER_LOGIN_MANAGEMENT get_password` is a `read`.
  - The raw API name or URL moved to `command` (also `vendor_action`).
  - New fields: `object`, `object_id`, `object_category`, `src` (client IP), `dest`; `change_type` is now `AAA`/`application`/`network`.
  - `status` is now `success`/`failure` (it used to alias the raw `result`). REST results like `201 CREATED` count as success.
  - The `aviatrix_audit_success`/`aviatrix_audit_failure`/`aviatrix_audit_policy_change` event types use the new fields.
- **Event types**: `aviatrix_traffic_allowed`/`aviatrix_traffic_blocked` use the normalized `action`.
- **L4 direction**: 100.64.0.0/10 (CGNAT, used for EKS/AKS pod networks) now counts as private, so those flows are `internal`/`outbound` instead of `inbound`.
- **Protocol**: CIM `protocol` is now `ip` on L4/L7/IDS. The transport protocol stays in `transport`.
- **Controller audit**: CIM `user` is `unknown` (not the literal `%{username}`) when the connector couldn't parse the username.
- **Gateway network stats**: The connector drops the unit and decimals from `total_rx_rate`/`total_tx_rate` (`80.33Mb` arrives as `80`), so `thruput_in`/`thruput_out` were wrong by up to 1000x. Rates are now parsed from the original syslog text. New fields: `rx_kbps`/`tx_kbps`.
- **Gateway system stats**: Tagged `cpu`, `memory`, `storage` so events populate the CIM Performance datasets. `mem*`/`storage*` fields are now in MB as CIM expects (the raw values are KB). Added `mem` and `storage` totals.


## Version 2.0.1

- **IDS (Suricata)**: Support raw EVE JSON with nested `alert.*`, `http.*`, and `flow.*` objects. New search-time field aliases flatten `alert.signature`, `alert.severity`, `alert.category`, `alert.signature_id`, `alert.action`, HTTP, and flow byte fields to the top-level names used by dashboards, lookups, and CIM mappings. Legacy pre-flattened events continue to work unchanged.

## Version 2.0.0

Initial release with support for Aviatrix Distributed Cloud Firewall:

- **L4 Firewall**: DCF micro-segmentation log parsing with full CIM Network Traffic compliance
- **L7 Firewall**: TLS/SNI inspection log parsing with CIM Network Traffic compliance
- **IDS (Suricata)**: Intrusion detection alert parsing with CIM Intrusion Detection compliance
- **FQDN Filtering**: Egress filter log parsing with action normalization
- **Gateway Health**: Network and system statistics (CPU, memory, disk, throughput)
- **Controller Audit**: API audit log parsing with CIM Change Analysis compliance
- **Lookups**: Action normalization, severity mapping, protocol resolution, session end reasons
