# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains two Splunk apps for **Aviatrix Distributed Cloud Firewall** security visibility, TA 2.1.0 / app 2.1.0. Logs are ingested via HEC (HTTP Event Collector) with CIM-compliant field normalization.

## Architecture

### Two-App Design

**TA-aviatrix** (Technology Add-on) -- field extractions, lookups, CIM compliance:
```
TA-aviatrix/
├── default/
│   ├── app.conf            # Add-on metadata (hidden from UI)
│   ├── props.conf          # Field extractions for all sourcetypes
│   ├── transforms.conf     # Lookup definitions (action, protocol, severity)
│   ├── eventtypes.conf     # Event type definitions for CIM mapping
│   └── tags.conf           # CIM data model tags
├── lookups/                # CSV lookup tables
│   ├── aviatrix_action_lookup.csv
│   ├── aviatrix_protocol_lookup.csv
│   ├── aviatrix_severity_lookup.csv
│   └── aviatrix_session_end_reason_lookup.csv
└── metadata/default.meta
```

**aviatrix-security** (Visualization App) -- dashboards and navigation:
```
aviatrix-security/
├── default/
│   ├── app.conf            # App metadata (visible in UI)
│   ├── macros.conf         # Search macros (aviatrix_index, aviatrix_l4, etc.)
│   └── data/ui/
│       ├── nav/default.xml
│       └── views/          # 7 dashboards
│           ├── overview.xml
│           ├── traffic_analysis.xml
│           ├── threat_detection.xml
│           ├── policy_enforcement.xml
│           ├── gateway_health.xml
│           ├── audit_trail.xml
│           └── vpn_sessions.xml
└── metadata/default.meta
```

### Sourcetypes

| Sourcetype | Description |
|---|---|
| `aviatrix:firewall:l4` | DCF L4 micro-segmentation logs |
| `aviatrix:firewall:l7` | DCF L7 TLS/SNI inspection logs |
| `aviatrix:firewall:fqdn` | FQDN egress filtering logs |
| `aviatrix:ids` | Suricata IDS alerts (EVE JSON) |
| `aviatrix:gateway:network` | Gateway network statistics |
| `aviatrix:gateway:system` | Gateway CPU/memory/disk statistics |
| `aviatrix:controller:audit` | Controller API audit logs |
| `aviatrix:vpn:session` | User VPN session connect/disconnect |

### Key Macros (in aviatrix-security)

- `aviatrix_index` -- base index filter (default: `index=main`)
- `aviatrix_l4` -- L4 firewall events
- `aviatrix_l7` -- L7 firewall events
- `aviatrix_fqdn` -- FQDN egress events
- `aviatrix_ids` -- IDS/Suricata alerts
- `aviatrix_audit` -- Controller audit logs
- `aviatrix_vpn` -- User VPN session events; `aviatrix_vpn_fields` normalizes them (works with TA < 2.1.0)

### CIM Field Mapping

For L4/L7, `action` is normalized to the CIM value with calculated fields (`EVAL-action`), as of TA 2.0.2:
- L4: `PERMIT` -> `allowed`, `DENY` -> `blocked`. L7: `Permit` -> `allowed`, `Deny` -> `blocked`.
- Monitor mode: `DENY` with `enforced=false` -> `action=allowed` (traffic not dropped). `action_cim` stays `blocked` (policy verdict).
- The raw value is preserved in `vendor_action` (`EVAL-vendor_action = action`). Calculated fields run in parallel against extracted values, so both EVALs see the raw action.
- `action_cim` (policy verdict) is populated by `aviatrix_action_lookup` with `vendor_action` as input.
- Don't use `LOOKUP ... OUTPUT x AS action` with `action` as the input: Splunk reports a reference cycle. The EVAL approach avoids it.
- Dashboards use the `aviatrix_traffic_action` macro for the traffic outcome, so app 2.0.1 works with TA 2.0.0 through 2.0.2. The L7 Firewall Activity dashboard deliberately uses `action_cim` (policy verdict).
- IDS: `severity` is the CIM string and `severity_id` is numeric. Dashboards filter on `severity_id`.
- Audit: `action` is the CIM verb (from the REST `method=` in `syslog`, or the legacy command name plus argv sub-op). The raw API name or URL is in `command`. `status`/`result_status` are `success`/`failure`; raw `result` can be `Success`, `Fail`, or an HTTP status line like `201 CREATED`. The app normalizes these through the `aviatrix_audit_fields` macro.

- VPN (TA 2.1.0): Network_Sessions (tags `network session vpn` + `start`/`end`) and Authentication (connect events only, tag `authentication`). `action` is `success` on connect (Authentication needs it) and `deleted` on disconnect; raw status in `vendor_action`. Fields are parsed from the `AviatrixVPNSession:` text in `_raw` (the connector's `vpn_gateway_ip` is a `%{...}` placeholder when empty), so plain-syslog events with this sourcetype work too. `dest_ip` = virtual IP, `src` = client public IP, `dvc`/`dest` = gateway, `duration` in seconds, `bytes_in` = RX (from client), `bytes_out` = TX (1024-based units).

**SPL gotcha:** `OR` binds tighter than the implied `AND`, so never write `(`macro_a` OR `macro_b`)` when the macros expand to multiple terms. Use `` `aviatrix_index` (sourcetype=a OR sourcetype=b) ``.

## Development Notes

### Splunk Test Environment
- **Web UI**: http://18.219.247.244:8000/ (free license, no auth required)
- **App upload**: Web UI at `/en-US/manager/appinstall/_upload` with "Upgrade app" checkbox
- **Note**: Props.conf changes require Splunk restart to take effect

### Building Packages
```bash
tar -czf TA-aviatrix.tgz TA-aviatrix
tar -czf aviatrix-security.tgz aviatrix-security
```

### Testing
1. Upload TA-aviatrix first (field extractions must be available)
2. Upload aviatrix-security second
3. Restart Splunk
4. Navigate to Aviatrix Security app and verify dashboards load
