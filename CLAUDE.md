# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains two Splunk apps for **Aviatrix Distributed Cloud Firewall** security visibility, version 2.0.0. Logs are ingested via HEC (HTTP Event Collector) with CIM-compliant field normalization.

## Architecture

### Two-App Design

**TA-aviatrix** (Technology Add-on) -- field extractions, lookups, CIM compliance:
```
TA-aviatrix/
├── default/
│   ├── app.conf            # Add-on metadata (v2.0.0, hidden from UI)
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
│   ├── app.conf            # App metadata (v2.0.0, visible in UI)
│   ├── macros.conf         # Search macros (aviatrix_index, aviatrix_l4, etc.)
│   └── data/ui/
│       ├── nav/default.xml
│       └── views/          # 6 dashboards
│           ├── overview.xml
│           ├── traffic_analysis.xml
│           ├── threat_detection.xml
│           ├── policy_enforcement.xml
│           ├── gateway_health.xml
│           └── audit_trail.xml
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

### Key Macros (in aviatrix-security)

- `aviatrix_index` -- base index filter (default: `index=main`)
- `aviatrix_l4` -- L4 firewall events
- `aviatrix_l7` -- L7 firewall events
- `aviatrix_fqdn` -- FQDN egress events
- `aviatrix_ids` -- IDS/Suricata alerts
- `aviatrix_audit` -- Controller audit logs

### CIM Field Mapping

Action normalization uses `aviatrix_action_lookup` with output field `action_cim`:
- L4: `PERMIT` -> `allowed`, `DENY` -> `blocked`
- L7: `Permit` -> `allowed`, `Deny` -> `blocked`

**Important:** The lookup outputs to `action_cim` (not `action`) to avoid a reference cycle in Splunk. Dashboards use `action_cim` for the normalized action value.

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
