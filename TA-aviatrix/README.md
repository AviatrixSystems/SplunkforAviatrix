# Aviatrix Add-on for Splunk

Technology Add-on (TA) for Aviatrix Cloud Firewall logs. Provides field extractions, lookups, CIM compliance, and data normalization for Aviatrix security logs ingested via HEC (HTTP Event Collector).

## Supported Log Types

| Sourcetype | Description | CIM Data Model |
|---|---|---|
| `aviatrix:firewall:l4` | Distributed Cloud Firewall L4 micro-segmentation | Network Traffic |
| `aviatrix:firewall:l7` | L7 TLS/SNI inspection | Network Traffic |
| `aviatrix:firewall:fqdn` | FQDN egress filtering | Network Traffic |
| `aviatrix:ids` | Suricata IDS alerts (EVE JSON) | Intrusion Detection |
| `aviatrix:gateway:network` | Gateway network throughput statistics | Performance |
| `aviatrix:gateway:system` | Gateway CPU, memory, disk health | Performance |
| `aviatrix:controller:audit` | Controller API audit logs | Change Analysis |

## Installation

1. Install this add-on on your Splunk search heads and indexers.
2. Configure an HEC token on your Splunk instance.
3. Configure your Aviatrix Controller to send logs to Splunk via HEC using the sourcetypes above.

For dashboards and visualizations, install the companion app **Aviatrix Security** (`aviatrix-security`).

## Configuration

### Index

By default, this add-on expects data in `index=main`. If you use a custom index, the companion Aviatrix Security app provides an `aviatrix_index` macro that can be customized via **Settings > Advanced Search > Search Macros**.

### HEC Setup

Create an HEC token in Splunk and configure your Aviatrix Controller's CoPilot or syslog integration to forward logs using the appropriate sourcetype. The add-on auto-extracts JSON fields from HEC payloads.

## CIM Compliance

This add-on maps Aviatrix fields to the Splunk Common Information Model:

**Network Traffic** (L4, L7, FQDN):
- `src`, `dest`, `transport`, `bytes`, `packets`, `duration`, `action`, `rule`, `dvc`, `vendor_product`

**Intrusion Detection** (IDS):
- `src`, `dest`, `signature`, `ids_type`, `severity`, `category`, `vendor_product`

**Change Analysis** (Audit):
- `user`, `object`, `status`, `change_type`, `dvc`, `vendor_product`

## Lookups

| Lookup | Purpose |
|---|---|
| `aviatrix_action_lookup` | Normalizes action values (PERMIT/Permit/Allow -> allowed, DENY/Deny/Block -> blocked) |
| `aviatrix_severity_lookup` | Maps Suricata severity integers to names (1=critical, 2=high, etc.) |
| `aviatrix_protocol_lookup` | Resolves protocol numbers/names (6=tcp, 17=udp, 1=icmp) |
| `aviatrix_session_end_reason_lookup` | Maps session end reason codes to descriptions |

## Compatibility

- Splunk Enterprise 8.0+
- Splunk Cloud
- Splunk CIM 4.0+

## License

Apache License 2.0

## Support

For issues and feature requests, visit the [GitHub repository](https://github.com/AviatrixSystems/SplunkforAviatrix).
