# Aviatrix Add-on for Splunk - Release Notes

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
