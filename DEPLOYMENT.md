# Aviatrix Splunk Apps Deployment Guide

## Apps Created

Two separate Splunk apps have been created:

### 1. TA-aviatrix (Technology Add-on)
**Location:** `TA-aviatrix/`

This add-on provides:
- Field extractions for all Aviatrix log types
- CIM (Common Information Model) compliance
- Lookup tables for action normalization
- Event types and tags for data model mapping

**Supported Sourcetypes:**
| Sourcetype | Description |
|------------|-------------|
| `aviatrix:firewall:l4` | DCF L4 micro-segmentation logs |
| `aviatrix:firewall:l7` | DCF L7 TLS/SNI inspection logs |
| `aviatrix:firewall:fqdn` | FQDN egress filtering logs |
| `aviatrix:ids` | Suricata IDS alerts (EVE JSON) |
| `aviatrix:gateway:network` | Gateway network stats |
| `aviatrix:gateway:system` | Gateway CPU/memory/disk stats |
| `aviatrix:controller:audit` | Controller API audit logs |

### 2. aviatrix-security (Visualization App)
**Location:** `aviatrix-security/`

This app provides 7 dashboards:
1. **Security Overview** - Executive security posture summary
2. **Traffic Analysis** - Deep-dive with Sankey diagrams
3. **Threat Detection** - IDS/Suricata alert analysis
4. **Policy Enforcement** - DCF policy effectiveness
5. **Egress Monitoring** - FQDN/L7 egress visibility
6. **Gateway Health** - Infrastructure monitoring
7. **Audit Trail** - Controller change tracking

---

## Deployment Instructions

### Option 1: Manual Deployment

1. **Copy TA-aviatrix to Splunk:**
```bash
# SSH to Splunk server
scp -r TA-aviatrix admin@3.15.239.57:/opt/splunk/etc/apps/
```

2. **Copy aviatrix-security to Splunk:**
```bash
scp -r aviatrix-security admin@3.15.239.57:/opt/splunk/etc/apps/
```

3. **Restart Splunk:**
```bash
ssh admin@3.15.239.57 "/opt/splunk/bin/splunk restart"
```

### Option 2: Package and Upload via UI

1. **Create deployment packages:**
```bash
cd /Users/christophermchenry/Documents/Scripting/SplunkforAviatrix
tar -czf TA-aviatrix.tgz TA-aviatrix
tar -czf aviatrix-security.tgz aviatrix-security
```

2. **Upload via Splunk Web UI:**
   - Navigate to: `Apps` > `Manage Apps` > `Install app from file`
   - Upload `TA-aviatrix.tgz` first
   - Then upload `aviatrix-security.tgz`
   - Restart Splunk when prompted

### Option 3: Deployment Server (Enterprise)

If using a Splunk deployment server:
```bash
# Copy to deployment-apps
cp -r TA-aviatrix $SPLUNK_HOME/etc/deployment-apps/
cp -r aviatrix-security $SPLUNK_HOME/etc/deployment-apps/

# Reload deployment server
$SPLUNK_HOME/bin/splunk reload deploy-server
```

---

## Verification

### 1. Verify TA Field Extractions
```spl
index=main sourcetype=aviatrix:firewall:l4 | head 5
| table _time, src, dest, src_port, dest_port, action, transport, vendor_product, duration, bytes
```

Expected: You should see CIM-normalized fields like `src`, `dest`, `transport`, `vendor_product`.

### 2. Verify CIM Compliance
```spl
| datamodel Network_Traffic All_Traffic search | head 5
| table _time, src, dest, action, transport, vendor_product
```

### 3. Verify Event Types
```spl
| eventcount summarize=false index=main | search eventtype=aviatrix_*
```

### 4. Test Dashboards
Navigate to: `Aviatrix Security` > `Security Overview`

---

## CIM Fields Mapped

### Network Traffic Data Model
| CIM Field | L4 Source | L7 Source |
|-----------|-----------|-----------|
| src | src_ip | src |
| dest | dst_ip | dest |
| src_port | src_port | src_port |
| dest_port | dst_port | dest_port |
| action | PERMIT→allowed, DENY→blocked | Permit→allowed, Deny→blocked |
| transport | proto | proto |
| bytes | session_byte_cnt | request_bytes+response_bytes |
| duration | session_dur (converted to seconds) | session_time (converted to seconds) |
| vendor_product | "Aviatrix Cloud Firewall" | "Aviatrix Cloud Firewall" |

### Intrusion Detection Data Model
| CIM Field | IDS Source |
|-----------|------------|
| signature | signature |
| signature_id | signature_id |
| severity | severity (1-4) |
| category | category |
| ids_type | "network" |
| vendor_product | "Aviatrix IDS (Suricata)" |

---

## Troubleshooting

### Fields Not Appearing
1. Ensure TA-aviatrix is installed in `$SPLUNK_HOME/etc/apps/`
2. Restart Splunk to reload configurations
3. Check that sourcetype matches exactly (e.g., `aviatrix:firewall:l4`)

### Dashboard Searches Failing
1. Verify the index name in `aviatrix-security/default/macros.conf`
2. Default index is `main` - update `[aviatrix_index]` macro if different

### Sankey Diagram Not Rendering
The Traffic Analysis dashboard uses the Sankey Diagram app:
- Install from: https://splunkbase.splunk.com/app/3112/
