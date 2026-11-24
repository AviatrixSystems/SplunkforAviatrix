#!/usr/bin/env python3
"""Generate the Aviatrix_Traffic data model (aviatrix-security/default/data/models).

One object, Flows: one event per firewall connection across L4, L7 and FQDN
(the `aviatrix_flows` macro), with the outcome/direction/domain normalizations
the dashboards need precomputed, so long time ranges read the acceleration
summary through tstats instead of re-parsing JSON events.
"""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "..", "aviatrix-security", "default", "data", "models",
                   "Aviatrix_Traffic.json")

PRIV = r'"^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\.|^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\."'
DENY = r'"^(deny|drop|block|blocked|reject)$"'


def field(name, owner="Flows", ftype="string", comment=""):
    return {"fieldName": name, "owner": owner, "type": ftype, "fieldSearch": "", "required": False,
            "multivalue": False, "hidden": False, "editable": True, "displayName": name, "comment": comment}


def calc(cid, name, expression, comment, ftype="string"):
    return {"calculationID": cid, "calculationType": "Eval", "owner": "Flows", "editable": True,
            "comment": comment, "expression": expression, "outputFields": [field(name, ftype=ftype)]}


extracted = [field("_time", "BaseEvent", "timestamp"), field("host", "BaseEvent"), field("source", "BaseEvent"),
             field("sourcetype", "BaseEvent")]
extracted += [field(n) for n in ["src", "dest", "transport", "enforced"]]
extracted += [field("dest_port", ftype="number")]

calcs = [
    calc("log_type", "log_type",
         'case(sourcetype=="aviatrix:firewall:l4", "l4", sourcetype=="aviatrix:firewall:l7", "l7", 1=1, "fqdn")',
         "l4 | l7 | fqdn"),
    calc("outcome", "outcome",
         f'case(sourcetype=="aviatrix:firewall:fqdn", if(action=="blocked", "Blocked", "Allowed"), '
         f'match(lower(coalesce(vendor_action, action)), {DENY}) AND lower(enforced)=="false", "Would block", '
         f'match(lower(coalesce(vendor_action, action)), {DENY}), "Blocked", 1=1, "Allowed")',
         "Allowed | Would block (deny rule in monitor mode) | Blocked; same as the aviatrix_outcome macro"),
    calc("outcome_key", "outcome_key",
         f'case(sourcetype=="aviatrix:firewall:fqdn", if(action=="blocked", "blocked", "allowed"), '
         f'match(lower(coalesce(vendor_action, action)), {DENY}) AND lower(enforced)=="false", "monitor", '
         f'match(lower(coalesce(vendor_action, action)), {DENY}), "blocked", 1=1, "allowed")',
         "allowed | monitor | blocked (dashboard token values)"),
    calc("direction", "direction",
         f'case(match(src, {PRIV}) AND match(dest, {PRIV}), "East-west", match(src, {PRIV}), "Egress", 1=1, "Ingress")',
         "East-west | Egress | Ingress"),
    calc("domain", "domain", 'coalesce(sni_hostname, hostname, if(sourcetype=="aviatrix:firewall:l7", dest, null()))',
         "TLS SNI (L7, destination IP when there is no SNI) or FQDN hostname; null for L4"),
    calc("port", "port", 'if(match(tostring(coalesce(dest_port, dst_port)), "^\\d+$"), tostring(coalesce(dest_port, dst_port)), "none")',
         "Destination port as a string; none for FQDN events, so port=* matches every flow"),
    calc("rule", "rule", 'coalesce(decided_by, uuid, if(match(rule, "^%\\{"), null(), rule))', "Policy rule UUID"),
    calc("flow_role", "flow_role",
         'if(tonumber(src_port)<10000 AND tonumber(coalesce(dest_port, dst_port))>=32768, "reply", "request")',
         "reply = from a service port to a client ephemeral port (return traffic); request otherwise. "
         "Scan and sweep detection counts requests only, so busy servers do not look like scanners."),
    calc("proto", "proto", 'upper(coalesce(transport, proto, "tcp"))', "TCP | UDP | ICMP"),
]

model = {
    "modelName": "Aviatrix_Traffic",
    "displayName": "Aviatrix Traffic",
    "description": "Aviatrix Distributed Cloud Firewall flows (L4, L7, FQDN), one event per connection.",
    "editable": True,
    "objectNameList": ["Flows"],
    "objects": [{
        "objectName": "Flows", "displayName": "Flows", "parentName": "BaseEvent", "comment": "",
        "lineage": "Flows",
        "constraints": [{"search": "`aviatrix_flows`", "owner": "Flows"}],
        "fields": extracted,
        "calculations": calcs,
    }],
}

os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as f:
    json.dump(model, f, indent=2)
print("wrote", os.path.relpath(OUT))
