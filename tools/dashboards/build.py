#!/usr/bin/env python3
"""Generate the aviatrix-security Dashboard Studio views.

    python3 tools/dashboards/build.py

Writes aviatrix-security/default/data/ui/views/*.xml. Edit the dashboards here
(or in the Studio editor, then port the change back) so the shared layout and
palette stay consistent across views.

Performance: each dashboard scans a dataset once or twice into a pre-aggregated
base search (time-binned counts, or per-entity counts) and every panel is a
chained post-process of it, so a 90-day or 1-year range costs a few scans, not
one scan per panel.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from studio import *  # noqa: E402,F401,F403

VIEWS = os.path.join(os.path.dirname(__file__), "..", "..", APP, "default", "data", "ui", "views")

FW_STS = '(sourcetype="aviatrix:firewall:l4" OR sourcetype="aviatrix:firewall:l7")'


def gw_dropdown(d, sourcetypes, field="host", title="Gateway"):
    d.dynamic_dropdown("gateway", title, f"""
| tstats count where `aviatrix_index` {sourcetypes} by host
| sort - count | head 300
| eval label=host, value=host | fields label value""", all_label="All gateways")


TIME_FMT = '"%Y-%m-%d %H:%M"'


# =================================================================== overview
def overview():
    d = Dashboard("overview", "Security Overview",
                  "Aviatrix Cloud Firewall posture at a glance: traffic outcomes, threats, risky changes and "
                  "remote access, with notable activity to triage first.")
    gw_dropdown(d, FW_STS)
    W = "host=$gateway$"

    fw_time = d.search(tstats_time(W), name="ds_fw_time")
    fw_dest = d.search(tstats_by(W + " Flows.outcome!=Allowed", "Flows.dest Flows.domain Flows.outcome",
                                 "count dc(Flows.src) as sources values(host) as gateways max(_time) as last"),
                       name="ds_fw_dest")
    fw_dom = d.search(tstats_by(W + " Flows.log_type!=l4", "Flows.domain Flows.outcome"), name="ds_fw_domains")
    fw_gw = d.search(tstats_by(W, "host Flows.outcome Flows.rule", "count max(_time) as last"), name="ds_fw_gateways")
    th_time = d.search(r"""
`aviatrix_threats` host=$gateway$
| `aviatrix_threat_fields`
| bin _time bins=100
| stats count by _time sev_label threat_outcome""", name="ds_threat_time")
    au_time = d.search(r"""
`aviatrix_audit`
| `aviatrix_audit_fields`
| where change_action!="read"
| bin _time bins=100
| stats count by _time""", name="ds_audit_time")
    vpn = d.search(r"""
`aviatrix_vpn`
| `aviatrix_vpn_fields`
| where vpn_status="active"
| bin _time bins=100
| stats count by _time""", name="ds_vpn_time")

    d.section("Posture", "Totals for the selected range. Flows count each connection once (session-end and TLS-check records excluded).")
    flows_k = kpi("Firewall flows", kpi_wide(d, fw_time, ALL_OUTCOMES))
    flows_k["eventHandlers"] = link("traffic_analysis")
    blk = kpi("Blocked", kpi_wide(d, fw_time, "coalesce(Blocked, 0)"), alert_color=BLOCKED,
              description="Dropped by enforced rules")
    blk["eventHandlers"] = link("traffic_analysis", ("action", "blocked"))
    wb = kpi("Would block", kpi_wide(d, fw_time, "coalesce('Would block', 0)"), alert_color=MONITOR,
             description="Deny rules in monitor mode: logged, not dropped")
    wb["eventHandlers"] = link("traffic_analysis", ("action", "monitor"))
    th = kpi("Threat alerts", kpi_chain(d, th_time), alert_color=SEV["High"], description="Suricata IDS + L7 inline IPS")
    th["eventHandlers"] = link("threat_detection")
    ch = kpi("Config changes", kpi_chain(d, au_time), description="Controller create, modify, delete")
    ch["eventHandlers"] = link("audit_trail")
    vp = kpi("VPN sessions", kpi_chain(d, vpn), description="User VPN connects")
    vp["eventHandlers"] = link("vpn_sessions")
    d.row(150, (2, flows_k), (2, blk), (2, wb), (2, th), (2, ch), (2, vp))

    d.row(290,
          (8, area("Firewall outcomes over time", fw_time, colors=OUTCOME_COLORS, stacked=True, y_title="flows")),
          (4, column("Threat alerts by severity", d.chain(th_time, "| timechart sum(count) by sev_label"),
                     colors=SEV, stacked=True)))

    d.section("Notable activity", "Detections across all Aviatrix sources, most severe first. Click a row to investigate.")
    notable = d.search(r"""
| tstats summariesonly=false count min(_time) as first max(_time) as last values(host) as gw values(Flows.dest) as dests from datamodel=Aviatrix_Traffic.Flows where host=$gateway$ Flows.log_type=l4 Flows.flow_role=request by Flows.src Flows.port
| rename Flows.src as src, Flows.port as port
| eval probe_port=port
| stats sum(count) as count min(first) as first max(last) as last values(gw) as gw dc(probe_port) as ports dc(dests) as hosts by src
| where ports>=100 OR hosts>=100
| join type=left src [| tstats summariesonly=false count as denied from datamodel=Aviatrix_Traffic.Flows where host=$gateway$ Flows.log_type=l4 Flows.outcome!=Allowed by Flows.src | rename Flows.src as src]
| eval denied=coalesce(denied, 0), severity=if(denied/count>0.5, "High", "Medium"), detection=if(ports>=hosts, "Port scan", "Host sweep"), entity=src, evidence=ports." ports on ".hosts." hosts, ".round(denied/count*100)."% denied", _view="traffic_analysis", _param="form.src"
| append [| tstats summariesonly=false fillnull_value="-" count min(_time) as first max(_time) as last dc(Flows.src) as srcs values(host) as gw from datamodel=Aviatrix_Traffic.Flows where host=$gateway$ Flows.outcome="Would block" Flows.direction=Egress by Flows.domain Flows.dest
    | eval entity=if('Flows.domain'=="-", 'Flows.dest', 'Flows.domain')
    | stats sum(count) as count min(first) as first max(last) as last max(srcs) as srcs values(gw) as gw by entity
    | sort - count | head 5
    | eval severity="Medium", detection="Egress allowed only by monitor mode", evidence=srcs." internal sources; a deny rule matched but is not enforced", _view="traffic_analysis", _param="form.dest" ]
| append [| tstats summariesonly=false count min(_time) as first max(_time) as last dc(Flows.src) as srcs values(host) as gw values(Flows.port) as ports from datamodel=Aviatrix_Traffic.Flows where host=$gateway$ Flows.direction=Ingress Flows.outcome=Allowed Flows.flow_role=request Flows.rule="defa11a1-0000-0000-0000-000000000000" by Flows.dest
    | rename Flows.dest as entity
    | eval sensitive=mvfilter(match(ports, "^(21|22|23|25|110|135|139|143|445|1433|1521|2375|2379|3306|3389|5432|5601|5900|6379|6443|8080|9092|9200|10250|11211|27017)$"))
    | eval severity=if(mvcount(sensitive)>0, "High", "Medium"), detection="Internet ingress allowed by default rule", evidence=srcs." external sources on ports ".mvjoin(mvindex(ports, 0, 5), ", ").if(mvcount(ports)>6, ", ...", "").": no explicit policy matched", _view="traffic_analysis", _param="form.dest"
    | sort - srcs | head 10 ]
| append [ search `aviatrix_threats` host=$gateway$
    | `aviatrix_threat_fields`
    | where severity_id<=2
    | stats count min(_time) as first max(_time) as last dc(internal_host) as hosts values(internal_host) as h values(host) as gw by signature sev_label threat_outcome
    | eval severity=sev_label, detection=if(threat_outcome=="Blocked", "Threat blocked", "Threat detected"), entity=signature, evidence=hosts." internal hosts: ".mvjoin(mvindex(h, 0, 2), ", ").if(hosts>3, ", ...", ""), _view="threat_detection", _param="form.signature" ]
| append [ search `aviatrix_audit`
    | `aviatrix_audit_fields` | `aviatrix_audit_risk`
    | where isnotnull(audit_risk)
    | stats count min(_time) as first max(_time) as last values(command) as cmds values(controller) as gw by audit_risk username
    | eval severity=if(audit_risk=="Logging change", "High", "Medium"), detection=audit_risk, entity=username, evidence=count." changes: ".mvjoin(mvindex(cmds, 0, 1), ", ").if(mvcount(cmds)>2, ", ...", ""), _view="audit_trail", _param="form.user" ]
| append [ search `aviatrix_audit`
    | `aviatrix_audit_fields`
    | where result_status="failure"
    | stats count min(_time) as first max(_time) as last dc(command) as cmds values(controller) as gw by username
    | where count>=25
    | eval severity="Low", detection="Repeated controller API failures", entity=username, evidence=count." failed calls across ".cmds." commands", _view="audit_trail", _param="form.user" ]
| append [ search `aviatrix_vpn`
    | `aviatrix_vpn_fields`
    | where vpn_status="active" AND isnotnull(src)
    | iplocation src
    | stats dc(Country) as countries values(Country) as c dc(src) as ips count min(_time) as first max(_time) as last values(dvc) as gw by user
    | where countries>1
    | eval severity="High", detection="VPN logins from multiple countries", entity=user, evidence=mvjoin(c, ", ")." from ".ips." public IPs", _view="vpn_sessions", _param="form.user" ]
| append [ search `aviatrix_vpn`
    | `aviatrix_vpn_fields`
    | where vpn_status="disconnected" AND bytes>1073741824
    | stats count sum(bytes) as b min(_time) as first max(_time) as last values(dvc) as gw by user
    | eval severity="Medium", detection="Large VPN transfer", entity=user, evidence=`aviatrix_bytes_format(b)`." in ".count." sessions over 1 GB", _view="vpn_sessions", _param="form.user" ]
| append [ search `aviatrix_tunnel`
    | stats latest(new_state) as state count(eval(new_state="Down")) as downs min(_time) as first max(_time) as last by src_gw dst_gw
    | where downs>0
    | eval severity=if(state=="Down", "High", "Low"), detection=if(state=="Down", "Tunnel down", "Tunnel flapped"), entity=replace(src_gw, "\(.*", "")." <> ".replace(dst_gw, "\(.*", ""), evidence=downs." down events, now ".state, gw=replace(src_gw, "\(.*", ""), _view="gateway_health", _param="form.gateway" ]
| eval rank=case(severity=="Critical", 1, severity=="High", 2, severity=="Medium", 3, 1=1, 4)
| sort 0 rank -last
| eval First=strftime(first, "%Y-%m-%d %H:%M"), Last=strftime(last, "%Y-%m-%d %H:%M"), Where=mvjoin(mvindex(gw, 0, 1), ", ").if(mvcount(gw)>2, " +".(mvcount(gw)-2), "")
| rename severity as Severity, detection as Detection, entity as Entity, evidence as Evidence, count as Events
| table Severity Detection Entity Evidence Where Events First Last _view _param""", name="ds_notable")
    d.row(400, (12, table("Notable activity", notable, count=10,
                          colored={"Severity": TEXT},
                          widths={"Severity": 80, "Detection": 230, "Entity": 260, "Evidence": 380, "Events": 80},
                          drilldown=[{"type": "drilldown.customUrl", "options": {
                              "url": "/app/aviatrix-security/$row._view.value$?$row._param.value$=$row.Entity.value|u$&form.time.earliest=$time.earliest|u$&form.time.latest=$time.latest|u$",
                              "newTab": False}}])))

    d.section("Where traffic is stopped")
    d.row(360,
          (7, table("Top blocked and would-block destinations", d.chain(fw_dest, r"""
| stats sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb max(sources) as Sources values(gateways) as gw max(last) as last by dest domain
| eval Total=Blocked+wb, Domain=domain, Gateways=mvjoin(mvindex(gw, 0, 1), ", ").if(mvcount(gw)>2, " +".(mvcount(gw)-2), ""), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Total | head 50
| rename dest as Destination, wb as "Would block"
| table Destination Domain Blocked "Would block" Sources Gateways "Last seen"
"""), count=8, drilldown=link("traffic_analysis", ("dest", "$row.Destination.value$")))),
          (5, bar("Top L7 domains (SNI) by outcome", d.chain(fw_dom, r"""
| where domain!="-"
| chart sum(count) over domain by outcome
| addtotals fieldname=_total
| sort - _total | head 12
| fields - _total"""), colors=OUTCOME_COLORS, stacked=True)))

    d.section("Gateway enforcement posture", "Monitor % = deny verdicts not enforced. Default rule % = flows matched by no explicit policy, only the DCF default rule. Both are policy rollout gaps.")
    d.row(330, (12, table("Gateways", d.chain(fw_gw, r"""
| stats sum(count) as Flows sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb sum(eval(if(rule=="defa11a1-0000-0000-0000-000000000000", count, 0))) as dflt max(last) as last by host
| eval "Block %"=round(Blocked/Flows*100, 1), "Monitor %"=if(Blocked+wb>0, round(wb/(Blocked+wb)*100, 1), 0), "Default rule %"=round(dflt/Flows*100, 1), "Last activity"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Flows
| rename host as Gateway, wb as "Would block"
| table Gateway Flows Blocked "Would block" "Block %" "Monitor %" "Default rule %" "Last activity"
"""), count=8, drilldown=link("traffic_analysis", ("gateway", "$row.Gateway.value$")))))
    return d


# =================================================================== traffic
def traffic():
    d = Dashboard("traffic_analysis", "Traffic Analysis",
                  "Hunt across Distributed Cloud Firewall flows (L4 micro-segmentation and L7): who talks to what, on which "
                  "services, and what policy did about it.")
    gw_dropdown(d, FW_STS)
    d.static_dropdown("log_type", "Log type", [("All", "*"), ("L4 micro-segmentation", "l4"), ("L7 / TLS", "l7")])
    d.static_dropdown("action", "Outcome", [("All", "*"), ("Allowed", "allowed"), ("Would block (monitor)", "monitor"), ("Blocked", "blocked")])
    d.static_dropdown("direction", "Direction", [("All", "*"), ("East-west", "East-west"), ("Egress", "Egress"), ("Ingress", "Ingress")])
    d.static_dropdown("proto", "Protocol", [("All", "*"), ("TCP", "TCP"), ("UDP", "UDP"), ("ICMP", "ICMP")])
    d.text_input("src", "Source IP / CIDR")
    d.text_input("dest", "Destination IP / CIDR")
    d.text_input("port", "Dest port")

    W = ("host=$gateway$ Flows.src=$src$ Flows.dest=$dest$ Flows.port=$port$ Flows.log_type=$log_type$ "
         "Flows.proto=$proto$ Flows.outcome_key=$action$ Flows.direction=$direction$")
    t = d.search(tstats_time(W), name="ds_flow_time")
    tdir = d.search(tstats_time(W, "Flows.direction"), name="ds_flow_dir")
    e = d.search(tstats_by(W, "Flows.src Flows.dest Flows.port Flows.proto Flows.outcome Flows.direction host Flows.domain Flows.flow_role",
                           "count min(_time) as first max(_time) as last"), name="ds_flow_entities")

    d.row(150,
          (2, kpi("Flows", kpi_wide(d, t, ALL_OUTCOMES))),
          (2, kpi("Blocked", kpi_wide(d, t, "coalesce(Blocked, 0)"), alert_color=BLOCKED)),
          (2, kpi("Would block", kpi_wide(d, t, "coalesce('Would block', 0)"), alert_color=MONITOR,
                  description="Monitor-mode deny matches")),
          (2, stat("Sources", d.chain(e, "| stats dc(src) as value"))),
          (2, stat("Destinations", d.chain(e, "| stats dc(dest) as value"))),
          (2, stat("Services (ports)", d.chain(e, '| where port!="none" | stats dc(port) as value'))))
    d.row(280,
          (8, area("Flows by outcome", t, colors=OUTCOME_COLORS, stacked=True, y_title="flows")),
          (4, column("Flows by direction", tdir, colors=DIRECTION_COLORS, stacked=True)))

    d.section("Who talks to what")
    d.row(400,
          (6, sankey("Traffic flow: source network to service to outcome", d.chain(e, r"""
| eval src_net=if(`aviatrix_private_ip(src)`, replace(src, "\.\d+$", ".0/24"), "external"), service=if(port=="none", "no port", coalesce(`aviatrix_service(port)`, "port ".port))
| stats sum(count) as count by src_net service outcome
| appendpipe [| stats sum(count) as t by src_net | sort - t | head 8 | eval keep_net=1 | fields src_net keep_net]
| eventstats max(keep_net) as kn by src_net
| appendpipe [| where isnull(keep_net) | stats sum(count) as t by service | sort - t | head 8 | eval keep_svc=1 | fields service keep_svc]
| eventstats max(keep_svc) as ks by service
| where isnull(keep_net) AND isnull(keep_svc) AND isnotnull(count)
| eval src_net=if(kn==1, src_net, "other networks"), service=if(ks==1, service, "other services")
| appendpipe [| stats sum(count) as value by src_net service | rename src_net as source, service as target]
| appendpipe [| where isnull(source) | stats sum(count) as value by service outcome | rename service as source, outcome as target]
| where isnotnull(source)
| table source target value"""), description="Top 8 source networks (/24) and services; the rest are grouped")),
          (6, bar("Top services by outcome", d.chain(e, r"""
| where port!="none"
| eval service=coalesce(`aviatrix_service(port)`, "port")." ".port
| chart sum(count) over service by outcome
| addtotals fieldname=_total
| sort - _total | head 15
| fields - _total"""), colors=OUTCOME_COLORS, stacked=True)))
    d.row(380,
          (6, table("Top sources", d.chain(e, r"""
| stats sum(count) as Flows dc(dest) as Destinations dc(port) as Ports sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb values(direction) as Direction by src
| eval "Denied %"=round((Blocked+wb)/Flows*100, 1)
| sort - Flows | head 100
| rename src as Source, wb as "Would block"
| table Source Flows Destinations Ports Blocked "Would block" "Denied %" Direction"""), count=9,
                    description="Click a row to filter the dashboard to that source",
                    drilldown=set_tokens(("src", "Source")))),
          (6, table("Top destinations", d.chain(e, r"""
| stats sum(count) as Flows dc(src) as Sources values(port) as ports sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb values(domain) as dom by dest
| eval Ports=mvjoin(mvindex(ports, 0, 3), ", ").if(mvcount(ports)>4, " +".(mvcount(ports)-4), ""), Domain=coalesce(mvindex(mvfilter(dom!="-"), 0), "-"), Zone=if(`aviatrix_private_ip(dest)`, "internal", "external")
| sort - Flows | head 100
| rename dest as Destination, wb as "Would block"
| table Destination Domain Zone Ports Flows Sources Blocked "Would block" """), count=9,
                    description="Click a row to filter the dashboard to that destination",
                    drilldown=set_tokens(("dest", "Destination")))))

    d.section("Reconnaissance", "Sources that fanned out to 25+ service ports or hosts: scans, sweeps and misbehaving workloads. Only requests count: replies from a service port to client ephemeral ports are excluded, so busy servers do not look like scanners.")
    d.row(330, (12, table("Scan and sweep suspects", d.chain(e, r"""
| eval probe_port=if(flow_role!="reply", port, null()), probe_dest=if(flow_role!="reply", dest, null())
| stats dc(probe_port) as Ports dc(probe_dest) as Hosts sum(count) as Flows sum(eval(if(outcome!="Allowed", count, 0))) as denied min(first) as first max(last) as last values(host) as gw by src
| where Ports>=25 OR Hosts>=25
| eval Pattern=case(Ports>=Hosts*5, "Port scan", Hosts>=Ports*5, "Host sweep", 1=1, "Mixed fan-out"), "Denied %"=round(denied/Flows*100, 1), Gateways=mvjoin(mvindex(gw, 0, 1), ", "), First=strftime(first, "%Y-%m-%d %H:%M"), Last=strftime(last, "%Y-%m-%d %H:%M")
| sort - Ports
| rename src as Source
| table Source Pattern Ports Hosts Flows "Denied %" Gateways First Last"""), count=7,
        drilldown=set_tokens(("src", "Source")))))

    d.section("Flow records", "Most recent 500 matching flows. Click a row to open it in Search.")
    d.row(470, (12, table("Flows", d.search(r"""
`aviatrix_flows` host=$gateway$ src=$src$ dest=$dest$
| eval log_type=if(sourcetype=="aviatrix:firewall:l4", "l4", "l7"), proto=upper(coalesce(transport, proto, "tcp")), port=coalesce(tostring(coalesce(dest_port, dst_port)), "none")
| search log_type=$log_type$ proto=$proto$ port=$port$
| `aviatrix_outcome`
| `aviatrix_direction`
| search outcome_key=$action$ direction=$direction$
| head 500
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S"), Domain=coalesce(sni_hostname, "-"), Policy=coalesce(decided_by, uuid, "-"), Log=upper(log_type)
| rename host as Gateway, src as Source, dest as Destination, port as Port, proto as Proto, outcome as Outcome, direction as Direction
| table Time Gateway Log Source Destination Port Proto Direction Outcome Domain Policy""", name="ds_flow_events"),
        count=12, colored={"Outcome": TEXT}, drilldown=open_search())))
    return d


# =================================================================== threats
def threats():
    d = Dashboard("threat_detection", "Threat Detection",
                  "Suricata IDS alerts and L7 inline IPS verdicts, pivoted on the affected workload and the "
                  "external peer, with MITRE ATT&CK context.", time_default="-7d@h,now")
    gw_dropdown(d, '(sourcetype="aviatrix:ids" OR sourcetype="aviatrix:firewall:l7")')
    d.static_dropdown("severity", "Severity", [("All", "*"), ("Critical", "1"), ("High", "2"), ("Medium", "3"), ("Low", "4")])
    d.static_dropdown("engine", "Engine", [("All", "*"), ("Suricata IDS", "Suricata IDS"), ("L7 inline IPS", "L7 inline IPS")])
    d.text_input("signature", "Signature")
    d.text_input("asset", "Asset IP (either side)")
    d.text_input("src_ip", "Source IP")
    d.text_input("dest_ip", "Destination IP")

    base = r"""
`aviatrix_threats` host=$gateway$
| `aviatrix_threat_fields`
| search severity_id=$severity$ engine=$engine|s$ signature=$signature|s$ src=$src_ip$ dest=$dest_ip$ (src=$asset$ OR dest=$asset$)"""
    t = d.search(base + "\n| bin _time bins=100\n| stats count by _time sev_label threat_outcome", name="ds_threat_time")
    a = d.search(base + r"""
| stats count min(_time) as first max(_time) as last values(category) as category values(tactic) as tactic values(mitre_technique) as technique values(domain) as domain by signature sid severity_id sev_label engine threat_outcome internal_host peer host""",
                 name="ds_threat_agg")

    d.row(150,
          (2, kpi("Alerts", kpi_chain(d, t))),
          (2, kpi("Critical + high", kpi_chain(d, t, 'where sev_label="Critical" OR sev_label="High"'), alert_color=SEV["Critical"])),
          (2, kpi("Blocked inline", kpi_chain(d, t, 'where threat_outcome="Blocked"'), color=INK,
                  description="Dropped by IPS")),
          (2, stat("Signatures", d.chain(a, "| stats dc(signature) as value"))),
          (2, stat("Internal hosts", d.chain(a, "| stats dc(internal_host) as value"), description="Workloads involved")),
          (2, stat("External peers", d.chain(a, '| where NOT `aviatrix_private_ip(peer)` | stats dc(peer) as value'))))
    d.row(290,
          (8, column("Alerts by severity", d.chain(t, "| timechart sum(count) by sev_label"), colors=SEV, stacked=True)),
          (4, bar("MITRE ATT&CK tactics", d.chain(a, r"""
| mvexpand tactic
| stats sum(count) as Alerts by tactic
| sort - Alerts""") , description="From ET rule metadata; Unmapped = no MITRE tag")))

    d.section("Signatures")
    d.row(400, (12, table("Top signatures", d.chain(a, r"""
| stats sum(count) as Alerts dc(internal_host) as Hosts dc(peer) as Peers values(category) as category values(engine) as Engine values(threat_outcome) as outcome min(first) as first max(last) as last by signature sid severity_id sev_label
| eval Outcome=mvjoin(outcome, " / "), Category=mvindex(category, 0), First=strftime(first, "%Y-%m-%d %H:%M"), Last=strftime(last, "%Y-%m-%d %H:%M")
| sort severity_id - Alerts
| rename sev_label as Severity, signature as Signature, sid as SID
| table Severity Signature SID Category Engine Outcome Alerts Hosts Peers First Last"""), count=10,
        colored={"Severity": TEXT, "Outcome": TEXT}, widths={"Severity": 80, "Signature": 420},
        description="Click a signature to focus the dashboard on it",
        drilldown=set_tokens(("signature", "Signature")))))

    d.section("Who is involved", "Internal host = the private side of the alert, whatever its direction.")
    d.row(380,
          (6, table("Affected internal hosts", d.chain(a, r"""
| stats sum(count) as Alerts min(severity_id) as sev dc(signature) as Signatures values(signature) as sigs dc(peer) as Peers max(last) as last by internal_host
| eval Severity=`aviatrix_severity_label(sev)`, "Top signature"=mvindex(sigs, 0), "Last alert"=strftime(last, "%Y-%m-%d %H:%M")
| sort sev - Alerts
| rename internal_host as Host
| table Host Severity Alerts Signatures Peers "Top signature" "Last alert" """), count=9,
                    colored={"Severity": TEXT}, drilldown=set_tokens(("asset", "Host")))),
          (6, table("External peers", d.chain(a, r"""
| where NOT `aviatrix_private_ip(peer)`
| stats sum(count) as Alerts min(severity_id) as sev dc(signature) as Signatures dc(internal_host) as Hosts values(domain) as dom by peer
| iplocation peer
| eval Severity=`aviatrix_severity_label(sev)`, Location=coalesce(nullif(mvjoin(mvappend(nullif(City, ""), nullif(Country, "")), ", "), ""), "-"), Domain=coalesce(mvindex(dom, 0), "-")
| sort sev - Alerts
| rename peer as Peer
| table Peer Domain Location Severity Alerts Signatures Hosts"""), count=9,
                    colored={"Severity": TEXT}, drilldown=set_tokens(("asset", "Peer")))))

    d.section("Alert records", "Most recent 500. Click a row to open the raw event in Search.")
    d.row(470, (12, table("Alerts", d.search(base + r"""
| head 500
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S"), Source=src.coalesce(":".src_port, ""), Destination=dest.coalesce(":".coalesce(dest_port, dst_port), ""), App=coalesce(app, app_proto, transport, "-"), Context=coalesce(http_hostname.coalesce(http_url, ""), tls_sni, sni_hostname, "-")
| rename sev_label as Severity, signature as Signature, engine as Engine, threat_outcome as Outcome, host as Gateway, tactic as Tactic
| table Time Severity Signature Engine Outcome Source Destination App Context Tactic Gateway""", name="ds_threat_events"),
        count=12, colored={"Severity": TEXT, "Outcome": TEXT}, drilldown=open_search())))
    return d


# =================================================================== L7
def l7():
    d = Dashboard("policy_enforcement", "L7 Firewall Activity",
                  "Distributed Cloud Firewall L7 (TLS/SNI) policy verdicts: which domains are allowed or denied, "
                  "which rules decide, and what monitor-mode rules would block once enforced.",
                  time_default="-24h@h,now")
    gw_dropdown(d, 'sourcetype="aviatrix:firewall:l7"')
    d.static_dropdown("action", "Outcome", [("All", "*"), ("Allowed", "Allowed"), ("Would block (monitor)", "Would block"), ("Blocked", "Blocked")])
    d.static_dropdown("enforced", "Rule mode", [("All", "*"), ("Enforced", "true"), ("Monitor only", "false")])
    d.text_input("domain_filter", "Domain (wildcards ok)")
    d.text_input("src", "Source IP / CIDR")

    base = r"""
`aviatrix_l7` host=$gateway$ src=$src$ enforced=$enforced$ NOT session_stage=end NOT reason=TLS_PROFILE
| eval domain=coalesce(sni_hostname, dest)
| where "$domain_filter$"="*" OR like(lower(domain), lower(replace("$domain_filter$", "\*", "%")))
| `aviatrix_outcome`
| search outcome=$action|s$"""
    W = ("Flows.log_type=l7 host=$gateway$ Flows.src=$src$ Flows.enforced=$enforced$ "
         "Flows.outcome=$action|s$ Flows.domain=$domain_filter|s$")
    t = d.search(tstats_time(W), name="ds_l7_time")
    a = d.search(tstats_by(W, "Flows.domain Flows.src Flows.port Flows.rule host Flows.enforced Flows.outcome",
                           "count max(_time) as last"), name="ds_l7_agg")

    d.row(150,
          (2, kpi("Sessions", kpi_wide(d, t, ALL_OUTCOMES))),
          (2, kpi("Blocked", kpi_wide(d, t, "coalesce(Blocked, 0)"), alert_color=BLOCKED)),
          (2, kpi("Would block", kpi_wide(d, t, "coalesce('Would block', 0)"), alert_color=MONITOR,
                  description="Monitor-mode deny matches")),
          (2, stat("Domains", d.chain(a, "| stats dc(domain) as value"))),
          (2, stat("Sources", d.chain(a, "| stats dc(src) as value"))),
          (2, stat("Rules hit", d.chain(a, "| stats dc(rule) as value"))))
    d.row(280,
          (8, area("Verdicts over time", t,
                   colors=OUTCOME_COLORS, stacked=True, y_title="sessions")),
          (4, bar("Verdicts by gateway", d.chain(a, r"""
| chart sum(count) over host by outcome
| addtotals fieldname=_total
| sort - _total | head 10
| fields - _total"""), colors=OUTCOME_COLORS, stacked=True)))

    d.section("Domains")
    d.row(400,
          (6, bar("Top domains by verdict", d.chain(a, r"""
| chart sum(count) over domain by outcome
| addtotals fieldname=_total
| sort - _total | head 15
| fields - _total"""), colors=OUTCOME_COLORS, stacked=True)),
          (6, table("Blocked domains", d.chain(a, r"""
| where outcome="Blocked"
| stats sum(count) as Blocked dc(src) as Sources dc(rule) as Rules values(host) as gw max(last) as last by domain
| eval Gateways=mvjoin(mvindex(gw, 0, 1), ", ").if(mvcount(gw)>2, " +".(mvcount(gw)-2), ""), "Last seen"=strftime(last, "%Y-%m-%d %H:%M"), "Looks like"=if(match(domain, "^\d{1,3}(\.\d{1,3}){3}$"), "IP as SNI", "")
| sort - Blocked
| rename domain as Domain
| table Domain Blocked Sources Rules Gateways "Last seen" "Looks like" """), count=10,
                    description="Click a domain to focus the dashboard on it",
                    drilldown=set_tokens(("domain_filter", "Domain")))))
    d.row(380,
          (6, table("Would be blocked if enforced", d.chain(a, r"""
| where outcome="Would block"
| stats sum(count) as Sessions dc(src) as Sources values(rule) as rules values(host) as gw max(last) as last by domain
| eval Rule=mvindex(rules, 0), Gateways=mvjoin(mvindex(gw, 0, 1), ", ").if(mvcount(gw)>2, " +".(mvcount(gw)-2), ""), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Sessions
| rename domain as Domain
| table Domain Sessions Sources Gateways Rule "Last seen" """), count=9,
                    description="Monitor-mode deny matches: the traffic that enforcing these rules would cut off",
                    drilldown=set_tokens(("domain_filter", "Domain")))),
          (6, table("Rules by hits", d.chain(a, r"""
| stats sum(count) as Hits sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb dc(domain) as Domains dc(src) as Sources values(enforced) as enf by rule
| eval Mode=case(mvcount(enf)>1, "mixed", enf=="true", "enforced", 1=1, "monitor"), Verdict=case(Blocked>0, "Blocked", wb>0, "Would block", 1=1, "Allowed")
| sort - Hits
| rename rule as Rule, wb as "Would block"
| table Rule Verdict Mode Hits Domains Sources"""), count=9, colored={"Verdict": TEXT},
                    description="Rule UUIDs as logged (decided_by). Click to open the rule's sessions in Search",
                    drilldown=open_search())))

    d.section("Inspection exceptions", "TLS validation failures, IDS engine unavailability and stalled handshakes: traffic the L7 engine could not fully inspect.")
    d.row(330, (12, table("Exceptions", d.search(r"""
`aviatrix_l7` host=$gateway$ src=$src$ (reason=TLS_PROFILE OR reason="*TIMEOUT*")
| eval domain=coalesce(sni_hostname, dest), issue=case(reason=="TLS_PROFILE", "TLS: ".coalesce(message, "profile check failed"), reason=="IDS_POLICY_TIMEOUT", "IDS unavailable: session passed uninspected", reason=="CONNECTION_SYN_ONLY_TIMEOUT", "TCP handshake stalled (server-speaks-first protocol?)", 1=1, reason)
| where "$domain_filter$"="*" OR like(lower(domain), lower(replace("$domain_filter$", "\*", "%")))
| stats count as Events dc(src) as Sources values(dest_port) as ports values(host) as gw max(_time) as last by issue domain
| eval Ports=mvjoin(mvindex(ports, 0, 2), ", "), Gateways=mvjoin(mvindex(gw, 0, 1), ", "), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Events
| rename issue as Issue, domain as Domain
| table Issue Domain Ports Events Sources Gateways "Last seen" """, name="ds_l7_exceptions"), count=7)))

    d.section("Sources and sessions")
    d.row(330, (12, table("Top sources", d.chain(a, r"""
| stats sum(count) as Sessions dc(domain) as Domains sum(eval(if(outcome=="Blocked", count, 0))) as Blocked sum(eval(if(outcome=="Would block", count, 0))) as wb values(domain) as doms by src
| eval "Denied %"=round((Blocked+wb)/Sessions*100, 1), "Sample domains"=mvjoin(mvindex(doms, 0, 2), ", ")
| sort - Sessions | head 100
| rename src as Source, wb as "Would block"
| table Source Sessions Domains Blocked "Would block" "Denied %" "Sample domains" """), count=7,
        drilldown=set_tokens(("src", "Source")))))
    d.row(470, (12, table("Sessions", d.search(base + r"""
| head 500
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S"), Mode=if(lower(enforced)=="false", "monitor", "enforced")
| rename host as Gateway, src as Source, dest as Destination, dest_port as Port, domain as Domain, outcome as Outcome, decided_by as Rule
| table Time Gateway Source Domain Destination Port Outcome Mode Rule""", name="ds_l7_events"),
        count=12, colored={"Outcome": TEXT}, drilldown=open_search())))
    return d


# =================================================================== gateways
def gateways():
    d = Dashboard("gateway_health", "Gateway Health",
                  "Aviatrix gateway and controller health: saturation, throughput, cloud network allowances, "
                  "tunnel stability and telemetry gaps.", time_default="-24h@h,now")
    d.dynamic_dropdown("gateway", "Gateway", r"""
| tstats count where `aviatrix_index` (sourcetype="aviatrix:gateway:system" OR sourcetype="aviatrix:gateway:network") by host
| sort - count | head 300
| eval label=host, value=host | fields label value""", all_label="All gateways")

    sys_t = d.search(r"""
`aviatrix_gateway_system` gateway=$gateway$
| eval cpu=100-tonumber(cpu_idle), mem=round((tonumber(memory_total)-tonumber(memory_available))/tonumber(memory_total)*100, 1), disk=round((tonumber(disk_total)-tonumber(disk_free))/tonumber(disk_total)*100, 1)
| bin _time bins=100
| stats max(cpu) as cpu max(mem) as mem max(disk) as disk by _time gateway""", name="ds_sys_time")
    net_t = d.search(r"""
`aviatrix_gateway_network` gateway=$gateway$
| eval rx=coalesce(rx_kbps, tonumber(total_rx_rate)), tx=coalesce(tx_kbps, tonumber(total_tx_rate)), ct=tonumber(conntrack_count)
| bin _time bins=100
| stats max(rx) as rx max(tx) as tx max(ct) as ct by _time gateway interface
| stats sum(rx) as rx sum(tx) as tx sum(ct) as ct by _time gateway""", name="ds_net_time")
    status = d.search(r"""
`aviatrix_gateway_system` gateway=$gateway$
| eval cpu=100-tonumber(cpu_idle), mem=round((tonumber(memory_total)-tonumber(memory_available))/tonumber(memory_total)*100, 1), disk=round((tonumber(disk_total)-tonumber(disk_free))/tonumber(disk_total)*100, 1)
| stats latest(cpu) as cpu max(cpu) as cpu_peak latest(mem) as mem latest(disk) as disk latest(_time) as last by gateway
| append [ search `aviatrix_gateway_network` gateway=$gateway$
    | eval rx=coalesce(rx_kbps, tonumber(total_rx_rate)), tx=coalesce(tx_kbps, tonumber(total_tx_rate))
    | stats latest(rx) as rx latest(tx) as tx latest(conntrack_count) as ct max(eval(tonumber(bw_in_limit_exceeded)))  as bi max(eval(tonumber(bw_out_limit_exceeded))) as bo max(eval(tonumber(pps_limit_exceeded))) as pps max(eval(tonumber(conntrack_limit_exceeded))) as ctx min(eval(tonumber(bw_in_limit_exceeded))) as bi0 min(eval(tonumber(bw_out_limit_exceeded))) as bo0 min(eval(tonumber(pps_limit_exceeded))) as pps0 min(eval(tonumber(conntrack_limit_exceeded))) as ctx0 latest(_time) as nlast by gateway interface
    | eval allowance=(bi-bi0)+(bo-bo0)+(pps-pps0)+(ctx-ctx0)
    | stats sum(rx) as rx sum(tx) as tx sum(ct) as ct sum(allowance) as allowance max(nlast) as nlast by gateway ]
| stats values(*) as * by gateway
| eval last=max(last, nlast)
| eventstats max(last) as newest
| eval Status=case(newest-last>900, "Silent", cpu>90 OR mem>90 OR disk>90, "Critical", cpu>75 OR mem>75 OR disk>85 OR allowance>0, "Warning", 1=1, "Healthy")
| eval rank=case(Status=="Critical", 1, Status=="Warning", 2, Status=="Silent", 3, 1=1, 4)
| sort 0 rank - cpu_peak""", name="ds_gw_status")
    tun = d.search(r"""
`aviatrix_tunnel`
| eval src_name=coalesce(src_gw_name, replace(src_gw, "\(.*", "")), dst_name=coalesce(dst_gw_name, replace(dst_gw, "\(.*", ""))
| where "$gateway$"="*" OR src_name="$gateway$" OR dst_name="$gateway$"
| eval tunnel=src_name." <> ".dst_name""", name="ds_tunnels")

    d.row(150,
          (2, stat("Gateways reporting", d.chain(status, "| stats count as value"))),
          (2, stat("Silent", d.chain(status, '| where Status="Silent" | stats count as value'), color=MONITOR,
                   description="Stopped reporting >15 min before the newest data")),
          (2, stat("Warning or critical", d.chain(status, '| where Status="Warning" OR Status="Critical" | stats count as value'), color=SEV["High"])),
          (2, stat("Peak CPU", d.chain(sys_t, "| stats max(cpu) as value"), unit="%")),
          (2, stat("Peak memory", d.chain(sys_t, "| stats max(mem) as value"), unit="%")),
          (2, kpi("Tunnel down events", d.chain(tun, r"""
| timechart count(eval(new_state="Down")) as value
| fillnull value=0 value
| eventstats sum(value) as total
| appendpipe [| stats count as n | where n=0 | eval value=0, total=0 | fields value total]"""), alert_color=BLOCKED)))

    d.section("Status", "Latest values per gateway, worst first. Allowance = AWS ENA packets shaped or dropped for exceeding the instance's bandwidth, PPS or conntrack allowance during the range.")
    d.row(400, (12, table("Gateways", d.chain(status, r"""
| eval "CPU %"=round(cpu, 0), "Peak CPU %"=round(cpu_peak, 0), "Memory %"=mem, "Disk %"=disk, "RX Mbps"=round(rx/1024, 2), "TX Mbps"=round(tx/1024, 2), Conntrack=ct, "Allowance exceeded"=coalesce(allowance, 0), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| rename gateway as Gateway
| table Gateway Status "CPU %" "Peak CPU %" "Memory %" "Disk %" "RX Mbps" "TX Mbps" Conntrack "Allowance exceeded" "Last seen" """),
        count=10, colored={"Status": TEXT},
        description="Click a gateway to focus the charts on it",
        drilldown=set_tokens(("gateway", "Gateway")))))

    d.section("Saturation", "Top 10 gateways by peak in the range.")
    d.row(290,
          (6, line("CPU used %", d.chain(sys_t, "| timechart max(cpu) by gateway where max in top10"),
                   extra={"yAxisMax": 100, "yAxisMin": 0})),
          (6, line("Memory used %", d.chain(sys_t, "| timechart max(mem) by gateway where max in top10"),
                   extra={"yAxisMax": 100, "yAxisMin": 0})))
    d.row(290,
          (6, line("Throughput, RX + TX (Mbps)", d.chain(net_t, "| eval mbps=round((rx+tx)/1024, 2) | timechart max(mbps) by gateway where max in top10"))),
          (6, line("Tracked connections", d.chain(net_t, "| timechart max(ct) by gateway where max in top10"))))

    d.section("Tunnels")
    d.row(330,
          (8, table("Tunnel state", d.chain(tun, r"""
| stats latest(new_state) as State count(eval(new_state="Down")) as "Down events" count as Changes latest(_time) as last values(src_cloud) as sc values(src_region) as sr values(dst_region) as dr by tunnel
| eval "Last change"=strftime(last, "%Y-%m-%d %H:%M"), Location=mvjoin(mvdedup(mvappend(sr, dr)), ", ")
| sort - "Down events"
| rename tunnel as Tunnel
| table Tunnel State "Down events" Changes Location "Last change" """), count=8, colored={"State": TEXT})),
          (4, column("Tunnel changes", d.chain(tun, "| timechart count by new_state"),
                     colors={"Up": GOOD, "Down": BLOCKED}, stacked=True)))
    return d


# =================================================================== audit
def audit():
    d = Dashboard("audit_trail", "Audit Trail",
                  "Aviatrix Controller change tracking: who created, modified or deleted what, when, from where, "
                  "whether it worked, and which changes matter for security.", time_default="-7d@d,now")
    d.static_dropdown("change_filter", "Operation", [
        ("Changes (exclude reads)", "NOT change_action=read"), ("All operations", "change_action=*"),
        ("Created", "change_action=created"), ("Modified", "change_action=modified"),
        ("Deleted", "change_action=deleted"), ("Read only", "change_action=read")], default="NOT change_action=read")
    d.static_dropdown("result", "Result", [("All", "*"), ("Success", "success"), ("Failure", "failure")])
    d.static_dropdown("risk", "Security relevance", [("All", "*"), ("Security-relevant only", "relevant"),
                                                      ("Logging change", "Logging change"), ("Identity change", "Identity change"),
                                                      ("Security policy change", "Security policy change")])
    d.text_input("user", "User")
    d.text_input("category", "Object category")
    d.text_input("action_filter", "Command")

    base = d.search(r"""
`aviatrix_audit`
| `aviatrix_audit_fields`
| `aviatrix_audit_risk`
| search username=$user|s$ command=$action_filter|s$ $change_filter$
| where ("$result$"="*" OR result_status="$result$") AND ("$category$"="*" OR object_category="$category$") AND ("$risk$"="*" OR ("$risk$"="relevant" AND isnotnull(audit_risk)) OR audit_risk="$risk$")
| eval command_group=if(match(command, "^/"), replace(replace(command, "[ ?].*$", ""), "/([0-9a-fA-F]{8}-[0-9a-fA-F-]{27}|[0-9a-fA-F]{24})(/|$)", "/{id}\2"), command)
| fields _time, username, src, controller, change_action, object_category, object, command, command_group, result, result_status, reason, error_code, error_message, audit_risk""",
                    name="ds_audit_base")

    d.row(150,
          (2, kpi("Operations", kpi_chain(d, base, agg="count"))),
          (2, kpi("Created", kpi_chain(d, base, 'where change_action="created"', agg="count"))),
          (2, kpi("Modified", kpi_chain(d, base, 'where change_action="modified"', agg="count"))),
          (2, kpi("Deleted", kpi_chain(d, base, 'where change_action="deleted"', agg="count"))),
          (2, kpi("Failed", kpi_chain(d, base, 'where result_status="failure"', agg="count"), alert_color=BLOCKED)),
          (2, kpi("Security-relevant", kpi_chain(d, base, 'where isnotnull(audit_risk)', agg="count"),
                  alert_color=MONITOR, description="Logging, identity or policy changes")))
    d.row(290,
          (8, column("Operations over time", d.chain(base, "| timechart count by change_action"), colors=VERB_COLORS, stacked=True)),
          (4, punchcard("When changes happen (UTC)", d.chain(base, r"""
| eval Hour=strftime(_time, "%H"), Day=strftime(_time, "%w %a")
| stats count by Hour Day
| sort Day Hour"""), description="Off-hours activity stands out")))

    d.section("Security-relevant changes", "Logging changes can be defense evasion; identity changes grant access; policy changes alter enforcement.")
    d.row(360, (12, table("Security-relevant changes", d.chain(base, r"""
| where isnotnull(audit_risk)
| sort - _time
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S"), Details=coalesce(error_message, if(reason=="None" OR reason=="", null(), substr(reason, 1, 120)), "-")
| rename audit_risk as Category, username as User, src as "Source IP", change_action as Operation, command as Command, result_status as Result
| table Time Category User "Source IP" Operation Command Result Details"""), count=9,
        colored={"Operation": TEXT, "Result": TEXT}, widths={"Command": 340})))

    d.section("Who and what")
    d.row(330,
          (4, bar("Activity by user", d.chain(base, r"""
| chart count over username by change_action
| addtotals fieldname=_total
| sort - _total | head 10
| fields - _total"""), colors=VERB_COLORS, stacked=True)),
          (8, table("Top commands", d.chain(base, r"""
| stats count as Count values(change_action) as Operation count(eval(result_status="failure")) as Failed dc(username) as Users latest(_time) as last by command_group
| eval "Fail %"=round(Failed/Count*100, 1), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Count
| rename command_group as Command
| table Command Operation Count Failed "Fail %" Users "Last seen" """), count=8,
                    description="Click a command to filter the dashboard to it",
                    drilldown=set_tokens(("action_filter", "Command")))))
    d.row(330,
          (8, table("Failures by controller error", d.chain(base, r"""
| where result_status="failure"
| eval Error=coalesce(error_code, "no error code"), Message=coalesce(error_message, if(reason=="None" OR reason=="", result, substr(reason, 1, 100)))
| stats count as Failures dc(username) as Users values(command_group) as cmds latest(_time) as last by Error Message
| eval Commands=mvjoin(mvindex(cmds, 0, 1), ", "), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Failures
| table Error Message Failures Users Commands "Last seen" """), count=8, widths={"Message": 380})),
          (4, bar("Changes by object category", d.chain(base, r"""
| stats count by object_category
| sort - count | head 12"""), description="Click to filter", )))

    d.section("Audit log", "Most recent 500 operations. Click a row to open it in Search.")
    d.row(470, (12, table("Operations", d.chain(base, r"""
| head 500
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S")
| rename username as User, src as "Source IP", controller as Controller, change_action as Operation, object_category as Category, command as Command, result as Result, result_status as Status
| table Time User "Source IP" Controller Operation Category Command Result Status"""), count=12,
        colored={"Operation": TEXT, "Status": TEXT}, widths={"Command": 360}, drilldown=open_search())))
    return d


# =================================================================== VPN
def vpn():
    d = Dashboard("vpn_sessions", "VPN Sessions",
                  "Aviatrix User VPN: who is connected, from where, for how long, how much data they moved, "
                  "and which sessions deserve a second look.", time_default="-7d@d,now")
    d.text_input("user", "User")
    d.text_input("gateway", "VPN gateway")
    d.text_input("src", "Client public IP")
    base = d.search(r"""
`aviatrix_vpn`
| `aviatrix_vpn_fields`
| search user=$user|s$ dvc=$gateway|s$
| where "$src$"="*" OR src="$src$"
| fields _time, session_id, vpn_status, user, src, dest_ip, dvc, vpn_login, vpn_logout, duration, bytes_in, bytes_out, bytes, client_platform, client_version""",
                    name="ds_vpn_base")

    open_q = r"""
| stats min(_time) as connected values(vpn_status) as states latest(src) as src latest(client_platform) as platform latest(client_version) as client by session_id, user, dvc, dest_ip
| eventstats max(connected) as newest by dvc, dest_ip
| where isnull(mvfind(states, "^disconnected$")) AND connected=newest"""
    d.row(150,
          (2, kpi("Sessions started", kpi_chain(d, base, 'where vpn_status="active"', agg="count"))),
          (2, stat("Still connected", d.chain(base, open_q + " | stats count as value"), color=GOOD)),
          (2, stat("Users", d.chain(base, "| stats dc(user) as value"))),
          (2, stat("Client public IPs", d.chain(base, "| stats dc(src) as value"))),
          (2, stat("Data transferred", d.chain(base, r"""
| where vpn_status="disconnected" | stats sum(bytes) as b
| eval value=`aviatrix_bytes_format(coalesce(b, 0))`"""))),
          (2, stat("Avg session", d.chain(base, r"""
| where vpn_status="disconnected" | stats avg(duration) as d
| eval value=`aviatrix_duration_format(round(coalesce(d, 0)))`"""))))

    d.row(300, (12, table("Open sessions", d.chain(base, open_q + r"""
| eval "Connected for"=tostring(now()-connected, "duration"), Connected=strftime(connected, "%Y-%m-%d %H:%M:%S")
| sort - connected
| rename user as User, dvc as Gateway, dest_ip as "Virtual IP", src as "Client public IP", platform as Platform, client as Client
| table Connected "Connected for" User Gateway "Virtual IP" "Client public IP" Platform Client"""), count=6,
        description="Connected in range with no disconnect logged, and the virtual IP not since reassigned")))

    d.section("Sessions worth a look", "Logins from more than one country, very large transfers, very long sessions, or many client IPs.")
    d.row(300, (12, table("Unusual sessions", d.chain(base, r"""
| eventstats dc(src) as user_ips by user
| iplocation src
| eventstats dc(Country) as user_countries values(Country) as countries by user
| eval reason=mvappend(if(user_countries>1, "Logins from ".user_countries." countries: ".mvjoin(countries, ", "), null()), if(bytes>1073741824, "Transferred ".`aviatrix_bytes_format(bytes)`, null()), if(duration>43200, "Session lasted ".tostring(duration, "duration"), null()), if(user_ips>3, user_ips." client IPs", null()))
| where isnotnull(reason)
| stats values(reason) as Why count as Events values(src) as ips values(dvc) as gw max(_time) as last by user
| eval "Client IPs"=mvjoin(mvindex(ips, 0, 3), ", "), Gateways=mvjoin(gw, ", "), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| rename user as User
| table User Why "Client IPs" Gateways Events "Last seen" """), count=6,
        drilldown=set_tokens(("user", "User")))))

    d.section("Trends and clients")
    d.row(290,
          (8, column("Sessions started by gateway", d.chain(base, '| where vpn_status="active" | timechart count by dvc'), stacked=True)),
          (4, table("Client platform and version", d.chain(base, r"""
| where vpn_status="active"
| stats count as Sessions dc(user) as Users by client_platform client_version
| sort - Sessions
| rename client_platform as Platform, client_version as Version"""), count=6)))

    d.section("Where users connect from")
    d.row(360,
          (6, bubble_map("Client locations", d.chain(base, r"""
| where vpn_status="active" AND isnotnull(src)
| iplocation src
| where isnotnull(lat)
| stats count by lat lon
| rename lat as latitude, lon as longitude"""))),
          (6, table("Client public IPs", d.chain(base, r"""
| where vpn_status="active" AND isnotnull(src)
| stats count as Sessions values(user) as Users max(_time) as last by src
| iplocation src
| eval Location=coalesce(nullif(mvjoin(mvappend(nullif(City, ""), nullif(Region, ""), nullif(Country, "")), ", "), ""), "private / unknown"), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| sort - Sessions
| rename src as "Client public IP"
| table "Client public IP" Location Users Sessions "Last seen" """), count=8,
                    drilldown=set_tokens(("src", "Client public IP")))))

    d.section("Users and session events")
    d.row(330, (12, table("Users", d.chain(base, r"""
| stats dc(eval(if(vpn_status="active", session_id, null()))) as Sessions sum(duration) as seconds sum(bytes_in) as bin sum(bytes_out) as bout dc(src) as "Client IPs" latest(_time) as last by user
| sort - seconds
| eval "Connected time"=if(isnull(seconds), "-", tostring(seconds, "duration")), "From clients"=if(isnull(bin), "-", `aviatrix_bytes_format(bin)`), "To clients"=if(isnull(bout), "-", `aviatrix_bytes_format(bout)`), "Last seen"=strftime(last, "%Y-%m-%d %H:%M")
| rename user as User
| table User Sessions "Connected time" "From clients" "To clients" "Client IPs" "Last seen" """), count=7,
        drilldown=set_tokens(("user", "User")))))
    d.row(470, (12, table("Session events", d.chain(base, r"""
| sort - _time | head 500
| eval Time=strftime(_time, "%Y-%m-%d %H:%M:%S"), Length=if(isnotnull(duration), tostring(duration, "duration"), ""), Data=if(isnotnull(bytes), `aviatrix_bytes_format(bytes)`, "")
| rename vpn_status as Status, user as User, dvc as Gateway, dest_ip as "Virtual IP", src as "Public IP", client_platform as Platform, client_version as Client
| table Time Status User Gateway "Virtual IP" "Public IP" Length Data Platform Client"""), count=12, colored={"Status": TEXT})))
    return d


ALL = [overview, traffic, threats, l7, gateways, audit, vpn]

if __name__ == "__main__":
    for make in ALL:
        dash = make()
        path = os.path.join(VIEWS, f"{dash.view}.xml")
        with open(path, "w") as f:
            f.write(dash.xml())
        print(f"wrote {os.path.relpath(path)}  ({len(dash.viz)} viz, {len(dash.ds)} data sources)")
