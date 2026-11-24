"""Small Dashboard Studio (v2) authoring kit for the Aviatrix Security app.

Every dashboard shares one design system: a dark canvas, rounded cards on a
12-column grid, KPI tiles that show the period total with a sparkline, and
reserved status colors. build.py describes the dashboards with these helpers and
writes the Simple XML wrappers into aviatrix-security/default/data/ui/views.
"""

import json
from xml.sax.saxutils import escape

APP = "aviatrix-security"

# ---------------------------------------------------------------- palette
# Dark-surface steps of the reference data-viz palette. Status colors are
# reserved for outcome/severity meaning and always ship with a text label.
CANVAS = "#0e0f12"
CARD = "#17181b"
CARD_BORDER = "#26282d"
INK = "#f0efec"
INK_2 = "#c3c2b7"
MUTED = "#898781"

ALLOWED = "#3987e5"
MONITOR = "#fab219"
BLOCKED = "#d03b3b"
GOOD = "#0ca30c"

SEV = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#3987e5", "Info": "#6b6f76"}
# Lighter text steps for colored labels inside tables (>= 4.5:1 on the card).
TEXT = {
    "Allowed": "#86b6ef", "Would block": "#fab219", "Blocked": "#ff8a85",
    "Critical": "#ff8a85", "High": "#f4a27f", "Medium": "#fab219", "Low": "#86b6ef", "Info": "#c3c2b7",
    "Healthy": "#4cc94c", "Warning": "#fab219", "Silent": "#c3c2b7",
    "Up": "#4cc94c", "Down": "#ff8a85", "Detected": "#fab219",
    "success": "#4cc94c", "failure": "#ff8a85",
    "created": "#4cc94c", "modified": "#86b6ef", "deleted": "#ff8a85", "read": "#898781",
    "active": "#4cc94c", "disconnected": "#898781",
}
CATEGORICAL = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#0ca30c", "#9085e9", "#e66767"]
OUTCOME_COLORS = {"Allowed": ALLOWED, "Would block": MONITOR, "Blocked": BLOCKED}
DIRECTION_COLORS = {"East-west": "#199e70", "Egress": "#3987e5", "Ingress": "#d55181"}
VERB_COLORS = {"created": "#199e70", "modified": "#3987e5", "deleted": "#d03b3b", "read": "#6b6f76", "unknown": "#9085e9"}

# ---------------------------------------------------------------- grid
WIDTH = 1440
PAD = 24
GUTTER = 16
COL = (WIDTH - 2 * PAD - 11 * GUTTER) / 12


def _match(field, values):
    return f'> table | seriesByName("{field}") | matchValue({values})'


class Dashboard:
    def __init__(self, view, label, description, time_default="-24h@h,now"):
        self.view = view
        self.label = label
        self.description = description
        self.viz = {}
        self.ds = {}
        self.inputs = {}
        self.input_order = []
        self.structure = []
        self.y = 0
        self.n = 0
        self.add_input("input_time", {
            "type": "input.timerange", "title": "Time range",
            "options": {"token": "time", "defaultValue": time_default},
        })

    # ------------------------------------------------------------ inputs
    def add_input(self, key, spec):
        self.inputs[key] = spec
        self.input_order.append(key)

    def text_input(self, token, title, default="*"):
        self.add_input(f"input_{token}", {
            "type": "input.text", "title": title,
            "options": {"token": token, "defaultValue": default},
        })

    def static_dropdown(self, token, title, choices, default="*"):
        self.add_input(f"input_{token}", {
            "type": "input.dropdown", "title": title,
            "options": {"token": token, "defaultValue": default,
                        "items": [{"label": l, "value": v} for l, v in choices]},
        })

    def dynamic_dropdown(self, token, title, query, all_label="All", default="*", earliest="$time.earliest$"):
        """query must return fields label and value."""
        ds = self.search(query, name=f"ds_input_{token}", earliest=earliest)
        self.add_input(f"input_{token}", {
            "type": "input.dropdown", "title": title,
            "dataSources": {"primary": ds},
            "options": {
                "token": token, "defaultValue": default,
                "items": ">frame(label, value) | prepend(formattedStatics) | objects()",
            },
            "encoding": {"label": "primary[0]", "value": "primary[1]"},
            "context": {
                "formattedConfig": {"number": {"prefix": ""}},
                "formattedStatics": ">statics | formatByType(formattedConfig)",
                "statics": [[all_label], [default]],
                "label": ">primary | seriesByName(\"label\") | renameSeries(\"label\") | formatByType(formattedConfig)",
                "value": ">primary | seriesByName(\"value\") | renameSeries(\"value\") | formatByType(formattedConfig)",
            },
        })

    # ------------------------------------------------------------ data
    def search(self, query, name=None, earliest=None, latest=None, refresh=None):
        self.n += 1
        name = name or f"ds_{self.n}"
        spec = {"type": "ds.search", "name": name, "options": {"query": query.strip()}}
        if earliest or latest:
            spec["options"]["queryParameters"] = {
                "earliest": earliest or "$time.earliest$", "latest": latest or "$time.latest$"}
        if refresh:
            spec["options"]["refresh"] = refresh
            spec["options"]["refreshType"] = "delay"
        self.ds[name] = spec
        return name

    def chain(self, base, query, name=None):
        self.n += 1
        name = name or f"ds_{self.n}"
        self.ds[name] = {"type": "ds.chain", "name": name,
                         "options": {"extend": base, "query": query.strip()}}
        return name

    # ------------------------------------------------------------ layout
    def section(self, title, subtitle=None):
        self.n += 1
        key = f"viz_section_{self.n}"
        md = f"#### {title.upper()}"
        if subtitle:
            md += f"\n{subtitle}"
        self.viz[key] = {"type": "splunk.markdown", "options": {
            "markdown": md, "fontColor": INK_2, "fontSize": "custom", "customFontSize": 13,
            "backgroundColor": "transparent"}}
        h = 76 if subtitle else 44
        self.structure.append({"item": key, "type": "block",
                               "position": {"x": 0, "y": self.y, "w": WIDTH, "h": h}})
        self.y += h

    def row(self, height, *panels):
        """panels: (span, viz_dict) with spans summing to 12. Grid layout: the
        row tiles the full width, and Studio scales widths to the browser."""
        assert sum(p[0] for p in panels) == 12, [p[0] for p in panels]
        x = 0
        for i, (span, viz) in enumerate(panels):
            w = WIDTH - x if i == len(panels) - 1 else round(WIDTH * span / 12)
            self.n += 1
            key = f"viz_{self.n}"
            viz.setdefault("options", {})["backgroundColor"] = CARD
            if viz["type"] == "splunk.map":
                viz["options"].pop("backgroundColor")
            self.viz[key] = viz
            self.structure.append({"item": key, "type": "block",
                                   "position": {"x": x, "y": self.y, "w": w, "h": height}})
            x += w
        self.y += height

    # ------------------------------------------------------------ output
    def definition(self):
        return {
            "title": self.label,
            "description": self.description,
            "inputs": self.inputs,
            "defaults": {"dataSources": {"ds.search": {"options": {"queryParameters": {
                "earliest": "$time.earliest$", "latest": "$time.latest$"}}}}},
            "visualizations": self.viz,
            "dataSources": self.ds,
            "layout": {
                "type": "grid",
                "options": {"width": WIDTH, "height": self.y},
                "structure": self.structure,
                "globalInputs": self.input_order,
            },
        }

    def xml(self):
        body = json.dumps(self.definition(), indent=2, ensure_ascii=False)
        assert "]]>" not in body
        return (
            '<dashboard version="2" theme="dark">\n'
            f"  <label>{escape(self.label)}</label>\n"
            f"  <description>{escape(self.description)}</description>\n"
            f"  <definition><![CDATA[\n{body}\n  ]]></definition>\n"
            '  <meta type="hiddenElements"><![CDATA[\n'
            '{"hideEdit": false, "hideOpenInSearch": false, "hideExport": false}\n'
            "  ]]></meta>\n"
            "</dashboard>\n"
        )


# ---------------------------------------------------------------- visualizations
def kpi(title, ds, color=INK, alert_color=None, description=None, unit=None, precision=0):
    """Period total with a sparkline. ds must return columns `value` (per
    bucket, from timechart) and `total` (period total on every row)."""
    opts = {
        "majorValue": '> primary | seriesByName("total") | lastPoint()',
        "sparklineValues": '> primary | seriesByName("value")',
        "trendDisplay": "off",
        "sparklineDisplay": "below",
        "showSparklineAreaGraph": True,
        "sparklineStrokeColor": color if color != INK else ALLOWED,
        "majorColor": color,
        "backgroundColor": "transparent",
        "numberPrecision": precision,
        "shouldUseThousandSeparators": True,
        "majorFontSize": 34,
    }
    if unit:
        opts["unit"] = unit
        opts["unitPosition"] = "after"
    v = {"type": "splunk.singlevalue", "title": title, "dataSources": {"primary": ds}, "options": opts}
    if alert_color:
        opts["majorColor"] = "> majorValue | rangeValue(alertColors)"
        opts["sparklineStrokeColor"] = alert_color
        v["context"] = {"alertColors": [{"to": 1, "value": INK}, {"from": 1, "value": alert_color}]}
    if description:
        v["description"] = description
    return v


def stat(title, ds, field="value", color=INK, description=None, unit=None, precision=0):
    """A single number with no sparkline (for values that are not counts over time)."""
    opts = {"majorValue": f'> primary | seriesByName("{field}") | lastPoint()', "trendDisplay": "off",
            "sparklineDisplay": "off", "majorColor": color, "backgroundColor": "transparent",
            "numberPrecision": precision, "shouldUseThousandSeparators": True, "majorFontSize": 34}
    if unit:
        opts["unit"] = unit
        opts["unitPosition"] = "after"
    v = {"type": "splunk.singlevalue", "title": title, "dataSources": {"primary": ds}, "options": opts}
    if description:
        v["description"] = description
    return v


def _chart(kind, title, ds, colors=None, stacked=False, description=None, y_title=None, legend="bottom",
           extra=None):
    opts = {"backgroundColor": "transparent", "legendDisplay": legend, "xAxisTitleVisibility": "hide",
            "seriesColors": CATEGORICAL}
    if y_title:
        opts["yAxisTitleText"] = y_title
    else:
        opts["yAxisTitleVisibility"] = "hide"
    if colors:
        opts["seriesColorsByField"] = colors
    if stacked:
        opts["stackMode"] = "stacked"
    if extra:
        opts.update(extra)
    v = {"type": kind, "title": title, "dataSources": {"primary": ds}, "options": opts}
    if description:
        v["description"] = description
    return v


def area(title, ds, **kw):
    kw.setdefault("extra", {})
    kw["extra"].setdefault("areaFillOpacity", 0.55)
    return _chart("splunk.area", title, ds, **kw)


def line(title, ds, **kw):
    kw.setdefault("extra", {})
    kw["extra"].setdefault("lineWidth", 2)
    return _chart("splunk.line", title, ds, **kw)


def column(title, ds, **kw):
    return _chart("splunk.column", title, ds, **kw)


def bar(title, ds, **kw):
    kw.setdefault("legend", "off" if not kw.get("colors") else "bottom")
    return _chart("splunk.bar", title, ds, **kw)


def table(title, ds, colored=None, description=None, count=10, drilldown=None, widths=None):
    """colored: {column: palette_dict} renders those columns' text in the
    palette color (status labels only)."""
    opts = {"backgroundColor": "transparent", "count": count, "showInternalFields": False,
            "headerVisibility": "fixed", "fontSize": "small"}
    ctx = {}
    col_fmt = {}
    for i, (col, palette) in enumerate((colored or {}).items()):
        name = f"colors{i}"
        ctx[name] = [{"match": k, "value": v} for k, v in palette.items()]
        col_fmt[col] = {"rowColors": _match(col, name)}
    for col, w in (widths or {}).items():
        col_fmt.setdefault(col, {})["width"] = w
    if col_fmt:
        opts["columnFormat"] = col_fmt
    v = {"type": "splunk.table", "title": title, "dataSources": {"primary": ds}, "options": opts}
    if ctx:
        v["context"] = ctx
    if description:
        v["description"] = description
    if drilldown:
        v["eventHandlers"] = drilldown
    return v


def sankey(title, ds, description=None):
    v = {"type": "splunk.sankey", "title": title, "dataSources": {"primary": ds},
         "options": {"backgroundColor": "transparent", "colorMode": "categorical", "linkOpacity": 0.45}}
    if description:
        v["description"] = description
    return v


def punchcard(title, ds, description=None, color=ALLOWED):
    v = {"type": "splunk.punchcard", "title": title, "dataSources": {"primary": ds},
         "options": {"backgroundColor": "transparent", "bubbleColor": color, "showDefaultSort": False}}
    if description:
        v["description"] = description
    return v


def bubble_map(title, ds, description=None, color=ALLOWED):
    """ds returns latitude, longitude, count."""
    v = {"type": "splunk.map", "title": title, "dataSources": {"primary": ds},
         "options": {"center": [30, -20], "zoom": 1.3, "backgroundColor": "transparent",
                     "layers": [{"type": "bubble",
                                 "latitude": '> primary | seriesByName("latitude")',
                                 "longitude": '> primary | seriesByName("longitude")',
                                 "bubbleSize": '> primary | seriesByName("count")',
                                 "dataColors": color}]}}
    if description:
        v["description"] = description
    return v


# ---------------------------------------------------------------- drilldowns
def set_tokens(*pairs):
    """pairs: (token, row_field) -> clicking a row filters this dashboard."""
    return [{"type": "drilldown.setToken", "options": {"tokens": [
        {"token": t, "key": f"row.{f}.value"} for t, f in pairs]}}]


def set_click_token(token):
    return [{"type": "drilldown.setToken", "options": {"tokens": [{"token": token, "key": "name"}]}}]


def link(view, *pairs, keep_time=True):
    """pairs: (target_token, value_expression) e.g. ("dest", "$row.Destination.value$")."""
    tokens = [{"token": t, "value": v} for t, v in pairs]
    if keep_time:
        tokens += [{"token": "time.earliest", "value": "$time.earliest$"},
                   {"token": "time.latest", "value": "$time.latest$"}]
    return [{"type": "drilldown.linkToDashboard",
             "options": {"app": APP, "dashboard": view, "tokens": tokens, "newTab": False}}]


def open_search():
    return [{"type": "drilldown.linkToSearch", "options": {"type": "auto", "newTab": True}}]


def kpi_chain(d, base, filter_spl="", agg="sum(count)"):
    """Chain on a time-binned base search producing value/total for kpi()."""
    q = f"""
{('| ' + filter_spl) if filter_spl else ''}
| timechart {agg} as value
| fillnull value=0 value
| eventstats sum(value) as total
| appendpipe [| stats count as n | where n=0 | eval value=0, total=0 | fields value total]"""
    return d.chain(base, q)


# ---------------------------------------------------------------- data model
DM = "datamodel=Aviatrix_Traffic.Flows"


def tstats_time(where, split="Flows.outcome"):
    """Adaptive-span timechart from the Aviatrix_Traffic data model."""
    return (f"| tstats summariesonly=false prestats=t count from {DM} where {where} by _time {split}\n"
            f"| timechart count by {split}")


def tstats_by(where, by, aggs="count"):
    """tstats drops rows with a null by-field (domain is null for L4), so nulls become "-"."""
    return (f"| tstats summariesonly=false fillnull_value=\"-\" {aggs} from {DM} where {where} by {by}\n"
            "| rename Flows.* as *")


def kpi_wide(d, base, expr):
    """KPI chain on a wide timechart base (one column per outcome)."""
    return d.chain(base, f"""
| eval value={expr}
| fields _time value
| eventstats sum(value) as total
| appendpipe [| stats count as n | where n=0 | eval value=0, total=0 | fields value total]""")


ALL_OUTCOMES = "coalesce(Allowed, 0)+coalesce(Blocked, 0)+coalesce('Would block', 0)"
