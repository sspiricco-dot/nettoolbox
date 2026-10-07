"""Parse Cisco IOS / MikroTik dumps into a topology graph and Excel workbook."""

from __future__ import annotations

import io
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape

MAX_DEVICES = 40
MAX_DUMP_CHARS = 900_000

IF_SHORT = (
    (re.compile(r"^gigabitethernet", re.I), "Gi"),
    (re.compile(r"^tengigabitethernet", re.I), "Te"),
    (re.compile(r"^ten-gigabitethernet", re.I), "Te"),
    (re.compile(r"^fastethernet", re.I), "Fa"),
    (re.compile(r"^ethernet", re.I), "Eth"),
    (re.compile(r"^port-channel", re.I), "Po"),
    (re.compile(r"^vlan", re.I), "Vl"),
    (re.compile(r"^loopback", re.I), "Lo"),
    (re.compile(r"^serial", re.I), "Se"),
    (re.compile(r"^tunnel", re.I), "Tu"),
)

CDP_ABBREV = {
    "gig": "Gi",
    "gi": "Gi",
    "fas": "Fa",
    "fa": "Fa",
    "ten": "Te",
    "te": "Te",
    "eth": "Eth",
    "poe": "Po",
    "po": "Po",
}

def _clip(text: str, n: int = MAX_DUMP_CHARS) -> str:
    text = text or ""
    if len(text) > n:
        return text[:n]
    return text


def short_if(name: str) -> str:
    raw = (name or "").strip().strip('"')
    if not raw:
        return ""
    compact = re.sub(r"\s+", " ", raw)
    m = re.match(r"^([A-Za-z][A-Za-z-]*)\s*([\d/.:].*)$", compact)
    if m:
        kind, num = m.group(1), m.group(2)
        low = kind.lower()
        if low in CDP_ABBREV:
            return CDP_ABBREV[low] + num
        for pat, prefix in IF_SHORT:
            if pat.match(kind):
                return prefix + num
        return compact
    low = compact.lower().replace(" ", "")
    for pat, prefix in IF_SHORT:
        m2 = pat.match(low)
        if m2:
            rest = low[m2.end() :]
            return prefix + rest
    return compact


def device_id_key(name: str) -> str:
    n = (name or "").strip().strip('"').lower()
    n = n.split("(")[0].strip()
    if "." in n and not re.match(r"^\d", n):
        n = n.split(".")[0]
    return n or "unknown"


def detect_vendor(blob: str) -> str:
    t = blob or ""
    if re.search(r"(?m)^/(system|interface|ip|ppp|user|bridge)\b", t) or "routeros" in t.lower():
        return "mikrotik"
    if re.search(r"(?im)^(hostname |interface |Current configuration|Building configuration|version \d+\.\d+)", t):
        return "cisco"
    if re.search(r"(?i)Device ID|Local Intrfce|Capability Codes", t):
        return "cisco"
    return "auto"


_CLI_PROMPT = re.compile(r"^\S+[#>]\s?")
_CISCO_CFG_START = re.compile(r"(?im)^(?:Building configuration\.\.\.|Current configuration\s*:)")
_CISCO_CFG_END = re.compile(r"(?im)^end\s*$")
_CISCO_NB_START = re.compile(
    r"(?im)^(?:\S+[#>]\s*)?(?:show\s+)?cdp\s+neighbors|^Capability Codes:|^Device ID(?:\s*:|\s{2,})"
)
_CISCO_NB_STOP = re.compile(
    r"(?im)^(?:\S+[#>]\s*)?show\s+run(?:ning-config)?\b|^Building configuration|^Current configuration\s*:"
)


def split_cisco_session(text: str) -> tuple[str, str]:
    """Pull running-config and CDP out of a mixed CLI paste (either order)."""
    s = (text or "").replace("\r\n", "\n")
    cfg = ""
    m = _CISCO_CFG_START.search(s)
    if m:
        chunk = s[m.start():]
        end = _CISCO_CFG_END.search(chunk)
        cfg = chunk[: end.end()] if end else chunk
    elif re.search(r"(?im)^hostname\s+\S+", s) and re.search(r"(?im)^interface\s+", s):
        h = re.search(r"(?im)^hostname\s+\S+", s)
        chunk = s[h.start():]
        end = _CISCO_CFG_END.search(chunk)
        cfg = chunk[: end.end()] if end else chunk
    cfg = cfg.strip()

    nb = ""
    n = _CISCO_NB_START.search(s)
    if n:
        chunk = s[n.start():]
        stop = _CISCO_NB_STOP.search(chunk)
        if stop and stop.start() > 8:
            chunk = chunk[: stop.start()]
        lines = []
        for ln in chunk.splitlines():
            if _CLI_PROMPT.match(ln) and not re.search(r"(?i)cdp neighbors|Device ID|Capability", ln):
                continue
            lines.append(ln)
        nb = "\n".join(lines).strip()
        if cfg and nb and nb in cfg:
            nb = ""
    return cfg, nb


# --- Cisco -----------------------------------------------------------------


def _parse_cisco_interfaces(text: str) -> list[dict]:
    ifaces = []
    blocks = re.split(r"(?im)^interface\s+", text)
    for block in blocks[1:]:
        lines = block.splitlines()
        if not lines:
            continue
        name = lines[0].strip().split()[0]
        rec = {
            "name": name,
            "short": short_if(name),
            "description": "",
            "mode": "",
            "vlan": "",
            "allowed": "",
            "ip": "",
            "shutdown": False,
            "channel_group": "",
        }
        for line in lines[1:]:
            if re.match(r"^\S", line) and not line.startswith(" "):
                break
            s = line.strip()
            m = re.match(r"(?i)^description\s+(.+)$", s)
            if m:
                rec["description"] = m.group(1).strip()
            elif re.match(r"(?i)^shutdown$", s):
                rec["shutdown"] = True
            elif re.match(r"(?i)^switchport mode\s+(\S+)", s):
                rec["mode"] = re.match(r"(?i)^switchport mode\s+(\S+)", s).group(1).lower()
            elif re.match(r"(?i)^switchport access vlan\s+(\d+)", s):
                rec["vlan"] = re.match(r"(?i)^switchport access vlan\s+(\d+)", s).group(1)
                rec["mode"] = rec["mode"] or "access"
            elif re.match(r"(?i)^switchport trunk allowed vlan(?: add)?\s+(.+)$", s):
                rec["allowed"] = re.match(
                    r"(?i)^switchport trunk allowed vlan(?: add)?\s+(.+)$", s
                ).group(1)
                rec["mode"] = rec["mode"] or "trunk"
            elif re.match(r"(?i)^switchport trunk native vlan\s+(\d+)", s):
                rec["vlan"] = rec["vlan"] or re.match(
                    r"(?i)^switchport trunk native vlan\s+(\d+)", s
                ).group(1)
            elif re.match(r"(?i)^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", s):
                ipm = re.match(
                    r"(?i)^ip address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", s
                )
                rec["ip"] = f"{ipm.group(1)} {ipm.group(2)}"
            elif re.match(r"(?i)^ip address\s+(\d+\.\d+\.\d+\.\d+/\d+)", s):
                rec["ip"] = re.match(r"(?i)^ip address\s+(\S+)", s).group(1)
            elif re.match(r"(?i)^channel-group\s+(\S+)", s):
                rec["channel_group"] = re.match(r"(?i)^channel-group\s+(\S+)", s).group(1)
        ifaces.append(rec)
    return ifaces


def _parse_cisco_vlans(text: str) -> list[dict]:
    vlans = []
    for m in re.finditer(r"(?im)^vlan\s+(\d+)\s*\n((?:(?!^vlan\s|^interface |^!).*\n)*)", text):
        vid = m.group(1)
        body = m.group(2)
        name = ""
        nm = re.search(r"(?im)^\s*name\s+(\S+)", body)
        if nm:
            name = nm.group(1)
        vlans.append({"id": vid, "name": name})
    if not vlans:
        for m in re.finditer(r"(?im)^vlan\s+(\d+)\s*$", text):
            vlans.append({"id": m.group(1), "name": ""})
    seen = set()
    uniq = []
    for v in vlans:
        if v["id"] in seen:
            continue
        seen.add(v["id"])
        uniq.append(v)
    return uniq


def parse_cdp_neighbors(text: str) -> list[dict]:
    text = _clip(text)
    nbs = []
    # detail blocks
    if re.search(r"(?im)^Device ID:", text) and re.search(r"(?i)Interface:", text):
        chunks = re.split(r"(?m)^-+\s*$", text)
        if len(chunks) < 2:
            chunks = re.split(r"(?im)(?=^Device ID:)", text)
        for chunk in chunks:
            did = re.search(r"(?im)^Device ID:\s*(\S+)", chunk)
            if not did:
                continue
            ipm = re.search(r"(?i)IP address:\s*(\d+\.\d+\.\d+\.\d+)", chunk)
            plat = re.search(r"(?i)Platform:\s*([^,\n]+)", chunk)
            cap = re.search(r"(?i)Capabilities:\s*([^\n]+)", chunk)
            iface = re.search(
                r"(?i)Interface:\s*([^,\n]+?)(?:,|\n).{0,40}Port ID[^:]*:\s*([^\n]+)",
                chunk,
            )
            if not iface:
                loc = re.search(r"(?i)Interface:\s*([^\n,]+)", chunk)
                rem = re.search(r"(?i)Port ID[^:]*:\s*([^\n]+)", chunk)
                local_if = loc.group(1).strip() if loc else ""
                remote_if = rem.group(1).strip() if rem else ""
            else:
                local_if = iface.group(1).strip()
                remote_if = iface.group(2).strip()
            nbs.append(
                {
                    "remote": did.group(1).strip(),
                    "remote_ip": ipm.group(1) if ipm else "",
                    "platform": (plat.group(1).strip() if plat else ""),
                    "capability": (cap.group(1).strip() if cap else ""),
                    "local_if": short_if(local_if),
                    "remote_if": short_if(remote_if),
                    "proto": "cdp",
                }
            )
        if nbs:
            return _dedupe_nb(nbs)

    nbs = _parse_cdp_brief(text)
    return _dedupe_nb(nbs)


_CDP_IF = (
    r"(?:TenGigabitEthernet|GigabitEthernet|FastEthernet|Ethernet|Port-channel|"
    r"Ten-GigabitEthernet|Gig|Gi|Fas|Fa|Ten|Te|Eth|Po)\s*[\d/.:]+"
)


def _cdp_header_cols(line: str) -> list[tuple[int, str]]:
    specs = (
        ("device", r"Device[- ]ID"),
        ("local", r"Local\s+Int"),
        ("hold", r"Hol?dtme"),
        ("cap", r"Capab"),
        ("plat", r"Platform"),
        ("port", r"Port\s*ID"),
    )
    found = []
    for key, pat in specs:
        m = re.search(pat, line, re.I)
        if m:
            found.append((m.start(), key))
    found.sort()
    return found if len(found) >= 4 else []


def _cdp_slice(line: str, cols: list[tuple[int, str]]) -> dict:
    padded = line.rstrip("\n")
    fields = {}
    for i, (start, key) in enumerate(cols):
        end = cols[i + 1][0] if i + 1 < len(cols) else max(len(padded), start)
        fields[key] = padded[start:end].strip() if start < len(padded) else ""
    return fields


def _cdp_unstick(plat: str, port: str) -> tuple[str, str]:
    plat, port = (plat or "").strip(), (port or "").strip()
    blob = f"{plat} {port}".strip()
    m = re.search(
        rf"(?i)^(?P<plat>.+?)-(?P<port>{_CDP_IF})\s*$",
        re.sub(r"\s+", " ", blob).strip(),
    )
    if m and re.search(r"(?i)WS-C|C\d{4}|3750|2960|3650|9300|3850|ISR|ASR|MikroTik", m.group("plat")):
        return m.group("plat").strip(" -"), m.group("port").strip()
    if not re.search(_CDP_IF, port, re.I) and re.search(rf"(?i){_CDP_IF}", plat):
        m2 = re.search(rf"(?i)(?P<port>{_CDP_IF})\s*$", blob)
        if m2:
            return blob[: m2.start()].strip(" -"), m2.group("port")
    return plat, port


def _parse_cdp_brief(text: str) -> list[dict]:
    nbs = []
    lines = text.splitlines()
    cols = []
    start = 0
    for i, line in enumerate(lines):
        found = _cdp_header_cols(line)
        if found:
            cols = found
            start = i + 1
            break
    pending = ""
    line_re = re.compile(
        rf"^(?:(?P<dev>\S+)\s+)?(?P<local>{_CDP_IF})\s+(?P<hold>\d+)\s+"
        rf"(?P<cap>[A-Za-z](?:\s+[A-Za-z]){{0,8}})\s+(?P<plat>\S+)\s+(?P<port>.+)$",
        re.I,
    )
    if_re = re.compile(_CDP_IF, re.I)

    def valid_row(fields: dict) -> bool:
        loc = fields.get("local") or ""
        hold = (fields.get("hold") or "").strip()
        return bool(if_re.search(loc) and re.fullmatch(r"\d+", hold))

    for line in lines[start:]:
        raw = line.rstrip()
        if not raw.strip() or raw.strip().startswith("Total ") or raw.strip().startswith("%"):
            continue
        if re.match(r"(?i)^\s*Capability Codes", raw) or _CLI_PROMPT.match(raw):
            continue
        if re.match(r"(?i)^\s*(Device[- ]ID|Local Int)", raw):
            continue
        fields = {}
        m = line_re.match(raw.strip())
        if m:
            gd = m.groupdict()
            fields = {
                "device": gd.get("dev") or "",
                "local": gd.get("local") or "",
                "hold": gd.get("hold") or "",
                "cap": gd.get("cap") or "",
                "plat": gd.get("plat") or "",
                "port": gd.get("port") or "",
            }
        if (not valid_row(fields)) and cols:
            sliced = _cdp_slice(line if line.endswith("\n") else line, cols)
            if valid_row(sliced):
                fields = sliced
        if not valid_row(fields):
            if not if_re.search(raw) and not re.match(r"(?i)^(show\s+)?cdp\b", raw.strip()):
                pending = raw.strip()
            continue
        if pending and not (fields.get("device") or "").strip():
            fields["device"] = pending
        if not fields.get("device") and pending:
            fields["device"] = pending
        remote = (fields.get("device") or "").strip()
        if not remote:
            continue
        pending = ""
        plat, port = _cdp_unstick(fields.get("plat") or "", fields.get("port") or "")
        nbs.append(
            {
                "remote": remote.split()[0],
                "remote_ip": "",
                "platform": plat,
                "capability": fields.get("cap") or "",
                "local_if": short_if(fields.get("local") or ""),
                "remote_if": short_if(port) or port,
                "proto": "cdp",
            }
        )
    return nbs


def parse_cisco(config: str, neighbors: str = "") -> dict:
    config = _clip(config)
    neighbors = _clip(neighbors)
    hostname = ""
    hm = re.search(r"(?im)^hostname\s+(\S+)", config)
    if hm:
        hostname = hm.group(1)
    version = ""
    vm = re.search(r"(?im)^version\s+(\S+)", config)
    if vm:
        version = vm.group(1)
    gw = ""
    gm = re.search(r"(?im)^ip default-gateway\s+(\S+)", config)
    if gm:
        gw = gm.group(1)
    routing = bool(re.search(r"(?im)^ip routing\s*$", config)) or bool(
        re.search(r"(?im)^router\s+", config)
    )
    ifaces = _parse_cisco_interfaces(config)
    vlans = _parse_cisco_vlans(config)
    mgmt = ""
    for iface in ifaces:
        if iface["ip"] and (iface["name"].lower().startswith("vlan") or "mgmt" in iface["name"].lower()):
            mgmt = iface["ip"].split()[0]
            break
    if not mgmt:
        for iface in ifaces:
            if iface["ip"]:
                mgmt = iface["ip"].split()[0]
                break
    nbs = parse_cdp_neighbors(neighbors) if neighbors.strip() else []
    if not nbs:
        nbs = parse_cdp_neighbors(config)
    has_swport = any(i["mode"] for i in ifaces)
    role = "router" if routing and not has_swport else ("switch" if has_swport or vlans else ("router" if routing else "switch"))
    if hostname.lower().startswith("r") and routing:
        role = "router"
    return {
        "hostname": hostname or "cisco-device",
        "vendor": "cisco",
        "role": role,
        "platform": "",
        "version": version,
        "mgmt_ip": mgmt,
        "gateway": gw,
        "interfaces": ifaces,
        "vlans": vlans,
        "neighbors": nbs,
        "source": "dump",
    }


# --- MikroTik --------------------------------------------------------------


def _mt_unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _mt_attrs(line: str) -> dict:
    attrs = {}
    for m in re.finditer(r'([A-Za-z0-9_-]+)=(".*?"|\S+)', line):
        attrs[m.group(1).lower()] = _mt_unquote(m.group(2))
    return attrs


def parse_mikrotik_neighbors(text: str) -> list[dict]:
    text = _clip(text)
    nbs = []
    for line in text.splitlines():
        if "identity=" in line.lower() or "mac-address=" in line.lower():
            a = _mt_attrs(line)
            ident = a.get("identity") or a.get("identity-name") or ""
            if not ident:
                continue
            nbs.append(
                {
                    "remote": ident,
                    "remote_ip": a.get("address", ""),
                    "platform": a.get("platform", a.get("board", "")),
                    "capability": "",
                    "local_if": short_if(a.get("interface", a.get("interface-name", ""))),
                    "remote_if": short_if(a.get("interface-name", "") if "unpack" in a else ""),
                    "proto": "neighbor",
                }
            )
    if nbs:
        return _dedupe_nb(nbs)
    # tabular print
    lines = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
    header_i = None
    cols = []
    for i, ln in enumerate(lines):
        up = ln.upper()
        if "IDENTITY" in up and ("INTERFACE" in up or "ADDRESS" in up):
            header_i = i
            cols = re.split(r"\s{2,}", ln.strip())
            break
    if header_i is not None and cols:
        keys = [c.strip().lower().replace("-", "_") for c in cols]
        for ln in lines[header_i + 1 :]:
            parts = re.split(r"\s{2,}", re.sub(r"^\s*\d+\s+[A-Z-]*\s*", "", ln.strip()))
            if len(parts) < 2:
                parts = re.split(r"\s{2,}", ln.strip())
            row = {keys[j]: parts[j] if j < len(parts) else "" for j in range(len(keys))}
            ident = row.get("identity") or ""
            if ident in ("", "IDENTITY"):
                continue
            nbs.append(
                {
                    "remote": ident,
                    "remote_ip": row.get("address", ""),
                    "platform": row.get("platform", ""),
                    "capability": "",
                    "local_if": short_if(row.get("interface", "")),
                    "remote_if": "",
                    "proto": "neighbor",
                }
            )
    return _dedupe_nb(nbs)


def parse_mikrotik(config: str, neighbors: str = "") -> dict:
    config = _clip(config)
    neighbors = _clip(neighbors)
    hostname = ""
    m = re.search(r"(?im)^/system identity\s*$([\s\S]*?)(?=^/|\Z)", config)
    if m:
        nm = re.search(r'(?im)name=(".*?"|\S+)', m.group(1))
        if nm:
            hostname = _mt_unquote(nm.group(1))
    if not hostname:
        nm = re.search(r'(?im)^set name=(".*?"|\S+)', config)
        if nm:
            hostname = _mt_unquote(nm.group(1))

    ifaces = []
    # /interface ethernet set [ find default-name=ether1 ] name=WAN comment="x"
    for m in re.finditer(
        r'(?im)^set\s+\[ find default-name=(\S+) \]\s+(.*)$',
        config,
    ):
        default, rest = m.group(1), m.group(2)
        a = _mt_attrs("x=" + default + " " + rest)
        name = a.get("name", default)
        ifaces.append(
            {
                "name": name,
                "short": name,
                "description": a.get("comment", ""),
                "mode": "",
                "vlan": "",
                "allowed": "",
                "ip": "",
                "shutdown": a.get("disabled", "") in ("yes", "true"),
                "channel_group": "",
                "default_name": default,
            }
        )
    addrs = []
    for m in re.finditer(r"(?im)^add\s+(.+)$", config):
        line = m.group(1)
        a = _mt_attrs(" " + line)
        if "address" in a and "interface" in a:
            addrs.append(a)
            ip = a["address"]
            ifn = a["interface"]
            found = next((i for i in ifaces if i["name"] == ifn), None)
            if found:
                found["ip"] = ip
            else:
                ifaces.append(
                    {
                        "name": ifn,
                        "short": ifn,
                        "description": a.get("comment", ""),
                        "mode": "",
                        "vlan": "",
                        "allowed": "",
                        "ip": ip,
                        "shutdown": False,
                        "channel_group": "",
                    }
                )
    vlans = []
    for m in re.finditer(
        r'(?im)^add\s+.*vlan-id=(\d+).*?(?:name=(".*?"|\S+)|comment=(".*?"|\S+))?',
        config,
    ):
        vlans.append({"id": m.group(1), "name": _mt_unquote(m.group(2) or m.group(3) or "")})

    mgmt = ""
    for a in addrs:
        ip = a.get("address", "").split("/")[0]
        if ip.startswith(("10.", "192.168.", "172.")) or True:
            if a.get("interface", "").lower() in ("bridge", "lan", "vlan1", "ether2"):
                mgmt = ip
                break
    if not mgmt and addrs:
        mgmt = addrs[0].get("address", "").split("/")[0]

    nbs = parse_mikrotik_neighbors(neighbors) if neighbors.strip() else []
    if not nbs:
        nbs = parse_mikrotik_neighbors(config)

    return {
        "hostname": hostname or "mikrotik",
        "vendor": "mikrotik",
        "role": "router",
        "platform": "MikroTik RouterOS",
        "version": "",
        "mgmt_ip": mgmt,
        "gateway": "",
        "interfaces": ifaces,
        "vlans": vlans,
        "neighbors": nbs,
        "source": "dump",
    }


def _dedupe_nb(nbs: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for n in nbs:
        key = (device_id_key(n.get("remote", "")), n.get("local_if", ""), n.get("remote_if", ""))
        if key in seen or not n.get("remote"):
            continue
        seen.add(key)
        out.append(n)
    return out


def parse_device(vendor: str, config: str, neighbors: str = "", label: str = "") -> dict:
    blob = (config or "") + "\n" + (neighbors or "")
    v = (vendor or "auto").lower()
    if v in ("auto", "", "detect"):
        v = detect_vendor(blob)
    if v == "mikrotik":
        cfg_s, nb_s = config, neighbors
        if not (neighbors or "").strip() and re.search(r"(?i)/ip neighbor|identity\s*=", config or ""):
            cut = re.search(r"(?im)^/ip neighbor|^\s*\d+\s+\S*\s+interface=", config or "")
            if cut and cut.start() > 20:
                cfg_s, nb_s = (config or "")[: cut.start()], (config or "")[cut.start():]
        dev = parse_mikrotik(cfg_s, nb_s)
    else:
        cfg_s, nb_s = split_cisco_session(blob)
        if not cfg_s.strip():
            cfg_s = config or ""
        if not nb_s.strip():
            nb_s = neighbors or ""
        dev = parse_cisco(cfg_s, nb_s)
        if v == "auto" and detect_vendor(blob) == "auto":
            # last resort: if looks like mikrotik neighbor table
            if parse_mikrotik_neighbors(blob) and "/ip" in blob:
                dev = parse_mikrotik(config, neighbors)
    if label.strip():
        if not re.search(r"(?im)^hostname\s+", config or "") and not re.search(
            r"(?im)name=", config or ""
        ):
            dev["hostname"] = label.strip()
        elif not dev.get("hostname"):
            dev["hostname"] = label.strip()
    return dev


def _role_from_cap(cap: str, platform: str) -> str:
    c = (cap or "").lower()
    p = (platform or "").lower()
    if "router" in c or re.search(r"(?i)\bR\b", cap or "") or "routeros" in p or "mikrotik" in p:
        if "switch" in c or "ws-c" in p or "catalyst" in p:
            return "router" if "router" in c or "mikrotik" in p else "switch"
        return "router"
    if "phone" in c or re.search(r"(?i)\bP\b", cap or "") or "ip phone" in p:
        return "phone"
    if "host" in c or "ap" in p or "aironet" in p:
        return "host"
    if "switch" in c or "ws-c" in p or "catalyst" in p or re.search(r"(?i)\bS\b", cap or ""):
        return "switch"
    return "unknown"


def _merge_dev(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if k in ("interfaces", "vlans", "neighbors"):
            continue
        if v and (not out.get(k) or out.get("source") != "dump"):
            if k == "source" and out.get("source") == "dump":
                continue
            out[k] = v
    if a.get("source") == "dump" or b.get("source") == "dump":
        out["source"] = "dump"
    seen_if = {i.get("short") or i.get("name") for i in out.get("interfaces") or []}
    for iface in b.get("interfaces") or []:
        key = iface.get("short") or iface.get("name")
        if key not in seen_if:
            out.setdefault("interfaces", []).append(iface)
            seen_if.add(key)
    seen_v = {v.get("id") for v in out.get("vlans") or []}
    for vlan in b.get("vlans") or []:
        if vlan.get("id") not in seen_v:
            out.setdefault("vlans", []).append(vlan)
            seen_v.add(vlan.get("id"))
    out["neighbors"] = _dedupe_nb((out.get("neighbors") or []) + (b.get("neighbors") or []))
    return out


def _link_kind(dev: dict, port: str) -> tuple[str, str]:
    port = short_if(port)
    for iface in dev.get("interfaces") or []:
        names = {short_if(iface.get("short") or ""), short_if(iface.get("name") or ""), iface.get("name")}
        if port and port in names:
            mode = (iface.get("mode") or "").lower()
            if mode == "trunk":
                return "trunk", iface.get("allowed") or iface.get("vlan") or ""
            if mode == "access":
                return "access", iface.get("vlan") or ""
            if iface.get("ip"):
                return "routed", iface.get("ip") or ""
    return "unknown", ""


def _bundle_map(dev: dict) -> dict:
    mapping = {}
    for iface in dev.get("interfaces") or []:
        cg = str(iface.get("channel_group") or "").strip()
        num = re.match(r"^(\d+)", cg)
        if not num:
            continue
        po = "Po" + num.group(1)
        for key in (iface.get("short"), iface.get("name")):
            if key:
                mapping[short_if(key)] = po
                mapping[key] = po
    return mapping


def _canon_port(dev: dict, port: str) -> tuple[str, str]:
    """Return (logical_port, physical_or_empty)."""
    phys = short_if(port)
    if not phys:
        return "", ""
    logical = _bundle_map(dev).get(phys) or phys
    return logical, (phys if logical != phys else "")


def build_topology(parsed: list[dict], site: str = "", customer: str = "") -> dict:
    devices = {}
    order = []

    def upsert(dev: dict):
        key = device_id_key(dev.get("hostname") or "")
        if key in devices:
            devices[key] = _merge_dev(devices[key], {**dev, "id": key})
        else:
            devices[key] = {**dev, "id": key}
            order.append(key)
        return key

    for dev in parsed:
        upsert(dev)

    for key in list(order):
        dev = devices[key]
        for nb in dev.get("neighbors") or []:
            nkey = device_id_key(nb.get("remote") or "")
            stub = {
                "hostname": nb.get("remote") or nkey,
                "vendor": "mikrotik"
                if "mikrotik" in (nb.get("platform") or "").lower()
                else ("cisco" if "cisco" in (nb.get("platform") or "").lower() or "ws-c" in (nb.get("platform") or "").lower() else "unknown"),
                "role": _role_from_cap(nb.get("capability", ""), nb.get("platform", "")),
                "platform": nb.get("platform") or "",
                "version": "",
                "mgmt_ip": nb.get("remote_ip") or "",
                "gateway": "",
                "interfaces": [],
                "vlans": [],
                "neighbors": [],
                "source": "inferred",
            }
            upsert(stub)

    links = []
    seen_links = {}
    for key, dev in devices.items():
        for nb in dev.get("neighbors") or []:
            b = device_id_key(nb.get("remote") or "")
            if not b or b == key:
                continue
            peer = devices.get(b, {})
            a_log, a_phys = _canon_port(dev, nb.get("local_if") or "")
            b_log, b_phys = _canon_port(peer, nb.get("remote_if") or "")
            pair = tuple(sorted((key, b)))
            if key == pair[0]:
                a_port, b_port = a_log, b_log
                members = [p for p in (a_phys, b_phys) if p]
            else:
                a_port, b_port = b_log, a_log
                members = [p for p in (b_phys, a_phys) if p]
            kind, extra = _link_kind(dev, a_log or (nb.get("local_if") or ""))
            if kind == "unknown":
                kind, extra = _link_kind(peer, b_log or (nb.get("remote_if") or ""))
            rec = {
                "a": pair[0],
                "b": pair[1],
                "a_port": a_port,
                "b_port": b_port,
                "kind": kind,
                "detail": extra,
                "proto": nb.get("proto") or "cdp",
                "bundle": bool(a_phys or b_phys or a_port.startswith("Po") or b_port.startswith("Po")),
                "members": members,
            }
            po_side = ""
            if a_port.startswith("Po"):
                po_side = "a:" + a_port
            elif b_port.startswith("Po"):
                po_side = "b:" + b_port
            link_key = (pair, po_side) if po_side else (pair, a_port, b_port)
            prev = seen_links.get(link_key)
            if prev:
                for mem in members:
                    if mem and mem not in prev["members"]:
                        prev["members"].append(mem)
                for p in (rec["a_port"], rec["b_port"]):
                    if p and not p.startswith("Po") and p not in prev["members"]:
                        prev["members"].append(p)
                prev["bundle"] = True if rec["bundle"] or prev.get("bundle") else prev.get("bundle")
                if rec["a_port"].startswith("Po"):
                    prev["a_port"] = rec["a_port"]
                if rec["b_port"].startswith("Po"):
                    prev["b_port"] = rec["b_port"]
                if prev["kind"] == "unknown" and rec["kind"] != "unknown":
                    prev["kind"] = rec["kind"]
                    prev["detail"] = rec["detail"]
                elif rec["kind"] == "trunk":
                    prev["kind"] = "trunk"
                    prev["detail"] = rec["detail"] or prev["detail"]
                continue
            seen_links[link_key] = rec
            links.append(rec)
    for lk in links:
        if lk.get("members"):
            extra = ", ".join(lk["members"])
            lk["detail"] = (lk.get("detail") + " · " if lk.get("detail") else "") + extra
            if lk.get("bundle") and not (lk.get("a_port") or "").startswith("Po") and not (lk.get("b_port") or "").startswith("Po"):
                pass

    adj = defaultdict(set)
    for lk in links:
        adj[lk["a"]].add(lk["b"])
        adj[lk["b"]].add(lk["a"])

    routers = [k for k, d in devices.items() if d.get("role") == "router"]
    for k, d in devices.items():
        role = d.get("role")
        if role == "router":
            d["layer"] = "router"
        elif role in ("phone", "host"):
            d["layer"] = "endpoint"
        elif role == "switch":
            neighbors_roles = {devices[n]["role"] for n in adj[k] if n in devices}
            if "router" in neighbors_roles and ("switch" in neighbors_roles or len(adj[k]) > 2):
                d["layer"] = "core"
            elif "router" in neighbors_roles:
                d["layer"] = "access"
            elif any(devices[n].get("layer") == "core" for n in adj[k] if n in devices):
                d["layer"] = "access"
            else:
                d["layer"] = "access" if len(order) <= 2 else "core"
        else:
            d["layer"] = "endpoint"

    # single dumped switch: keep it as access/core centre
    dumped = [k for k, d in devices.items() if d.get("source") == "dump"]
    if len(dumped) == 1 and devices[dumped[0]].get("role") == "switch":
        devices[dumped[0]]["layer"] = "core"

    wan = False
    for d in devices.values():
        if d.get("role") == "router":
            for iface in d.get("interfaces") or []:
                n = (iface.get("name") or "") + (iface.get("description") or "")
                if re.search(r"(?i)\b(wan|isp|pppoe|internet)\b", n):
                    wan = True
                ip = (iface.get("ip") or "").split("/")[0].split()[0]
                if ip and not ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.")):
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and not ip.startswith("172."):
                        wan = True
            if d.get("gateway"):
                wan = True
    extra_nodes = []
    if wan:
        extra_nodes.append(
            {
                "id": "_internet",
                "hostname": "Internet",
                "vendor": "cloud",
                "role": "wan",
                "platform": "",
                "mgmt_ip": "",
                "layer": "wan",
                "source": "virtual",
                "interfaces": [],
                "vlans": [],
                "neighbors": [],
            }
        )
        for k, d in devices.items():
            if d.get("role") == "router":
                links.append(
                    {
                        "a": "_internet",
                        "b": k,
                        "a_port": "",
                        "b_port": "WAN",
                        "kind": "routed",
                        "detail": "",
                        "proto": "logical",
                    }
                )
                break

    device_list = extra_nodes + [devices[k] for k in order]
    return {
        "site": site or "",
        "customer": customer or "",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "devices": device_list,
        "links": links,
        "stats": {
            "devices": len([d for d in device_list if d.get("source") != "virtual"]),
            "dumped": len(dumped),
            "links": len([lk for lk in links if lk.get("proto") != "logical"]),
            "vlans": len({(d["id"], v["id"]) for d in device_list for v in d.get("vlans") or []}),
        },
    }


def topology_from_payload(body: dict) -> dict:
    raw_devices = body.get("devices") or []
    if not isinstance(raw_devices, list) or not raw_devices:
        raise ValueError("paste at least one device dump")
    if len(raw_devices) > MAX_DEVICES:
        raise ValueError(f"too many devices (max {MAX_DEVICES})")
    parsed = []
    for item in raw_devices:
        if not isinstance(item, dict):
            continue
        cfg = item.get("config") or item.get("running") or ""
        nbs = item.get("neighbors") or ""
        if not str(cfg).strip() and not str(nbs).strip():
            continue
        parsed.append(
            parse_device(
                item.get("vendor") or "auto",
                str(cfg),
                str(nbs),
                str(item.get("label") or ""),
            )
        )
    if not parsed:
        raise ValueError("empty dumps")
    return build_topology(parsed, body.get("site") or "", body.get("customer") or "")


# --- XLSX ------------------------------------------------------------------

_ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _x(s) -> str:
    return xml_escape(_ILLEGAL_XML.sub("", str(s if s is not None else "")))[:32000]


def _col_letter(n: int) -> str:
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _sheet_xml(name: str, rows: list[list], col_widths: list[int] | None = None) -> str:
    max_c = max((len(r) for r in rows), default=1)
    dim = f"A1:{_col_letter(max_c - 1)}{max(len(rows), 1)}"
    cols = ""
    if col_widths:
        bits = []
        for i, w in enumerate(col_widths, 1):
            bits.append(f'<col min="{i}" max="{i}" width="{w}" customWidth="1"/>')
        cols = "<cols>" + "".join(bits) + "</cols>"
    body = []
    for r_i, row in enumerate(rows, 1):
        cells = []
        for c_i, val in enumerate(row):
            ref = f"{_col_letter(c_i)}{r_i}"
            style = ' s="1"' if r_i == 1 else ' s="2"'
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                cells.append(f'<c r="{ref}"{style} t="n"><v>{val}</v></c>')
            else:
                cells.append(f'<c r="{ref}"{style} t="inlineStr"><is><t>{_x(val)}</t></is></c>')
        body.append(f'<row r="{r_i}">{"".join(cells)}</row>')
    return f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
           xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<dimension ref="{dim}"/>
<sheetViews><sheetView tabSelected="1" workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews>
{cols}
<sheetData>{"".join(body)}</sheetData>
<autoFilter ref="{dim}"/>
</worksheet>"""


def _xlsx_bytes(sheets: list[tuple[str, list[list], list[int]]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(
            "[Content_Types].xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
"""
            + "".join(
                f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                for i in range(1, len(sheets) + 1)
            )
            + "</Types>",
        )
        z.writestr(
            "_rels/.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>""",
        )
        wb_sheets = []
        rels = []
        for i, (title, _, _) in enumerate(sheets, 1):
            safe = re.sub(r"[\[\]:*?/\\]", " ", title)[:31] or f"Sheet{i}"
            wb_sheets.append(f'<sheet name="{_x(safe)}" sheetId="{i}" r:id="rId{i}"/>')
            rels.append(
                f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i}.xml"/>'
            )
        rels.append(
            '<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
        )
        z.writestr(
            "xl/workbook.xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>"""
            + "".join(wb_sheets)
            + "</sheets></workbook>",
        )
        z.writestr(
            "xl/_rels/workbook.xml.rels",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"""
            + "".join(rels)
            + "</Relationships>",
        )
        z.writestr(
            "xl/styles.xml",
            """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="2">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><color rgb="FFFFFFFF"/><name val="Calibri"/></font>
</fonts>
<fills count="3">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FFC56A2D"/><bgColor indexed="64"/></patternFill></fill>
</fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf/></cellStyleXfs>
<cellXfs count="3">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="center"/></xf>
</cellXfs>
</styleSheet>""",
        )
        for i, (_, rows, widths) in enumerate(sheets, 1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(f"s{i}", rows, widths))
    return buf.getvalue()


def topology_xlsx(topo: dict) -> bytes:
    site = topo.get("site") or "—"
    customer = topo.get("customer") or "—"
    cover = [
        ["Field", "Value"],
        ["Customer", customer],
        ["Site", site],
        ["Generated", topo.get("generated_at") or ""],
        ["Devices", topo.get("stats", {}).get("devices", "")],
        ["Dumped configs", topo.get("stats", {}).get("dumped", "")],
        ["Links", topo.get("stats", {}).get("links", "")],
        ["Note", "Passwords and secrets are not included."],
    ]
    devices_rows = [["Hostname", "Role", "Layer", "Vendor", "Platform", "Mgmt IP", "Source", "VLANs"]]
    for d in topo.get("devices") or []:
        if d.get("source") == "virtual":
            continue
        vlans = ", ".join(
            f'{v.get("id")}{(" " + v["name"]) if v.get("name") else ""}' for v in (d.get("vlans") or [])[:24]
        )
        devices_rows.append(
            [
                d.get("hostname"),
                d.get("role"),
                d.get("layer"),
                d.get("vendor"),
                d.get("platform"),
                d.get("mgmt_ip"),
                d.get("source"),
                vlans,
            ]
        )
    if_rows = [["Device", "Interface", "Description", "Mode", "VLAN", "Allowed", "IP", "Shutdown"]]
    for d in topo.get("devices") or []:
        for iface in d.get("interfaces") or []:
            if_rows.append(
                [
                    d.get("hostname"),
                    iface.get("name") or iface.get("short"),
                    iface.get("description"),
                    iface.get("mode"),
                    iface.get("vlan"),
                    iface.get("allowed"),
                    iface.get("ip"),
                    "yes" if iface.get("shutdown") else "",
                ]
            )
    vlan_rows = [["Device", "VLAN ID", "Name"]]
    for d in topo.get("devices") or []:
        for v in d.get("vlans") or []:
            vlan_rows.append([d.get("hostname"), v.get("id"), v.get("name")])
    link_rows = [["Device A", "Port A", "Device B", "Port B", "Type", "Detail", "Protocol"]]
    for lk in topo.get("links") or []:
        if lk.get("proto") == "logical":
            continue
        names = {d["id"]: d.get("hostname") for d in topo.get("devices") or []}
        link_rows.append(
            [
                names.get(lk.get("a"), lk.get("a")),
                lk.get("a_port"),
                names.get(lk.get("b"), lk.get("b")),
                lk.get("b_port"),
                lk.get("kind"),
                lk.get("detail"),
                lk.get("proto"),
            ]
        )
    ip_rows = [["Device", "Interface", "Address"]]
    for d in topo.get("devices") or []:
        for iface in d.get("interfaces") or []:
            if iface.get("ip"):
                ip_rows.append([d.get("hostname"), iface.get("name") or iface.get("short"), iface.get("ip")])
        if d.get("mgmt_ip") and not any(r[2] == d.get("mgmt_ip") for r in ip_rows[1:]):
            ip_rows.append([d.get("hostname"), "mgmt", d.get("mgmt_ip")])

    return _xlsx_bytes(
        [
            ("Summary", cover, [22, 48]),
            ("Devices", devices_rows, [22, 12, 12, 12, 28, 16, 12, 36]),
            ("Interfaces", if_rows, [22, 22, 28, 12, 10, 22, 22, 10]),
            ("VLANs", vlan_rows, [22, 12, 24]),
            ("Links", link_rows, [22, 14, 22, 14, 12, 22, 12]),
            ("IP addressing", ip_rows, [22, 22, 24]),
        ]
    )
