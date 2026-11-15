"""CDP / LLDP listener on a raw AF_PACKET socket (replaces tshark: ~120 MB less in the image).

Needs CAP_NET_RAW (run.sh adds it). Joins the two link-local multicast groups instead of
putting the NIC in promiscuous mode.
"""
from __future__ import annotations

import ipaddress
import select
import socket
import struct
import time

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_MULTICAST = 0
PACKET_MR_ALLMULTI = 2

CDP_MAC = bytes.fromhex("01000ccccccc")
LLDP_MACS = (bytes.fromhex("0180c200000e"), bytes.fromhex("0180c2000003"), bytes.fromhex("0180c2000000"))


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _txt(b):
    return b.decode("utf-8", "replace").strip("\x00").strip()


# ---------------------------------------------------------------- CDP
def parse_cdp(payload):
    """payload = bytes after the SNAP header (starts at the CDP version byte)."""
    if len(payload) < 4:
        return None
    out = {"device_id": "", "platform": "", "port_id": "", "addresses": [], "software": "", "native_vlan": None}
    i = 4
    while i + 4 <= len(payload):
        t, ln = struct.unpack("!HH", payload[i:i + 4])
        if ln < 4:
            break
        v = payload[i + 4:i + ln]
        if t == 0x0001:
            out["device_id"] = _txt(v)
        elif t == 0x0003:
            out["port_id"] = _txt(v)
        elif t == 0x0006:
            out["platform"] = _txt(v)
        elif t == 0x0005:
            out["software"] = _txt(v).splitlines()[0][:160] if _txt(v) else ""
        elif t == 0x000A and len(v) >= 2:
            out["native_vlan"] = struct.unpack("!H", v[:2])[0]
        elif t in (0x0002, 0x0016) and len(v) >= 4:  # addresses / mgmt addresses
            n = struct.unpack("!I", v[:4])[0]
            j = 4
            for _ in range(min(n, 8)):
                if j + 2 > len(v):
                    break
                plen = v[j + 1]
                j += 2 + plen
                if j + 2 > len(v):
                    break
                alen = struct.unpack("!H", v[j:j + 2])[0]
                addr = v[j + 2:j + 2 + alen]
                j += 2 + alen
                if alen == 4:
                    out["addresses"].append(str(ipaddress.IPv4Address(addr)))
                elif alen == 16:
                    out["addresses"].append(str(ipaddress.IPv6Address(addr)))
        i += ln
    return out


# ---------------------------------------------------------------- LLDP
def _lldp_id(v):
    if not v:
        return ""
    sub, data = v[0], v[1:]
    if sub == 4 and len(data) == 6:  # MAC address
        return _mac(data)
    if sub == 5 and data:  # network address
        fam, addr = data[0], data[1:]
        try:
            if fam == 1 and len(addr) == 4:
                return str(ipaddress.IPv4Address(addr))
            if fam == 2 and len(addr) == 16:
                return str(ipaddress.IPv6Address(addr))
        except ValueError:
            pass
    return _txt(data)


def _lldp_port_id(v):
    if v and v[0] == 3 and len(v) == 7:
        return _mac(v[1:])
    if v and v[0] == 4 and len(v) > 2:
        return _lldp_id(bytes([5]) + v[1:])
    return _txt(v[1:]) if v else ""


def parse_lldp(payload):
    out = {"device_id": "", "platform": "", "port_id": "", "addresses": [], "software": "",
           "chassis_id": "", "port_desc": "", "native_vlan": None}
    i = 0
    while i + 2 <= len(payload):
        hdr = struct.unpack("!H", payload[i:i + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = payload[i + 2:i + 2 + ln]
        if t == 0:
            break
        if t == 1:
            out["chassis_id"] = _lldp_id(v)
        elif t == 2:
            out["port_id"] = _lldp_port_id(v)
        elif t == 4:
            out["port_desc"] = _txt(v)
        elif t == 5:
            out["device_id"] = _txt(v)
        elif t == 6:
            out["software"] = (_txt(v).splitlines() or [""])[0][:160]
        elif t == 8 and len(v) >= 2:
            alen = v[0]
            fam, addr = v[1], v[2:1 + alen]
            try:
                if fam == 1 and len(addr) == 4:
                    out["addresses"].append(str(ipaddress.IPv4Address(addr)))
                elif fam == 2 and len(addr) == 16:
                    out["addresses"].append(str(ipaddress.IPv6Address(addr)))
            except ValueError:
                pass
        elif t == 127 and len(v) >= 6 and v[:3] == b"\x00\x80\xc2" and v[3] == 1:
            out["native_vlan"] = struct.unpack("!H", v[4:6])[0]  # 802.1 port VLAN ID
        i += 2 + ln
    # same columns tshark gave: name / chassis / port
    out["platform"] = out["chassis_id"]
    if not out["device_id"]:
        out["device_id"] = out["chassis_id"]
    return out


# ---------------------------------------------------------------- frames
def parse_frame(frame, protocol):
    if len(frame) < 14:
        return None
    dst = frame[:6]
    etype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
        etype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if protocol == "lldp":
        if etype == 0x88CC:
            return parse_lldp(frame[off:])
        return None
    # CDP: 802.3 length field + LLC/SNAP AA AA 03 00 00 0C 20 00
    if dst == CDP_MAC and etype <= 1500 and frame[off:off + 8] == b"\xaa\xaa\x03\x00\x00\x0c\x20\x00":
        return parse_cdp(frame[off + 8:])
    return None


def _join(sock, ifindex, mac=None):
    mr_type = PACKET_MR_MULTICAST if mac else PACKET_MR_ALLMULTI
    addr = (mac or b"").ljust(8, b"\x00")
    mreq = struct.pack("iHH8s", ifindex, mr_type, len(mac or b""), addr)
    try:
        sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
    except OSError:
        pass


def listen(iface, protocol, duration):
    """Capture for `duration` seconds; returns a list of unique neighbours."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    try:
        sock.bind((iface, 0))
        ifindex = socket.if_nametoindex(iface)
        for mac in ((CDP_MAC,) if protocol == "cdp" else LLDP_MACS):
            _join(sock, ifindex, mac)
        found, seen = [], set()
        end = time.monotonic() + duration
        while True:
            left = end - time.monotonic()
            if left <= 0:
                break
            r, _, _ = select.select([sock], [], [], min(left, 0.5))
            if not r:
                continue
            frame, _addr = sock.recvfrom(65535)
            try:
                nb = parse_frame(frame, protocol)
            except (struct.error, IndexError, ValueError):
                nb = None
            if not nb or not nb["device_id"]:
                continue
            key = (nb["device_id"], nb["port_id"])
            if key in seen:
                continue
            seen.add(key)
            found.append(nb)
        return found
    finally:
        sock.close()
