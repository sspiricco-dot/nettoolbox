"""LAN checks on raw AF_PACKET sockets (needs CAP_NET_RAW):

* dhcp_probe  - broadcast DHCPDISCOVER (untagged and/or 802.1Q-tagged per VLAN) and collect every
                OFFER: finds rogue DHCP servers and shows which VLANs on a trunk actually hand out IPs.
                Only DISCOVER is sent, never REQUEST, so no lease is taken.
* arp_conflicts - ARP-sweep a subnet and report IPs answered by more than one MAC (duplicate IPs).
"""
from __future__ import annotations

import fcntl
import ipaddress
import os
import random
import select
import socket
import struct
import time

ETH_P_ALL = 0x0003
ETH_P_ARP = 0x0806
SOL_PACKET = 263
PACKET_AUXDATA = 8
TP_STATUS_VLAN_VALID = 1 << 4
SIOCGIFHWADDR = 0x8927
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
BCAST = b"\xff" * 6


class LanCheckError(Exception):
    pass


def _ifreq(sock, iface, req):
    return fcntl.ioctl(sock.fileno(), req, struct.pack("256s", iface.encode()[:15]))


def iface_info(iface):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        mac = _ifreq(s, iface, SIOCGIFHWADDR)[18:24]
        try:
            ip = socket.inet_ntoa(_ifreq(s, iface, SIOCGIFADDR)[20:24])
            mask = socket.inet_ntoa(_ifreq(s, iface, SIOCGIFNETMASK)[20:24])
        except OSError:
            ip, mask = None, None
    except OSError as exc:
        raise LanCheckError(f"interface {iface}: {exc.strerror or exc}") from None
    finally:
        s.close()
    return mac, ip, mask


def _mac(b):
    return ":".join(f"{x:02x}" for x in b)


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _raw(iface):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    try:
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    except OSError:
        pass
    return sock


def _recv(sock):
    """Returns (frame, vlan_id or None). Re-inserts the VLAN the NIC may have stripped."""
    data, anc, _flags, _addr = sock.recvmsg(65535, socket.CMSG_SPACE(64))
    vlan = None
    for level, ctype, cdata in anc:
        if level == SOL_PACKET and ctype == PACKET_AUXDATA and len(cdata) >= 20:
            status, _len, _snap, _mac_off, _net, tci, _tpid = struct.unpack("IIIHHHH", cdata[:20])
            if status & TP_STATUS_VLAN_VALID:
                vlan = tci & 0x0FFF
    etype = struct.unpack("!H", data[12:14])[0] if len(data) >= 14 else 0
    if etype == 0x8100 and len(data) >= 18:
        vlan = struct.unpack("!H", data[14:16])[0] & 0x0FFF
        data = data[:12] + data[16:]
    return data, vlan


# ---------------------------------------------------------------- DHCP
def _dhcp_discover(mac, xid, vlan):
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, xid, 0, 0x8000,
                        b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4, mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    opts = (b"\x63\x82\x53\x63" + b"\x35\x01\x01" + b"\x3d\x07\x01" + mac +
            b"\x37\x07\x01\x03\x06\x0f\x1a\x2a\x33" + b"\x0c\x0anettoolbox" + b"\xff")
    payload = bootp + opts
    payload += b"\0" * max(0, 300 - len(payload))
    udp = struct.pack("!HHHH", 68, 67, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0x10, 20 + len(udp), random.randint(0, 0xFFFF), 0, 64, 17, 0,
                     b"\0" * 4, b"\xff" * 4)
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    eth = BCAST + mac
    if vlan is not None:
        eth += struct.pack("!HH", 0x8100, vlan & 0x0FFF)
    return eth + struct.pack("!H", 0x0800) + ip + udp


def _parse_dhcp(frame):
    if len(frame) < 14 + 20 + 8 + 240 or struct.unpack("!H", frame[12:14])[0] != 0x0800:
        return None
    ihl = (frame[14] & 0x0F) * 4
    if frame[23] != 17:
        return None
    udp = 14 + ihl
    sport, dport = struct.unpack("!HH", frame[udp:udp + 4])
    if sport != 67 or dport != 68:
        return None
    b = frame[udp + 8:]
    if len(b) < 240 or b[0] != 2 or b[236:240] != b"\x63\x82\x53\x63":
        return None
    xid = struct.unpack("!I", b[4:8])[0]
    out = {"xid": xid, "offered_ip": socket.inet_ntoa(b[16:20]), "server_mac": _mac(frame[6:12]),
           "server_src_ip": socket.inet_ntoa(frame[14 + 12:14 + 16]), "dns": [], "router": []}
    i = 240
    while i < len(b):
        code = b[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(b):
            break
        ln = b[i + 1]
        v = b[i + 2:i + 2 + ln]
        if code == 53 and v:
            out["type"] = {1: "DISCOVER", 2: "OFFER", 5: "ACK", 6: "NAK"}.get(v[0], str(v[0]))
        elif code == 54 and ln == 4:
            out["server_id"] = socket.inet_ntoa(v)
        elif code == 1 and ln == 4:
            out["mask"] = socket.inet_ntoa(v)
        elif code == 3 and ln >= 4:
            out["router"] = [socket.inet_ntoa(v[j:j + 4]) for j in range(0, ln - ln % 4, 4)]
        elif code == 6 and ln >= 4:
            out["dns"] = [socket.inet_ntoa(v[j:j + 4]) for j in range(0, ln - ln % 4, 4)]
        elif code == 51 and ln == 4:
            out["lease"] = struct.unpack("!I", v)[0]
        elif code == 15:
            out["domain"] = v.decode("utf-8", "replace")
        i += 2 + ln
    return out


def parse_vlans(text):
    vlans = []
    for part in (text or "").replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if not (1 <= a <= b <= 4094):
                raise LanCheckError(f"bad VLAN range {part}")
            vlans.extend(range(a, b + 1))
        else:
            v = int(part)
            if not 1 <= v <= 4094:
                raise LanCheckError(f"bad VLAN {part}")
            vlans.append(v)
    vlans = sorted(set(vlans))
    if len(vlans) > 256:
        raise LanCheckError("at most 256 VLANs per probe")
    return vlans


def dhcp_probe(iface, vlans=None, untagged=True, wait=4.0, rounds=2):
    """vlans: list of VLAN IDs to probe with 802.1Q tags. Returns results per VLAN (None = untagged)."""
    mac, _ip, _mask = iface_info(iface)
    targets = ([None] if untagged else []) + list(vlans or [])
    if not targets:
        raise LanCheckError("nothing to probe")
    xids = {}
    for v in targets:
        x = random.getrandbits(32)
        while x in xids:
            x = random.getrandbits(32)
        xids[x] = v
    sock = _raw(iface)
    results = {v: [] for v in targets}
    seen = set()
    try:
        for r in range(rounds):
            for x, v in xids.items():
                sock.send(_dhcp_discover(mac, x, v))
                if len(xids) > 20:
                    time.sleep(0.002)
            end = time.monotonic() + (wait if r == rounds - 1 else min(1.5, wait))
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                rr, _, _ = select.select([sock], [], [], min(left, 0.3))
                if not rr:
                    continue
                frame, fvlan = _recv(sock)
                off = _parse_dhcp(frame)
                if not off or off["xid"] not in xids:
                    continue
                v = xids[off["xid"]]
                key = (v, off.get("server_id"), off["server_mac"], off["offered_ip"])
                if key in seen:
                    continue
                seen.add(key)
                off["vlan_seen"] = fvlan
                off.pop("xid", None)
                results[v].append(off)
            if all(results[v] for v in targets):
                break
    finally:
        sock.close()
    servers = {}
    for v, offers in results.items():
        for o in offers:
            sid = o.get("server_id") or o["server_src_ip"]
            servers.setdefault(sid, {"server": sid, "mac": o["server_mac"], "vlans": []})["vlans"].append(v)
    return {
        "iface": iface,
        "client_mac": _mac(mac),
        "results": [{"vlan": v, "offers": results[v]} for v in targets],
        "servers": list(servers.values()),
    }


# ---------------------------------------------------------------- duplicate IPs
def _arp_request(mac, src_ip, dst_ip):
    return (BCAST + mac + struct.pack("!H", ETH_P_ARP) +
            struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac, socket.inet_aton(src_ip), b"\0" * 6,
                        socket.inet_aton(dst_ip)))


def arp_conflicts(iface, cidr=None, wait=2.5):
    mac, ip, mask = iface_info(iface)
    if not ip:
        raise LanCheckError(f"{iface} has no IPv4 address")
    net = ipaddress.ip_network(cidr if cidr else f"{ip}/{mask}", strict=False)
    if net.num_addresses > 4096:
        raise LanCheckError("subnet too large (max /20)")
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 2 else [str(net.network_address)]
    sock = _raw(iface)
    seen: dict[str, set] = {}
    vendors_mac = {}

    def drain(deadline):
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return
            r, _, _ = select.select([sock], [], [], min(left, 0.1))
            if not r:
                continue
            frame, _v = _recv(sock)
            if len(frame) < 42 or struct.unpack("!H", frame[12:14])[0] != ETH_P_ARP:
                continue
            op = struct.unpack("!H", frame[20:22])[0]
            sha, spa = frame[22:28], socket.inet_ntoa(frame[28:32])
            if sha == mac or spa == "0.0.0.0":
                continue
            if op in (1, 2) and ipaddress.ip_address(spa) in net:
                seen.setdefault(spa, set()).add(_mac(sha))
                vendors_mac[_mac(sha)] = True

    try:
        for i, h in enumerate(hosts):
            sock.send(_arp_request(mac, ip, h))
            if i % 32 == 31:
                drain(time.monotonic() + 0.01)
        drain(time.monotonic() + wait)
        # second pass on the conflicting / own address to be sure
        recheck = [h for h, m in seen.items() if len(m) > 1] + [ip]
        for h in recheck:
            sock.send(_arp_request(mac, ip, h))
        drain(time.monotonic() + 1.0)
    finally:
        sock.close()
    conflicts = [{"ip": h, "macs": sorted(m), "own": h == ip} for h, m in sorted(seen.items(),
                 key=lambda kv: ipaddress.ip_address(kv[0])) if len(m) > 1 or h == ip]
    return {
        "iface": iface,
        "subnet": str(net),
        "own_ip": ip,
        "own_mac": _mac(mac),
        "probed": len(hosts),
        "answered": len(seen),
        "conflicts": conflicts,
        "hosts": [{"ip": h, "macs": sorted(m)} for h, m in sorted(seen.items(), key=lambda kv: ipaddress.ip_address(kv[0]))],
    }
