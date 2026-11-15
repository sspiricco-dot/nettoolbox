"""Turn whatever a CA / customer sends (crt, cer, ca-bundle, p7b, pfx, key ...) into
fullchain.pem + privkey.pem (+ cert.pem, chain.pem) for nginx / apache / haproxy.

Everything happens in memory: private keys are never written to disk or logged.
"""
from __future__ import annotations

import datetime as _dt
import io
import re
import urllib.request
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

MAX_FILES = 20
MAX_TOTAL = 4 * 1024 * 1024
PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\s.*?-----END \1-----", re.S)


class SslConvError(Exception):
    pass


class NeedPassword(SslConvError):
    pass


# ---------------------------------------------------------------- parsing
def _load_key_pem(block, password):
    try:
        return serialization.load_pem_private_key(block, password=password or None)
    except TypeError as exc:  # encrypted but no password / password given to plain key
        if password and "not encrypted" in str(exc).lower():
            return serialization.load_pem_private_key(block, password=None)
        raise NeedPassword("private key is encrypted: enter its password") from exc
    except ValueError as exc:
        if b"ENCRYPTED" in block:
            raise NeedPassword("wrong password for the encrypted private key") from exc
        raise


def _parse(name, data, password, notes):
    certs, keys = [], []
    pw = password.encode() if password else None
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    if b"-----BEGIN" in data:
        found = False
        for m in PEM_RE.finditer(data):
            found = True
            kind, block = m.group(1).decode(), m.group(0)
            try:
                if kind in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
                    if kind == "TRUSTED CERTIFICATE":
                        block = block.replace(b"TRUSTED CERTIFICATE", b"CERTIFICATE")
                    certs.append(x509.load_pem_x509_certificate(block))
                elif kind == "PKCS7":
                    certs += pkcs7.load_pem_pkcs7_certificates(block)
                elif kind.endswith("PRIVATE KEY"):
                    keys.append(_load_key_pem(block, pw))
                elif "REQUEST" in kind:
                    notes.append(f"{name}: CSR ignored (it is only the request, not the certificate)")
                else:
                    notes.append(f"{name}: skipped PEM block '{kind}'")
            except NeedPassword:
                raise
            except Exception as exc:  # noqa: BLE001 - report and keep going
                notes.append(f"{name}: could not read a {kind} block ({exc})")
        if not found:
            notes.append(f"{name}: no complete PEM block found")
        return certs, keys

    # binary formats: DER cert, PKCS#12, DER PKCS#7, DER key
    try:
        return [x509.load_der_x509_certificate(data)], []
    except Exception:  # noqa: BLE001
        pass
    if name.lower().endswith((".pfx", ".p12")) or data[:1] == b"\x30":
        for cand in ([pw] if pw else []) + [None, b""]:
            try:
                key, cert, extra = pkcs12.load_key_and_certificates(data, cand)
            except ValueError:
                continue
            except Exception:  # noqa: BLE001
                break
            out = ([cert] if cert else []) + list(extra or [])
            return out, ([key] if key else [])
        if name.lower().endswith((".pfx", ".p12")):
            raise NeedPassword(f"{name}: PFX/P12 needs its password" if not pw else f"{name}: wrong PFX/P12 password")
    try:
        return list(pkcs7.load_der_pkcs7_certificates(data)), []
    except Exception:  # noqa: BLE001
        pass
    try:
        return [], [serialization.load_der_private_key(data, password=pw)]
    except TypeError as exc:
        raise NeedPassword(f"{name}: private key is encrypted: enter its password") from exc
    except Exception:  # noqa: BLE001
        pass
    notes.append(f"{name}: not a certificate, key, PFX or P7B — skipped")
    return [], []


# ---------------------------------------------------------------- helpers
def _pub_bytes(pub):
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _fp(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def _ext(cert, oid):
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _ski(cert):
    v = _ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return v.digest if v else None


def _aki(cert):
    v = _ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    return v.key_identifier if v else None


def _is_ca(cert):
    v = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    return bool(v and v.ca)


def _self_signed(cert):
    if cert.subject != cert.issuer:
        return False
    a, s = _aki(cert), _ski(cert)
    return not (a and s and a != s)


def _issued_by(child, parent):
    if child.issuer != parent.subject:
        return False
    a, s = _aki(child), _ski(parent)
    return not (a and s and a != s)


def _cn(name):
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return attrs[0].value
    except Exception:  # noqa: BLE001
        pass
    return name.rfc4514_string()[:120]


def _not_after(cert):
    v = getattr(cert, "not_valid_after_utc", None)
    return v if v else cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)


def _not_before(cert):
    v = getattr(cert, "not_valid_before_utc", None)
    return v if v else cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)


def _key_desc(pub):
    if isinstance(pub, rsa.RSAPublicKey):
        return f"RSA {pub.key_size}"
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return f"EC {pub.curve.name}"
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    if isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    if isinstance(pub, dsa.DSAPublicKey):
        return f"DSA {pub.key_size}"
    return type(pub).__name__


def _describe(cert, role):
    now = _dt.datetime.now(_dt.timezone.utc)
    na = _not_after(cert)
    san = _ext(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    names = []
    if san:
        names = [str(v) for v in san.get_values_for_type(x509.DNSName)]
        names += [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    return {
        "role": role,
        "subject": _cn(cert.subject),
        "issuer": _cn(cert.issuer),
        "not_before": _not_before(cert).strftime("%Y-%m-%d"),
        "not_after": na.strftime("%Y-%m-%d"),
        "days_left": (na - now).days,
        "expired": na < now,
        "key": _key_desc(cert.public_key()),
        "sha256": _fp(cert),
        "san": names[:50],
        "self_signed": _self_signed(cert),
    }


def _fetch_issuer(cert, notes):
    aia = _ext(cert, ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    if not aia:
        return None
    for desc in aia:
        if desc.access_method.dotted_string != "1.3.6.1.5.5.7.48.2":  # caIssuers
            continue
        url = desc.access_location.value
        if not str(url).lower().startswith(("http://", "https://")):
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "nettoolbox"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = resp.read(256 * 1024)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"could not download the intermediate from {url} ({exc})")
            continue
        cands = []
        for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
            try:
                cands = [loader(data)]
                break
            except Exception:  # noqa: BLE001
                pass
        if not cands:
            for loader in (pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
                try:
                    cands = list(loader(data))
                    break
                except Exception:  # noqa: BLE001
                    pass
        for c in cands:
            if _issued_by(cert, c):
                notes.append(f"downloaded missing intermediate '{_cn(c.subject)}' from {url}")
                return c
    return None


_ROOTS = None


def _system_roots():
    """Debian's ca-certificates bundle, parsed once."""
    global _ROOTS
    if _ROOTS is None:
        fps, by_subject = set(), {}
        try:
            with open("/etc/ssl/certs/ca-certificates.crt", "rb") as fh:
                data = fh.read()
            for m in PEM_RE.finditer(data):
                try:
                    c = x509.load_pem_x509_certificate(m.group(0))
                except Exception:  # noqa: BLE001
                    continue
                fps.add(_fp(c))
                by_subject.setdefault(c.subject.public_bytes(), []).append(c)
        except OSError:
            pass
        _ROOTS = {"fps": fps, "by_subject": by_subject}
    return _ROOTS


def _trusted_issuer(cert):
    return next((r for r in _system_roots()["by_subject"].get(cert.issuer.public_bytes(), []) if _issued_by(cert, r)), None)


def _is_system_root(cert):
    pb = _pub_bytes(cert.public_key())
    return any(_pub_bytes(r.public_key()) == pb for r in _system_roots()["by_subject"].get(cert.subject.public_bytes(), []))


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------- main
def build(files, password="", include_root=False, fetch_missing=True):
    """files: list of (name, bytes). Returns dict with outputs + diagnostics."""
    if not files:
        raise SslConvError("upload at least one file (certificate, key, bundle, PFX ...)")
    if len(files) > MAX_FILES:
        raise SslConvError(f"too many files (max {MAX_FILES})")
    if sum(len(d) for _, d in files) > MAX_TOTAL:
        raise SslConvError("files are too large for certificates")

    notes, warnings = [], []
    certs, keys = [], []
    for name, data in files:
        c, k = _parse(name, data, password, notes)
        certs += c
        keys += k

    seen, pool = set(), []
    for c in certs:
        fp = _fp(c)
        if fp not in seen:
            seen.add(fp)
            pool.append(c)
    kseen, uniq_keys = set(), []
    for k in keys:
        pb = _pub_bytes(k.public_key())
        if pb not in kseen:
            kseen.add(pb)
            uniq_keys.append(k)

    if not pool:
        raise SslConvError("no certificate found in the uploaded files")

    # leaf: the cert matching a private key, else the end-entity cert nobody else was issued by
    leaf, key = None, None
    for k in uniq_keys:
        pb = _pub_bytes(k.public_key())
        for c in pool:
            if _pub_bytes(c.public_key()) == pb:
                leaf, key = c, k
                break
        if leaf:
            break
    if uniq_keys and not key:
        warnings.append("key_mismatch")
    if not leaf:
        parents = {_fp(p) for c in pool for p in pool if p is not c and _issued_by(c, p)}
        ends = [c for c in pool if not _is_ca(c) and _fp(c) not in parents] or \
               [c for c in pool if _fp(c) not in parents] or pool
        leaf = sorted(ends, key=_not_after, reverse=True)[0]

    chain, used = [leaf], {_fp(leaf)}
    cur = leaf
    while not _self_signed(cur) and len(chain) < 10:
        nxt = next((p for p in pool if _fp(p) not in used and _issued_by(cur, p)), None)
        if nxt is None and (_trusted_issuer(cur) or _is_system_root(cur)):
            break  # clients already have the next certificate
        if nxt is None and fetch_missing:
            nxt = _fetch_issuer(cur, notes)
        if nxt is None:
            break
        chain.append(nxt)
        used.add(_fp(nxt))
        cur = nxt

    # finish the chain against the system trust store (roots are never uploaded by CAs)
    roots = _system_roots()
    last = chain[-1]
    root, trusted = None, False
    if _self_signed(last) and len(chain) > 1:
        root = last
        trusted = _fp(last) in roots["fps"]
    elif not _self_signed(last):
        sys_root = _trusted_issuer(last)
        if sys_root is not None:
            trusted = True
            if include_root:
                chain.append(sys_root)
                used.add(_fp(sys_root))
                root = sys_root
        elif _is_system_root(last):
            trusted = True
        else:
            warnings.append("incomplete")
    elif _fp(last) in roots["fps"]:
        trusted = True
    complete = "incomplete" not in warnings
    unused = [c for c in pool if _fp(c) not in used]
    if unused:
        notes.append("ignored certificates that are not part of this chain: " +
                     ", ".join(_cn(c.subject) for c in unused[:6]))
    if _self_signed(leaf):
        warnings.append("self_signed")
    for c in chain:
        if _not_after(c) < _dt.datetime.now(_dt.timezone.utc):
            warnings.append("expired")
            break
    if not uniq_keys:
        warnings.append("no_key")

    served = [c for c in chain if c is not root or include_root]
    if len(served) > 1 and root is not None and not include_root:
        served = [c for c in served if c is not root]
    fullchain = "".join(_pem(c) for c in served)
    outputs = {
        "fullchain.pem": fullchain,
        "cert.pem": _pem(leaf),
        "chain.pem": "".join(_pem(c) for c in served[1:]),
    }
    if key:
        outputs["privkey.pem"] = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
    if not outputs["chain.pem"]:
        outputs.pop("chain.pem")

    roles = []
    for i, c in enumerate(chain):
        role = "leaf" if i == 0 else ("root" if c is root else "intermediate")
        d = _describe(c, role)
        d["in_fullchain"] = any(c is x for x in served)
        roles.append(d)

    return {
        "chain": roles,
        "outputs": outputs,
        "key": {"present": bool(key), "type": _key_desc(key.public_key()) if key else None,
                "matches": bool(key)},
        "complete": complete,
        "trusted": trusted,
        "warnings": sorted(set(warnings), key=warnings.index),
        "notes": notes,
        "counts": {"certs": len(pool), "keys": len(uniq_keys)},
    }


def zip_outputs(result):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in result["outputs"].items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o600 if name == "privkey.pem" else 0o644) << 16
            zf.writestr(info, text)
    return buf.getvalue()
