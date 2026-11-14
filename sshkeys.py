"""SSH key manager: generate / import / list keys, install them on servers, test logins.

Keys live in NETTOOLBOX_SSH_DIR (default /data/ssh-keys). run.sh mounts that folder
from the host so keys survive container rebuilds — losing a key can lock you out.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import time

KEY_DIR = os.environ.get("NETTOOLBOX_SSH_DIR", "/data/ssh-keys")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TYPES = {
    "ed25519": ["-t", "ed25519"],
    "rsa4096": ["-t", "rsa", "-b", "4096"],
    "rsa3072": ["-t", "rsa", "-b", "3072"],
    "ecdsa521": ["-t", "ecdsa", "-b", "521"],
}


class SshKeyError(Exception):
    pass


def _own(path):
    """Hand files to the host user (run.sh passes its uid/gid) so `ssh -i` works from the laptop too."""
    try:
        uid = int(os.environ.get("NETTOOLBOX_HOST_UID", ""))
        gid = int(os.environ.get("NETTOOLBOX_HOST_GID", "") or uid)
    except ValueError:
        return
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


def _dir():
    os.makedirs(KEY_DIR, mode=0o700, exist_ok=True)
    try:
        os.chmod(KEY_DIR, 0o700)
    except OSError:
        pass
    return KEY_DIR


def persistent():
    """True when KEY_DIR (or a parent) is a bind mount, i.e. survives the container."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            points = {line.split()[4] for line in fh if len(line.split()) > 4}
    except OSError:
        return False
    path = os.path.realpath(KEY_DIR)
    while path and path != "/":
        if path in points:
            return True
        path = os.path.dirname(path)
    return False


def valid_name(name):
    return bool(name and NAME_RE.match(name) and not name.endswith(".pub") and not name.endswith(".json"))


def key_path(name):
    if not valid_name(name):
        raise SshKeyError("invalid key name (letters, digits, . _ -)")
    return os.path.join(_dir(), name)


def _run(args, timeout=30, input_text=None, env=None):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input_text, env=env)


def _fingerprints(pub_path):
    out = {}
    for algo in ("sha256", "md5"):
        proc = _run(["ssh-keygen", "-l", "-E", algo, "-f", pub_path], timeout=10)
        line = (proc.stdout or "").strip()
        # "256 SHA256:abc... comment (ED25519)"
        parts = line.split()
        if proc.returncode == 0 and len(parts) >= 2:
            out["bits"] = int(parts[0]) if parts[0].isdigit() else None
            out[algo] = parts[1].split(":", 1)[1] if algo == "md5" else parts[1]
            m = re.search(r"\(([A-Z0-9-]+)\)\s*$", line)
            if m:
                out["type"] = m.group(1)
    return out


def _is_encrypted(priv_path):
    proc = _run(["ssh-keygen", "-y", "-P", "", "-f", priv_path], timeout=10)
    return proc.returncode != 0


def _meta_path(name):
    return os.path.join(_dir(), name + ".json")


def _write_meta(name, **meta):
    path = _meta_path(name)
    try:
        with open(path, encoding="utf-8") as fh:
            old = json.load(fh)
    except (OSError, ValueError):
        old = {}
    old.update(meta)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(old, fh)
    os.chmod(path, 0o600)
    _own(path)


def info(name):
    priv = key_path(name)
    pub = priv + ".pub"
    if not os.path.isfile(priv) or not os.path.isfile(pub):
        raise SshKeyError("key not found")
    with open(pub, encoding="utf-8") as fh:
        public = fh.read().strip()
    try:
        with open(_meta_path(name), encoding="utf-8") as fh:
            meta = json.load(fh)
    except (OSError, ValueError):
        meta = {}
    fp = _fingerprints(pub)
    parts = public.split(None, 2)
    if "encrypted" not in meta:
        meta["encrypted"] = _is_encrypted(priv)
        _write_meta(name, encrypted=meta["encrypted"])
    return {
        "name": name,
        "type": fp.get("type") or (parts[0] if parts else ""),
        "bits": fp.get("bits"),
        "comment": parts[2] if len(parts) > 2 else "",
        "fp_sha256": fp.get("sha256", ""),
        "fp_md5": fp.get("md5", ""),
        "public": public,
        "encrypted": bool(meta.get("encrypted")),
        "created": meta.get("created") or os.path.getmtime(priv),
        "imported": bool(meta.get("imported")),
        "installed": meta.get("installed", []),
    }


def list_keys():
    out = []
    for fname in sorted(os.listdir(_dir())):
        if fname.endswith(".pub") or fname.endswith(".json") or fname.startswith("."):
            continue
        if not valid_name(fname) or not os.path.isfile(os.path.join(KEY_DIR, fname + ".pub")):
            continue
        try:
            out.append(info(fname))
        except (SshKeyError, OSError, subprocess.SubprocessError):
            continue
    out.sort(key=lambda k: -float(k["created"] or 0))
    return out


def generate(name, ktype="ed25519", comment="", passphrase=""):
    if ktype not in TYPES:
        raise SshKeyError("unknown key type")
    priv = key_path(name)
    if os.path.exists(priv) or os.path.exists(priv + ".pub"):
        raise SshKeyError("a key with this name already exists")
    comment = re.sub(r"[\r\n]", " ", comment or "").strip()[:120] or f"{name}@nettoolbox"
    proc = _run(["ssh-keygen", *TYPES[ktype], "-a", "64", "-C", comment, "-N", passphrase or "", "-f", priv, "-q"], timeout=60)
    if proc.returncode != 0:
        for p in (priv, priv + ".pub"):
            if os.path.exists(p):
                os.remove(p)
        raise SshKeyError((proc.stderr or "ssh-keygen failed").strip()[-300:])
    os.chmod(priv, 0o600)
    _own(priv)
    _own(priv + ".pub")
    _write_meta(name, created=time.time(), encrypted=bool(passphrase), imported=False, installed=[])
    return info(name)


def import_key(name, private_text, passphrase=""):
    priv = key_path(name)
    if os.path.exists(priv) or os.path.exists(priv + ".pub"):
        raise SshKeyError("a key with this name already exists")
    text = (private_text or "").replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    if "PRIVATE KEY-----" not in text or len(text) > 20000:
        raise SshKeyError("paste a private key (-----BEGIN ... PRIVATE KEY-----)")
    fd, tmp = tempfile.mkstemp(dir=_dir(), prefix=".import-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        proc = _run(["ssh-keygen", "-y", "-P", passphrase or "", "-f", tmp], timeout=15)
        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            if "incorrect passphrase" in err.lower() or ("passphrase" in err.lower() and not passphrase):
                raise SshKeyError("this key is passphrase-protected: enter the correct passphrase")
            raise SshKeyError(err[-300:] or "not a valid private key")
        public = proc.stdout.strip()
        os.replace(tmp, priv)
        tmp = None
        with open(priv + ".pub", "w", encoding="utf-8") as fh:
            fh.write(public + "\n")
        _own(priv)
        _own(priv + ".pub")
        _write_meta(name, created=time.time(), encrypted=bool(passphrase), imported=True, installed=[])
        return info(name)
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)


def delete(name):
    priv = key_path(name)
    found = False
    for p in (priv, priv + ".pub", _meta_path(name)):
        if os.path.exists(p):
            os.remove(p)
            found = True
    if not found:
        raise SshKeyError("key not found")


def read_file(name, part):
    priv = key_path(name)
    path = priv + ".pub" if part == "public" else priv
    if not os.path.isfile(path):
        raise SshKeyError("key not found")
    with open(path, "rb") as fh:
        return fh.read()


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=8",
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=2",
]


def _ensure_home_ssh():
    """ssh-copy-id and known_hosts need ~/.ssh; a fresh container has none."""
    path = os.path.join(os.path.expanduser("~"), ".ssh")
    os.makedirs(path, mode=0o700, exist_ok=True)


def _target(user, host):
    return f"{user}@{host}" if user else host


def install(name, host, port, user, password):
    """Append the public key to ~/.ssh/authorized_keys on host (password login)."""
    _ensure_home_ssh()
    priv = key_path(name)
    if not os.path.isfile(priv + ".pub"):
        raise SshKeyError("key not found")
    if not password:
        raise SshKeyError("the server password is needed once to install the key")
    env = os.environ.copy()
    env["SSHPASS"] = password
    proc = _run(
        ["sshpass", "-e", "ssh-copy-id", "-f", "-i", priv + ".pub", "-p", str(port),
         *_SSH_OPTS, "-o", "PreferredAuthentications=password,keyboard-interactive",
         "-o", "PubkeyAuthentication=no", _target(user, host)],
        timeout=45, env=env,
    )
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    if proc.returncode != 0:
        if proc.returncode == 5 or "permission denied" in out.lower():
            raise SshKeyError("wrong password, or password login is disabled on the server")
        raise SshKeyError(out[-400:] or f"ssh-copy-id failed ({proc.returncode})")
    target = f"{_target(user, host)}:{port}"
    meta = info(name)
    installed = [x for x in meta.get("installed", []) if x != target] + [target]
    _write_meta(name, installed=installed[-20:])
    return out[-400:]


def test(name, host, port, user, passphrase=""):
    """Try a key-only login and run a tiny command. Returns (ok, output)."""
    _ensure_home_ssh()
    priv = key_path(name)
    if not os.path.isfile(priv):
        raise SshKeyError("key not found")
    cmd = ["ssh", "-i", priv, "-p", str(port), *_SSH_OPTS,
           "-o", "IdentitiesOnly=yes", "-o", "PreferredAuthentications=publickey",
           "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
           _target(user, host), "echo NTB_OK; uname -a 2>/dev/null || ver"]
    env = os.environ.copy()
    if passphrase:
        env["SSHPASS"] = passphrase
        cmd = ["sshpass", "-e", "-P", "passphrase", *cmd]
    else:
        cmd[1:1] = ["-o", "BatchMode=yes"]
    proc = _run(cmd, timeout=30, env=env)
    out = ((proc.stdout or "") + (proc.stderr or "")).strip()
    ok = proc.returncode == 0 and "NTB_OK" in (proc.stdout or "")
    return ok, out.replace("NTB_OK", "").strip()[-600:]
