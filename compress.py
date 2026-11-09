"""Compression lab: canonical Huffman + LZW (pure Python) and standard codecs.

Custom formats
  .huff  b"NTHF" | u8 version | u64 original length | 256 x u8 code lengths | bitstream (MSB first)
  .lzw   b"NTLZ" | u8 version | u64 original length | LZW codes, 9..16 bit, LSB first, CLEAR=256
"""
from __future__ import annotations

import bz2
import heapq
import lzma
import math
import struct
import time
import zlib
from collections import Counter

try:
    import zstandard
except ImportError:  # pragma: no cover
    zstandard = None
try:
    import brotli
except ImportError:  # pragma: no cover
    brotli = None

HUFF_MAGIC = b"NTHF"
LZW_MAGIC = b"NTLZ"
HUFF_MAX_LEN = 15
LZW_MAX_BITS = 16
LZW_CLEAR = 256

PURE_PY_LIMIT = 16 * 1024 * 1024     # Huffman / LZW are pure Python: keep them snappy
ANALYZE_LIMIT = 64 * 1024 * 1024


class CompressError(Exception):
    pass


# --------------------------------------------------------------------------- stats

def entropy(data, counts=None):
    """Shannon entropy in bits per byte."""
    n = len(data)
    if not n:
        return 0.0
    counts = counts or Counter(data)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


# --------------------------------------------------------------------------- Huffman

def _huff_lengths(counts):
    """Code length per symbol (dict sym -> len), limited to HUFF_MAX_LEN bits."""
    freqs = {s: c for s, c in counts.items() if c}
    if not freqs:
        return {}
    if len(freqs) == 1:
        return {next(iter(freqs)): 1}
    while True:
        heap = [(c, i, (s,)) for i, (s, c) in enumerate(freqs.items())]
        heapq.heapify(heap)
        depth = {s: 0 for s in freqs}
        uid = len(heap)
        while len(heap) > 1:
            c1, _, a = heapq.heappop(heap)
            c2, _, b = heapq.heappop(heap)
            for s in a + b:
                depth[s] += 1
            heapq.heappush(heap, (c1 + c2, uid, a + b))
            uid += 1
        if max(depth.values()) <= HUFF_MAX_LEN:
            return depth
        # Too deep: flatten the distribution and rebuild (classic length-limiting trick).
        freqs = {s: (c >> 1) | 1 for s, c in freqs.items()}


def _canonical(lengths):
    """sym -> (code int, length) from code lengths, canonical order (len, sym)."""
    codes = {}
    code = 0
    prev_len = 0
    for sym, ln in sorted(lengths.items(), key=lambda kv: (kv[1], kv[0])):
        code <<= ln - prev_len
        codes[sym] = (code, ln)
        code += 1
        prev_len = ln
    return codes


def huffman_compress(data):
    counts = Counter(data)
    lengths = _huff_lengths(counts)
    codes = _canonical(lengths)
    table = [""] * 256
    for sym, (code, ln) in codes.items():
        table[sym] = format(code, f"0{ln}b")
    bits = "".join(map(table.__getitem__, data))
    pad = (-len(bits)) % 8
    bits += "0" * pad
    body = int(bits, 2).to_bytes(len(bits) // 8, "big") if bits else b""
    header = HUFF_MAGIC + bytes([1]) + struct.pack("!Q", len(data))
    header += bytes(lengths.get(s, 0) for s in range(256))
    return header + body


def huffman_decompress(blob):
    if len(blob) < 13 + 256 or blob[:4] != HUFF_MAGIC:
        raise CompressError("not a .huff file")
    n = struct.unpack("!Q", blob[5:13])[0]
    lens = blob[13:13 + 256]
    body = blob[13 + 256:]
    lengths = {s: ln for s, ln in enumerate(lens) if ln}
    if n == 0:
        return b""
    if not lengths or max(lengths.values()) > HUFF_MAX_LEN:
        raise CompressError("corrupt Huffman header")
    codes = _canonical(lengths)
    L = max(lengths.values())
    lut = [None] * (1 << L)
    for sym, (code, ln) in codes.items():
        start = code << (L - ln)
        for k in range(start, start + (1 << (L - ln))):
            lut[k] = (sym, ln)
    bits = bin(int.from_bytes(body, "big"))[2:].zfill(len(body) * 8) if body else ""
    bits += "0" * L
    if len(bits) - L < n:  # every symbol costs at least 1 bit
        raise CompressError("truncated Huffman stream")
    out = bytearray(n)
    i = 0
    for k in range(n):
        hit = lut[int(bits[i:i + L], 2)]
        if hit is None:
            raise CompressError("corrupt Huffman stream")
        out[k] = hit[0]
        i += hit[1]
    if i > len(bits) - L:
        raise CompressError("truncated Huffman stream")
    return bytes(out)


def huffman_details(data, counts=None, limit=256):
    counts = counts or Counter(data)
    lengths = _huff_lengths(counts)
    codes = _canonical(lengths)
    n = len(data) or 1
    rows = []
    for sym, cnt in counts.most_common(limit):
        code, ln = codes[sym]
        rows.append({
            "byte": sym,
            "char": _printable(sym),
            "count": cnt,
            "prob": cnt / n,
            "len": ln,
            "code": format(code, f"0{ln}b"),
        })
    avg = sum(counts[s] * codes[s][1] for s in counts) / n if counts else 0.0
    return {
        "symbols": len(counts),
        "avg_len": avg,
        "max_len": max(lengths.values()) if lengths else 0,
        "table": rows,
    }


def _printable(b):
    names = {9: "\\t", 10: "\\n", 13: "\\r", 32: "space", 0: "NUL"}
    if b in names:
        return names[b]
    if 33 <= b < 127:
        return chr(b)
    return f"0x{b:02X}"


# --------------------------------------------------------------------------- LZW

def lzw_compress(data, max_bits=LZW_MAX_BITS):
    limit = 1 << max_bits
    out = bytearray(LZW_MAGIC + bytes([1]) + struct.pack("!Q", len(data)))
    acc = 0
    nacc = 0

    def emit(code, width):
        nonlocal acc, nacc
        acc |= code << nacc
        nacc += width
        while nacc >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nacc -= 8

    table = {bytes([i]): i for i in range(256)}
    next_code, width = 257, 9
    w = b""
    for byte in data:
        c = bytes((byte,))
        wc = w + c
        if wc in table:
            w = wc
            continue
        emit(table[w], width)
        if next_code < limit:
            table[wc] = next_code
            next_code += 1
            if next_code > (1 << width) and width < max_bits:
                width += 1
        else:
            emit(LZW_CLEAR, width)
            table = {bytes([i]): i for i in range(256)}
            next_code, width = 257, 9
        w = c
    if w:
        emit(table[w], width)
    if nacc:
        out.append(acc & 0xFF)
    return bytes(out)


def lzw_decompress(blob, max_bits=LZW_MAX_BITS):
    if len(blob) < 13 or blob[:4] != LZW_MAGIC:
        raise CompressError("not a .lzw file")
    n = struct.unpack("!Q", blob[5:13])[0]
    body = blob[13:]
    limit = 1 << max_bits
    out = bytearray()
    table = [bytes([i]) for i in range(256)] + [b""]
    width = 9
    prev = None
    pos = 0          # bit position
    total_bits = len(body) * 8
    while len(out) < n:
        if pos + width > total_bits:
            raise CompressError("truncated LZW stream")
        byte_i, bit_i = divmod(pos, 8)
        chunk = int.from_bytes(body[byte_i:byte_i + 4], "little")
        code = (chunk >> bit_i) & ((1 << width) - 1)
        pos += width
        if code == LZW_CLEAR:
            table = [bytes([i]) for i in range(256)] + [b""]
            width, prev = 9, None
            continue
        if code < len(table):
            entry = table[code]
        elif code == len(table) and prev is not None:
            entry = prev + prev[:1]
        else:
            raise CompressError("corrupt LZW stream")
        out += entry
        if prev is not None and len(table) < limit:
            table.append(prev + entry[:1])
        prev = entry
        if len(table) + 1 > (1 << width) and width < max_bits:
            width += 1
    return bytes(out[:n])


# --------------------------------------------------------------------------- codecs

LEVELS = {"fast": 0, "default": 1, "max": 2}


def _codecs():
    c = {
        "huffman": {
            "name": "Huffman", "ext": ".huff", "family": "entropy coding (canonical, ≤15-bit codes)",
            "pure": True, "c": lambda d, lv: huffman_compress(d), "d": huffman_decompress,
        },
        "lzw": {
            "name": "LZW", "ext": ".lzw", "family": "dictionary (9–16 bit codes)",
            "pure": True, "c": lambda d, lv: lzw_compress(d), "d": lzw_decompress,
        },
        "gzip": {
            "name": "Deflate / gzip", "ext": ".gz", "family": "LZ77 + Huffman",
            "c": lambda d, lv: _gzip(d, (1, 6, 9)[lv]), "d": _gunzip,
        },
        "bzip2": {
            "name": "bzip2", "ext": ".bz2", "family": "BWT + MTF + Huffman",
            "c": lambda d, lv: bz2.compress(d, (1, 9, 9)[lv]), "d": bz2.decompress,
        },
        "xz": {
            "name": "LZMA / xz", "ext": ".xz", "family": "LZ77 + range coder",
            "c": lambda d, lv: lzma.compress(d, preset=(1, 6, 9 | lzma.PRESET_EXTREME)[lv]),
            "d": lzma.decompress,
        },
    }
    if zstandard:
        c["zstd"] = {
            "name": "Zstandard", "ext": ".zst", "family": "LZ77 + FSE/ANS + Huffman",
            "c": lambda d, lv: zstandard.ZstdCompressor(level=(1, 3, 19)[lv]).compress(d),
            "d": lambda b: zstandard.ZstdDecompressor().decompress(b, max_output_size=1 << 32),
        }
    if brotli:
        c["brotli"] = {
            "name": "Brotli", "ext": ".br", "family": "LZ77 + Huffman + context modeling",
            "c": lambda d, lv: brotli.compress(d, quality=(1, 6, 11)[lv]),
            "d": brotli.decompress,
        }
    return c


def _gzip(data, level):
    co = zlib.compressobj(level, zlib.DEFLATED, 31)
    return co.compress(data) + co.flush()


def _gunzip(blob):
    return zlib.decompress(blob, 47)


CODECS = _codecs()


def codec_list():
    return [{"id": k, "name": v["name"], "ext": v["ext"], "family": v["family"],
             "pure": bool(v.get("pure"))} for k, v in CODECS.items()]


def compress(data, algo, level="default"):
    codec = CODECS.get(algo)
    if not codec:
        raise CompressError("unknown algorithm")
    if codec.get("pure") and len(data) > PURE_PY_LIMIT:
        raise CompressError(f"{codec['name']} runs in pure Python here; max {PURE_PY_LIMIT // (1024 * 1024)} MB")
    return codec["c"](data, LEVELS.get(level, 1)), codec["ext"]


def detect(blob, filename=""):
    name = (filename or "").lower()
    if blob[:4] == HUFF_MAGIC:
        return "huffman"
    if blob[:4] == LZW_MAGIC:
        return "lzw"
    if blob[:2] == b"\x1f\x8b":
        return "gzip"
    if blob[:3] == b"BZh":
        return "bzip2"
    if blob[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if blob[:4] == b"\x28\xb5\x2f\xfd" and "zstd" in CODECS:
        return "zstd"
    if name.endswith(".br") and "brotli" in CODECS:
        return "brotli"
    return None


def decompress(blob, filename=""):
    algo = detect(blob, filename)
    if not algo:
        raise CompressError("unknown format (supported: .huff .lzw .gz .bz2 .xz .zst .br)")
    try:
        data = CODECS[algo]["d"](blob)
    except CompressError:
        raise
    except Exception as exc:
        raise CompressError(f"{CODECS[algo]['name']}: {exc}")
    out_name = filename or "file"
    ext = CODECS[algo]["ext"]
    if out_name.lower().endswith(ext):
        out_name = out_name[: -len(ext)] or "file"
    else:
        out_name += ".out"
    return data, algo, out_name


def analyze(data, level="default", algos=None):
    if len(data) > ANALYZE_LIMIT:
        raise CompressError(f"max {ANALYZE_LIMIT // (1024 * 1024)} MB for analysis")
    counts = Counter(data)
    n = len(data)
    h = entropy(data, counts)
    results = []
    for algo, codec in CODECS.items():
        if algos and algo not in algos:
            continue
        row = {"id": algo, "name": codec["name"], "family": codec["family"], "ext": codec["ext"]}
        if codec.get("pure") and n > PURE_PY_LIMIT:
            row["skipped"] = f"> {PURE_PY_LIMIT // (1024 * 1024)} MB (pure Python)"
            results.append(row)
            continue
        try:
            t0 = time.perf_counter()
            packed = codec["c"](data, LEVELS.get(level, 1))
            t1 = time.perf_counter()
            back = codec["d"](packed)
            t2 = time.perf_counter()
        except Exception as exc:  # report, don't crash the whole analysis
            row["error"] = str(exc)
            results.append(row)
            continue
        row.update(
            size=len(packed),
            ratio=(len(packed) / n) if n else 1.0,
            bpb=(len(packed) * 8 / n) if n else 0.0,
            c_ms=round((t1 - t0) * 1000, 1),
            d_ms=round((t2 - t1) * 1000, 1),
            mbps=round(n / 1e6 / (t1 - t0), 1) if t1 > t0 and n else None,
            ok=back == data,
        )
        results.append(row)
    return {
        "size": n,
        "entropy": h,
        "entropy_bytes": math.ceil(h * n / 8),
        "unique": len(counts),
        "results": results,
        "huffman": huffman_details(data, counts, limit=64) if n else None,
    }
