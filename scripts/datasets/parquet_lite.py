"""Minimal pure-Python Parquet reader (no pyarrow / pandas needed).

Why this exists: the dataset build scripts must run on a stock Python with no
extra dependencies (see README "Datasets"). Nemotron-PII ships as Parquet, and
pyarrow is a ~40 MB wheel we do not otherwise need. If pyarrow IS installed the
build script uses it instead; this module is the fallback.

Supported subset (enough for flat string/int tables such as Nemotron-PII):
  * Thrift compact-protocol footer (FileMetaData)
  * DATA_PAGE (v1) and DATA_PAGE_V2, DICTIONARY_PAGE
  * PLAIN, PLAIN_DICTIONARY / RLE_DICTIONARY encodings
  * Codecs: UNCOMPRESSED, SNAPPY (pure-Python decoder), GZIP, ZSTD (only if
    the `zstandard` module or Python 3.14 `compression.zstd` is available)
  * Flat (non-nested) columns, optional or required
Anything else raises NotImplementedError rather than returning wrong data.
"""
from __future__ import annotations

import gzip
import struct
import zlib
from typing import Any, Iterator

# --------------------------------------------------------------------------- thrift
CT_STOP, CT_TRUE, CT_FALSE, CT_BYTE, CT_I16, CT_I32, CT_I64, CT_DOUBLE, CT_BINARY, CT_LIST, CT_SET, CT_MAP, CT_STRUCT = (
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)


class _Thrift:
    def __init__(self, buf: bytes, pos: int = 0):
        self.b = buf
        self.p = pos

    def varint(self) -> int:
        shift = result = 0
        while True:
            byte = self.b[self.p]
            self.p += 1
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return result
            shift += 7

    def zigzag(self) -> int:
        n = self.varint()
        return (n >> 1) ^ -(n & 1)

    def value(self, t: int) -> Any:
        if t in (CT_TRUE, CT_FALSE):
            return t == CT_TRUE
        if t == CT_BYTE:
            v = self.b[self.p]
            self.p += 1
            return v
        if t in (CT_I16, CT_I32, CT_I64):
            return self.zigzag()
        if t == CT_DOUBLE:
            v = struct.unpack_from("<d", self.b, self.p)[0]
            self.p += 8
            return v
        if t == CT_BINARY:
            n = self.varint()
            v = self.b[self.p:self.p + n]
            self.p += n
            return v
        if t in (CT_LIST, CT_SET):
            head = self.b[self.p]
            self.p += 1
            size, et = head >> 4, head & 0x0F
            if size == 15:
                size = self.varint()
            out = []
            for _ in range(size):
                if et in (CT_TRUE, CT_FALSE):  # bools in lists are one byte each
                    out.append(self.b[self.p] == 1)
                    self.p += 1
                else:
                    out.append(self.value(et))
            return out
        if t == CT_MAP:
            size = self.varint()
            if size == 0:
                return {}
            kv = self.b[self.p]
            self.p += 1
            return {self.value(kv >> 4): self.value(kv & 0x0F) for _ in range(size)}
        if t == CT_STRUCT:
            return self.struct()
        raise NotImplementedError(f"thrift type {t}")

    def struct(self) -> dict[int, Any]:
        out: dict[int, Any] = {}
        last = 0
        while True:
            head = self.b[self.p]
            self.p += 1
            if head == CT_STOP:
                return out
            delta, t = head >> 4, head & 0x0F
            fid = last + delta if delta else self.zigzag()
            out[fid] = self.value(t)
            last = fid


# --------------------------------------------------------------------------- codecs
def snappy_decompress(src: bytes) -> bytes:
    """Pure-Python raw snappy decoder (format description in google/snappy)."""
    t = _Thrift(src)
    length = t.varint()
    p = t.p
    out = bytearray()
    n = len(src)
    while p < n:
        tag = src[p]
        p += 1
        kind = tag & 3
        if kind == 0:  # literal
            ln = tag >> 2
            if ln >= 60:
                nb = ln - 59
                ln = int.from_bytes(src[p:p + nb], "little")
                p += nb
            ln += 1
            out += src[p:p + ln]
            p += ln
            continue
        if kind == 1:
            ln = ((tag >> 2) & 7) + 4
            off = ((tag >> 5) << 8) | src[p]
            p += 1
        elif kind == 2:
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[p:p + 2], "little")
            p += 2
        else:
            ln = (tag >> 2) + 1
            off = int.from_bytes(src[p:p + 4], "little")
            p += 4
        start = len(out) - off
        if off >= ln:
            out += out[start:start + ln]
        else:  # overlapping copy
            for i in range(ln):
                out.append(out[start + i])
    if len(out) != length:
        raise ValueError("snappy: length mismatch")
    return bytes(out)


def _zstd(data: bytes, size: int) -> bytes:
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(data)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompress(data, max_output_size=size)
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise NotImplementedError("ZSTD parquet needs pyarrow, zstandard or Python 3.14") from exc


CODECS = {0: "UNCOMPRESSED", 1: "SNAPPY", 2: "GZIP", 3: "LZO", 4: "BROTLI", 5: "LZ4", 6: "ZSTD", 7: "LZ4_RAW"}


def decompress(codec: int, data: bytes, size: int) -> bytes:
    if codec == 0:
        return data
    if codec == 1:
        return snappy_decompress(data)
    if codec == 2:
        return gzip.decompress(data) if data[:2] == b"\x1f\x8b" else zlib.decompress(data)
    if codec == 6:
        return _zstd(data, size)
    raise NotImplementedError(f"codec {CODECS.get(codec, codec)}")


# --------------------------------------------------------------------------- encodings
def _rle_bitpacked(buf: bytes, pos: int, end: int, bit_width: int, count: int) -> list[int]:
    out: list[int] = []
    byte_w = (bit_width + 7) // 8
    t = _Thrift(buf, pos)
    while len(out) < count and t.p < end:
        header = t.varint()
        if header & 1:  # bit-packed groups of 8
            groups = header >> 1
            nbytes = groups * bit_width
            chunk = int.from_bytes(buf[t.p:t.p + nbytes], "little")
            t.p += nbytes
            mask = (1 << bit_width) - 1
            for i in range(groups * 8):
                out.append((chunk >> (i * bit_width)) & mask if bit_width else 0)
        else:
            run = header >> 1
            val = int.from_bytes(buf[t.p:t.p + byte_w], "little") if byte_w else 0
            t.p += byte_w
            out.extend([val] * run)
    return out[:count]


PHYS = {0: "BOOLEAN", 1: "INT32", 2: "INT64", 3: "INT96", 4: "FLOAT", 5: "DOUBLE", 6: "BYTE_ARRAY", 7: "FIXED_LEN_BYTE_ARRAY"}


def _plain(buf: bytes, pos: int, ptype: int, n: int) -> list[Any]:
    out: list[Any] = []
    if ptype == 6:
        for _ in range(n):
            ln = struct.unpack_from("<i", buf, pos)[0]
            pos += 4
            out.append(buf[pos:pos + ln])
            pos += ln
    elif ptype == 1:
        out = list(struct.unpack_from(f"<{n}i", buf, pos))
    elif ptype == 2:
        out = list(struct.unpack_from(f"<{n}q", buf, pos))
    elif ptype == 5:
        out = list(struct.unpack_from(f"<{n}d", buf, pos))
    elif ptype == 4:
        out = list(struct.unpack_from(f"<{n}f", buf, pos))
    elif ptype == 0:
        out = [bool((buf[pos + i // 8] >> (i % 8)) & 1) for i in range(n)]
    else:
        raise NotImplementedError(f"physical type {PHYS.get(ptype, ptype)}")
    return out


# --------------------------------------------------------------------------- reader
class ParquetFile:
    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            fh.seek(-8, 2)
            tail = fh.read(8)
            if tail[4:] != b"PAR1":
                raise ValueError("not a parquet file")
            flen = struct.unpack("<i", tail[:4])[0]
            fh.seek(-8 - flen, 2)
            self.meta = _Thrift(fh.read(flen)).struct()
        # FileMetaData: 1 version, 2 schema, 3 num_rows, 4 row_groups, 5 kv, 6 created_by
        self.schema = self.meta[2]
        self.num_rows = self.meta[3]
        self.row_groups = self.meta.get(4, [])
        self.created_by = (self.meta.get(6) or b"").decode("utf-8", "replace")
        self.columns: list[dict[str, Any]] = []
        for el in self.schema[1:]:
            if el.get(5):  # num_children -> nested
                raise NotImplementedError("nested schema")
            self.columns.append({
                "name": el[4].decode(),
                "type": PHYS.get(el.get(1), el.get(1)),
                "ptype": el.get(1),
                "optional": el.get(3, 0) == 1,
                "converted": el.get(6),
            })

    def describe(self) -> dict[str, Any]:
        codecs = sorted({CODECS.get(c[3][4], c[3][4]) for rg in self.row_groups for c in rg[1]})
        kv = {k[1].decode(): (k.get(2) or b"")[:200].decode("utf-8", "replace") for k in self.meta.get(5, []) or []}
        return {"rows": self.num_rows, "row_groups": len(self.row_groups), "created_by": self.created_by,
                "codecs": codecs, "columns": [{k: v for k, v in c.items() if k != "ptype"} for c in self.columns],
                "kv_keys": list(kv)}

    def _read_chunk(self, fh, col_idx: int, chunk: dict[int, Any]) -> list[Any]:
        cmeta = chunk[3]
        codec, nvals = cmeta[4], cmeta[5]
        start = cmeta.get(11) or cmeta[9]  # dictionary_page_offset or data_page_offset
        if cmeta.get(11) is not None:
            start = min(cmeta[11], cmeta[9])
        fh.seek(start)
        raw = fh.read(cmeta[7])  # total_compressed_size
        col = self.columns[col_idx]
        ptype, optional = col["ptype"], col["optional"]
        dictionary: list[Any] | None = None
        values: list[Any] = []
        p = 0
        while len(values) < nvals and p < len(raw):
            t = _Thrift(raw, p)
            hdr = t.struct()
            p = t.p
            ptype_page, usize, csize = hdr[1], hdr[2], hdr[3]
            body = raw[p:p + csize]
            p += csize
            if ptype_page == 2:  # DICTIONARY_PAGE
                d = decompress(codec, body, usize)
                dictionary = _plain(d, 0, ptype, hdr[7][1])
                continue
            if ptype_page == 0:  # DATA_PAGE v1
                dph = hdr[5]
                n, enc = dph[1], dph[2]
                data = decompress(codec, body, usize)
                q = 0
                defs = [1] * n
                if optional:
                    ln = struct.unpack_from("<i", data, q)[0]
                    q += 4
                    defs = _rle_bitpacked(data, q, q + ln, 1, n)
                    q += ln
            elif ptype_page == 3:  # DATA_PAGE_V2
                dph = hdr[8]
                n, nnull, enc = dph[1], dph[2], dph[4]
                dl, rl = dph[5], dph[6]
                compressed = dph.get(7, True)
                levels = body[:rl + dl]
                payload = body[rl + dl:]
                data = levels + (decompress(codec, payload, usize - rl - dl) if compressed else payload)
                defs = _rle_bitpacked(data, rl, rl + dl, 1, n) if optional and dl else [1] * n
                q = rl + dl
            else:
                continue
            present = sum(defs)
            if enc == 0:
                vals = _plain(data, q, ptype, present)
            elif enc in (2, 8):
                bw = data[q]
                vals = [dictionary[i] for i in _rle_bitpacked(data, q + 1, len(data), bw, present)]  # type: ignore[index]
            else:
                raise NotImplementedError(f"encoding {enc}")
            it = iter(vals)
            values.extend(next(it) if d else None for d in defs)
        return values

    def iter_row_groups(self, columns: list[str] | None = None) -> Iterator[dict[str, list[Any]]]:
        names = [c["name"] for c in self.columns]
        wanted = columns or names
        with open(self.path, "rb") as fh:
            for rg in self.row_groups:
                out: dict[str, list[Any]] = {}
                for idx, chunk in enumerate(rg[1]):
                    if names[idx] not in wanted:
                        continue
                    vals = self._read_chunk(fh, idx, chunk)
                    if self.columns[idx]["ptype"] == 6:
                        vals = [v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else v for v in vals]
                    out[names[idx]] = vals
                yield out

    def iter_rows(self, columns: list[str] | None = None) -> Iterator[dict[str, Any]]:
        for rg in self.iter_row_groups(columns):
            keys = list(rg)
            for i in range(len(rg[keys[0]]) if keys else 0):
                yield {k: rg[k][i] for k in keys}


if __name__ == "__main__":  # quick inspection: python parquet_lite.py file.parquet
    import json
    import sys
    pf = ParquetFile(sys.argv[1])
    print(json.dumps(pf.describe(), indent=2))
