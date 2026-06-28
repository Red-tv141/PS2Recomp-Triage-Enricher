#!/usr/bin/env python3
"""
gs_dump_to_summary.py - PCSX2 GS dump parser -> enricher summary JSON
=====================================================================

Reads a PCSX2 single-frame GS dump (`.gs` / `.gs.xz` / `.gs.zst`) and emits
`gs_dump_summary.json` next to it. The summary is a compact set of facts the
PS2Recomp Triage Enricher consumes to cross-validate static predictions
against ground-truth runtime behavior.

Usage:
    python gs_dump_to_summary.py <path/to/dump.gs[.xz|.zst]> [--checkpoint NAME] [--out PATH]

Format (from pcsx2/GS/GSDump.h):
    [0xFFFFFFFF / 4] [header_size / 4] [GSDumpHeader / 36]
    [serial / N] [screenshot / W*H*4] [freeze data / state_size]
    [GSPrivRegSet / 0x2000]
    repeated:
        id=0 Transfer:  [0/1] [path/1] [size/4] [data/size]
        id=1 VSync:     [1/1] [field/1]
        id=2 ReadFIFO2: [2/1] [size/4]
        id=3 Regs:      [3/1] [GSPrivRegSet/0x2000]

Path values: 0=Path1 (VU1→GIF), 1=Path2 (VIF1 DIRECT), 2=Path3 (DMA→GIF).

GIFTAG (16 bytes, little-endian):
    bits  0..14  NLOOP (15)
    bit   15     EOP
    bit   46     PRE
    bits 47..57  PRIM (11)
    bits 58..59  FLG (0=PACKED, 1=REGLIST, 2=IMAGE, 3=IMAGE2)
    bits 60..63  NREG (0 = 16)
    bits 64..127 REGS (16 nibbles, regDesc per nibble)

PACKED A+D (regDesc=0x0E): each 16-byte qword has reg# in low byte of upper
half, register value in low half.
"""

from __future__ import annotations
import argparse, json, os, struct, sys
from pathlib import Path

# =========================================================
# GS register name maps (mirror Java enricher v6 KNOWN_GS_REGS / KNOWN_GS_PRIV_REGS)
# =========================================================

GIF_A_D_REG_NAMES = {
    0x00: "PRIM",  0x01: "RGBAQ", 0x02: "ST",    0x03: "UV",
    0x04: "XYZF2", 0x05: "XYZ2",  0x06: "TEX0_1",0x07: "TEX0_2",
    0x08: "CLAMP_1", 0x09: "CLAMP_2", 0x0a: "FOG",
    0x0c: "XYZF3", 0x0d: "XYZ3",  0x0e: "A_D",   0x0f: "NOP",
    0x14: "TEX1_1", 0x15: "TEX1_2", 0x16: "TEX2_1", 0x17: "TEX2_2",
    0x18: "XYOFFSET_1", 0x19: "XYOFFSET_2",
    0x1a: "PRMODECONT", 0x1b: "PRMODE", 0x1c: "TEXCLUT",
    0x22: "SCANMSK",
    0x34: "MIPTBP1_1", 0x35: "MIPTBP1_2", 0x36: "MIPTBP2_1", 0x37: "MIPTBP2_2",
    0x3b: "TEXA", 0x3d: "FOGCOL", 0x3f: "TEXFLUSH",
    0x40: "SCISSOR_1", 0x41: "SCISSOR_2",
    0x42: "ALPHA_1", 0x43: "ALPHA_2",
    0x44: "DIMX", 0x45: "DTHE", 0x46: "COLCLAMP",
    0x47: "TEST_1", 0x48: "TEST_2",
    0x49: "PABE", 0x4a: "FBA_1", 0x4b: "FBA_2",
    0x4c: "FRAME_1", 0x4d: "FRAME_2", 0x4e: "ZBUF_1", 0x4f: "ZBUF_2",
    0x50: "BITBLTBUF", 0x51: "TRXPOS", 0x52: "TRXREG", 0x53: "TRXDIR",
    0x54: "HWREG",
    0x60: "SIGNAL", 0x61: "FINISH", 0x62: "LABEL",
}

GIF_FLG_NAMES = {0: "PACKED", 1: "REGLIST", 2: "IMAGE", 3: "IMAGE2"}
GIF_PATH_NAMES = {0: "PATH1", 1: "PATH2", 2: "PATH3"}

# GSPrivRegSet offsets (PCSX2 GSRegs.h GSPrivRegSet)
PRIV_PMODE     = 0x00
PRIV_SMODE1    = 0x10
PRIV_SMODE2    = 0x20
PRIV_SRFSH     = 0x30
PRIV_SYNCH1    = 0x40
PRIV_SYNCH2    = 0x50
PRIV_SYNCV     = 0x60
PRIV_DISPFB1   = 0x70
PRIV_DISPLAY1  = 0x80
PRIV_DISPFB2   = 0x90
PRIV_DISPLAY2  = 0xA0
PRIV_BGCOLOR   = 0xE0
PRIV_CSR       = 0x1000
PRIV_IMR       = 0x1010
PRIV_BUSDIR    = 0x1040
PRIV_SIGLBLID  = 0x1080

GSPRIV_SIZE = 0x2000

# Magic at file start
GS_DUMP_MAGIC = 0xFFFFFFFF


# =========================================================
# Decompression
# =========================================================

def _read_dump_bytes(path: Path) -> bytes:
    """Read the dump, transparently decompressing .xz / .zst variants."""
    suf = path.suffix.lower()
    if suf == ".xz" or path.name.lower().endswith(".gs.xz"):
        import lzma
        with lzma.open(path, "rb") as f:
            return f.read()
    if suf == ".zst" or path.name.lower().endswith(".gs.zst"):
        try:
            import zstandard as zstd
        except ImportError:
            sys.exit("ERROR: .gs.zst requires `pip install zstandard`. "
                     "Or convert via PCSX2 to .gs.xz first.")
        dctx = zstd.ZstdDecompressor()
        with open(path, "rb") as f:
            return dctx.decompress(f.read())
    return path.read_bytes()


# =========================================================
# Bitfield decoders
# =========================================================

def _dispfb_decode(qword: int) -> dict:
    return {
        "fbp": qword & 0x1FF,
        "fbw": (qword >> 9) & 0x3F,
        "psm": (qword >> 15) & 0x1F,
        "dbx": (qword >> 32) & 0x7FF,
        "dby": (qword >> 43) & 0x7FF,
    }


def _frame_decode(qword: int) -> dict:
    return {
        "fbp": qword & 0x1FF,
        "fbw": (qword >> 16) & 0x3F,
        "psm": (qword >> 24) & 0x3F,
        "fbmsk": (qword >> 32) & 0xFFFFFFFF,
    }


def _zbuf_decode(qword: int) -> dict:
    return {
        "zbp": qword & 0x1FF,
        "psm": (qword >> 24) & 0xF,
        "zmsk": (qword >> 32) & 1,
    }


def _tex0_decode(qword: int) -> dict:
    return {
        "tbp": qword & 0x3FFF,
        "tbw": (qword >> 14) & 0x3F,
        "psm": (qword >> 20) & 0x3F,
        "tw":  (qword >> 26) & 0xF,
        "th":  (qword >> 30) & 0xF,
        "tcc": (qword >> 34) & 1,
        "tfx": (qword >> 35) & 3,
        "cbp": (qword >> 37) & 0x3FFF,
        "cpsm": (qword >> 51) & 0xF,
    }


def _bitbltbuf_decode(qword: int) -> dict:
    return {
        "sbp": qword & 0x3FFF, "sbw": (qword >> 16) & 0x3F, "spsm": (qword >> 24) & 0x3F,
        "dbp": (qword >> 32) & 0x3FFF, "dbw": (qword >> 48) & 0x3F, "dpsm": (qword >> 56) & 0x3F,
    }


# =========================================================
# Parser state
# =========================================================

class Cursor:
    __slots__ = ("buf", "pos")
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def remain(self) -> int:
        return len(self.buf) - self.pos

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise EOFError(f"need {n} bytes, have {self.remain()} (pos={self.pos})")
        d = self.buf[self.pos:self.pos + n]
        self.pos += n
        return d

    def u8(self) -> int:  return self.take(1)[0]
    def u32(self) -> int: return struct.unpack("<I", self.take(4))[0]
    def u64(self) -> int: return struct.unpack("<Q", self.take(8))[0]


def _parse_priv_reg_block(blob: bytes) -> dict:
    """Decode the relevant fields of a GSPrivRegSet (0x2000 bytes)."""
    if len(blob) < GSPRIV_SIZE:
        return {"_truncated": True}
    def u64(off: int) -> int:
        return struct.unpack_from("<Q", blob, off)[0]
    return {
        "PMODE":    f"0x{u64(PRIV_PMODE):016X}",
        "DISPFB1":  _dispfb_decode(u64(PRIV_DISPFB1)),
        "DISPLAY1": f"0x{u64(PRIV_DISPLAY1):016X}",
        "DISPFB2":  _dispfb_decode(u64(PRIV_DISPFB2)),
        "DISPLAY2": f"0x{u64(PRIV_DISPLAY2):016X}",
        "BGCOLOR":  f"0x{u64(PRIV_BGCOLOR):016X}",
        "CSR":      f"0x{u64(PRIV_CSR):016X}",
        "IMR":      f"0x{u64(PRIV_IMR):016X}",
        "BUSDIR":   f"0x{u64(PRIV_BUSDIR):016X}",
        "SIGLBLID": f"0x{u64(PRIV_SIGLBLID):016X}",
    }


# =========================================================
# GIF packet walker
# =========================================================

class GifStats:
    def __init__(self):
        self.flg_counts = {"PACKED": 0, "REGLIST": 0, "IMAGE": 0, "IMAGE2": 0}
        self.a_d_regs_written: set[int] = set()
        self.psm_tex0: set[int] = set()
        self.psm_frame: set[int] = set()
        self.psm_zbuf: set[int] = set()
        self.tex0_tbps: set[int] = set()
        self.vram_upload_tbps: set[int] = set()
        # F32 retro: BITBLTBUF destination-PSM witnesses. PSMT4HH (0x2C) /
        # PSMT4HL (0x24) / PSMT8H (0x1B) appearing here = upload-side
        # Z-buffer-alias writes, distinct from sampler-side TEX0.psm.
        self.bitbltbuf_dpsms: set[int] = set()
        self.bitbltbuf_spsms: set[int] = set()
        self.prim_history: list[int] = []
        self.prim_distinct: set[int] = set()
        self.last_frame: dict | None = None
        self.last_zbuf: dict | None = None
        self.last_bitbltbuf: dict | None = None
        self.giftag_count = 0
        self.malformed_tags = 0

    def to_dict(self) -> dict:
        return {
            "giftag_count": self.giftag_count,
            "malformed_tags": self.malformed_tags,
            "gif_flg_counts": self.flg_counts,
            "a_d_regs_written": sorted(self.a_d_regs_written),
            "a_d_regs_written_named": sorted(
                {GIF_A_D_REG_NAMES.get(r, f"REG_{r:02X}") for r in self.a_d_regs_written}
            ),
            "psm_seen_tex0": sorted(self.psm_tex0),
            "psm_seen_frame": sorted(self.psm_frame),
            "psm_seen_zbuf": sorted(self.psm_zbuf),
            "tex0_tbps_used": sorted(self.tex0_tbps),
            "vram_upload_tbps": sorted(self.vram_upload_tbps),
            "bitbltbuf_dpsms_used": sorted(self.bitbltbuf_dpsms),
            "bitbltbuf_spsms_used": sorted(self.bitbltbuf_spsms),
            "prim_distinct_count": len(self.prim_distinct),
            "prim_distinct_values": [f"0x{p:04X}" for p in sorted(self.prim_distinct)],
            "frame_final": self.last_frame,
            "zbuf_final": self.last_zbuf,
            "bitbltbuf_last": self.last_bitbltbuf,
        }


def _handle_ad_pair(reg: int, val: int, st: GifStats) -> None:
    st.a_d_regs_written.add(reg)
    if reg == 0x00:  # PRIM
        prim = val & 0x7FF
        st.prim_history.append(prim)
        st.prim_distinct.add(prim)
    elif reg in (0x06, 0x07):  # TEX0_1, TEX0_2
        t = _tex0_decode(val)
        st.psm_tex0.add(t["psm"])
        st.tex0_tbps.add(t["tbp"])
    elif reg in (0x4C, 0x4D):  # FRAME_1, FRAME_2
        f = _frame_decode(val)
        st.psm_frame.add(f["psm"])
        st.last_frame = f
    elif reg in (0x4E, 0x4F):  # ZBUF_1, ZBUF_2
        z = _zbuf_decode(val)
        st.psm_zbuf.add(z["psm"])
        st.last_zbuf = z
    elif reg == 0x50:  # BITBLTBUF
        b = _bitbltbuf_decode(val)
        st.last_bitbltbuf = b
        st.vram_upload_tbps.add(b["dbp"])
        st.bitbltbuf_dpsms.add(b["dpsm"])
        st.bitbltbuf_spsms.add(b["spsm"])


def _walk_gif_packet(buf: bytes, st: GifStats) -> None:
    """Walk a GIF packet stream and accumulate stats into `st`."""
    cur = Cursor(buf)
    while cur.remain() >= 16:
        lo = cur.u64()
        hi = cur.u64()
        st.giftag_count += 1
        nloop = lo & 0x7FFF
        eop   = (lo >> 15) & 1
        pre   = (lo >> 46) & 1
        prim  = (lo >> 47) & 0x7FF
        flg   = (lo >> 58) & 3
        nreg  = (lo >> 60) & 0xF
        if nreg == 0:
            nreg = 16
        if pre and 0 not in st.prim_distinct:
            st.prim_distinct.add(prim)
            st.prim_history.append(prim)
        flg_name = GIF_FLG_NAMES[flg]
        st.flg_counts[flg_name] += 1

        if flg == 0:  # PACKED — nloop * nreg quadwords
            payload_qws = nloop * nreg
            for q in range(payload_qws):
                if cur.remain() < 16:
                    st.malformed_tags += 1
                    return
                qlo = cur.u64()
                qhi = cur.u64()
                reg_idx = q % nreg
                regdesc = (hi >> (reg_idx * 4)) & 0xF
                if regdesc == 0x0E:  # A+D
                    reg = qhi & 0xFF
                    _handle_ad_pair(reg, qlo, st)
                # Other regdescs encode specific reg types but with their own
                # layouts (PRIM/RGBAQ/ST/UV/XYZ etc.); we don't need them for
                # the bullseye summary.
        elif flg == 1:  # REGLIST — ceil(nreg*nloop/2) quadwords (two regs per qw)
            total_regs = nreg * nloop
            qws = (total_regs + 1) // 2
            need = qws * 16
            if cur.remain() < need:
                st.malformed_tags += 1
                return
            cur.take(need)
        elif flg in (2, 3):  # IMAGE / IMAGE2 — nloop qwords raw image data
            need = nloop * 16
            if cur.remain() < need:
                st.malformed_tags += 1
                return
            cur.take(need)


# =========================================================
# Top-level parser
# =========================================================

def parse_dump(path: Path) -> dict:
    blob = _read_dump_bytes(path)
    cur = Cursor(blob)

    magic = cur.u32()
    if magic != GS_DUMP_MAGIC:
        # Old-format dump (no magic, no GSDumpHeader). Bail with a hint.
        sys.exit(f"ERROR: {path} does not start with 0xFFFFFFFF magic "
                 "(pre-2020 PCSX2 dump format unsupported).")

    header_size = cur.u32()
    if header_size < 36:
        sys.exit(f"ERROR: header_size={header_size} too small to be a GSDumpHeader.")

    # GSDumpHeader: 9 u32 fields = 36 bytes
    hdr_fields = struct.unpack("<9I", cur.take(36))
    (state_version, state_size, serial_offset, serial_size, crc,
     screenshot_w, screenshot_h, screenshot_off, screenshot_sz) = hdr_fields

    # The header_size INCLUDES the GSDumpHeader + serial + screenshot.
    remaining_in_header = header_size - 36
    if remaining_in_header < serial_size + screenshot_sz:
        # Defensive: don't trust header_size blindly; advance by computed size instead.
        pass
    serial_bytes = cur.take(serial_size) if serial_size else b""
    serial = serial_bytes.decode("ascii", errors="replace").strip()
    # Skip screenshot
    if screenshot_sz:
        cur.take(screenshot_sz)

    # Freeze data (GS state)
    if state_size > cur.remain():
        sys.exit(f"ERROR: state_size={state_size} > remaining bytes {cur.remain()}.")
    _freeze_data = cur.take(state_size)

    # Initial GSPrivRegSet
    init_priv_regs = cur.take(GSPRIV_SIZE)
    init_priv = _parse_priv_reg_block(init_priv_regs)

    # Walk packet stream
    transfers = {"PATH1": {"count": 0, "total_bytes": 0},
                 "PATH2": {"count": 0, "total_bytes": 0},
                 "PATH3": {"count": 0, "total_bytes": 0}}
    vsyncs = 0
    readfifo2_calls = 0
    readfifo2_bytes = 0
    gif_stats = GifStats()
    priv_snapshots: list[dict] = []

    packet_count = 0
    while cur.remain() > 0:
        try:
            pid = cur.u8()
        except EOFError:
            break
        packet_count += 1
        if pid == 0:
            # Transfer
            if cur.remain() < 5:
                break
            path_idx = cur.u8()
            size = cur.u32()
            if size > cur.remain():
                break
            data = cur.take(size)
            name = GIF_PATH_NAMES.get(path_idx, f"PATH{path_idx}")
            if name not in transfers:
                transfers[name] = {"count": 0, "total_bytes": 0}
            transfers[name]["count"] += 1
            transfers[name]["total_bytes"] += size
            _walk_gif_packet(data, gif_stats)
        elif pid == 1:
            # VSync
            if cur.remain() < 1:
                break
            _field = cur.u8()
            vsyncs += 1
        elif pid == 2:
            # ReadFIFO2 — size only (no data follows per header spec)
            if cur.remain() < 4:
                break
            sz = cur.u32()
            readfifo2_calls += 1
            readfifo2_bytes += sz
        elif pid == 3:
            # Regs snapshot
            if cur.remain() < GSPRIV_SIZE:
                break
            regs = cur.take(GSPRIV_SIZE)
            priv_snapshots.append(_parse_priv_reg_block(regs))
        else:
            # Unknown packet id — abort to avoid resync hazards
            break

    # Build summary
    summary = {
        "source_file": str(path),
        "serial": serial,
        "crc": f"0x{crc:08X}",
        "state_version": state_version,
        "state_size_bytes": state_size,
        "screenshot": {"width": screenshot_w, "height": screenshot_h},
        "transfers": transfers,
        "vsyncs": vsyncs,
        "readfifo2_calls": readfifo2_calls,
        "readfifo2_bytes": readfifo2_bytes,
        "priv_regs_initial": init_priv,
        "priv_regs_snapshots_count": len(priv_snapshots),
        "priv_regs_final": priv_snapshots[-1] if priv_snapshots else init_priv,
        "gif": gif_stats.to_dict(),
    }

    # Enricher-facing flat fields (the high-signal ones)
    final_priv = summary["priv_regs_final"] if not summary["priv_regs_final"].get("_truncated") else None
    summary["summary_for_enricher"] = _build_enricher_flat(summary, final_priv)
    return summary


def _build_enricher_flat(s: dict, final_priv: dict | None) -> dict:
    gif = s["gif"]
    psm_tex0 = set(gif["psm_seen_tex0"])
    bitbltbuf_dpsms = set(gif.get("bitbltbuf_dpsms_used", []))
    transfers = s["transfers"]
    path3_active = transfers.get("PATH3", {}).get("count", 0) > 0
    path1_active = transfers.get("PATH1", {}).get("count", 0) > 0
    path2_active = transfers.get("PATH2", {}).get("count", 0) > 0
    # Sampler-side witness (TEX0.psm)
    psmt4hh_used = 44 in psm_tex0
    psmt4hl_used = 36 in psm_tex0
    psmt8h_used  = 27 in psm_tex0
    # F32 retro: upload-side witness (BITBLTBUF.dpsm). Same PSM constants,
    # different significance — these are the destination format of host->local
    # uploads. F32 break point: dpsm=0x2C (PSMT4HH) upload not parsed correctly.
    psmt4hh_upload = 44 in bitbltbuf_dpsms
    psmt4hl_upload = 36 in bitbltbuf_dpsms
    psmt8h_upload  = 27 in bitbltbuf_dpsms
    prim_garbage = (gif["prim_distinct_count"] > 32 or
                    any(int(p, 16) > 0x7FF for p in gif["prim_distinct_values"]))
    flat = {
        "path1_active": path1_active,
        "path2_active": path2_active,
        "path3_active": path3_active,
        "psmt4hh_used": psmt4hh_used,
        "psmt4hl_used": psmt4hl_used,
        "psmt8h_used":  psmt8h_used,
        "psmt4hh_upload": psmt4hh_upload,
        "psmt4hl_upload": psmt4hl_upload,
        "psmt8h_upload":  psmt8h_upload,
        "z_alias_used": psmt4hh_used or psmt4hl_used or psmt8h_used or
                        psmt4hh_upload or psmt4hl_upload or psmt8h_upload,
        "prim_garbage_detected": prim_garbage,
        "psm_seen_tex0":  gif["psm_seen_tex0"],
        "psm_seen_frame": gif["psm_seen_frame"],
        "psm_seen_zbuf":  gif["psm_seen_zbuf"],
        "bitbltbuf_dpsms_used": sorted(bitbltbuf_dpsms),
        "gif_flg_counts": gif["gif_flg_counts"],
        "a_d_regs_written_named": gif["a_d_regs_written_named"],
        "tex0_tbps_used": gif["tex0_tbps_used"],
        "vram_upload_tbps": gif["vram_upload_tbps"],
        "frame_final": gif["frame_final"],
        "zbuf_final":  gif["zbuf_final"],
    }
    if final_priv:
        flat["dispfb1"] = final_priv.get("DISPFB1")
        flat["dispfb2"] = final_priv.get("DISPFB2")
        flat["pmode"]   = final_priv.get("PMODE")
        flat["csr"]     = final_priv.get("CSR")
    return flat


# =========================================================
# CLI
# =========================================================

def main() -> int:
    p = argparse.ArgumentParser(description="PCSX2 GS dump -> enricher summary JSON.")
    p.add_argument("dump", help="Path to .gs / .gs.xz / .gs.zst file")
    p.add_argument("--checkpoint", default="generic",
                   help="Label for this capture (sce_logo / title_screen / 3d_scene / menu_main / generic)")
    p.add_argument("--out", help="Output JSON path (default: <dump>.summary.json next to source)")
    args = p.parse_args()

    src = Path(args.dump)
    if not src.exists():
        sys.exit(f"ERROR: {src} not found.")

    print(f"Parsing: {src}  ({src.stat().st_size:,} bytes)")
    summary = parse_dump(src)
    summary["checkpoint"] = args.checkpoint

    out = Path(args.out) if args.out else src.with_suffix(src.suffix + ".summary.json")
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    g = summary["gif"]
    e = summary["summary_for_enricher"]
    print(f"\n[OK] Wrote {out}")
    print(f"  checkpoint={args.checkpoint}  serial={summary['serial']}  crc={summary['crc']}")
    print(f"  transfers: PATH1={summary['transfers']['PATH1']['count']} "
          f"PATH2={summary['transfers']['PATH2']['count']} "
          f"PATH3={summary['transfers']['PATH3']['count']}")
    print(f"  giftags={g['giftag_count']} (malformed={g['malformed_tags']})  vsyncs={summary['vsyncs']}")
    print(f"  PSM seen (TEX0)  : {g['psm_seen_tex0']}")
    print(f"  PSM seen (FRAME) : {g['psm_seen_frame']}")
    print(f"  PSM seen (ZBUF)  : {g['psm_seen_zbuf']}")
    print(f"  A+D regs written : {', '.join(g['a_d_regs_written_named'][:12])}"
          f"{' ...' if len(g['a_d_regs_written_named']) > 12 else ''}")
    print(f"  PRIM distinct    : {g['prim_distinct_count']}")
    print(f"  TEX0 TBPs used   : {g['tex0_tbps_used'][:10]}"
          f"{' ...' if len(g['tex0_tbps_used']) > 10 else ''}")
    if g["frame_final"]:
        print(f"  FRAME final      : {g['frame_final']}")
    if g["zbuf_final"]:
        print(f"  ZBUF final       : {g['zbuf_final']}")
    if "dispfb1" in e and e["dispfb1"]:
        print(f"  DISPFB1          : {e['dispfb1']}")
        print(f"  DISPFB2          : {e['dispfb2']}")
    print(f"\n  >>> Bullseye flags:")
    print(f"      PSMT4HH used (4HH font alias) : {e['psmt4hh_used']}")
    print(f"      Path3 active                  : {e['path3_active']}")
    print(f"      PRIM garbage detected         : {e['prim_garbage_detected']}")
    print(f"      Z-buffer alias used (any)     : {e['z_alias_used']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
