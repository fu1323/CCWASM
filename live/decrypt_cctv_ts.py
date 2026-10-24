#!/usr/bin/env python3
"""Decrypt the CCTV H.264 mode-1 TS format verified in this investigation.

Python 3.9+; the decryption itself uses only the standard library.
FFmpeg is needed only for --verify / --mp4. See CCTV_WASM_Analysis.md.

Scope: 188-byte MPEG-TS, H.264 mode 1, one complete access unit per video PES.
Do not apply this transform twice. It is not a general DRM or HLS decryptor.
"""

import argparse
from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
from typing import Optional

PACKET_SIZE = 188
MASK32 = 0xFFFFFFFF
DELTA = 0x9E3779B9
ROUNDS = 16
START_CODE = re.compile(rb"\x00\x00\x00\x01|\x00\x00\x01")
OUTER_ESCAPE = re.compile(rb"\x00\x00\x03(?=[\x00-\x03])")


class FormatError(ValueError):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def packet_pid(packet):
    return ((packet[1] & 31) << 8) | packet[2]


def payload_start(packet):
    """Return the payload offset, or None for adaptation-only packets."""
    control = (packet[3] >> 4) & 3
    if control == 0:
        raise FormatError("Reserved adaptation_field_control=0")
    if control & 2:
        end = 5 + packet[4]
        if end > PACKET_SIZE:
            raise FormatError("Adaptation field extends beyond TS packet")
    else:
        end = 4
    if not control & 1:
        return None
    if end >= PACKET_SIZE:
        raise FormatError("TS header claims payload but leaves no payload bytes")
    return end


def split_packets(data):
    if not data or len(data) % PACKET_SIZE:
        raise FormatError("Input must be a nonempty sequence of 188-byte TS packets")
    packets = []
    for offset in range(0, len(data), PACKET_SIZE):
        packet = bytearray(data[offset:offset + PACKET_SIZE])
        if packet[0] != 0x47:
            raise FormatError("Missing TS sync byte at offset %d" % offset)
        if packet[1] & 0x80:
            raise FormatError("TS transport_error_indicator at packet %d" % (offset // 188))
        payload_start(packet)
        packets.append(packet)
    return packets


def psi_sections(packets, pid):
    """Assemble PSI sections, including pointer fields and multi-packet sections."""
    buffer = bytearray()

    def consume():
        result = []
        while buffer:
            if buffer[0] == 0xFF:
                buffer.clear()
                break
            if len(buffer) < 3:
                break
            length = 3 + (((buffer[1] & 15) << 8) | buffer[2])
            if length < 7 or length > 1024:
                raise FormatError("Invalid PSI section length on PID %d" % pid)
            if len(buffer) < length:
                break
            result.append(bytes(buffer[:length]))
            del buffer[:length]
        return result

    for packet in packets:
        if packet_pid(packet) != pid:
            continue
        offset = payload_start(packet)
        if offset is None:
            continue
        payload = packet[offset:]
        if packet[1] & 0x40:
            pointer = payload[0]
            if 1 + pointer > len(payload):
                raise FormatError("Invalid PSI pointer field")
            if buffer:
                buffer.extend(payload[1:1 + pointer])
                yield from consume()
                if buffer:
                    raise FormatError("Incomplete PSI section before new section")
            buffer.clear()
            buffer.extend(payload[1 + pointer:])
        elif buffer:
            buffer.extend(payload)
        yield from consume()


def find_h264_pid(packets):
    pmt_pids = set()
    for section in psi_sections(packets, 0):
        if section[0] != 0 or not section[5] & 1:
            continue
        for offset in range(8, len(section) - 4, 4):
            if offset + 4 > len(section) - 4:
                raise FormatError("Truncated PAT entry")
            program = int.from_bytes(section[offset:offset + 2], "big")
            if program:
                pmt_pids.add(((section[offset + 2] & 31) << 8) | section[offset + 3])
    video_pids = set()
    for pmt_pid in sorted(pmt_pids):
        for section in psi_sections(packets, pmt_pid):
            if section[0] != 2 or len(section) < 16 or not section[5] & 1:
                continue
            offset = 12 + (((section[10] & 15) << 8) | section[11])
            while offset + 5 <= len(section) - 4:
                stream_type = section[offset]
                pid = ((section[offset + 1] & 31) << 8) | section[offset + 2]
                info_len = ((section[offset + 3] & 15) << 8) | section[offset + 4]
                if offset + 5 + info_len > len(section) - 4:
                    raise FormatError("Truncated PMT stream descriptor")
                if stream_type == 0x1B:
                    video_pids.add(pid)
                offset += 5 + info_len
    if len(video_pids) != 1:
        raise FormatError("Expected one H.264 PID, found %r; use --video-pid if needed" % sorted(video_pids))
    return video_pids.pop()


def tea16_decrypt(block, key):
    """One independent 64-bit TEA block, 16 cycles, little-endian words."""
    left, right = struct.unpack("<2I", block)
    total = (DELTA * ROUNDS) & MASK32
    for _ in range(ROUNDS):
        right = (right - (((left << 4) + key[2]) ^
                          (left + total) ^ ((left >> 5) + key[3]))) & MASK32
        left = (left - (((right << 4) + key[0]) ^
                        (right + total) ^ ((right >> 5) + key[1]))) & MASK32
        total = (total - DELTA) & MASK32
    return struct.pack("<2I", left, right)


@dataclass
class VideoState:
    mode: Optional[int] = None
    nals: Counter = field(default_factory=Counter)
    decrypted_slices: int = 0
    tea_blocks: int = 0
    outer_escape_bytes_removed: int = 0


def decrypt_nal(nal, state):
    """Return the final player-equivalent NAL, without the temporary name XOR."""
    if not nal:
        raise FormatError("Empty NAL")
    nal_type = nal[0] & 31
    state.nals[nal_type] += 1
    if nal_type == 7:
        if len(nal) < 4:
            raise FormatError("Truncated SPS")
        state.mode = nal[2] & 3
        if state.mode != 1:
            raise FormatError("Unsupported SPS encryption mode %d; only mode 1 was verified" % state.mode)
        return nal
    if nal_type not in (1, 5) or len(nal) < 129:
        return nal
    if state.mode != 1:
        raise FormatError("Slice precedes a mode-1 SPS; use --assume-mode1 only with a known mode-1 stream")
    # Remove the encryption layer's prevention bytes once. The recovered bytes
    # already contain the original encoded video syntax; do not escape again.
    data = bytearray(OUTER_ESCAPE.sub(b"\x00\x00", nal))
    state.outer_escape_bytes_removed += len(nal) - len(data)
    if len(data) < 40:
        raise FormatError("Slice became too short after outer unescaping")
    key = struct.unpack("<4I", data[16:32])
    for offset in range(32, len(data) - 7, 80):
        data[offset:offset + 8] = tea16_decrypt(data[offset:offset + 8], key)
        state.tea_blocks += 1
    state.decrypted_slices += 1
    # WASM applies a name-derived middle XOR. The downstream JS applies it
    # again. Those two operations cancel in the complete player pipeline.
    return bytes(data)


def decrypt_access_unit(es, state):
    starts = list(START_CODE.finditer(es))
    if not starts or any(es[:starts[0].start()]):
        raise FormatError("PES payload does not start with Annex B video")
    if starts[0].end() >= len(es) or (es[starts[0].end()] & 31) != 9:
        raise FormatError("This tool expects each video PES to begin with an AUD (NAL type 9)")
    output = bytearray(es[:starts[0].start()])
    aud_count = 0
    for index, start in enumerate(starts):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(es)
        raw = es[start.end():end]
        nal = raw.rstrip(b"\x00")
        if nal and (nal[0] & 31) == 9:
            aud_count += 1
        output.extend(start.group())
        output.extend(decrypt_nal(nal, state))
        # Preserve Annex B trailing_zero_8bits / original trailing zero words.
        output.extend(raw[len(nal):])
    if aud_count != 1:
        raise FormatError("Expected one complete access unit per video PES")
    return bytes(output)


def video_pes_groups(packets, video_pid):
    groups = []
    expected_cc = None
    for index, packet in enumerate(packets):
        if packet_pid(packet) != video_pid:
            continue
        if packet[3] & 0xC0:
            raise FormatError("Transport-scrambled video is outside this tool's scope")
        if packet[3] & 32 and packet[4] and packet[5] & 0x80:
            expected_cc = None
        offset = payload_start(packet)
        if offset is None:
            continue
        cc = packet[3] & 15
        if expected_cc is not None and cc != expected_cc:
            raise FormatError("Video continuity counter gap at packet %d" % index)
        expected_cc = (cc + 1) & 15
        if packet[1] & 0x40:
            groups.append([])
        if not groups:
            raise FormatError("Input starts in the middle of a video PES")
        groups[-1].append(index)
    if not groups:
        raise FormatError("No video PES found on PID %d" % video_pid)
    return groups


def write_pes_to_original_slots(packets, indices, data):
    """Keep packet positions and old adaptation data, expanding stuffing."""
    cursor = 0
    for index in indices:
        packet = packets[index]
        offset = payload_start(packet)
        take = min(188 - offset, len(data) - cursor)
        if take == 188 - offset:
            packet[offset:] = data[cursor:cursor + take]
        else:
            adaptation_length = 183 - take
            old_adaptation = bytes(packet[5:offset]) if packet[3] & 32 else b""
            adaptation = (old_adaptation or b"\x00") if adaptation_length else b""
            adaptation += b"\xff" * (adaptation_length - len(adaptation))
            header = bytearray(packet[:4])
            header[3] = (header[3] & 0xCF) | (0x30 if take else 0x20)
            if not take:
                header[1] &= ~0x40
            packet = header + bytes([adaptation_length]) + adaptation + data[cursor:cursor + take]
        if len(packet) != 188:
            raise FormatError("Internal TS repacketization length error")
        packets[index] = bytearray(packet)
        cursor += take
    if cursor != len(data):
        raise FormatError("Decrypted PES does not fit original packet slots")


def normalize_video_cc(packets, video_pid):
    next_cc = None
    for packet in packets:
        if packet_pid(packet) != video_pid:
            continue
        if next_cc is None or (packet[3] & 32 and packet[4] and packet[5] & 0x80):
            next_cc = packet[3] & 15
        if payload_start(packet) is not None:
            packet[3] = (packet[3] & 0xF0) | next_cc
            next_cc = (next_cc + 1) & 15
        else:
            packet[3] = (packet[3] & 0xF0) | ((next_cc - 1) & 15)


def decrypt_ts(data, video_pid=None, assume_mode1=False):
    packets = split_packets(data)
    if video_pid is None:
        video_pid = find_h264_pid(packets)
    groups = video_pes_groups(packets, video_pid)
    state = VideoState(mode=1 if assume_mode1 else None)
    for indices in groups:
        pes = b"".join(bytes(packets[i][payload_start(packets[i]):]) for i in indices)
        if len(pes) < 9 or pes[:3] != b"\x00\x00\x01" or not 0xE0 <= pes[3] <= 0xEF:
            raise FormatError("Unexpected video PES header")
        if pes[6] & 0xC0 != 0x80:
            raise FormatError("Only MPEG-2 style PES headers are supported")
        header_length = 9 + pes[8]
        if header_length >= len(pes):
            raise FormatError("Truncated PES header or empty video access unit")
        declared_size = int.from_bytes(pes[4:6], "big")
        if declared_size and len(pes) != declared_size + 6:
            raise FormatError("PES size disagrees with assembled TS payload")
        body = decrypt_access_unit(pes[header_length:], state)
        header = bytearray(pes[:header_length])
        if declared_size:
            new_size = header_length + len(body) - 6
            if new_size > 65535:
                raise FormatError("PES length overflow")
            header[4:6] = new_size.to_bytes(2, "big")
        write_pes_to_original_slots(packets, indices, bytes(header) + body)
    if not state.decrypted_slices:
        raise FormatError("No mode-1 encrypted slices were processed")
    normalize_video_cc(packets, video_pid)
    result = b"".join(packets)
    return result, {
        "input_sha256": sha256(data), "output_ts_sha256": sha256(result),
        "input_bytes": len(data), "output_ts_bytes": len(result),
        "ts_packets": len(packets), "video_pid": video_pid,
        "video_pes": len(groups), "mode": state.mode,
        "nal_counts": {str(k): v for k, v in sorted(state.nals.items())},
        "decrypted_slices": state.decrypted_slices, "tea_blocks": state.tea_blocks,
        "outer_escape_bytes_removed": state.outer_escape_bytes_removed,
    }


def run_ffmpeg(arguments):
    binary = shutil.which("ffmpeg")
    if not binary:
        raise FormatError("FFmpeg was not found in PATH; omit --verify/--mp4 or install it")
    result = subprocess.run([binary] + arguments, capture_output=True, text=True)
    if result.returncode or result.stderr.strip():
        raise FormatError("FFmpeg did not complete cleanly:\n" + result.stderr.strip())


def verify_media(path):
    run_ffmpeg(["-v", "error", "-xerror", "-err_detect", "explode", "-i", str(path),
                "-map", "0:v:0", "-map", "0:a?", "-f", "null", "-"])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="Original encrypted .ts or .bin")
    parser.add_argument("output", type=Path, help="Output decrypted TS")
    parser.add_argument("--video-pid", type=lambda s: int(s, 0), help="Override PAT/PMT H.264 PID detection")
    parser.add_argument("--assume-mode1", action="store_true", help="Allow a known mode-1 segment without an initial SPS")
    parser.add_argument("--verify", action="store_true", help="Decode all output media using FFmpeg and fail on errors")
    parser.add_argument("--mp4", type=Path, help="Also remux decrypted TS into MP4, without re-encoding")
    parser.add_argument("--report", type=Path, help="Write JSON statistics and verification status")
    args = parser.parse_args()
    try:
        paths = [args.input, args.output] + [p for p in (args.mp4, args.report) if p is not None]
        if len({p.resolve() for p in paths}) != len(paths):
            raise FormatError("Input, TS, MP4 and report paths must be different")
        if args.video_pid is not None and not 0 <= args.video_pid < 8191:
            raise FormatError("Video PID must be between 0 and 8190")
        plain, report = decrypt_ts(args.input.read_bytes(), args.video_pid, args.assume_mode1)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(plain)
        report["verification"] = "not_requested"
        if args.verify:
            verify_media(args.output)
            report["verification"] = "ffmpeg_full_decode_clean"
        if args.mp4:
            args.mp4.parent.mkdir(parents=True, exist_ok=True)
            run_ffmpeg(["-y", "-v", "error", "-i", str(args.output), "-map", "0:v:0",
                        "-map", "0:a?", "-c", "copy", "-movflags", "+faststart", str(args.mp4)])
            report["output_mp4_sha256"] = sha256(args.mp4.read_bytes())
            if args.verify:
                verify_media(args.mp4)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    except (OSError, FormatError, struct.error) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
