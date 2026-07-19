"""
Static Analysis (PRD Section 7.3). No sandbox required — pure file
parsing, safe to run on Render.
"""
import hashlib
import math
import os
from collections import Counter

import pefile
import yara

YARA_RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "yara_rules")


def hash_file(path: str) -> dict:
    sha256, sha1, md5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "sha1": sha1.hexdigest(), "md5": md5.hexdigest()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def analyze_pe(path: str) -> dict:
    """Returns a dict matching the StaticAnalysis model fields."""
    result = {
        "pe_header": {},
        "imports": [],
        "exports": [],
        "sections": [],
        "entropy": 0.0,
        "is_signed": False,
        "signature_info": {},
        "strings_sample": [],
        "yara_matches": [],
        "is_packed": False,
        "packer_signature": None,
    }

    with open(path, "rb") as f:
        raw = f.read()
    result["entropy"] = round(shannon_entropy(raw), 3)

    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])

        result["pe_header"] = {
            "machine": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        }

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors="ignore")
                funcs = [imp.name.decode(errors="ignore") for imp in entry.imports if imp.name]
                result["imports"].append({"dll": dll, "functions": funcs})

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result["exports"].append(exp.name.decode(errors="ignore"))

        max_section_entropy = 0.0
        for section in pe.sections:
            sec_entropy = section.get_entropy()
            max_section_entropy = max(max_section_entropy, sec_entropy)
            result["sections"].append({
                "name": section.Name.decode(errors="ignore").strip("\x00"),
                "entropy": round(sec_entropy, 3),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
            })

        # Simple packing heuristic: any section with entropy > 7.2 is a strong signal
        if max_section_entropy > 7.2:
            result["is_packed"] = True

        result["is_signed"] = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size
        )

        pe.close()
    except pefile.PEFormatError:
        result["pe_header"] = {"error": "Not a valid PE file or parsing failed"}

    # Extract printable strings (basic ASCII scan, capped for storage)
    result["strings_sample"] = _extract_strings(raw, min_len=6)[:200]

    # YARA scan, if rules exist
    result["yara_matches"] = _run_yara(path)
    for match in result["yara_matches"]:
        if "packer" in [t.lower() for t in match.get("tags", [])]:
            result["is_packed"] = True
            result["packer_signature"] = match["rule"]

    return result


def _extract_strings(data: bytes, min_len: int = 6) -> list[str]:
    strings = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_len:
                strings.append(current.decode(errors="ignore"))
            current = bytearray()
    if len(current) >= min_len:
        strings.append(current.decode(errors="ignore"))
    return strings


def _run_yara(path: str) -> list[dict]:
    if not os.path.isdir(YARA_RULES_DIR):
        return []
    rule_files = [f for f in os.listdir(YARA_RULES_DIR) if f.endswith((".yar", ".yara"))]
    if not rule_files:
        return []

    matches_out = []
    try:
        filepaths = {os.path.splitext(f)[0]: os.path.join(YARA_RULES_DIR, f) for f in rule_files}
        rules = yara.compile(filepaths=filepaths)
        matches = rules.match(path)
        for m in matches:
            matches_out.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta),
            })
    except yara.Error:
        pass
    return matches_out
