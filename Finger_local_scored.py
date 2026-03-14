# -*- coding: utf-8 -*-
"""
Finger_local - local-only IDA plugin with scored matching for function naming.

Features
- No network access; uses only a local JSON signature database.
- Stores multi-factor signatures instead of a single hash.
- Factors include structure, normalized mnemonic sequence, immediates,
  referenced strings, raw/function chunk hashes, and optional anchors.
- Supports strict or scored matching policies per signature.
- Can add the current function into the local DB using its current name.

Tested target: IDA 9.x / Python 3.
Requires: finger_sdk.ida_func import to remain available only for compatibility with
older environments is NOT required by this plugin.
"""

import os
import re
import json
import math
import hashlib
import traceback

import idaapi
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin as kw
import ida_name
import ida_nalt
import ida_ua
import idautils
import idc


# Compatibility shim for libraries that still call idaapi.get_inf_structure()
if not hasattr(idaapi, "get_inf_structure"):
    class _InfProxy:
        @property
        def procname(self):
            return ida_ida.inf_get_procname()

        @property
        def procName(self):
            return ida_ida.inf_get_procname()

        @property
        def filetype(self):
            return ida_ida.inf_get_filetype()

        @property
        def fileType(self):
            return ida_ida.inf_get_filetype()

        def is_be(self):
            return ida_ida.inf_is_be()

        def isBe(self):
            return ida_ida.inf_is_be()

        def is_64bit(self):
            return ida_ida.inf_is_64bit()

        def is_32bit(self):
            return ida_ida.inf_is_32bit_exactly()

        def is64bit(self):
            return ida_ida.inf_is_64bit()

        def is32bit(self):
            return ida_ida.inf_is_32bit_exactly()

    def get_inf_structure():
        return _InfProxy()

    idaapi.get_inf_structure = get_inf_structure


PLUGIN_NAME = "Finger_local"
DB_FILENAME = "finger_local_db.json"
DB_VERSION = 2
COLOR_MATCHED = 0x98FF98
MAX_STRINGS = 16
MAX_IMMS = 32
WINDOW_SIZE = 32
MAX_WINDOWS = 24
DEFAULT_WEIGHTS = {
    "strict_hash": 100,
    "masked_bytes_hash": 45,
    "mnemonic_norm_hash": 28,
    "func_size": 8,
    "bb_count": 8,
    "call_count": 6,
    "imm_values": 14,
    "string_refs": 18,
    "anchor_strings": 24,
    "anchor_immediates": 18,
    "window_hashes": 16,
}
DEFAULT_THRESHOLDS = {
    "auto_rename": 80,
    "candidate": 55,
}


def _plugin_dir():
    try:
        return os.path.dirname(os.path.abspath(__file__))
    except Exception:
        return os.getcwd()


def _sha256_text(data):
    if isinstance(data, str):
        data = data.encode("utf-8", errors="ignore")
    return hashlib.sha256(data).hexdigest()


def _clean_string(s):
    if not s:
        return ""
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            s = repr(s)
    s = s.replace("\r", " ").replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s[:200]


def _tokenize_string(s):
    s = _clean_string(s).lower()
    if not s:
        return []
    parts = re.split(r"[^a-z0-9_]+", s)
    return [p for p in parts if p]


def _jaccard(a, b):
    sa = set(a or [])
    sb = set(b or [])
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return float(len(sa & sb)) / float(len(sa | sb))


def _ratio_close(a, b):
    if a is None or b is None:
        return 0.0
    if a == b:
        return 1.0
    ma = max(abs(a), abs(b), 1)
    diff = abs(a - b)
    return max(0.0, 1.0 - (float(diff) / float(ma)))


class SignatureExtractor:
    def __init__(self):
        self.inf = idaapi.get_inf_structure()

    def current_arch(self):
        bits = "64" if self.inf.is_64bit() else "32" if self.inf.is_32bit() else "unknown"
        endian = "be" if self.inf.is_be() else "le"
        return "%s-%s-%s" % (self.inf.procname, bits, endian)

    def _flowchart_stats(self, pfn):
        bb_count = 0
        edge_count = 0
        try:
            fc = idaapi.FlowChart(pfn)
            for block in fc:
                bb_count += 1
                succs = 0
                try:
                    for _ in block.succs():
                        succs += 1
                except Exception:
                    pass
                edge_count += succs
        except Exception:
            pass
        return bb_count, edge_count

    def _collect_items(self, pfn):
        for ea in idautils.FuncItems(pfn.start_ea):
            if ida_bytes.is_code(ida_bytes.get_flags(ea)):
                yield ea

    def _get_disasm_tokens(self, ea):
        mnem = idc.print_insn_mnem(ea) or ""
        op_count = ida_ua.ua_mnem(ea)  # not operand count; used only to ensure decoding side effect if any
        _ = op_count
        ops = []
        for n in range(8):
            txt = idc.print_operand(ea, n)
            if not txt:
                break
            ops.append(txt)
        return mnem.lower(), ops

    def _normalize_operand(self, op_text):
        s = (op_text or "").strip().lower()
        if not s:
            return ""
        if "ptr" in s and "[" in s:
            return "MEM"
        if "[" in s and "]" in s:
            return "MEM"
        if re.search(r"^(xmm|ymm|zmm)\d+$", s):
            return "VREG"
        if re.search(r"^(r\d+|e[a-d]x|e[bs]p|e[sd]i|r[a-d]x|r[bs]p|r[sd]i|[abcd][lh]|[abcd]x|[sd]i|[bs]p|[re]ip|[re]flags|cl|dl|sil|dil|bpl|spl)$", s):
            return "REG"
        if re.search(r"^offset\s+", s) or re.match(r"^(loc_|sub_|unk_|off_|qword_|dword_|byte_|word_)", s):
            return "ADDR"
        if re.match(r"^-?(0x[0-9a-f]+|\d+h?|\d+)$", s):
            return "IMM"
        return re.sub(r"\s+", "", s)

    def _normalized_insn(self, ea):
        mnem, ops = self._get_disasm_tokens(ea)
        norm_ops = [self._normalize_operand(x) for x in ops if x]
        return "%s %s" % (mnem, ",".join(norm_ops)) if norm_ops else mnem

    def _raw_function_bytes(self, pfn):
        pieces = []

        try:
            for start_ea, end_ea in idautils.Chunks(pfn.start_ea):
                if start_ea == idaapi.BADADDR or end_ea == idaapi.BADADDR or end_ea <= start_ea:
                    continue

                chunk = ida_bytes.get_bytes(start_ea, end_ea - start_ea) or b""
                if chunk:
                    pieces.append(chunk)
        except Exception:
            pass

        if not pieces:
            size = max(0, pfn.end_ea - pfn.start_ea)
            return ida_bytes.get_bytes(pfn.start_ea, size) or b""

        return b"".join(pieces)

    def _masked_bytes(self, pfn):
        data = bytearray(self._raw_function_bytes(pfn))
        if not data:
            return b""
        base = pfn.start_ea
        for ea in self._collect_items(pfn):
            size = idc.get_item_size(ea)
            if size <= 0:
                continue
            off = ea - base
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if mnem in ("call", "jmp") and size >= 5:
                for i in range(1, min(size, 5)):
                    idx = off + i
                    if 0 <= idx < len(data):
                        data[idx] = 0
            if mnem.startswith("j") and size >= 2:
                for i in range(1, min(size, 6)):
                    idx = off + i
                    if 0 <= idx < len(data):
                        data[idx] = 0
        return bytes(data)

    def _string_refs(self, ea):
        found = []
        seen = set()
        for ref in idautils.DataRefsFrom(ea):
            try:
                for strtype in (idc.STRTYPE_C, idc.STRTYPE_C_16):
                    raw = idc.get_strlit_contents(ref, -1, strtype)
                    if raw:
                        s = _clean_string(raw)
                        if s and s not in seen:
                            seen.add(s)
                            found.append(s)
                            break
            except Exception:
                continue
        return found

    def extract(self, start_ea):
        pfn = idaapi.get_func(start_ea)
        if not pfn:
            return None

        func_size = int(max(0, pfn.end_ea - pfn.start_ea))
        bb_count, edge_count = self._flowchart_stats(pfn)
        strings = []
        string_tokens = set()
        imms = []
        calls = []
        normalized_lines = []
        mnems = []
        call_count = 0
        ret_count = 0

        for ea in self._collect_items(pfn):
            mnem = (idc.print_insn_mnem(ea) or "").lower()
            if not mnem:
                continue
            mnems.append(mnem)
            normalized_lines.append(self._normalized_insn(ea))
            if mnem == "call":
                call_count += 1
                target = idc.get_operand_value(ea, 0)
                nm = ida_name.get_name(target) or idc.print_operand(ea, 0)
                nm = _clean_string(nm)
                if nm:
                    calls.append(nm)
            if mnem.startswith("ret"):
                ret_count += 1

            for opn in range(2):
                optype = idc.get_operand_type(ea, opn)
                if optype in (idc.o_imm,):
                    val = idc.get_operand_value(ea, opn)
                    try:
                        if val is not None:
                            imms.append(int(val) & 0xFFFFFFFFFFFFFFFF)
                    except Exception:
                        pass

            for s in self._string_refs(ea):
                if s not in strings:
                    strings.append(s)
                    for tok in _tokenize_string(s):
                        string_tokens.add(tok)

        raw_bytes = self._raw_function_bytes(pfn)
        masked = self._masked_bytes(pfn)
        norm_blob = "\n".join(normalized_lines)
        windows = []
        if raw_bytes:
            for i in range(0, len(raw_bytes), WINDOW_SIZE):
                chunk = raw_bytes[i:i + WINDOW_SIZE]
                if chunk:
                    windows.append(hashlib.sha1(chunk).hexdigest())
                if len(windows) >= MAX_WINDOWS:
                    break

        strings = strings[:MAX_STRINGS]
        imms = sorted(set(imms))[:MAX_IMMS]
        calls = sorted(set(calls))[:MAX_STRINGS]
        anchor_strings = strings[:6]
        anchor_imms = imms[:8]

        return {
            "func_size": func_size,
            "bb_count": bb_count,
            "edge_count": edge_count,
            "call_count": call_count,
            "ret_count": ret_count,
            "strict_hash": _sha256_text(raw_bytes) if raw_bytes else "",
            "raw_bytes_hash": _sha256_text(raw_bytes) if raw_bytes else "",
            "masked_bytes_hash": _sha256_text(masked) if masked else "",
            "mnemonic_norm_hash": _sha256_text(norm_blob) if norm_blob else "",
            "mnemonic_bag": self._bag(mnems),
            "imm_values": imms,
            "imm_values_hash": _sha256_text(json.dumps(imms, separators=(",", ":"))) if imms else "",
            "string_refs": strings,
            "string_tokens": sorted(string_tokens)[:32],
            "anchor_strings": anchor_strings,
            "anchor_immediates": anchor_imms,
            "window_hashes": windows,
            "api_calls": calls,
        }

    def _bag(self, items):
        bag = {}
        for it in items:
            bag[it] = bag.get(it, 0) + 1
        return bag


class LocalFeatureDB:
    def __init__(self, db_path=None):
        self.db_path = db_path or os.path.join(_plugin_dir(), DB_FILENAME)
        self.data = {"version": DB_VERSION, "functions": []}
        self.load()

    def load(self):
        if not os.path.exists(self.db_path):
            self.data = {"version": DB_VERSION, "functions": []}
            return
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "functions" in data:
                self.data = data
                if "version" not in self.data:
                    self.data["version"] = DB_VERSION
            elif isinstance(data, dict):
                # migrate old key->entry format
                funcs = []
                for _, entry in sorted(data.items()):
                    funcs.append({
                        "name": entry.get("name", ""),
                        "arch": entry.get("arch", ""),
                        "source": entry.get("source", "manual"),
                        "desc": entry.get("desc", ""),
                        "match_policy": "strict",
                        "signature": {
                            "strict_hash": "",
                            "raw_bytes_hash": "",
                            "masked_bytes_hash": "",
                            "mnemonic_norm_hash": "",
                            "func_size": 0,
                            "bb_count": 0,
                            "edge_count": 0,
                            "call_count": 0,
                            "ret_count": 0,
                            "mnemonic_bag": {},
                            "imm_values": [],
                            "imm_values_hash": "",
                            "string_refs": [],
                            "string_tokens": [],
                            "anchor_strings": [],
                            "anchor_immediates": [],
                            "window_hashes": [],
                            "api_calls": [],
                        },
                        "weights": dict(DEFAULT_WEIGHTS),
                        "thresholds": dict(DEFAULT_THRESHOLDS),
                    })
                self.data = {"version": DB_VERSION, "functions": funcs}
            else:
                self.data = {"version": DB_VERSION, "functions": []}
        except Exception:
            print("[-] Failed to load local DB: %s" % self.db_path)
            print(traceback.format_exc())
            self.data = {"version": DB_VERSION, "functions": []}

    def save(self):
        try:
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2, sort_keys=False)
        except Exception:
            print("[-] Failed to save local DB: %s" % self.db_path)
            print(traceback.format_exc())

    def count(self):
        return len(self.data.get("functions", []))

    def iter_functions(self):
        for item in self.data.get("functions", []):
            yield item

    def add_or_update(self, name, arch, signature, desc="", source="manual", match_policy="scored", weights=None, thresholds=None):
        weights = dict(DEFAULT_WEIGHTS if weights is None else weights)
        thresholds = dict(DEFAULT_THRESHOLDS if thresholds is None else thresholds)
        funcs = self.data.setdefault("functions", [])
        for entry in funcs:
            if entry.get("name") == name and entry.get("arch") == arch:
                entry["desc"] = desc
                entry["source"] = source
                entry["match_policy"] = match_policy
                entry["signature"] = signature
                entry["weights"] = weights
                entry["thresholds"] = thresholds
                self.save()
                return "updated"
        funcs.append({
            "name": name,
            "arch": arch,
            "source": source,
            "desc": desc,
            "match_policy": match_policy,
            "signature": signature,
            "weights": weights,
            "thresholds": thresholds,
        })
        self.save()
        return "added"


class Matcher:
    def _score_field_equal(self, a, b, max_score):
        if a and b and a == b:
            return float(max_score)
        return 0.0

    def _score_ratio(self, a, b, max_score):
        return _ratio_close(a, b) * float(max_score)

    def _score_jaccard(self, a, b, max_score):
        return _jaccard(a, b) * float(max_score)

    def _anchor_bonus(self, anchors, observed, per_hit, max_bonus):
        observed_set = set(observed or [])
        bonus = 0.0
        for x in anchors or []:
            if x in observed_set:
                bonus += per_hit
                if bonus >= max_bonus:
                    return float(max_bonus)
        return min(float(max_bonus), bonus)

    def _hard_filter(self, sig_a, sig_b):
        fa = int(sig_a.get("func_size") or 0)
        fb = int(sig_b.get("func_size") or 0)
        if fa and fb:
            ratio = min(float(fa), float(fb)) / max(float(fa), float(fb))
            if ratio < 0.35:
                return False
        bba = int(sig_a.get("bb_count") or 0)
        bbb = int(sig_b.get("bb_count") or 0)
        if bba and bbb and abs(bba - bbb) > max(12, int(max(bba, bbb) * 0.8)):
            return False
        return True

    def match(self, observed_arch, observed_sig, entry):
        entry_arch = entry.get("arch", "")
        if entry_arch and observed_arch and entry_arch != observed_arch:
            return {"matched": False, "score": 0.0, "reason": "arch_mismatch"}

        target = entry.get("signature", {})
        if not self._hard_filter(observed_sig, target):
            return {"matched": False, "score": 0.0, "reason": "hard_filter"}

        policy = entry.get("match_policy", "scored")
        weights = dict(DEFAULT_WEIGHTS)
        weights.update(entry.get("weights") or {})
        thresholds = dict(DEFAULT_THRESHOLDS)
        thresholds.update(entry.get("thresholds") or {})

        if policy == "strict":
            observed = observed_sig.get("strict_hash")
            expected = target.get("strict_hash")
            ok = bool(observed and expected and observed == expected)
            return {
                "matched": ok,
                "score": 100.0 if ok else 0.0,
                "policy": policy,
                "rename": ok,
                "candidate": ok,
                "details": {"strict_hash": 100.0 if ok else 0.0},
            }

        details = {}
        score = 0.0

        if observed_sig.get("strict_hash") and target.get("strict_hash") and observed_sig["strict_hash"] == target["strict_hash"]:
            return {
                "matched": True,
                "score": 100.0,
                "policy": policy,
                "rename": True,
                "candidate": True,
                "details": {"strict_hash": 100.0},
            }

        details["masked_bytes_hash"] = self._score_field_equal(
            observed_sig.get("masked_bytes_hash"), target.get("masked_bytes_hash"), weights.get("masked_bytes_hash", 0)
        )
        details["mnemonic_norm_hash"] = self._score_field_equal(
            observed_sig.get("mnemonic_norm_hash"), target.get("mnemonic_norm_hash"), weights.get("mnemonic_norm_hash", 0)
        )
        details["func_size"] = self._score_ratio(
            observed_sig.get("func_size"), target.get("func_size"), weights.get("func_size", 0)
        )
        details["bb_count"] = self._score_ratio(
            observed_sig.get("bb_count"), target.get("bb_count"), weights.get("bb_count", 0)
        )
        details["call_count"] = self._score_ratio(
            observed_sig.get("call_count"), target.get("call_count"), weights.get("call_count", 0)
        )
        details["imm_values"] = self._score_jaccard(
            observed_sig.get("imm_values"), target.get("imm_values"), weights.get("imm_values", 0)
        )
        details["string_refs"] = self._score_jaccard(
            observed_sig.get("string_tokens") or observed_sig.get("string_refs"),
            target.get("string_tokens") or target.get("string_refs"),
            weights.get("string_refs", 0),
        )
        details["window_hashes"] = self._score_jaccard(
            observed_sig.get("window_hashes"), target.get("window_hashes"), weights.get("window_hashes", 0)
        )
        details["anchor_strings"] = self._anchor_bonus(
            target.get("anchor_strings"),
            (observed_sig.get("string_refs") or []) + (observed_sig.get("string_tokens") or []),
            8,
            weights.get("anchor_strings", 0),
        )
        details["anchor_immediates"] = self._anchor_bonus(
            target.get("anchor_immediates"),
            observed_sig.get("imm_values") or [],
            8,
            weights.get("anchor_immediates", 0),
        )

        score = sum(details.values())
        score = min(score, 100.0)
        return {
            "matched": score >= float(thresholds.get("candidate", DEFAULT_THRESHOLDS["candidate"])),
            "score": score,
            "policy": policy,
            "rename": score >= float(thresholds.get("auto_rename", DEFAULT_THRESHOLDS["auto_rename"])),
            "candidate": score >= float(thresholds.get("candidate", DEFAULT_THRESHOLDS["candidate"])),
            "details": details,
            "thresholds": thresholds,
        }


class FingerLocalManager:
    def __init__(self):
        self.db = LocalFeatureDB()
        self.extractor = SignatureExtractor()
        self.matcher = Matcher()

    def _safe_current_name(self, pfn):
        return idc.get_func_name(pfn.start_ea) or ("sub_%X" % pfn.start_ea)

    def _apply_symbol(self, pfn, new_name, old_name=None):
        current_name = idc.get_func_name(pfn.start_ea) or ""
        if current_name and not current_name.startswith("sub_") and current_name != new_name:
            print("[*] Skip already-renamed function 0x%x: %s" % (pfn.start_ea, current_name))
            return False
        idc.set_color(pfn.start_ea, idc.CIC_FUNC, COLOR_MATCHED)
        idaapi.set_name(pfn.start_ea, new_name, idaapi.SN_FORCE)
        idaapi.update_func(pfn)
        print("[+] Local matched %s -> %s" % (old_name or current_name or hex(pfn.start_ea), new_name))
        return True

    def _best_match(self, start_ea):
        observed = self.extractor.extract(start_ea)
        if not observed:
            return None, None
        arch = self.extractor.current_arch()
        best_entry = None
        best_result = None
        for entry in self.db.iter_functions():
            result = self.matcher.match(arch, observed, entry)
            if not result.get("matched"):
                continue
            if best_result is None or result.get("score", 0.0) > best_result.get("score", 0.0):
                best_entry = entry
                best_result = result
        return best_entry, best_result

    def recognize_function(self, start_ea):
        entry, result = self._best_match(start_ea)
        return entry, result

    def recognize_function_callback(self, ctx):
        ea = kw.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if not pfn:
            print("[-] 0x%x is not a function" % ea)
            return
        old_name = self._safe_current_name(pfn)
        entry, result = self.recognize_function(pfn.start_ea)
        if not entry or not result:
            print("[-] %s local recognize failed" % old_name)
            return
        if result.get("rename"):
            self._apply_symbol(pfn, entry.get("name", ""), old_name)
        else:
            print("[*] Candidate for %s: %s (score=%.2f)" % (old_name, entry.get("name", ""), result.get("score", 0.0)))
            print("    details=%s" % result.get("details", {}))

    def recognize_selected_function(self, funcs):
        for pfn in funcs:
            if not pfn:
                continue
            old_name = self._safe_current_name(pfn)
            entry, result = self.recognize_function(pfn.start_ea)
            if not entry or not result:
                print("[-] %s local recognize failed" % old_name)
                continue
            if result.get("rename"):
                self._apply_symbol(pfn, entry.get("name", ""), old_name)
            else:
                print("[*] Candidate for %s: %s (score=%.2f)" % (old_name, entry.get("name", ""), result.get("score", 0.0)))

    def recognize_functions_callback(self, ctx):
        funcs = [idaapi.get_func(ea) for ea in idautils.Functions()]
        self.recognize_selected_function(funcs)

    def add_current_function_to_local_db(self, ctx):
        ea = kw.get_screen_ea()
        pfn = idaapi.get_func(ea)
        if not pfn:
            print("[-] 0x%x is not a function" % ea)
            return
        func_name = idc.get_func_name(pfn.start_ea)
        if not func_name or func_name.startswith("sub_"):
            print("[-] Please rename the function first, then add it to local DB")
            return
        sig = self.extractor.extract(pfn.start_ea)
        if not sig:
            print("[-] Failed to extract signature at 0x%x" % pfn.start_ea)
            return
        arch = self.extractor.current_arch()
        action = self.db.add_or_update(func_name, arch, sig)
        print("[+] %s local signature: %s" % (action, func_name))
        print("[+] DB path: %s" % self.db.db_path)
        print("[+] Total signatures: %d" % self.db.count())

    def reload_db_callback(self, ctx):
        self.db.load()
        print("[+] Reloaded local DB: %s" % self.db.db_path)
        print("[+] Total signatures: %d" % self.db.count())

    def show_db_info_callback(self, ctx):
        print("[*] Local DB path: %s" % self.db.db_path)
        print("[*] DB version: %s" % self.db.data.get("version"))
        print("[*] Total signatures: %d" % self.db.count())


class FingerLocalUIManager:
    class UIHooks(kw.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup):
            wtype = kw.get_widget_type(widget)
            if wtype == kw.BWN_FUNCS:
                kw.attach_action_to_popup(widget, popup, "FingerLocal:RecognizeSelected", "Finger_local/")
            if wtype == kw.BWN_DISASM:
                kw.attach_action_to_popup(widget, popup, "FingerLocal:RecognizeFunction", "Finger_local/")
                kw.attach_action_to_popup(widget, popup, "FingerLocal:AddToLocalDB", "Finger_local/")

    class ActionHandler(kw.action_handler_t):
        def __init__(self, name, label, shortcut=None, tooltip=None, icon=-1, flags=0):
            super().__init__()
            self.name = name
            self.callback = None
            self.action_desc = kw.action_desc_t(name, label, self, shortcut, tooltip, icon, flags)

        def register_action(self, callback, menupath=None):
            self.callback = callback
            if not kw.register_action(self.action_desc):
                return False
            if menupath and not kw.attach_action_to_menu(menupath, self.name, kw.SETMENU_APP):
                return False
            return True

        def activate(self, ctx):
            try:
                if self.callback:
                    self.callback(ctx)
            except Exception:
                print(traceback.format_exc())
            return 1

        def update(self, ctx):
            return kw.AST_ENABLE_ALWAYS

    def __init__(self, name):
        self.name = name
        self.mgr = FingerLocalManager()
        self.hooks = FingerLocalUIManager.UIHooks()

    def register_actions(self):
        menupath = self.name
        kw.create_menu(menupath, self.name, "Help")
        actions = [
            ("FingerLocal:RecognizeFunctions", "Recognize all functions (local)", self.mgr.recognize_functions_callback),
            ("FingerLocal:RecognizeFunction", "Recognize function (local)", self.mgr.recognize_function_callback),
            ("FingerLocal:AddToLocalDB", "Add function to local DB", self.mgr.add_current_function_to_local_db),
            ("FingerLocal:ReloadDB", "Reload local DB", self.mgr.reload_db_callback),
            ("FingerLocal:DBInfo", "Show local DB info", self.mgr.show_db_info_callback),
        ]
        for name, label, cb in actions:
            action = FingerLocalUIManager.ActionHandler(name, label, "")
            if not action.register_action(cb, menupath):
                return False

        recognize_action = FingerLocalUIManager.ActionHandler(
            "FingerLocal:RecognizeSelected", "Recognize selected functions (local)"
        )
        if recognize_action.register_action(self.selected_function_callback):
            self.hooks.hook()
            return True
        return False

    def selected_function_callback(self, ctx):
        funcs = [idaapi.getn_func(i) for i in ctx.chooser_selection]
        if ctx.action == "FingerLocal:RecognizeSelected":
            self.mgr.recognize_selected_function(funcs)


def check_ida_version():
    if idaapi.IDA_SDK_VERSION < 700:
        print("[-] Finger_local supports IDA 7.x+ (IDAPython). Please update your IDA version.")
        return False
    return True


class FingerLocalPlugin(idaapi.plugin_t):
    wanted_name = PLUGIN_NAME
    comment, help, wanted_hotkey = "", "", ""
    flags = idaapi.PLUGIN_FIX | idaapi.PLUGIN_HIDE | idaapi.PLUGIN_MOD

    def init(self):
        if check_ida_version():
            idaapi.msg("[+] %s plugin starts\n" % self.wanted_name)
            manager = FingerLocalUIManager(self.wanted_name)
            if manager.register_actions():
                return idaapi.PLUGIN_OK
        return idaapi.PLUGIN_SKIP

    def run(self, ctx):
        return

    def term(self):
        return


def PLUGIN_ENTRY():
    return FingerLocalPlugin()
