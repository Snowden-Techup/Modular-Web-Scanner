import os
import re
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass(frozen=True, slots=True)
class Payload:
    value: str
    attack_type: str
    risk_level: str
    target_os: str = "Unix"
    action_level: str = "SHELL"

def _resolve_payload_file() -> str | None:
    candidates = [os.path.join("config", "payloads", "oob_osci", "oob_osci.txt")]
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate
    return None

def _get_suffixes(p_is_windows, p_is_shell, p_is_php, p_attack_type, mode=None):
    if p_is_windows:
        if p_is_shell:
            # Windows CMD/PS suffix
            return ["", "\"", "&", "^", "|"]
        if p_is_php:
            # Windows PHP suffix
            return ["", ";", ";//", ";#"]
    else: # Unix
        if p_is_shell:
            if "oob" in p_attack_type.lower() or "in-band" in p_attack_type.lower():
                return ["", "\"", "&", "'", "//", "\\", "\\\\", "|"]
            else: # time-based
                return ["", " \"", " #", " &", " '", " //", " \\\\", " |"]
        if p_is_php:
            if mode == 'dot':
                return [")}", ";#", ";.\"", ";.'", ";//", ";", ";\\\\"]
            else:
                return [";#", ";)}", ";.\"", ";.'", ";//", ";", ";\\\\"]
    return [""]

def get_oob_osci_payloads(target_filter: str = "Unix") -> list[Payload]:
    """
    target_filter: "Unix", "Windows", 또는 "all".
    """
    file_path = _resolve_payload_file()
    if not file_path:
        return []

    intermediate_payloads = [] # Prefix 까지만 다중화된 데이터 보관
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":::" not in line:
                continue
            
            parts = [p.strip() for p in line.split(":::", 4)]
            if len(parts) < 5: continue
                
            skel_raw = parts[0]
            m_type, m_risk, m_os, m_level = parts[1], parts[2], parts[3], parts[4]

            # [1] OS 필터링 로직
            if target_filter != "all" and m_os != target_filter:
                continue

            # [2] Prefix 다중화 로직
            prefix_set = [""]
            
            if m_os == "Unix":
                if m_level == "PHP":
                    if skel_raw.startswith("${"): prefix_set = [""]
                    elif "}print" in skel_raw: prefix_set = ["\")", "')", ")"]
                    elif "print(" in skel_raw and "[CONCAT]print" not in skel_raw:
                        prefix_set = ["", "\")", "')", ")", "'"]
                    elif "[CONCAT]print" in skel_raw: prefix_set = ["", "\"", "'"]
                elif m_level == "SHELL COMMAND":
                    if not skel_raw.startswith("&"): prefix_set = ["", "\"", "'"]
                    else: prefix_set = [""]
            
            elif m_os == "Windows":
                if m_level == "PHP":
                    if skel_raw.startswith("${"): 
                        prefix_set = [""]
                    elif "}print" in skel_raw: 
                        prefix_set = ["\")", "')", ")"]
                    elif "[CONCAT]print" in skel_raw or "print(" in skel_raw:
                        prefix_set = ["", "\")", "')", ")"]
                elif m_level in ("SHELL COMMAND (CMD)", "SHELL COMMAND (PS)"):
                    prefix_set = ["", "\"", "^"]

            for pre in prefix_set:
                val = skel_raw.replace("[PREFIX]", pre) if "[PREFIX]" in skel_raw else pre + skel_raw
                intermediate_payloads.append({
                    "payload": val,
                    "m_type": m_type,
                    "m_risk": m_risk,
                    "m_os": m_os,
                    "m_level": m_level
                })

    # [3] Concat 및 Suffix 다중화
    final_payload_objects = []
    
    for item in intermediate_payloads:
        payload = item["payload"]
        m_os = item["m_os"]
        m_level = item["m_level"]
        attack_type = item["m_type"]
        
        is_unix    = (m_os == "Unix")
        is_windows = (m_os == "Windows")
        is_php     = (m_level == "PHP")
        is_cmd     = (m_level == "SHELL COMMAND (CMD)")
        is_ps      = (m_level == "SHELL COMMAND (PS)")
        is_shell   = (m_level == "SHELL COMMAND")

        if is_unix:
            if is_shell:
                shell_delimiters = ["\n", "&&", "&", ";", "|", "||"]
                for d in shell_delimiters:
                    temp_payload = payload
                    if d == ";":
                        new_p = temp_payload.replace("[CONCAT]echo", ";echo").replace("[CONCAT]", "; ")
                    else:
                        new_p = temp_payload.replace("[CONCAT]", d)
                    
                    for s in _get_suffixes(False, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), item))

            elif is_php:
                for mode in ['nl', 'semi', 'dot']:
                    if mode == 'nl':
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print")
                    elif mode == 'semi':
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print")
                    else:
                        p = payload.replace(")[CONCAT]}", ");}").replace("[CONCAT]print", ".print")
                    
                    for s in _get_suffixes(False, False, True, attack_type, mode):
                        final_payload_objects.append(_finalize(p.replace("[SUFFIX]", s), item))
        
        elif is_windows:
            if is_cmd:
                shell_delimiters = ["&", "&&", "|", "||", "\r\n"]
                for d in shell_delimiters:
                    new_p = payload
                    if d == "&":
                        new_p = new_p.replace("[CONCAT]echo", " & echo").replace("[CONCAT]set", " & set")\
                                     .replace("[CONCAT]call", " & call").replace("[CONCAT]if", " & if")\
                                     .replace("[CONCAT]cmd", " & cmd").replace("[CONCAT]timeout", " & timeout")\
                                     .replace("[CONCAT]ping", " & ping")
                    new_p = new_p.replace("[CONCAT]", d)
                    for s in _get_suffixes(True, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), item))

            elif is_ps:
                shell_delimiters = [";", "&", "&&", "|", "||"]
                for d in shell_delimiters:
                    new_p = payload.replace("[CONCAT]", d)
                    for s in _get_suffixes(True, True, False, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), item))

            elif is_php:
                php_delimiters = [";", "\n"]
                for d in php_delimiters:
                    new_p = payload
                    if ")[CONCAT]}" in new_p:
                        new_p = new_p.replace(")[CONCAT]}", ");}")
                    
                    if d == ";":
                        new_p = new_p.replace("[CONCAT]echo", " & echo").replace("[CONCAT]set", " & set").replace("[CONCAT]call", " & call")
                    elif d == "\n":
                        new_p = new_p.replace("[CONCAT]echo", "\necho").replace("[CONCAT]set", "\nset").replace("[CONCAT]call", "\ncall")
                    
                    new_p = new_p.replace("[CONCAT]print", f"{d}print").replace("[CONCAT]", d)
                    for s in _get_suffixes(True, False, True, attack_type):
                        final_payload_objects.append(_finalize(new_p.replace("[SUFFIX]", s), item))
        
    return final_payload_objects

def _finalize(val: str, meta: Dict[str, Any]) -> Payload:
    """
    나중에 치환할 [OOB_HOST] 토큰 유지.
    """
    
    # 최종 결과물 반환
    return Payload(
        value=val,
        attack_type=meta["m_type"],
        risk_level=meta["m_risk"],
        target_os=meta["m_os"],
        action_level=meta["m_level"]
    )