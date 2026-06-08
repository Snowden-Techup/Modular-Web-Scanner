import re
import html
import asyncio
from urllib.parse import unquote
from difflib import SequenceMatcher

def _get_pure_text(html_content: str) -> str:
    if not html_content:
        return ""
    text = re.sub(r'<(script|style).*?>.*?</\1>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<[^>]+?>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def _remove_direct_reflection(text: str, payload_value: str) -> str:
    scrubbed = text
    payload_variants = [
        payload_value,
        unquote(payload_value),
        unquote(unquote(payload_value)),
        html.escape(payload_value),
        html.unescape(payload_value)
    ]
    for variant in filter(None, set(payload_variants)):
        scrubbed = scrubbed.replace(variant, "[DIRECT_REFLECTION_REMOVED]")
    return scrubbed

def _analyze_marker_context(text: str, marker: str) -> str:
    positions = [m.start() for m in re.finditer(re.escape(marker), text)]
    for pos in positions:
        start = max(0, pos - 100)
        end = min(len(text), pos + len(marker) + 100)
        context = text[start:end]
        if re.search(r'<[^>]*' + re.escape(marker) + r'[^>]*>', context):
            return "reflection_html"
        error_patterns = [
            r'error.*?' + re.escape(marker),
            r'invalid.*?' + re.escape(marker),
            r'not\s+allowed.*?' + re.escape(marker),
            r'forbidden.*?' + re.escape(marker),
            r'denied.*?' + re.escape(marker),
            r'failed.*?' + re.escape(marker)
        ]
        if any(re.search(p, context, re.I) for p in error_patterns):
            return "reflection_error"
    return "execution_output"

async def detect_osci(response, payload, elapsed_time, original_res=None, requester=None):
    evidences = []
    attack_type = getattr(payload, "attack_type", "").lower()
    payload_value = getattr(payload, "value", "")
    is_time_based = "time-based" in attack_type or "time" in attack_type
    
    # Status 0면 최대 2회 재요청
    if not is_time_based and requester:
        current_status = getattr(response, "status", getattr(response, "status_code", 0)) or 0 if response else 0
        
        retry_count = 0
        while current_status == 0 and retry_count < 2:
            await asyncio.sleep(1.5)
            try:
                retry_res = await requester(payload_value)
                if retry_res is not None:
                    current_status = getattr(retry_res, "status", getattr(retry_res, "status_code", 0)) or 0
                    elapsed_time = getattr(retry_res, "elapsed_time", getattr(retry_res, "elapsed", elapsed_time))
                    response = retry_res
            except Exception:
                pass
            retry_count += 1

    marker = "SVSDAAAA"
    arithmetic_sum = 100

    # [1] 타임아웃 탐지
    if is_time_based and response is None:
        if elapsed_time >= 10.0:
            evidences.append(f"[Time] Request timed out: {elapsed_time:.2f}s")
            return True, evidences

    # [2] Time-based 탐지
    if is_time_based and response:
        orig_elapsed = 0.0
        if original_res:
            orig_elapsed = getattr(original_res, "elapsed_time",
                                   getattr(getattr(original_res, "elapsed", object()),
                                           "total_seconds", lambda: 0.0)())
        threshold = 3.0
        if elapsed_time >= (threshold + orig_elapsed):
            evidences.append(f"[Time] Response delayed: {elapsed_time:.2f}s (baseline: {orig_elapsed:.2f}s)")
            return True, evidences

    # [3] In-band 탐지
    if response and not is_time_based:
        res_text = response.text

        if original_res and marker in original_res.text:
            evidences.append(f"[False Positive] Marker exists in baseline response")
            return False, evidences

        scrubbed_text = _remove_direct_reflection(res_text, payload_value)
        arithmetic_pattern = re.compile(rf"{marker}\D*(\d+)\D*{marker}", re.I | re.DOTALL)
        matches_scrubbed = arithmetic_pattern.findall(scrubbed_text)

        # Case 1: 산술 결과 검출
        if matches_scrubbed:
            for match in matches_scrubbed:
                if int(match) == arithmetic_sum:
                    evidences.append(f"[Output] Command execution confirmed (Arithmetic): {marker}...{match}...{marker}")
                    return True, evidences

        # Case 2: 마커 뒤에 100이 바로 오는 경우
        fallback_pattern = re.compile(rf"{marker}\D*({arithmetic_sum})", re.I | re.DOTALL)
        if fallback_pattern.search(scrubbed_text):
            evidences.append(f"[Output] Command execution detected (Clipped Output): Found {marker} followed by {arithmetic_sum}")
            return True, evidences
        
        marker_count_scrubbed = scrubbed_text.count(marker)
        
        # Case 3: 산술 결과 없이 다중 마커 검출
        if marker_count_scrubbed >= 3:
            context_type = _analyze_marker_context(scrubbed_text, marker)
            evidences.append(f"[Output] Potential execution: {marker_count_scrubbed} markers in {context_type} context (requires verification)")
            return True, evidences

        # Case 4: 산술 결과 없이 단일 마커 검출
        if marker_count_scrubbed >= 1:
            marker_count_original = res_text.count(marker)
            if marker_count_original > marker_count_scrubbed:
                return False, []
                
            context_type = _analyze_marker_context(scrubbed_text, marker)
            evidences.append(f"[Output] Single marker found in {context_type} context (requires verification)")
            return True, evidences

    return len(evidences) > 0, evidences

async def verify_osci_logic(response, payload, original_res, requester, is_hit, evidences):
    if not requester or not is_hit:
        return is_hit, evidences

    marker = "SVSDAAAA"
    arithmetic_sum = 100
    payload_value = getattr(payload, "value", "")

    # [A] 강한 증거 즉시 반환
    strong_evidence_tags = [
        "Command execution confirmed",
        "Clipped Output",
        "Request timed out",
    ]
    if any(tag in str(evidences) for tag in strong_evidence_tags):
        return True, evidences

    # [B] 시간 지연 경계값 재검증 비활성화
    if "[Time]" in str(evidences):
        return True, evidences

    # [C] 단순 마커 재검증
    if "requires verification" in str(evidences):
        try:
            retry_res = await requester(payload_value)
            r_status = getattr(retry_res, "status", getattr(retry_res, "status_code", 0)) or 0 if retry_res else 0
            # Status 0면 최대 2회 재요청
            retry_count = 0
            while r_status == 0 and retry_count < 2:
                await asyncio.sleep(1.5)
                try:
                    retry_res = await requester(payload_value)
                    r_status = getattr(retry_res, "status", getattr(retry_res, "status_code", 0)) or 0 if retry_res else 0
                except Exception:
                    pass
                retry_count += 1

            if r_status == 0 or retry_res is None:
                return False, evidences + ["[False Positive] Network dropped during re-verification"]

            retry_text = retry_res.text
            has_marker_in_raw = marker in retry_text
            scrubbed_retry = _remove_direct_reflection(retry_text, payload_value)

            arith_pattern = re.compile(rf"{marker}\D*(\d+)\D*{marker}", re.I | re.DOTALL)
            arith_matches = arith_pattern.findall(scrubbed_retry)
            if arith_matches:
                for val in arith_matches:
                    if int(val) == arithmetic_sum:
                        return True, evidences + [f"[Verified] Arithmetic result ({val}) confirmed on retry"]

            clip_pattern = re.compile(rf"{marker}\D*({arithmetic_sum})", re.I | re.DOTALL)
            clip_match = clip_pattern.search(scrubbed_retry)
            if clip_match:
                val = clip_match.group(1)
                return True, evidences + [f"[Verified] Clipped output result ({val}) confirmed on retry"]

        except Exception:
            return False, []
            
    return False, []