from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from fuzzer import EngineStats, Finding

from reporter.dedupe import (
    dedupe_vulnerabilities,
    full_report_path,
    get_attack_guidance,
    vulnerability_sort_key,
)


def _severity_rank(raw: str) -> int:
    """Lower is more severe (critical first)."""
    key = str(raw or "").strip().lower()
    if key in ("critical", "crit"):
        return 0
    if key == "high":
        return 1
    if key in ("medium", "med"):
        return 2
    if key == "low":
        return 3
    return 4


def _finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    payload_obj = finding.payload
    severity = str(getattr(payload_obj, "risk_level", "high"))
    url = str(getattr(finding.surface, "url", "") or "")
    param = str(finding.parameter or "")
    return (_severity_rank(severity), url, param)


class ReportGenerator:
    """
    Converts fuzzing engine statistics and findings into readable reports.
    """

    def __init__(self, stats: EngineStats, findings: list[Finding]) -> None:
        self.stats = stats
        self.findings = findings
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_cli_report(self) -> None:
        """
        Prints the scan result in a table-like CLI format.
        """
        table_width = 126
        severity_width = 10
        location_width = 10
        parameter_width = 14
        type_width = 34

        print("\n" + "=" * table_width)
        print("Modular Web Scanner Security Scan Report")
        print(f"Scan completed at: {self.timestamp}")
        print("=" * table_width)

        print("\n[1] Summary")
        print(f"  - queued:    {self.stats.queued}")
        print(f"  - completed: {self.stats.completed}")
        print(f"  - failures:  {self.stats.failures}")
        print(f"  - findings:  {self.stats.findings}")

        if not self.findings:
            print("\nNo findings were detected.")
            print("=" * table_width + "\n")
            return

        print("\n[2] Findings")
        print("-" * table_width)
        print(
            f"{'Severity':<{severity_width}} | {'Location':<{location_width}} | "
            f"{'Parameter':<{parameter_width}} | {'Type':<{type_width}} | Payload"
        )
        print("-" * table_width)

        for finding in sorted(self.findings, key=_finding_sort_key):
            payload_obj = finding.payload
            severity = getattr(payload_obj, "risk_level", "HIGH")
            attack_type = getattr(payload_obj, "attack_type", "PotentialIssue")
            raw_payload = getattr(finding.payload, "value", str(finding.payload))
            safe_payload = raw_payload.replace("\n", "\\n").replace("\r", "\\r")
            payload_value = safe_payload

            param_location = getattr(finding.surface, "param_location", "unknown")
            location_text = getattr(param_location, "name", str(param_location))

            display_payload = (
                payload_value[:37] + "..." if len(payload_value) > 40 else payload_value
            )
            display_type = (
                attack_type[: type_width - 3] + "..."
                if len(attack_type) > type_width
                else attack_type
            )
            print(
                f"{severity:<{severity_width}} | {location_text:<{location_width}} | "
                f"{finding.parameter:<{parameter_width}} | {display_type:<{type_width}} | "
                f"{display_payload}"
            )

        print("-" * table_width)
        print(f"Total findings: {len(self.findings)}")
        print("=" * table_width + "\n")

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        payload_obj = finding.payload
        payload_value = getattr(payload_obj, "value", str(payload_obj))
        attack_type = getattr(payload_obj, "attack_type", "Unknown")
        severity = getattr(payload_obj, "risk_level", "high")
        description = getattr(payload_obj, "description", "")

        response = finding.response
        status_code = getattr(response, "status", 0)
        response_time = getattr(response, "elapsed_time", getattr(response, "elapsed", 0.0))
        error_log = getattr(response, "error", None)

        method = getattr(finding.surface.method, "name", str(finding.surface.method))
        location = getattr(
            getattr(finding.surface, "param_location", "unknown"),
            "name",
            str(getattr(finding.surface, "param_location", "unknown")),
        )

        row: dict[str, Any] = {
            "target": {
                "url": finding.surface.url,
                "method": method,
                "location": location,
                "parameter": finding.parameter,
            },
            "attack_info": {
                "payload_value": payload_value,
                "type": attack_type,
                "severity": severity,
                "description": description,
            },
            "evidence": {
                "status_code": status_code,
                "response_time": round(float(response_time), 4),
                "error_log": error_log,
            },
        }
        if finding.module_name:
            row["module"] = finding.module_name
        ch = getattr(payload_obj, "channel", None)
        if ch is not None:
            row["ssrf_channel"] = ch
        return row

    def _group_vulnerabilities_by_type(
        self, records: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """
        Group flat vulnerability records by attack_type.

        Each group contains:
          - attack_type, severity (worst across instances), reference,
            secure_coding_guide, count, instances[]
        Instance objects retain target / attack_info (without redundant type field)
        / evidence / module.
        """
        _sev_rank_to_label = {0: "critical", 1: "high", 2: "medium", 3: "low"}

        groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        group_sev_rank: dict[str, int] = {}

        for rec in records:
            attack_info = rec.get("attack_info") or {}
            attack_type = str(attack_info.get("type") or "Unknown")
            sev = _severity_rank(str(attack_info.get("severity") or "high"))
            if attack_type not in group_sev_rank:
                group_sev_rank[attack_type] = sev
            else:
                group_sev_rank[attack_type] = min(group_sev_rank[attack_type], sev)

            instance_attack: dict[str, Any] = {
                k: v for k, v in attack_info.items() if k != "type"
            }
            instance: dict[str, Any] = {
                "target": rec.get("target"),
                "attack_info": instance_attack,
                "evidence": rec.get("evidence"),
            }
            if rec.get("module"):
                instance["module"] = rec["module"]
            if rec.get("ssrf_channel"):
                instance["ssrf_channel"] = rec["ssrf_channel"]
            groups[attack_type].append(instance)

        result: list[dict[str, Any]] = []
        for attack_type, instances in groups.items():
            guidance = get_attack_guidance(attack_type)
            sev_label = _sev_rank_to_label.get(group_sev_rank[attack_type], "info")
            entry: dict[str, Any] = {
                "attack_type": attack_type,
                "severity": sev_label,
                "reference": guidance.get("reference", ""),
                "secure_coding_guide": guidance.get("secure_coding_guide", ""),
                "count": len(instances),
                "instances": instances,
            }
            result.append(entry)

        result.sort(key=lambda g: (_severity_rank(g["severity"]), g["attack_type"]))
        return result

    def build_full_report(self) -> dict[str, Any]:
        full_vulnerabilities = [
            self._finding_to_dict(f) for f in sorted(self.findings, key=_finding_sort_key)
        ]
        return {
            "metadata": {
                "scan_time": self.timestamp,
                "summary": {
                    "queued": self.stats.queued,
                    "completed": self.stats.completed,
                    "failures": self.stats.failures,
                    "findings": self.stats.findings,
                },
            },
            "vulnerabilities": full_vulnerabilities,
        }

    def build_deduped_report(self) -> dict[str, Any]:
        discovery_vulnerabilities = [self._finding_to_dict(f) for f in self.findings]
        return self.build_deduped_report_from_records(
            discovery_vulnerabilities,
            raw_findings_count=self.stats.findings,
        )

    def build_deduped_report_from_records(
        self,
        records: list[dict[str, Any]],
        *,
        raw_findings_count: int | None = None,
    ) -> dict[str, Any]:
        deduped = dedupe_vulnerabilities(records, mode="first_in_order")
        deduped_sorted = sorted(deduped, key=vulnerability_sort_key)
        grouped = self._group_vulnerabilities_by_type(deduped_sorted)
        raw_count = len(records) if raw_findings_count is None else raw_findings_count
        return {
            "metadata": {
                "scan_time": self.timestamp,
                "summary": {
                    "queued": self.stats.queued,
                    "completed": self.stats.completed,
                    "failures": self.stats.failures,
                    "vulnerability_types": len(grouped),
                    "findings_deduped": len(deduped_sorted),
                    "findings_raw": raw_count,
                },
            },
            "vulnerabilities": grouped,
        }

    def export_to_json(self, filepath: str = "scan_result.json") -> None:
        """
        Writes a deduplicated report to ``filepath`` (one PoC per URL / parameter / type)
        and the complete per-payload list to ``<stem>_full<suffix>``.
        """
        full_report = self.build_full_report()
        deduped_report = self.build_deduped_report()

        full_path = full_report_path(filepath)
        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(deduped_report, file, ensure_ascii=False, indent=2)
        with open(full_path, "w", encoding="utf-8") as file:
            json.dump(full_report, file, ensure_ascii=False, indent=2)

        print(f"report saved (deduplicated): {filepath}")
        print(f"report saved (full payloads): {full_path}")