"""
Risk Score (PRD Section 7.9).

Weighted rules. v3.0 groups rules that can be different views of the
same underlying evidence (e.g. Packed Binary + High Entropy + UPX
signature all firing from one packing decision) so that fact isn't
counted three times. Within a group, only the highest-weight rule
counts toward the score; the rest still display at +0 with a
"redundant evidence" label.

NOTE: this deployment is static-analysis + threat-intel only (no
sandbox). Persistence and Process Injection rules require dynamic
behavioral data and will not fire until sandbox infra exists — this
is intentional per the scope decision, not a bug.
"""
from dataclasses import dataclass

RULE_WEIGHTS = {
    "persistence": 20,           # dynamic-only — will not fire in this deployment
    "process_injection": 25,     # dynamic-only — will not fire in this deployment
    "network_communication": 15, # dynamic-only — will not fire in this deployment
    "known_malicious_hash": 30,  # from VirusTotal / MalwareBazaar
    "packed_binary": 10,         # static
    "high_entropy": 5,           # static
    "unsigned_binary": 5,        # static
    "embedded_executable": 15,   # static
    "upx_signature": 10,         # static
}

EVIDENCE_GROUPS = {
    "packing": ["packed_binary", "high_entropy", "upx_signature"],
    "network_c2": ["network_communication", "ioc_domain_match"],
    "persistence": ["persistence", "registry_run_key"],
}

RISK_LEVELS = [
    (0, 24, "low"),
    (25, 49, "medium"),
    (50, 74, "high"),
    (75, 100, "critical"),
]


def risk_level_for(score: int) -> str:
    for lo, hi, label in RISK_LEVELS:
        if lo <= score <= hi:
            return label
    return "critical" if score > 100 else "low"


@dataclass
class RiskResult:
    score: int
    level: str
    contributions: dict  # {"rule_name": {"weight": int, "counted": bool, "group": str|None}}


def calculate_risk(fired_rules: set[str]) -> RiskResult:
    """
    `fired_rules` is the set of rule names that fired for this sample
    (e.g. from static_analysis + threat_intel service outputs). This
    function only does the scoring/dedup logic — callers decide which
    rules fired.
    """
    contributions = {}
    total = 0

    # Map each fired rule to its evidence group, if any
    rule_to_group = {}
    for group, rules in EVIDENCE_GROUPS.items():
        for r in rules:
            rule_to_group[r] = group

    grouped_fired = {}
    ungrouped_fired = []
    for rule in fired_rules:
        group = rule_to_group.get(rule)
        if group:
            grouped_fired.setdefault(group, []).append(rule)
        else:
            ungrouped_fired.append(rule)

    # Ungrouped rules: each counts fully
    for rule in ungrouped_fired:
        weight = RULE_WEIGHTS.get(rule, 0)
        contributions[rule] = {"weight": weight, "counted": True, "group": None}
        total += weight

    # Grouped rules: only the highest-weight rule in each group counts
    for group, rules in grouped_fired.items():
        rules_sorted = sorted(rules, key=lambda r: RULE_WEIGHTS.get(r, 0), reverse=True)
        winner = rules_sorted[0]
        for rule in rules_sorted:
            weight = RULE_WEIGHTS.get(rule, 0)
            if rule == winner:
                contributions[rule] = {"weight": weight, "counted": True, "group": group}
                total += weight
            else:
                contributions[rule] = {"weight": 0, "counted": False, "group": group,
                                        "label": "redundant evidence"}

    total = min(total, 100)
    return RiskResult(score=total, level=risk_level_for(total), contributions=contributions)
