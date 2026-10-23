"""Rule registry: all detection rules live under app/rules/.

To add a rule (see ADMIN_GUIDE):
  1. create an ObsRule/PCRule subclass in the right module (or a new one),
  2. add it to that module's OBS_RULES / PC_RULES list,
  3. add its id to KNOWN_RULE_IDS here and its weight to config/scoring.yaml,
  4. optionally reference it from config/incident_types.yaml for suggestions.
"""
from __future__ import annotations

from . import account, evasion, execution, miner, network, persistence, ransomware
from .base import CATEGORIES, Ctx, ObsRule, PCRule, SignalDraft

_MODULES = (miner, network, execution, persistence, account, evasion, ransomware)

# Every rule id the code can emit. Checked against config/scoring.yaml at startup.
KNOWN_RULE_IDS = (
    # miner
    "dns_mining_pool", "conn_mining_port", "proc_miner_name", "cpu_high_offhours",
    # network
    "dns_c2_domain", "net_unapproved_rat",
    # execution
    "proc_suspicious_path", "proc_unsigned", "exec_temp_unsigned", "proc_bad_hash",
    "defender_detection", "exec_suspicious_command", "exec_office_spawn",
    # persistence
    "pers_run_key", "pers_service", "pers_task", "pers_startup", "pers_wmi",
    "pers_new_admin",
    # account
    "acct_failed_burst", "acct_success_after_burst", "acct_offhours_login",
    "acct_unusual_source",
    # evasion
    "evade_defender_rtp", "evade_defender_exclusion", "evade_defender_stopped",
    "evade_log_cleared",
    # ransomware
    "ransom_extension", "ransom_note", "ransom_mass_change", "ransom_shadow_copy",
)


def all_obs_rules() -> list[ObsRule]:
    rules: list[ObsRule] = []
    for mod in _MODULES:
        rules.extend(getattr(mod, "OBS_RULES", []))
    return rules


def all_pc_rules() -> list[PCRule]:
    rules: list[PCRule] = []
    for mod in _MODULES:
        rules.extend(getattr(mod, "PC_RULES", []))
    return rules


def validate_rule_ids(weights: dict) -> list[str]:
    """Warnings for rule ids missing a weight and weights with no rule."""
    warnings = []
    for rid in sorted(set(KNOWN_RULE_IDS) - set(weights)):
        warnings.append(f"rule {rid!r} has no weight in config/scoring.yaml")
    for rid in sorted(set(weights) - set(KNOWN_RULE_IDS)):
        warnings.append(f"scoring.yaml weight {rid!r} matches no rule id")
    return warnings


__all__ = ["Ctx", "ObsRule", "PCRule", "SignalDraft", "CATEGORIES",
           "KNOWN_RULE_IDS", "all_obs_rules", "all_pc_rules", "validate_rule_ids"]
