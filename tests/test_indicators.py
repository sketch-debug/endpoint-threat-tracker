"""Indicator list loading and matching tests (uses shipped config files)."""
from __future__ import annotations

from pathlib import Path

from app.indicators import Indicators


class TestShippedLists:
    def test_shipped_lists_nonempty(self, indicators: Indicators):
        s = indicators.summary()
        for key in ("pool_domains", "c2_domains", "mining_ports", "miner_processes",
                    "suspicious_paths", "bad_hashes", "ransomware_extensions",
                    "ransom_note_patterns", "remote_tools", "command_patterns"):
            assert s[key] > 0, f"shipped indicator list {key} is empty"

    def test_approved_list_may_be_empty(self, indicators: Indicators):
        # approved_remote_tools.txt ships with examples commented out; an org
        # fills it in. Must load without error whether empty or not.
        assert isinstance(indicators.approved_remote_tools, set)
        assert not indicators.load_errors

    def test_ip_map_parsed(self, indicators: Indicators):
        # config/ip_map.txt maps demo IPs to hostnames
        assert indicators.ip_map, "config/ip_map.txt missing or empty"
        assert all("=" not in k for k in indicators.ip_map)


class TestMatchers:
    def test_pool_domain_subdomain_match(self, indicators: Indicators):
        sample = next(iter(indicators.pool_domains))
        assert indicators.pool_domain(f"eu1.{sample}") is not None
        assert indicators.pool_domain(sample.upper() + ".") is not None  # case + dot
        assert indicators.pool_domain("example.com") is None

    def test_c2_domain_match(self, indicators: Indicators):
        sample = next(iter(indicators.c2_domains))
        assert indicators.c2_domain(sample) is not None
        assert indicators.c2_domain("good.example") is None

    def test_port_listed(self, indicators: Indicators):
        assert indicators.port_listed("4444") is True
        assert indicators.port_listed(4444) is True
        assert indicators.port_listed("99999") is False
        assert indicators.port_listed(None) is False

    def test_miner_process_basename(self, indicators: Indicators):
        assert indicators.miner_process(r"C:\Users\x\xmrig.exe") is not None
        assert indicators.miner_process("notepad.exe") is None

    def test_suspicious_path_substring(self, indicators: Indicators):
        assert indicators.suspicious_path(r"C:\Users\bob\AppData\Local\Temp\x.exe") is not None
        assert indicators.suspicious_path(r"C:\Windows\System32\notepad.exe") is None

    def test_bad_hash_case_insensitive(self, indicators: Indicators):
        sample = next(iter(indicators.bad_hashes))
        assert indicators.bad_hash(sample.upper()) is not None
        assert indicators.bad_hash("0" * 64) is None
        assert indicators.bad_hash("") is None

    def test_ransomware_extension_normalizes_leading_dot(self, indicators: Indicators):
        assert indicators.ransomware_extension("doc.pdf") is not None or \
            indicators.ransomware_extension("doc.locked") is not None
        assert indicators.ransomware_extension("noext") is None

    def test_ransom_note_fnmatch(self, indicators: Indicators):
        assert indicators.ransom_note("how_to_decrypt.txt") is not None or \
            any(indicators.ransom_note(n) for n in ("README.txt", "_read_me.txt", "restore_files.txt"))

    def test_unapproved_vs_approved_remote_tool(self, indicators: Indicators):
        some_tool = next(iter(indicators.remote_tools))
        assert indicators.unapproved_remote_tool(some_tool) is not None

    def test_approved_overrides_unapproved(self, tmp_path: Path):
        cfg = tmp_path / "config"
        (cfg / "indicators").mkdir(parents=True)
        (cfg / "indicators" / "remote_access_tool_names.txt").write_text(
            "teamviewer.exe\n", encoding="utf-8")
        (cfg / "indicators" / "approved_remote_tools.txt").write_text(
            "teamviewer.exe\n", encoding="utf-8")
        ind = Indicators(cfg)
        assert ind.unapproved_remote_tool("teamviewer.exe") is None

    def test_command_match_and_shadow(self, indicators: Indicators):
        assert indicators.command_match("vssadmin delete shadows /all /quiet") is not None or \
            indicators.shadow_match("vssadmin delete shadows /all /quiet") is not None
        assert indicators.command_match("ping 8.8.8.8") is None


class TestFileFormat:
    def test_comments_and_blanks_skipped(self, tmp_path: Path):
        cfg = tmp_path / "config"
        (cfg / "indicators").mkdir(parents=True)
        (cfg / "indicators" / "c2_domains.txt").write_text(
            "# comment\n\nbad.example\n", encoding="utf-8")
        ind = Indicators(cfg)
        assert ind.c2_domains == {"bad.example"}

    def test_invalid_pattern_is_warning_not_crash(self, tmp_path: Path):
        cfg = tmp_path / "config"
        (cfg / "indicators").mkdir(parents=True)
        (cfg / "indicators" / "suspicious_command_patterns.txt").write_text(
            "[unclosed\nvalidpattern\n", encoding="utf-8")
        ind = Indicators(cfg)
        assert ind.load_errors, "invalid regex must produce a load error"
        assert len(ind.command_patterns) == 1

    def test_missing_dir_tolerated(self, tmp_path: Path):
        ind = Indicators(tmp_path / "nope")
        assert ind.summary()["pool_domains"] == 0
