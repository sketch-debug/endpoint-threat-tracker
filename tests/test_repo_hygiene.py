"""Two leftovers that once sat untracked in this working tree.

`watch.out` was a `gh run watch` redirect left at the repository root, showing
up in every `git status`. `config/indicators/test_domains.txt` (and its .bak)
was a hand-dropped fixture in the one directory the detector loads its lists
from: invisible to review because it was never tracked, and able to feed
example.com and friends into detection if it ever shipped.

Neither has a generator in the repo, so both are guarded from the other side:
shell output redirected at the root is ignored, and the indicator directory
must hold exactly the lists that ship with the product.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INDICATOR_LISTS = {
    "approved_remote_tools.txt",
    "bad_hashes.txt",
    "c2_domains.txt",
    "miner_process_names.txt",
    "mining_pool_domains.txt",
    "mining_ports.txt",
    "ransom_note_filenames.txt",
    "ransomware_extensions.txt",
    "remote_access_tool_names.txt",
    "shadow_copy_tamper_patterns.txt",
    "suspicious_command_patterns.txt",
    "suspicious_paths.txt",
}


class TestTheDetectorOnlySeesShippedLists:
    def test_config_indicators_holds_exactly_the_shipped_lists(self):
        found = {p.name for p in (ROOT / "config" / "indicators").glob("*.txt")}
        assert found == INDICATOR_LISTS, (
            "config/indicators changed: the detector loads every .txt there.\n"
            f"  stray   : {sorted(found - INDICATOR_LISTS)}\n"
            f"  missing : {sorted(INDICATOR_LISTS - found)}\n"
            "Delete a hand-dropped fixture, or ship a new list deliberately "
            "and list it in INDICATOR_LISTS here."
        )


class TestShellJunkNeverEntersGit:
    def test_command_output_at_the_root_is_ignored(self):
        # `gh run watch > watch.out` (and any sibling redirect) must not be
        # able to reappear as an untracked file in every status
        patterns = [
            line.strip()
            for line in (ROOT / ".gitignore").read_text(
                encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        assert any(p in ("/*.out", "*.out", "watch.out") for p in patterns), (
            ".gitignore no longer ignores root-level command output"
        )
