"""Indicator list loading from editable config/indicators/* files.

File format (all list files): one entry per line, '#' starts a comment,
blank lines ignored. Matching is case-insensitive. Patterns are PCRE and
invalid lines are skipped with a warning instead of crashing the tool.
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path


def _read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def _read_patterns(path: Path) -> tuple[list[re.Pattern], list[str]]:
    patterns: list[re.Pattern] = []
    errors: list[str] = []
    for line in _read_lines(path):
        try:
            patterns.append(re.compile(line))
        except re.error as exc:
            errors.append(f"{path.name}: invalid pattern {line!r} ({exc})")
    return patterns, errors


class Indicators:
    def __init__(self, config_dir: Path):
        ind = Path(config_dir) / "indicators"
        self.load_errors: list[str] = []

        self.pool_domains = {d.lower() for d in _read_lines(ind / "mining_pool_domains.txt")}
        self.c2_domains = {d.lower() for d in _read_lines(ind / "c2_domains.txt")}
        self.mining_ports = {int(p) for p in _read_lines(ind / "mining_ports.txt") if p.isdigit()}
        self.miner_processes = {p.lower() for p in _read_lines(ind / "miner_process_names.txt")}
        self.suspicious_paths = [p.lower() for p in _read_lines(ind / "suspicious_paths.txt")]
        self.bad_hashes = {h.lower() for h in _read_lines(ind / "bad_hashes.txt")}
        self.ransomware_extensions = {
            e.lower() if e.startswith(".") else f".{e.lower()}"
            for e in _read_lines(ind / "ransomware_extensions.txt")
        }
        self.ransom_note_patterns = [p.lower() for p in _read_lines(ind / "ransom_note_filenames.txt")]
        self.remote_tools = {p.lower() for p in _read_lines(ind / "remote_access_tool_names.txt")}
        self.approved_remote_tools = {p.lower() for p in _read_lines(ind / "approved_remote_tools.txt")}

        cmd, cmd_errs = _read_patterns(ind / "suspicious_command_patterns.txt")
        shadow, shadow_errs = _read_patterns(ind / "shadow_copy_tamper_patterns.txt")
        self.command_patterns = cmd
        self.shadow_patterns = shadow
        self.load_errors.extend(cmd_errs + shadow_errs)

        # Optional static IP map: IP=HOSTNAME (config/ip_map.txt)
        self.ip_map: dict[str, str] = {}
        ip_file = Path(config_dir) / "ip_map.txt"
        for line in _read_lines(ip_file):
            if "=" in line:
                ip, host = line.split("=", 1)
                self.ip_map[ip.strip()] = host.strip()

    # ---- matchers --------------------------------------------------------
    @staticmethod
    def _domain_in(domain: str, indicators: set[str]) -> str | None:
        d = (domain or "").strip().lower().rstrip(".")
        if not d:
            return None
        for ind in indicators:
            if d == ind or d.endswith("." + ind):
                return ind
        return None

    def pool_domain(self, domain: str) -> str | None:
        return self._domain_in(domain, self.pool_domains)

    def c2_domain(self, domain: str) -> str | None:
        return self._domain_in(domain, self.c2_domains)

    def port_listed(self, port) -> bool:
        try:
            return int(port) in self.mining_ports
        except (TypeError, ValueError):
            return False

    def miner_process(self, name: str) -> str | None:
        n = (name or "").strip().lower()
        n = n.split("\\")[-1]
        return n if n in self.miner_processes else None

    def suspicious_path(self, image_path: str) -> str | None:
        p = (image_path or "").strip().lower()
        for frag in self.suspicious_paths:
            if frag and frag in p:
                return frag
        return None

    def bad_hash(self, value: str) -> str | None:
        v = (value or "").strip().lower()
        return v if v and v in self.bad_hashes else None

    def ransomware_extension(self, filename: str) -> str | None:
        name = (filename or "").lower()
        dot = name.rfind(".")
        if dot <= 0:
            return None
        ext = name[dot:]
        return ext if ext in self.ransomware_extensions else None

    def ransom_note(self, filename: str) -> str | None:
        name = (filename or "").lower()
        for pat in self.ransom_note_patterns:
            if fnmatch.fnmatch(name, pat):
                return pat
        return None

    def unapproved_remote_tool(self, process_name: str) -> str | None:
        n = (process_name or "").strip().lower()
        n = n.split("\\")[-1]
        if n in self.approved_remote_tools:
            return None
        if n in self.remote_tools:
            return n
        # tolerate missing .exe in lists
        if not n.endswith(".exe") and f"{n}.exe" in self.remote_tools and f"{n}.exe" not in self.approved_remote_tools:
            return f"{n}.exe"
        return None

    def command_match(self, command_line: str) -> re.Match | None:
        cmd = command_line or ""
        if not cmd:
            return None
        for pat in self.command_patterns:
            if pat.search(cmd):
                return pat
        return None

    def shadow_match(self, command_line: str) -> re.Match | None:
        cmd = command_line or ""
        for pat in self.shadow_patterns:
            if pat.search(cmd):
                return pat
        return None

    def summary(self) -> dict:
        return {
            "pool_domains": len(self.pool_domains),
            "c2_domains": len(self.c2_domains),
            "mining_ports": len(self.mining_ports),
            "miner_processes": len(self.miner_processes),
            "suspicious_paths": len(self.suspicious_paths),
            "bad_hashes": len(self.bad_hashes),
            "ransomware_extensions": len(self.ransomware_extensions),
            "ransom_note_patterns": len(self.ransom_note_patterns),
            "remote_tools": len(self.remote_tools),
            "approved_remote_tools": len(self.approved_remote_tools),
            "command_patterns": len(self.command_patterns),
            "shadow_patterns": len(self.shadow_patterns),
            "load_errors": list(self.load_errors),
        }
