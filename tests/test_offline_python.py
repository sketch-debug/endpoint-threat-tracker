"""install.ps1 -Offline must build .venv with the interpreter packages\\ holds.

The offline CI step deletes .venv before running install.bat from a pwsh
prompt, and install.ps1 used to choose whatever Find-BasePython saw first -
the `py` launcher, whose default on that runner is NEWER than the wheels in
packages\\. pip then found no wheel for pyyaml==6.0.2 and the install died
with "no matching distribution", even though a perfectly matching Python sat
on PATH. The same trap waits for any admin whose machine has several
Pythons.

The wheel-tag parsing runs for real under Windows PowerShell or pwsh; the
selection logic around it and the CI step that proves it are pinned against
the script text, the way the other installer scripts are tested.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _script() -> str:
    return (ROOT / "install.ps1").read_text(encoding="utf-8").replace("\r\n", "\n")


def _function(name: str) -> str:
    """The named function, from its declaration to its column-0 closing brace."""
    text = _script()
    start = text.index(f"function {name} {{")
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def _shell() -> str:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if exe is None:
        pytest.skip("no PowerShell on PATH to run the extracted function")
    return exe


def _minors(directory: Path) -> list[int]:
    proc = subprocess.run(
        [_shell(), "-NoProfile", "-Command",
         f"{_function('Get-PackagesWheelMinors')}\n"
         f"Get-PackagesWheelMinors -Directory '{directory}'\n"],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return [int(line) for line in proc.stdout.splitlines() if line.strip()]


def _wheels(directory: Path, *names: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    for name in names:
        (directory / name).write_text("", encoding="utf-8")
    return directory


class TestWheelTagsSayWhoCanInstallThem:
    def test_a_cp_tag_pins_the_minor(self, tmp_path):
        pkgs = _wheels(tmp_path,
                       "pyyaml-6.0.2-cp313-cp313-win_amd64.whl",
                       "fastapi-0.115.6-py3-none-any.whl")
        assert _minors(pkgs) == [13]

    def test_pure_wheels_impose_no_constraint(self, tmp_path):
        pkgs = _wheels(tmp_path, "fastapi-0.115.6-py3-none-any.whl",
                       "jinja2-3.1.5-py3-none-any.whl")
        assert _minors(pkgs) == []

    def test_a_missing_directory_is_not_an_error(self, tmp_path):
        assert _minors(tmp_path / "not-there") == []

    def test_every_interpreter_present_is_reported_in_order(self, tmp_path):
        pkgs = _wheels(tmp_path,
                       "some_lib-1.0.0-cp313-cp313-win_amd64.whl",
                       "other_lib-2.0.0-cp312-cp312-win_amd64.whl")
        assert _minors(pkgs) == [12, 13]


class TestTheMatchingInterpreterWins:
    def test_find_base_python_accepts_a_preference(self):
        assert "param([int[]]$PreferMinors = @())" in _function("Find-BasePython")

    def test_a_match_is_returned_before_position_order(self):
        fn = _function("Find-BasePython")
        match = fn.index("$PreferMinors -contains ($candidate.Version % 100)")
        fallback = fn.index("return $valid[0]")
        assert match < fallback, (
            "the launcher would keep winning by position alone")

    def test_the_original_order_still_fallbacks_online(self):
        # an online install constrains nothing, so behaviour there is unchanged
        fn = _function("Find-BasePython")
        assert "$valid[0]" in fn
        assert "$PreferMinors -contains" in fn

    def test_only_offline_installations_read_the_wheels(self):
        text = _script()
        offline = text.index("if ($Offline) {")
        read = text.index("Get-PackagesWheelMinors -Directory $PackagesDir")
        call = text.index("Find-BasePython -PreferMinors $wheelMinors")
        assert offline < read < call


class TestThePreferenceActuallyMovesTheChoice:
    """Not just present in the text: two fake interpreters, one real call."""

    HARNESS = r"""
$MinPython = 310
function Get-Command {
    param([string]$Name)
    if ($Name -eq 'py') { return [pscustomobject]@{ Source = 'C:\fake\py.exe' } }
    if ($Name -eq 'python') { return [pscustomobject]@{ Source = 'C:\fake\python.exe' } }
    return $null
}
function Get-PythonVersion {
    param([string]$FilePath, [string[]]$Arguments = @())
    if ($FilePath -like '*py.exe') { return 315 }
    return 313
}
"""

    def _choice(self, prefer: str) -> str:
        script = (self.HARNESS + _function("Find-BasePython")
                  + f"\n(Find-BasePython {prefer}).Exe\n")
        proc = subprocess.run([_shell(), "-NoProfile", "-Command", script],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
        assert len(lines) == 1, lines
        return lines[0]

    def test_without_a_preference_the_launcher_keeps_winning(self):
        # the pre-fix behaviour, and still the online behaviour
        assert self._choice("") == r"C:\fake\py.exe"

    def test_a_matching_interpreter_is_moved_to_the_front(self):
        # the CI scenario: py defaults to 3.15, packages\ holds cp313 wheels
        assert self._choice("-PreferMinors @(13)") == r"C:\fake\python.exe"

    def test_an_unmatched_preference_falls_back_to_the_original_order(self):
        assert self._choice("-PreferMinors @(12)") == r"C:\fake\py.exe"


class TestAVenvForTheWrongInterpreterIsRebuilt:
    def test_a_mismatched_venv_is_recreated_only_when_a_match_exists(self):
        text = _script()
        assert "$wheelMinors -notcontains ($venvVersion % 100)" in text
        assert "$wheelMinors -contains ($basePython.Version % 100)" in text
        assert "Existing .venv is unusable" in text

    def test_it_is_left_alone_when_nothing_can_rebuild_it(self):
        # deleting the venv would only remove the interpreter that is there, so
        # the warning - not the rebuild - is what the else of the match guard
        # does
        text = _script()
        guard = text.index("if ($wheelMinors -contains ($basePython.Version % 100)) {")
        rebuild = text.index("$venvUsable = $false", guard)
        else_at = text.index("} else {", rebuild)
        warning = text.index("WARNING: the existing .venv runs Python")
        assert guard < rebuild < else_at < warning

    def test_a_healthy_venv_is_still_reused(self):
        assert "Reusing the existing .venv" in _script()


class TestTheCiStepProvesTheInstallerChooses:
    def test_the_pwsh_step_does_not_prebuild_the_venv(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8").replace("\r\n", "\n")
        step = ci.split("Offline install also works from a PowerShell 7 prompt", 1)[1]
        assert "Remove-Item -Recurse -Force .venv" in step
        assert "install.bat -Offline" in step
        assert "python -m venv .venv" not in step, (
            "pre-building the venv hides the interpreter choice this step must prove")
