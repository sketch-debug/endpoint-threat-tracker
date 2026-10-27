"""The .env password and the admin account in the database must agree.

install.ps1 writes TRACKER_ADMIN_PASSWORD into .env, but bootstrap_admin only
creates 'admin' when the user table is empty - it never updates an existing
account. So on a re-run over a surviving database the file printed as "your
admin password" was refused at the login page, five refusals locked the
account for five minutes, and the only documented reset was deleting the
database.

auth.adopt_env_password() closes that: install.ps1 adopts the value it just
wrote, and reports which of the four cases it hit so a failure prints a
warning instead of a false "Existing admin account now uses this password".
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import auth
from app.db import Database

ROOT = Path(__file__).resolve().parent.parent

# the literal block install.ps1 hands to the venv's python
_SYNC_SNIPPET = re.compile(r"\$pwCode = @'\n(.*?)\n'@", re.S)

# password must be something other than what is already stored
_UNCHANGED_PASSWORD = "correct horse battery staple"


def _pw(db: Database, username: str, password: str) -> bool:
    row = db.one("SELECT password_hash FROM users WHERE username=?",
                 (username,))
    return bool(row) and auth.verify_password(password, row["password_hash"])


def test_adopt_reports_synced_and_password_actually_works(db: Database) -> None:
    auth.create_user(db, "admin", "the-old-one", "admin", actor="system")

    assert auth.adopt_env_password(db, "admin", "the-new-one") == "synced"
    # the replacement is real, not just reported
    assert _pw(db, "admin", "the-new-one")
    assert not _pw(db, "admin", "the-old-one")

    # and it is idempotent: adopting the same value again changes nothing
    assert auth.adopt_env_password(db, "admin", "the-new-one") == "matched"
    assert _pw(db, "admin", "the-new-one")


def test_adopt_reports_matched_when_env_already_agrees(db: Database) -> None:
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")

    assert auth.adopt_env_password(db, "admin", _UNCHANGED_PASSWORD) == "matched"
    # unchanged: same password still verifies
    assert _pw(db, "admin", _UNCHANGED_PASSWORD)


def test_adopt_reports_no_password_instead_of_touching_the_account(
        db: Database) -> None:
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")

    assert auth.adopt_env_password(db, "admin", "") == "no-password"
    assert _pw(db, "admin", _UNCHANGED_PASSWORD)


def test_adopt_never_touches_non_admin_accounts(db: Database) -> None:
    auth.create_user(db, "admin", "admin-old", "admin", actor="system")
    auth.create_user(db, "analyst", "analyst-pw", "analyst", actor="system")

    assert auth.adopt_env_password(db, "admin", "admin-new") == "synced"
    assert _pw(db, "analyst", "analyst-pw")
    # the deployer's variable is never applied to other users
    assert not _pw(db, "analyst", "admin-new")


def test_adopt_reports_no_admin_when_the_table_is_empty(db: Database) -> None:
    assert auth.adopt_env_password(db, "admin", "whatever") == "no-admin"


def test_adopt_refuses_a_password_shorter_than_the_users_page_minimum(
        db: Database) -> None:
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")

    assert auth.adopt_env_password(db, "admin", "short") == "short"
    assert _pw(db, "admin", _UNCHANGED_PASSWORD)


def test_install_adopts_the_password_it_just_wrote_and_warns_on_failure() -> None:
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")
    match = _SYNC_SNIPPET.search(script)
    assert match, "install.ps1 no longer hands auth.adopt_env_password to python"

    # the block runs only once .env has been written, so it adopts the value
    # actually on disk rather than one generated but never saved
    assert script.index("[System.IO.File]::WriteAllLines($EnvFile, $lines)") < \
        match.start()

    body = match.group(1)
    compile(body, "<install.ps1 pw>", "exec")  # syntax is valid python
    assert "adopt_env_password" in body
    assert "env_password_status" in body, "the stale-.env path must be able to check"
    assert "print('error:' + str(exc))" in body, "must report a traceback"

    # the install-time guard: adopt only when this run wrote the password
    assert "if ($shouldSetAdmin) {" in script
    assert "Invoke-AdminPasswordHelper 'adopt'" in script
    # ...and only the 'synced' result may print the success line; every other
    # result falls through to the warning or to no message at all
    assert "$syncResult -eq 'synced'" in script
    assert "WARNING: could not reconcile" in script
    benign = "@('matched', 'no-admin', 'no-password')"
    assert benign in script, "benign results must not be reported as failures"


def test_install_warns_instead_of_overwriting_when_its_env_is_stale() -> None:
    """The other direction: a non-default .env the account no longer matches.

    install did not choose that password, so adopting it would silently undo
    a password set on the Users page. It must only say the .env value will be
    refused - the final "password in .env" line is otherwise a false promise.
    """
    script = (ROOT / "install.ps1").read_text(encoding="utf-8")

    # check-only branch, entered only when .env was left untouched and holds
    # a non-default password (the default case is warned about separately)
    assert "elseif ($currentPassword -and $currentPassword -ne 'admin1234')" in script
    assert "Invoke-AdminPasswordHelper 'check'" in script
    # and it must never call adopt outside the shouldSetAdmin branch
    adopt_calls = script.count("Invoke-AdminPasswordHelper 'adopt'")
    assert adopt_calls == 1
    warn_at = script.index("does not match TRACKER_ADMIN_PASSWORD in .env")
    assert warn_at > script.index("elseif ($currentPassword")
    # the warning must say which password wins
    assert "The account keeps its password" in script


def test_status_check_never_writes(db: Database) -> None:
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")
    before = db.one("SELECT password_hash FROM users WHERE username='admin'")
    assert auth.env_password_status(db, "admin", "something-else") == "mismatch"
    after = db.one("SELECT password_hash FROM users WHERE username='admin'")
    assert before["password_hash"] == after["password_hash"]
    # and the mismatch it reports is real
    assert _pw(db, "admin", _UNCHANGED_PASSWORD)


def test_status_reports_every_case(db: Database) -> None:
    assert auth.env_password_status(db, "admin", "") == "no-password"
    assert auth.env_password_status(db, "admin", "short") == "short"
    assert auth.env_password_status(db, "admin", _UNCHANGED_PASSWORD) == \
        "no-admin"
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")
    assert auth.env_password_status(db, "admin", _UNCHANGED_PASSWORD) == \
        "matched"
    assert auth.env_password_status(db, "admin", "something-else") == \
        "mismatch"


def test_startup_bootstrap_still_never_resets_an_existing_password(
        tmp_path: Path) -> None:
    """The inverse guard: re-running the app must NOT adopt anything.

    Otherwise a password changed on the Users page would be reverted to the
    .env value on the next restart, silently and without an audit trail.
    """
    from app.config import Settings

    db_path = str(tmp_path / "tracker.db")
    settings = Settings(base_dir=ROOT, path_overrides={"db_path": db_path})
    database = Database(db_path)
    try:
        auth.create_user(database, "admin", "changed-on-users-page",
                         "admin", actor="system")
        from app.main import bootstrap_admin
        bootstrap_admin(database, settings)
        # still the password set through the UI, not the env default
        assert _pw(database, "admin", "changed-on-users-page")
        assert not _pw(database, "admin", "admin1234")
    finally:
        database.close()


def test_matching_keeps_the_stored_hash_byte_identical(db: Database) -> None:
    """A match must not re-hash: no needless write, no audit noise."""
    auth.create_user(db, "admin", _UNCHANGED_PASSWORD, "admin", actor="system")
    before = db.one("SELECT password_hash FROM users WHERE username='admin'")
    auth.adopt_env_password(db, "admin", _UNCHANGED_PASSWORD)
    after = db.one("SELECT password_hash FROM users WHERE username='admin'")
    assert before["password_hash"] == after["password_hash"]


def test_adopt_writes_a_hash_the_login_path_accepts(db: Database) -> None:
    """The new hash must pass the same parser authenticate() uses."""
    auth.create_user(db, "admin", "old-password", "admin", actor="system")
    auth.adopt_env_password(db, "admin", "brand-new")
    stored = db.one("SELECT password_hash FROM users "
                    "WHERE username='admin'")["password_hash"]
    assert stored.startswith("pbkdf2_sha256$")
    assert auth.verify_password("brand-new", stored)
