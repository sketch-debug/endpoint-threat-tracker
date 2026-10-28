"""HTTP coverage for incident detail, workflow and report routes.

The domain functions in incidents.py were tested directly long before the
routes were; this file drives them the way the dashboard does - through
POSTed forms and redirects - including the error redirects (bad type, bad
state, PC not on the incident) and both report endpoints.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import incidents
from app.normalize import iso, utcnow


@pytest.fixture()
def app(settings, monkeypatch):
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    return main_mod.create_app(settings)


@pytest.fixture()
def admin(app):
    client = TestClient(app)
    client.post("/login", data={"username": "admin", "password": "TestAdmin123!"})
    return client


@pytest.fixture()
def inc_id(admin):
    db = admin.app.state.db
    db.execute("INSERT INTO incidents(incident_key, type, created_at) "
               "VALUES(?,?,?)", ("IR-77", "miner", iso(utcnow())))
    row = db.one("SELECT MAX(id) AS i FROM incidents")
    ident = int(row["i"])
    db.execute("INSERT INTO incident_pcs(incident_id, pc) VALUES(?,?)",
               (ident, "PC-1"))
    return ident


def _db(client):
    return client.app.state.db


class TestIncidentPages:
    def test_detail_renders_with_pc_and_actions(self, admin, inc_id):
        resp = admin.get(f"/incidents/{inc_id}")
        assert resp.status_code == 200
        assert "IR-77" in resp.text
        assert "PC-1" in resp.text

    def test_detail_missing_is_404(self, admin):
        assert admin.get("/incidents/99999").status_code == 404

    def test_list_filter_params_render(self, admin, inc_id):
        resp = admin.get("/incidents?status=open&severity=low&itype=miner")
        assert resp.status_code == 200
        assert "IR-77" in resp.text


class TestWorkflowRoutes:
    def test_entry_point_and_actions_save(self, admin, inc_id):
        r1 = admin.post(f"/incidents/{inc_id}/entry-point",
                        data={"entry_point": "USB stick"},
                        follow_redirects=False)
        assert r1.status_code == 303
        assert "msg=" in r1.headers["location"]
        assert "Entry point saved." in admin.get(r1.headers["location"]).text
        assert incidents.get(_db(admin), inc_id)["entry_point"] == "USB stick"

        r2 = admin.post(f"/incidents/{inc_id}/actions",
                        data={"containment_actions": "isolate PC-1"},
                        follow_redirects=False)
        assert r2.status_code == 303
        assert "Actions saved." in admin.get(r2.headers["location"]).text
        assert incidents.get(_db(admin), inc_id)["containment_actions"] == \
            "isolate PC-1"

    def test_type_override_and_unknown_type_error(self, admin, settings, inc_id):
        real_type = next(t for t in settings.types if t != "miner")
        ok = admin.post(f"/incidents/{inc_id}/type", data={"itype": real_type},
                        follow_redirects=False)
        assert ok.status_code == 303
        assert "analyst override" in admin.get(ok.headers["location"]).text
        assert incidents.get(_db(admin), inc_id)["type"] == real_type

        bad = admin.post(f"/incidents/{inc_id}/type", data={"itype": "no_such"},
                         follow_redirects=False)
        assert bad.status_code == 303
        assert "err=" in bad.headers["location"]
        assert "unknown incident type" in admin.get(bad.headers["location"]).text

    def test_reimaged_flag_persists(self, admin, inc_id):
        resp = admin.post(f"/incidents/{inc_id}/reimaged", data={"reimaged": "1"},
                          follow_redirects=False)
        assert resp.status_code == 303
        assert incidents.get(_db(admin), inc_id)["reimaged"] == 1

    def test_checklist_toggle_persists(self, admin, inc_id):
        resp = admin.post(f"/incidents/{inc_id}/checklist",
                          data={"item": "collect images", "done": "1"},
                          follow_redirects=False)
        assert resp.status_code == 303
        row = _db(admin).one(
            "SELECT done FROM checklist_state WHERE incident_id=? AND item=?",
            (inc_id, "collect images"))
        assert row and row["done"] == 1

    def test_pc_transition_happy_path(self, admin, inc_id):
        resp = admin.post(f"/incidents/{inc_id}/pc/PC-1/transition",
                          data={"new_state": "isolated", "note": "pulled cable"},
                          follow_redirects=False)
        assert resp.status_code == 303
        assert "msg=" in resp.headers["location"]
        # pin the exact (encoded) message in the Location, then that the
        # page rendered it as a success flash
        assert "PC-1+-%3E+isolated." in resp.headers["location"]
        page = admin.get(resp.headers["location"])
        assert "flash-ok" in page.text and "isolated." in page.text
        row = _db(admin).one(
            "SELECT state FROM incident_pcs WHERE incident_id=? AND pc=?",
            (inc_id, "PC-1"))
        assert row["state"] == "isolated"

    def test_pc_transition_error_redirects(self, admin, inc_id):
        bad_state = admin.post(f"/incidents/{inc_id}/pc/PC-1/transition",
                               data={"new_state": "bogus"},
                               follow_redirects=False)
        assert bad_state.status_code == 303
        assert "err=" in bad_state.headers["location"]
        assert "invalid state" in admin.get(bad_state.headers["location"]).text

        bad_pc = admin.post(f"/incidents/{inc_id}/pc/PC-404/transition",
                            data={"new_state": "isolated"},
                            follow_redirects=False)
        assert bad_pc.status_code == 303
        assert "not part of incident" in admin.get(bad_pc.headers["location"]).text

    def test_close_then_reopen_round_trip(self, admin, inc_id):
        closed = admin.post(f"/incidents/{inc_id}/close", data={"note": "clean"},
                            follow_redirects=False)
        assert closed.status_code == 303
        assert "Incident closed." in admin.get(closed.headers["location"]).text
        assert incidents.get(_db(admin), inc_id)["status"] == "closed"

        reopened = admin.post(f"/incidents/{inc_id}/reopen",
                              data={"reason": "new signal"},
                              follow_redirects=False)
        assert reopened.status_code == 303
        assert "Incident reopened." in admin.get(reopened.headers["location"]).text
        assert incidents.get(_db(admin), inc_id)["status"] == "open"

    def test_workflow_requires_analyst(self, settings, monkeypatch, inc_id):
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
        app = main_mod.create_app(settings)
        admin = TestClient(app)
        admin.post("/login", data={"username": "admin",
                                   "password": "TestAdmin123!"})
        admin.post("/users", data={"username": "vic",
                                   "password": "ViewerPass123", "role": "viewer"})
        viewer = TestClient(app)
        viewer.post("/login", data={"username": "vic", "password": "ViewerPass123"})
        # reads are allowed for viewers...
        assert viewer.get(f"/incidents/{inc_id}").status_code == 200
        # ...writes are not
        assert viewer.post(f"/incidents/{inc_id}/actions",
                           data={"containment_actions": "x"}).status_code == 403


class TestReports:
    def test_report_renders_html(self, admin, inc_id):
        resp = admin.get(f"/incidents/{inc_id}/report")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "IR-77" in resp.text

    def test_report_missing_is_404(self, admin):
        assert admin.get("/incidents/99999/report").status_code == 404

    def test_report_download_serves_a_file(self, admin, settings, inc_id):
        resp = admin.get(f"/incidents/{inc_id}/report/download")
        assert resp.status_code == 200
        assert "attachment" in resp.headers["content-disposition"]
        assert "IR-77" in resp.text
        assert any(settings.reports_dir.glob("*.html")), \
            "download must materialize the report in reports/"

    def test_download_missing_is_404(self, admin):
        assert admin.get("/incidents/99999/report/download").status_code == 404


class TestSignalTruncation:
    """The page shows 200 signals and the report 300; when the list is cut,
    both must say so instead of reading as the complete history."""

    def test_page_and_report_flag_truncated_signal_lists(self, admin, inc_id):
        db = _db(admin)
        ts = iso(utcnow())
        for i in range(301):
            db.execute(
                "INSERT INTO signals(ts, pc, rule_id, category, weight, "
                "title, detail, incident_id, dedup_key) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, "PC-1", "rule.test", "execution", 10, f"sig {i}",
                 "", inc_id, f"trunc-{i}"))
        page = admin.get(f"/incidents/{inc_id}")
        assert page.status_code == 200
        assert "showing first 200 of" in page.text
        assert "301 signals" in page.text
        assert "Signals (301)" in page.text  # heading still shows the total
        report = admin.get(f"/incidents/{inc_id}/report")
        assert report.status_code == 200
        assert "first 300 of 301 signals" in report.text
        assert "1 stored but not printed here" in report.text
