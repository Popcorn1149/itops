"""Monitoring report: uptime / outages / latency over 1-7-14-30 days, still correct after raw results are purged."""
from datetime import timedelta

from app import models, reports
from app.db import SessionLocal
from app.models import now


def _mk(db, name):
    c = models.Check(name=name, type="ping", target="10.9.9.9", interval=60, enabled=True, config={})
    db.add(c)
    db.flush()
    return c


def _res(db, cid, t, down, lat=None):
    db.add(models.CheckResult(check_id=cid, ts=t, status="fail" if down else "ok", latency=lat, message="no reply" if down else "",
                              down=down))


def test_report_uptime_outages_and_old_data(client, admin):
    with SessionLocal() as db:
        a, b = _mk(db, "rep-A"), _mk(db, "rep-B")
        t0 = now() - timedelta(hours=3)
        for i in range(120):                                   # A: 2h, a 10-minute outage in the middle
            t = t0 + timedelta(minutes=i)
            down = 50 <= i < 60
            _res(db, a.id, t, down, None if down else 2.0 + (i % 3))
            _res(db, b.id, t, False, 1.0)
        # B had an outage 20 days ago: raw rows already purged, only the summaries remain
        old = reports._midnight(now() - timedelta(days=20))
        db.add(models.CheckDaily(check_id=b.id, day=old, total=1440, down=30, lat_n=1410, lat_sum=1410.0, lat_min=0.5, lat_max=9.0))
        db.add(models.CheckOutage(check_id=b.id, start=old + timedelta(hours=5), end=old + timedelta(hours=5, minutes=30), message="x"))
        db.commit()
        ida, idb = a.id, b.id

    r = client.get("/api/reports/monitoring", params={"days": 1}, headers=admin).json()
    A = next(c for c in r["checks"] if c["id"] == ida)
    B = next(c for c in r["checks"] if c["id"] == idb)
    assert A["runs"] == 120 and A["down_runs"] == 10 and abs(A["uptime"] - 91.667) < 0.01
    assert A["outages"] == 1 and 600 <= A["downtime_s"] <= 660 and A["lat_min"] == 2.0 and A["lat_max"] == 4.0
    assert B["uptime"] == 100 and B["outages"] == 0
    o = [x for x in r["outage_list"] if x["check_id"] == ida]
    assert len(o) == 1 and o[0]["end"] and o[0]["message"] == "no reply"

    r30 = client.get("/api/reports/monitoring", params={"days": 30}, headers=admin).json()
    B30 = next(c for c in r30["checks"] if c["id"] == idb)
    assert B30["runs"] == 1440 + 120 and B30["down_runs"] == 30 and B30["outages"] == 1 and B30["downtime_s"] == 1800

    # rollup twice must not duplicate outages
    with SessionLocal() as db:
        reports.rollup(db, 2)
        reports.rollup(db, 2)
        assert db.query(models.CheckOutage).filter(models.CheckOutage.check_id == ida).count() == 1
    assert client.get("/api/reports/monitoring", params={"days": 5}, headers=admin).json()["days"] == 7   # only 1/7/14/30


def test_report_single_check(client, admin):
    with SessionLocal() as db:
        a, b = _mk(db, "one-A"), _mk(db, "one-B")
        db.commit()
        ida = a.id
    r = client.get("/api/reports/monitoring", params={"days": 7, "check_id": ida}, headers=admin).json()
    assert [c["id"] for c in r["checks"]] == [ida] and r["check"] == "one-A"


def test_report_several_checks(client, admin):
    with SessionLocal() as db:
        a, b, c = _mk(db, "many-A"), _mk(db, "many-B"), _mk(db, "many-C")
        db.commit()
        ids = [a.id, c.id]
    r = client.get("/api/reports/monitoring", params={"days": 7, "check_ids": f"{ids[0]},{ids[1]}"}, headers=admin).json()
    assert sorted(x["id"] for x in r["checks"]) == sorted(ids) and r["check"] == "many-A, many-C"
