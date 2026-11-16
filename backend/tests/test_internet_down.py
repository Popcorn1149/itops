"""Internet check: when IT's own targets (e.g. one WAN's public IP) stop answering, the check is DOWN even if
DNS / HTTP still work through the server's other route – otherwise uptime / reports show 100% during a WAN outage."""
import asyncio

from app.collectors import network as n


def _run(monkeypatch, target, alive):
    async def ping_one(t, count, timeout):
        return {"target": t, "loss": 0.0 if alive else 100.0, "rtt": 3.0 if alive else None, "jitter": 0.1 if alive else None}

    async def dns(name, timeout):
        return {"name": name, "ok": True, "ms": 5.0}

    async def http(url, timeout):
        return {"url": url, "ok": True, "code": 204, "ms": 20.0}

    async def pub(timeout):
        return "1.2.3.4"

    monkeypatch.setattr(n, "_ping_one", ping_one)
    monkeypatch.setattr(n, "_dns", dns)
    monkeypatch.setattr(n, "_http_probe", http)
    monkeypatch.setattr(n, "_public_ip", pub)
    return asyncio.run(n.internet(target, {}))


def test_own_target_silent_is_down(monkeypatch):
    r = _run(monkeypatch, "1.53.78.90", alive=False)
    assert r.status == "fail" and r.down is True and r.latency is None and "1.53.78.90" in r.message


def test_default_targets_silent_stays_warning(monkeypatch):
    r = _run(monkeypatch, "", alive=False)                 # public resolvers silent but DNS/HTTP fine → ICMP blocked?
    assert r.status == "warn" and not r.down and r.latency is None


def test_alive_reports_rtt(monkeypatch):
    r = _run(monkeypatch, "1.53.78.90", alive=True)
    assert r.status == "ok" and r.latency == 3.0


def test_custom_rule():
    assert n.is_custom_inet("1.53.78.90") and n.is_custom_inet("8.8.8.8, 1.53.78.90")
    assert not n.is_custom_inet("") and not n.is_custom_inet("1.1.1.1") and not n.is_custom_inet("8.8.8.8;9.9.9.9")


def test_migration_fixes_history(client, admin):
    """0013 marks past 100%-loss results of own-target internet checks as DOWN (run its upgrade again on test data)."""
    import importlib.util
    import pathlib
    from datetime import timedelta
    import sqlalchemy as sa
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from app import models
    from app.db import SessionLocal, engine
    from app.models import now
    with SessionLocal() as db:
        own = models.Check(name="mig-own", type="internet", target="1.53.78.90", interval=60, enabled=True, config={})
        pub = models.Check(name="mig-pub", type="internet", target="", interval=60, enabled=True, config={})
        db.add_all([own, pub])
        db.flush()
        for c in (own, pub):
            db.add(models.CheckResult(check_id=c.id, ts=now() - timedelta(minutes=5), status="warn", latency=14288.6, value=100.0, down=False))
            db.add(models.CheckResult(check_id=c.id, ts=now() - timedelta(minutes=4), status="ok", latency=3.0, value=0.0, down=False))
        db.commit()
        ido, idp = own.id, pub.id
    spec = importlib.util.spec_from_file_location("m13", pathlib.Path(__file__).parent.parent / "migrations/versions/0013_internet_down_history.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    with engine.begin() as conn:
        import alembic.op as op_mod
        ops = Operations(MigrationContext.configure(conn))
        op_mod._proxy = ops
        m.upgrade()
    with SessionLocal() as db:
        r = {(x.check_id, x.value): x for x in db.query(models.CheckResult).filter(models.CheckResult.check_id.in_([ido, idp]))}
        assert r[(ido, 100.0)].down is True and r[(ido, 100.0)].latency is None
        assert r[(idp, 100.0)].down is False and r[(idp, 100.0)].latency is None      # public resolvers: still only a warning
        assert r[(ido, 0.0)].down is False and r[(ido, 0.0)].latency == 3.0
