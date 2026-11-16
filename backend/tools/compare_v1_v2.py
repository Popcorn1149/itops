"""Comparison report v1 (SQLite) ↔ v2 (PostgreSQL) while running in parallel.

    python tools/compare_v1_v2.py [V1_FOLDER] [--hours 24]

Reads the v1 database READ-ONLY (v1 keeps running normally) and the v2 database (v2 app running or not).
Compares each check: runs, DOWN count, uptime %, last status – over the last N hours; newly opened alerts,
open alerts, logs received. Writes an HTML report to backend/data-v2-local/reports/ and prints a summary.
"""
import html
import os
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DATA_DIR", str(BACKEND / "data-v2-local"))
os.environ.setdefault("PG_LOCAL", "1")
os.environ.setdefault("PG_LOCAL_PORT", "5434")

UPTIME_TOL = 2.0   # uptime differs by more than 2 % points → flag


def _ts(v):
    if v is None or isinstance(v, datetime):
        return v
    s = str(v).replace("T", " ")[:26]
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None


def collect(q, since: datetime) -> dict:
    """q(sql, params) → list[tuple]. SQL uses only syntax common to SQLite/PostgreSQL."""
    checks = {r[0]: {"name": r[1], "type": r[2], "asset": r[3] or "", "enabled": bool(r[4])}
              for r in q("SELECT c.id, c.name, c.type, a.name, c.enabled FROM checks c "
                         "LEFT JOIN assets a ON a.id = c.asset_id", {})}
    per = {cid: {"n": 0, "down": 0, "last": None, "last_ts": None} for cid in checks}
    for cid, status, down, ts in q("SELECT check_id, status, down, ts FROM check_results WHERE ts >= :s ORDER BY ts", {"s": since}):
        if cid not in per:
            continue
        p = per[cid]
        p["n"] += 1
        is_down = bool(down) if down is not None else status == "down"
        p["down"] += is_down
        p["last"], p["last_ts"] = status, _ts(ts)
    for cid, p in per.items():
        p["uptime"] = round(100 * (p["n"] - p["down"]) / p["n"], 2) if p["n"] else None
    alerts_new = {}
    for sev, n in q("SELECT severity, COUNT(*) FROM alerts WHERE opened_at >= :s GROUP BY severity", {"s": since}):
        alerts_new[sev] = n
    open_now = q("SELECT COUNT(*) FROM alerts WHERE status <> 'resolved'", {})[0][0]
    events = q("SELECT COUNT(*) FROM events WHERE ts >= :s", {"s": since})[0][0]
    return {"checks": checks, "per": per, "alerts_new": alerts_new, "open": open_now, "events": events}


def sqlite_q(path: Path):
    con = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, timeout=30)

    def q(sql, params):
        p = {k: (v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v) for k, v in params.items()}
        return con.execute(sql, p).fetchall()
    return q, con


def pg_q():
    from sqlalchemy import text
    from app.db import engine
    conn = engine.connect()

    def q(sql, params):
        return [tuple(r) for r in conn.execute(text(sql), params).fetchall()]
    return q, conn


def compare(a: dict, b: dict) -> list[dict]:
    rows = []
    for cid in sorted(set(a["checks"]) | set(b["checks"])):
        c = a["checks"].get(cid) or b["checks"][cid]
        p1, p2 = a["per"].get(cid), b["per"].get(cid)
        flags = []
        if p1 is None:
            flags.append("only in v2")
        elif p2 is None:
            flags.append("only in v1")
        else:
            if p1["n"] and not p2["n"]:
                flags.append("v2 did not run check")
            elif p2["n"] and not p1["n"]:
                flags.append("v1 did not run check")
            if p1["last"] and p2["last"] and p1["last"] != p2["last"]:
                flags.append(f"status differs ({p1['last']} / {p2['last']})")
            if p1["uptime"] is not None and p2["uptime"] is not None and abs(p1["uptime"] - p2["uptime"]) > UPTIME_TOL:
                flags.append(f"uptime differs by {abs(p1['uptime'] - p2['uptime']):.1f}%")
        rows.append({"id": cid, **c, "v1": p1, "v2": p2, "flags": flags})
    return rows


def _fmt(p):
    if not p or not p["n"]:
        return "–", "–", "–", "–"
    return str(p["n"]), str(p["down"]), f"{p['uptime']:.2f}%", p["last"] or "–"


def render(rows, a, b, hours, v1_path) -> str:
    gen = datetime.now().strftime("%Y-%m-%d %H:%M")
    ok = sum(1 for r in rows if not r["flags"])
    tr = []
    for r in rows:
        f1, f2 = _fmt(r["v1"]), _fmt(r["v2"])
        cls = "bad" if r["flags"] else ""
        cells = "".join(f"<td>{html.escape(x)}</td>" for x in (r["name"], r["asset"], r["type"]))
        cells += "".join(f"<td class=n>{x}</td>" for x in f1) + "".join(f"<td class=n>{x}</td>" for x in f2)
        cells += f"<td>{html.escape('; '.join(r['flags']) or 'match')}</td>"
        tr.append(f"<tr class='{cls}'>{cells}</tr>")

    def sev(d):
        return ", ".join(f"{k}: {v}" for k, v in sorted(d.items())) or "0"
    return f"""<!DOCTYPE html><html lang=en><meta charset=utf-8><title>Compare v1 ↔ v2 – {gen}</title>
<style>body{{font:14px system-ui,sans-serif;margin:24px;color:#222}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:4px 8px;text-align:left}}th{{background:#f4f4f4}}td.n{{text-align:right}}
tr.bad td{{background:#fff3f0}}.s{{display:flex;gap:24px;margin:12px 0}}.s div{{border:1px solid #ddd;border-radius:6px;padding:8px 12px}}</style>
<h1>Compare v1 ↔ v2</h1><p>Period: last {hours} hours · generated {gen} · v1: {html.escape(str(v1_path))}</p>
<div class=s><div><b>{ok}/{len(rows)}</b> checks match</div>
<div>New alerts – v1: {sev(a['alerts_new'])} · v2: {sev(b['alerts_new'])}</div>
<div>Open – v1: {a['open']} · v2: {b['open']}</div>
<div>Logs received – v1: {a['events']} · v2: {b['events']}</div></div>
<p>In parallel mode v2 does not receive logs on 514/162, so v2 shows fewer logs and log-based alerts – this is normal.</p>
<table><tr><th rowspan=2>Check</th><th rowspan=2>Asset</th><th rowspan=2>Type</th><th colspan=4>v1</th><th colspan=4>v2</th><th rowspan=2>Result</th></tr>
<tr><th>Runs</th><th>DOWN</th><th>Uptime</th><th>Last status</th><th>Runs</th><th>DOWN</th><th>Uptime</th><th>Last status</th></tr>
{''.join(tr)}</table></html>"""


def main(argv):
    hours = 24
    if "--hours" in argv:
        hours = int(argv[argv.index("--hours") + 1])
    args = [x for i, x in enumerate(argv) if not x.startswith("--") and (i == 0 or argv[i - 1] != "--hours")]
    v1 = Path(args[0]) if args else ROOT.parent / "itops"
    db1 = v1 / "backend" / "data-local" / "itops.db"
    if not db1.is_file():
        print(f"[ERROR] v1 database not found: {db1}")
        return 1
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
    q1, c1 = sqlite_q(db1)
    q2, c2 = pg_q()
    try:
        a, b = collect(q1, since), collect(q2, since)
    finally:
        c1.close()
        c2.close()
    rows = compare(a, b)
    out_dir = Path(os.environ["DATA_DIR"]) / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"compare-v1-v2-{datetime.now():%Y%m%d-%H%M}.html"
    out.write_text(render(rows, a, b, hours, v1), encoding="utf-8")
    bad = [r for r in rows if r["flags"]]
    print(f"{len(rows) - len(bad)}/{len(rows)} checks match over {hours} hours. Logs received: v1 {a['events']} / v2 {b['events']}. "
          f"Open alerts: v1 {a['open']} / v2 {b['open']}.")
    for r in bad:
        print(f"  ! {r['name']} ({r['asset']}): {'; '.join(r['flags'])}")
    print(f"Report: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
