"""Read Windows Events over SSH (no agent required) – B9 / C14 / C15.

- Read by EventRecordID: store the last RecordId for each log on each server → no duplicates or missed events when IT Ops restarts.
- On first run, record only the current position (do not import old logs).
- If a new RecordId is lower than the stored position, or the oldest record is greater than position + 1, logs may have been cleared / overwritten; report the gap."""
import base64
import json
import logging
import time

log = logging.getLogger("winevents")

WANT = {"Security": [1102, 1100, 4720, 4728, 4732, 4756], "System": [104, 1074, 6006]}
PLANNED = {1074, 6006}   # disabled machines có kế hoạch (User32 1074) / service log dừng do disabled machines (6006)

PS_TEMPLATE = r"""
$ErrorActionPreference='SilentlyContinue'
$cur=ConvertFrom-Json '__CUR__'
$want=ConvertFrom-Json '__WANT__'
foreach($ln in 'Security','System'){
  $n=Get-WinEvent -LogName $ln -MaxEvents 1
  $o=Get-WinEvent -LogName $ln -MaxEvents 1 -Oldest
  if(-not $n){ "##ERR $ln"; continue }
  "##LOG $ln $($n.RecordId) $($o.RecordId)"
  $c=[int64]($cur.$ln)
  if($c -gt 0 -and $n.RecordId -gt $c){
    $ids=($want.$ln | ForEach-Object { "EventID=$_" }) -join ' or '
    $x="*[System[($ids) and EventRecordID>$c]]"
    Get-WinEvent -LogName $ln -FilterXPath $x -MaxEvents 300 | Sort-Object RecordId | ForEach-Object {
      $p=@($_.Properties | ForEach-Object { "$($_.Value)" })
      $m=''
      if($_.Message){ $m=(($_.Message -split "`n")[0]).Trim() }
      $o=[ordered]@{log=$ln;id=$_.Id;rec=$_.RecordId;t=$_.TimeCreated.ToUniversalTime().ToString('o');p=$p;m=$m}
      "##EV "+($o | ConvertTo-Json -Compress)
    }
  }
}
"""


def build_command(cursor: dict) -> str:
    ps = PS_TEMPLATE.replace("__CUR__", json.dumps({k: int(cursor.get(k, 0)) for k in WANT})) \
                    .replace("__WANT__", json.dumps(WANT))
    return "powershell -NoProfile -NonInteractive -EncodedCommand " + base64.b64encode(ps.encode("utf-16-le")).decode()


def _p(props, i):
    return props[i] if isinstance(props, list) and len(props) > i else ""


def describe(ev: dict) -> str:
    """Chuỗi chuẩn hoá cho log rule: 'EventID=4720 Log=Security Record=… target=…; …'."""
    i, p = ev.get("id"), ev.get("p") or []
    extra = ""
    if i == 4720:
        extra = f"target={_p(p, 0)}; by={_p(p, 4)}"
    elif i in (4728, 4732, 4756):
        extra = f"member={_p(p, 0)}; group={_p(p, 2)}; by={_p(p, 6)}"
    elif i == 1102:
        extra = f"by={_p(p, 1)}"
    elif i == 104:
        extra = f"by={_p(p, 0)}; channel={_p(p, 2)}"
    elif i == 1100:
        extra = f"planned={1 if ev.get('_planned') else 0}"
    return f"EventID={i} Log={ev.get('log')} Record={ev.get('rec')} {extra} | {(ev.get('m') or '')[:300]}".strip()


def parse_output(text: str, cursor: dict) -> tuple[dict, list[dict], list[str]]:
    """Trả (cursor mới, danh sách normalized events, ghi chú)."""
    new_cur = dict(cursor)
    evs, notes, anomalies = [], [], []
    logs = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("##LOG "):
            parts = line.split()
            try:
                logs[parts[1]] = (int(parts[2]), int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0)
            except (IndexError, ValueError):
                pass
        elif line.startswith("##ERR "):
            notes.append(f"Unable to read the log {line[6:]} (Event Log Readers permission may be missing)")
        elif line.startswith("##EV "):
            try:
                evs.append(json.loads(line[5:]))
            except ValueError:
                pass
    for ln, (newest, oldest) in logs.items():
        c = int(cursor.get(ln, 0))
        if c == 0:
            new_cur[ln] = newest                 # lần đầu: chỉ ghi nhận vị trí
            continue
        if newest < c:
            anomalies.append(f"RecordId decreased from {c} to {newest} Log={ln} – the log may have been cleared or recreated")
            new_cur[ln] = newest
            continue
        if oldest > c + 1:
            anomalies.append(f"RecordId has a gap: last read position was {c}, the oldest current record is {oldest} Log={ln} "
                             f"– the log was cleared or overwritten before it could be read")
        got = [e["rec"] for e in evs if e.get("log") == ln and isinstance(e.get("rec"), int)]
        new_cur[ln] = max([c, newest] + got)
    planned_t = [e.get("t", "") for e in evs if e.get("id") in PLANNED]
    for e in evs:
        if e.get("id") == 1100:
            e["_planned"] = any(abs(_ts(e.get("t")) - _ts(t)) < 900 for t in planned_t)
    out = [{"id": e.get("id"), "log": e.get("log"), "t": e.get("t", ""), "message": describe(e),
            "severity": 2 if e.get("id") in (1102, 104) else 4 if e.get("id") in (4720, 4728, 4732, 4756) else 5}
           for e in evs if e.get("id") not in PLANNED]
    out += [{"id": 0, "log": "", "t": "", "message": a, "severity": 3} for a in anomalies]
    return new_cur, out, notes


def _ts(s: str) -> float:
    from datetime import datetime
    try:
        return datetime.fromisoformat((s or "").replace("Z", "+00:00")[:32]).timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------- vị trí đọc (lưu trong Setting "win_cursor")
def load_cursor(key: str) -> dict:
    from ..db import SessionLocal
    from .. import models
    db = SessionLocal()
    try:
        s = db.get(models.Setting, "win_cursor")
        return dict(((s.value if s else {}) or {}).get(key) or {})
    finally:
        db.close()


def save_cursor(key: str, cur: dict):
    from ..db import SessionLocal
    from .. import models
    db = SessionLocal()
    try:
        s = db.get(models.Setting, "win_cursor")
        v = dict((s.value if s else {}) or {})
        v[key] = {k: int(x) for k, x in cur.items()}
        if s:
            s.value = v
        else:
            db.add(models.Setting(key="win_cursor", value=v))
        db.commit()
    finally:
        db.close()


def submit_events(target: str, hostname: str, events: list[dict]):
    """Enqueue into the shared queue (bỏ qua danh sách IP cho phép vì do chính IT Ops chủ động đọc)."""
    import asyncio
    from ..events import get_queue, STATS
    q = get_queue()
    for e in events:
        try:
            q.put_nowait({"kind": "winlog", "source_ip": target, "severity": e["severity"], "facility": None,
                          "host": hostname or target, "app": "WinEvent", "message": e["message"], "device_ts": e["t"][:40],
                          "data": {"event_id": e["id"], "log": e["log"]}})
            STATS["received"] += 1
        except asyncio.QueueFull:
            STATS["dropped_queue"] += 1


async def collect(conn, target: str, hostname: str) -> tuple[int, list[str]]:
    """Gọi trong sessions SSH đang mở of check Windows. Trả (số sự kiện, ghi chú)."""
    import asyncio
    key = target.lower()
    cur = load_cursor(key)
    t0 = time.time()
    r = await asyncio.wait_for(conn.run(build_command(cur), check=False), timeout=60)
    new_cur, evs, notes = parse_output(r.stdout or "", cur)
    save_cursor(key, new_cur)
    if evs:
        submit_events(target, hostname, evs)
    log.debug("winevents %s: %d events in %.1fs", target, len(evs), time.time() - t0)
    return len(evs), notes
