"""Stand-in for the GoFlow2 binary in tests: prints the JSON lines of a file on stdout (like `goflow2 -format json`),
logs one INFO line on stderr like the real collector, then waits until it is stopped.

    python tests/fake_goflow2.py <flows.jsonl> [--exit]
"""
import sys
import time

print('time=2026-11-13T15:25:54+07:00 level=INFO msg="starting collection" scheme=netflow port=2055', file=sys.stderr, flush=True)
with open(sys.argv[1], encoding="utf-8") as fh:
    for line in fh:
        sys.stdout.write(line)
sys.stdout.flush()
if "--exit" in sys.argv:
    print('level=ERROR msg="application error" error="listen udp :2055: bind: address already in use"', file=sys.stderr, flush=True)
    sys.exit(1)
while True:
    time.sleep(1)
