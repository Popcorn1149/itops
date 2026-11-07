import os
import sys
import tempfile

# Phải đặt env trước khi import app (db.py đọc DATA_DIR khi import)
_TMP = tempfile.mkdtemp(prefix="itops-qa-")
os.environ.update({"DATA_DIR": _TMP, "DISABLE_SCHEDULER": "1", "ADMIN_USER": "admin", "ADMIN_PASSWORD": "Admin@12345", "LOG_LEVEL": "WARNING",
                   # test cũ chạy với admin chưa bật 2FA; test_security_p1.py tự bật lại để kiểm tra cổng bắt buộc 2FA
                   "REQUIRE_2FA_ADMIN": "0"})
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests import pgtest  # noqa: E402
pgtest.setup()          # tạo CSDL PostgreSQL riêng cho lần chạy test này (xem tests/pgtest.py)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tests import simulators  # noqa: E402

SIM_PORT = simulators.start_sim()
RX = {"udp": simulators.free_port(), "trap": simulators.free_port()}
os.environ.update({"SYSLOG_UDP_PORT": str(RX["udp"]), "SYSLOG_TCP_PORT": str(RX["udp"]), "TRAP_PORT": str(RX["trap"]),
                   "RECEIVER_BIND": "127.0.0.1", "EVENTS_PER_SEC_PER_SOURCE": "300"})
os.environ["TELEGRAM_API_BASE"] = f"http://127.0.0.1:{SIM_PORT}"

from app.main import app  # noqa: E402
from app import notify  # noqa: E402
notify.TELEGRAM_API = os.environ["TELEGRAM_API_BASE"]


def pytest_sessionfinish(session, exitstatus):
    pgtest.teardown()


@pytest.fixture(scope="session")
def rx():
    return RX


@pytest.fixture(scope="session")
def sim_port():
    return SIM_PORT


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _no_shared_cookies(client):
    """Đăng nhập giờ đặt cookie phiên; TestClient dùng chung giữ cookie → xoá trước mỗi test để
    request không kèm header Authorization thật sự là "chưa đăng nhập"."""
    client.cookies.clear()
    yield
    client.cookies.clear()


@pytest.fixture(scope="session")
def admin(client):
    r = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@12345"})
    assert r.status_code == 200, r.text
    h = {"Authorization": f"Bearer {r.json()['token']}"}
    client.cookies.clear()
    # cảnh báo audit (UC-14) tắt mặc định trong test để không lẫn với cảnh báo đang kiểm; test_secmon tự bật lại
    assert client.put("/api/secmon", json={"audit_alert": {"enabled": False}}, headers=h).status_code == 200
    return h


@pytest.fixture(scope="session")
def viewer(client, admin):
    client.post("/api/users", json={"username": "helpdesk", "password": "Viewer@123", "role": "viewer"}, headers=admin)
    r = client.post("/api/auth/login", json={"username": "helpdesk", "password": "Viewer@123"})
    client.cookies.clear()
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture
def clean(client, admin):
    """Xoá dữ liệu hạ tầng trước mỗi test cần status sạch."""
    client.post("/api/reset-data", json={"confirm": "XOA"}, headers=admin)
    from app import events
    events.invalidate_caches()
    events._window.clear()
    simulators.STATE["telegram"].clear()
    simulators.STATE["webhook"].clear()
    yield
