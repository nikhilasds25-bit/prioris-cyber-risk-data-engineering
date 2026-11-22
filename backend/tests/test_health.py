from fastapi.testclient import TestClient
from app.main import app


def test_liveness_is_available_without_database():
    client = TestClient(app)
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "prioris-api"}


def test_service_root_identifies_api():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["service"] == "PRIORIS API"


def test_read_api_is_get_only():
    client = TestClient(app)
    response = client.post("/api/v1/dashboard/summary")
    assert response.status_code == 405
