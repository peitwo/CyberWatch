"""Isolated CyberWatch API tests using a temporary SQLite database."""
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from app.main import app, get_session


@pytest.fixture
def client():
    """Provide a test client backed by a temporary database, never the app DB."""
    with TemporaryDirectory() as temp:
        db = Path(temp) / "test.db"
        test_engine = create_engine(
            f"sqlite:///{db}", connect_args={"check_same_thread": False}
        )
        SQLModel.metadata.create_all(test_engine)

        def override_session():
            with Session(test_engine) as session:
                yield session

        app.dependency_overrides[get_session] = override_session
        try:
            # Do not enter TestClient's context manager: it would run the
            # application's lifespan, which initializes the main database.
            with closing(TestClient(app)) as test_client:
                yield test_client
        finally:
            app.dependency_overrides.pop(get_session, None)
            # Dispose the SQLite connection pool *before* TemporaryDirectory
            # removes test.db. Windows otherwise raises WinError 32.
            test_engine.dispose()


def test_event_lifecycle(client):
    created = client.post(
        "/events", json={"title": "Failed login attempts", "severity": "high"}
    )
    assert created.status_code == 201, created.text
    event_id = created.json()["id"]
    assert client.get(f"/events/{event_id}").status_code == 200
    assert len(client.get("/events", params={"severity": "high"}).json()) == 1
    updated = client.patch(f"/events/{event_id}", json={"severity": "medium"})
    assert updated.status_code == 200, updated.text
    assert updated.json()["severity"] == "medium"
    assert client.delete(f"/events/{event_id}").status_code == 204
    assert client.get(f"/events/{event_id}").status_code == 404


def test_validation(client):
    response = client.post("/events", json={"title": "a", "severity": "critical"})
    assert response.status_code == 422
