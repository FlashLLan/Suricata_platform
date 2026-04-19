"""
Shared pytest fixtures for all backend tests.

Uses an in-memory SQLite database (via StaticPool so every connection shares
the same DB) and overrides FastAPI's get_db dependency so no test ever touches
the real application database.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.main import app
from app.database import Base, get_db

# ─── In-memory test database ─────────────────────────────────────────────────

SQLALCHEMY_TEST_URL = "sqlite://"   # pure in-memory

engine = create_engine(
    SQLALCHEMY_TEST_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,           # all connections share one in-memory DB
)
TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def reset_db():
    """Create all tables before each test and drop them after."""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client():
    """Return a FastAPI TestClient wired to the in-memory DB."""
    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ─── Helpers ──────────────────────────────────────────────────────────────────

def register_and_login(client: TestClient, email: str = "user@test.com", password: str = "pass1234") -> dict:
    """Register a user and return Bearer auth headers."""
    client.post("/api/auth/register", json={"email": email, "password": password})
    resp = client.post(
        "/api/auth/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
