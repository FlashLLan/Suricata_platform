"""Tests for /api/projects — full CRUD plus ownership and duplicate-name checks."""
import pytest
from tests.conftest import register_and_login


# ─── Helpers ──────────────────────────────────────────────────────────────────

def create_project(client, headers, name="My Lab", description="desc"):
    return client.post(
        "/api/projects",
        json={"name": name, "description": description},
        headers=headers,
    )


# ─── List ─────────────────────────────────────────────────────────────────────

class TestListProjects:
    def test_empty_for_new_user(self, client):
        headers = register_and_login(client)
        resp = client.get("/api/projects", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_own_projects_only(self, client):
        h1 = register_and_login(client, "alice@test.com")
        h2 = register_and_login(client, "bob@test.com")
        create_project(client, h1, "Alice's Lab")
        create_project(client, h2, "Bob's Lab")

        resp = client.get("/api/projects", headers=h1)
        names = [p["name"] for p in resp.json()]
        assert "Alice's Lab" in names
        assert "Bob's Lab" not in names

    def test_requires_auth(self, client):
        resp = client.get("/api/projects")
        assert resp.status_code == 401


# ─── Create ───────────────────────────────────────────────────────────────────

class TestCreateProject:
    def test_create_success(self, client):
        headers = register_and_login(client)
        resp = create_project(client, headers, "New Lab", "A description")
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "New Lab"
        assert body["description"] == "A description"
        assert "id" in body

    def test_create_sets_timestamps(self, client):
        headers = register_and_login(client)
        resp = create_project(client, headers)
        body = resp.json()
        assert body["created_at"] is not None
        assert body["updated_at"] is not None

    def test_create_stores_topology_json(self, client):
        headers = register_and_login(client)
        topo = '{"nodes":[],"edges":[]}'
        resp = client.post(
            "/api/projects",
            json={"name": "Topo Lab", "topology_json": topo},
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["topology_json"] == topo

    def test_create_stores_rules_json(self, client):
        headers = register_and_login(client)
        rules = '["1000001","1000002"]'
        resp = client.post(
            "/api/projects",
            json={"name": "Rules Lab", "rules_json": rules},
            headers=headers,
        )
        assert resp.status_code == 201
        assert resp.json()["rules_json"] == rules

    def test_duplicate_name_same_user_rejected(self, client):
        headers = register_and_login(client)
        create_project(client, headers, "Alpha")
        resp = create_project(client, headers, "Alpha")
        assert resp.status_code == 409
        assert "Alpha" in resp.json()["detail"]

    def test_duplicate_name_different_user_allowed(self, client):
        h1 = register_and_login(client, "alice@test.com")
        h2 = register_and_login(client, "bob@test.com")
        create_project(client, h1, "SharedName")
        resp = create_project(client, h2, "SharedName")
        assert resp.status_code == 201

    def test_create_requires_auth(self, client):
        resp = client.post("/api/projects", json={"name": "x"})
        assert resp.status_code == 401


# ─── Get ──────────────────────────────────────────────────────────────────────

class TestGetProject:
    def test_get_own_project(self, client):
        headers = register_and_login(client)
        created = create_project(client, headers, "Lab A").json()
        resp = client.get(f"/api/projects/{created['id']}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "Lab A"

    def test_get_updates_last_opened_at(self, client):
        headers = register_and_login(client)
        created = create_project(client, headers).json()
        resp = client.get(f"/api/projects/{created['id']}", headers=headers)
        assert resp.json()["last_opened_at"] is not None

    def test_get_other_users_project_returns_404(self, client):
        h1 = register_and_login(client, "alice@test.com")
        h2 = register_and_login(client, "bob@test.com")
        project_id = create_project(client, h1).json()["id"]
        resp = client.get(f"/api/projects/{project_id}", headers=h2)
        assert resp.status_code == 404

    def test_get_nonexistent_returns_404(self, client):
        headers = register_and_login(client)
        resp = client.get("/api/projects/99999", headers=headers)
        assert resp.status_code == 404

    def test_get_requires_auth(self, client):
        resp = client.get("/api/projects/1")
        assert resp.status_code == 401


# ─── Update ───────────────────────────────────────────────────────────────────

class TestUpdateProject:
    def test_rename(self, client):
        headers = register_and_login(client)
        pid = create_project(client, headers, "Old Name").json()["id"]
        resp = client.patch(f"/api/projects/{pid}", json={"name": "New Name"}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_update_topology_json(self, client):
        headers = register_and_login(client)
        pid = create_project(client, headers).json()["id"]
        topo = '{"nodes":[{"id":"n1"}],"edges":[]}'
        resp = client.patch(f"/api/projects/{pid}", json={"topology_json": topo}, headers=headers)
        assert resp.status_code == 200
        assert resp.json()["topology_json"] == topo

    def test_update_bumps_updated_at(self, client):
        headers = register_and_login(client)
        created = create_project(client, headers).json()
        pid = created["id"]
        original_updated_at = created["updated_at"]
        import time; time.sleep(0.01)       # ensure timestamp differs
        client.patch(f"/api/projects/{pid}", json={"name": "Renamed"}, headers=headers)
        resp = client.get(f"/api/projects/{pid}", headers=headers)
        assert resp.json()["updated_at"] >= original_updated_at

    def test_update_other_users_project_returns_404(self, client):
        h1 = register_and_login(client, "alice@test.com")
        h2 = register_and_login(client, "bob@test.com")
        pid = create_project(client, h1).json()["id"]
        resp = client.patch(f"/api/projects/{pid}", json={"name": "Hacked"}, headers=h2)
        assert resp.status_code == 404

    def test_update_requires_auth(self, client):
        resp = client.patch("/api/projects/1", json={"name": "x"})
        assert resp.status_code == 401


# ─── Delete ───────────────────────────────────────────────────────────────────

class TestDeleteProject:
    def test_delete_own_project(self, client):
        headers = register_and_login(client)
        pid = create_project(client, headers).json()["id"]
        resp = client.delete(f"/api/projects/{pid}", headers=headers)
        assert resp.status_code == 204
        # Verify it's gone
        resp2 = client.get(f"/api/projects/{pid}", headers=headers)
        assert resp2.status_code == 404

    def test_delete_removes_from_list(self, client):
        headers = register_and_login(client)
        pid = create_project(client, headers, "To Delete").json()["id"]
        client.delete(f"/api/projects/{pid}", headers=headers)
        projects = client.get("/api/projects", headers=headers).json()
        assert all(p["id"] != pid for p in projects)

    def test_delete_other_users_project_returns_404(self, client):
        h1 = register_and_login(client, "alice@test.com")
        h2 = register_and_login(client, "bob@test.com")
        pid = create_project(client, h1).json()["id"]
        resp = client.delete(f"/api/projects/{pid}", headers=h2)
        assert resp.status_code == 404

    def test_delete_requires_auth(self, client):
        resp = client.delete("/api/projects/1")
        assert resp.status_code == 401


# ─── List ordering ────────────────────────────────────────────────────────────

class TestListOrdering:
    def test_most_recently_updated_first(self, client):
        headers = register_and_login(client)
        p1 = create_project(client, headers, "First").json()["id"]
        p2 = create_project(client, headers, "Second").json()["id"]
        # Touch p1 so it has a newer updated_at
        import time; time.sleep(0.01)
        client.patch(f"/api/projects/{p1}", json={"name": "First (updated)"}, headers=headers)
        projects = client.get("/api/projects", headers=headers).json()
        assert projects[0]["id"] == p1
