"""
BlackBox Recon - API Endpoint Tests
Phase 10: Tests + Docker
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Test root endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "BlackBox Recon" in data["name"]


def test_health_check():
    """Test health check endpoint."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_list_targets_empty():
    """Test listing targets when empty."""
    response = client.get("/api/targets")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_create_target():
    """Test creating a target."""
    target_data = {
        "name": "Test Target",
        "url": "test.local",
        "notes": "Test notes"
    }
    response = client.post("/api/targets", json=target_data)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Target"
    assert data["url"] == "test.local"
    
    # Cleanup
    client.delete(f"/api/targets/{data['id']}")


def test_create_duplicate_target():
    """Test creating duplicate target fails."""
    target_data = {
        "name": "Duplicate Test",
        "url": "duplicate.local"
    }
    # Create first
    response1 = client.post("/api/targets", json=target_data)
    assert response1.status_code == 201
    
    # Try to create duplicate
    response2 = client.post("/api/targets", json=target_data)
    assert response2.status_code == 400
    
    # Cleanup
    client.delete(f"/api/targets/{response1.json()['id']}")


def test_get_nonexistent_target():
    """Test getting nonexistent target."""
    response = client.get("/api/targets/99999")
    assert response.status_code == 404


def test_list_scans_empty():
    """Test listing scans when empty."""
    response = client.get("/api/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
