import sys
from pathlib import Path

sys.path.insert(0, "/home/aadi/safecheck/app")

import os
os.environ["SAFECHECK_DB_PATH"] = "/tmp/safecheck_test.db"
import app as safecheck_app


def test_safecheck_app_file_exists():
    assert Path("/home/aadi/safecheck/app/app.py").exists()


def test_safecheck_docker_compose_exists():
    assert Path("/home/aadi/safecheck/docker-compose.yml").exists()


def test_homepage_loads():
    safecheck_app.app.config["TESTING"] = True
    client = safecheck_app.app.test_client()

    response = client.get("/")
    assert response.status_code == 200


def test_history_page_loads():
    safecheck_app.app.config["TESTING"] = True
    client = safecheck_app.app.test_client()

    response = client.get("/history")
    assert response.status_code == 200


def test_history_csv_loads():
    safecheck_app.app.config["TESTING"] = True
    client = safecheck_app.app.test_client()

    response = client.get("/history.csv")
    assert response.status_code == 200
