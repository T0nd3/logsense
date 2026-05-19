from pathlib import Path

import pytest

DATA_DIR = Path(__file__).parent / "data"


@pytest.fixture
def nginx_log() -> Path:
    return DATA_DIR / "nginx_access.log"


@pytest.fixture
def auth_log() -> Path:
    return DATA_DIR / "auth.log"


@pytest.fixture
def syslog_log() -> Path:
    return DATA_DIR / "syslog.log"


@pytest.fixture
def json_log() -> Path:
    return DATA_DIR / "json_lines.log"
