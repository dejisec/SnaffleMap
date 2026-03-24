from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_tsv() -> Path:
    return FIXTURES_DIR / "sample.tsv"


@pytest.fixture
def sample_json() -> Path:
    return FIXTURES_DIR / "sample.json"


@pytest.fixture
def malformed_tsv() -> Path:
    return FIXTURES_DIR / "malformed.tsv"
