"""
Общие фикстуры для тестов. Namespace app.* не импортируется здесь ничего с побочными
эффектами (в отличие от app.main, который на импорте создаёт глобальные engine/store
поверх РЕАЛЬНЫХ путей из app/config.py - siem.db и дефолтный рулсет) - тесты собирают
Store/ZircoliteEngine руками, каждый со своим временным путём, см. фикстуры ниже.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.store import Store

BASE_DIR = Path(__file__).resolve().parent.parent
ZIRCOLITE_CONFIG_PATH = str(BASE_DIR / "Zircolite" / "config" / "config.yaml")

# Одно тестовое Sigma-правило в УЖЕ СКОМПИЛИРОВАННОМ формате Zircolite (тот же формат, что
# built-in rules_*.json - список правил с готовым SQL в поле "rule", без похода в pySigma).
# channel/eventid пустые -> EventFilter Zircolite отключает пред-фильтрацию по каналу/EventID
# целиком (см. zircolite/rules.py:EventFilter) - события с любым EventID сюда долетают.
TEST_RULE_ID = "test-rule-0001"
TEST_RULESET = [
    {
        "title": "Test Rule - Suspicious Image",
        "id": TEST_RULE_ID,
        "status": "test",
        "description": "Обнаруживает подозрительный процесс (тестовое правило для pytest)",
        "author": "pytest",
        "tags": ["attack.execution", "attack.t1059"],
        "falsepositives": ["unit test"],
        "level": "high",
        "rule": ["SELECT * FROM logs WHERE Image LIKE '%malicious.exe' ESCAPE '\\'"],
        "filename": "",
        "channel": [],
        "eventid": [],
    }
]


@pytest.fixture
def zircolite_config_path() -> str:
    if not Path(ZIRCOLITE_CONFIG_PATH).exists():
        pytest.skip("Локальный клон Zircolite не найден (Zircolite/config/config.yaml) - см. README")
    return ZIRCOLITE_CONFIG_PATH


@pytest.fixture
def test_ruleset_path(tmp_path: Path) -> str:
    path = tmp_path / "test_ruleset.json"
    path.write_text(json.dumps(TEST_RULESET), encoding="utf-8")
    return str(path)


@pytest.fixture
def test_events_path(tmp_path: Path):
    """Фабрика: список dict-событий -> путь к NDJSON-файлу (формат, который ждёт
    ZircoliteEngine.run_batch(..., input_type="json"), см. app/main.py:_process_events)."""

    def _write(events: list[dict]) -> str:
        path = tmp_path / "events.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, default=str) + "\n")
        return str(path)

    return _write


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(db_path=str(tmp_path / "test.db"))
    yield s
    s.close()
