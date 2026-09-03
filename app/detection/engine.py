"""
ZircoliteEngine - обёртка над библиотечным API Zircolite.

Ключевая идея (проверено тестом): RulesetHandler (загрузка + компиляция Sigma-правил
в SQL) должен создаваться ОДИН РАЗ при старте сервиса - это самая дорогая операция
(секунды на тысячи правил). На каждый батч событий создаём лёгкий ZircoliteCore
с in-memory SQLite и переиспользуем уже скомпилированный ruleset.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

# Путь к клонированному репозиторию Zircolite - поправь под свою структуру проекта
# (файл лежит в app/detection/, поэтому до корня проекта — три уровня вверх)
ZIRCOLITE_REPO_PATH = Path(__file__).resolve().parent.parent.parent / "Zircolite"
sys.path.insert(0, str(ZIRCOLITE_REPO_PATH))

from zircolite.config import ProcessingConfig, RulesetConfig  # noqa: E402
from zircolite.rules import RulesetHandler  # noqa: E402
from zircolite.core import ZircoliteCore  # noqa: E402


class ZircoliteEngine:
    def __init__(
        self,
        config_path: str,
        default_ruleset_path: str,
        time_field: str = "SystemTime",
    ) -> None:
        self.config_path = config_path
        self.default_ruleset_path = default_ruleset_path
        self.time_field = time_field
        self._rulesets_cache: dict[str, RulesetHandler] = {}
        # Прогреваем ruleset по умолчанию сразу при старте сервиса
        self._load_ruleset(default_ruleset_path)

    def _load_ruleset(self, ruleset_path: str) -> RulesetHandler:
        """Загружает и компилирует ruleset, кэширует по пути к файлу правил."""
        if ruleset_path not in self._rulesets_cache:
            t0 = time.time()
            ruleset_config = RulesetConfig(ruleset=[ruleset_path], time_field=self.time_field)
            handler = RulesetHandler(ruleset_config)
            elapsed = time.time() - t0
            self._rulesets_cache[ruleset_path] = handler
            print(f"[engine] Ruleset '{ruleset_path}' загружен за {elapsed:.2f}s "
                  f"({len(handler.rulesets)} правил)")
        return self._rulesets_cache[ruleset_path]

    def _run_core(
        self,
        events_path: str,
        input_type: str,
        rules: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, float]:
        """
        Общее тело прогона: лёгкий ZircoliteCore с in-memory SQLite поверх уже готового
        (скомпилированного) списка правил.

        Возвращает:
            raw_results   - сработавшие правила в сыром формате Zircolite (matches содержит row_id)
            all_events    - ВСЕ события, реально попавшие в БД (плоские, после flatten),
                             включая те, что не вызвали ни одного правила
            total_events  - число обработанных событий
            elapsed       - время выполнения в секундах
        """
        t0 = time.time()
        # Correlation-правила (Sigma type: event_count/value_count/temporal/temporal_ordered)
        # сюда в норме и не должны попадать вовсе: они хранятся в custom-рулсетах под
        # app/rules_catalog.CORRELATION_EXT (не .yml/.yaml), поэтому RulesetHandler их не
        # компилирует и они физически не появляются ни в main_ruleset.resolve(), ни в
        # handler.rulesets прямого custom-ruleset прогона - их эвалуацией целиком занимается
        # app/detection/correlation.py поверх постоянной таблицы events/rule_hits (см.
        # app/main.py:_process_batch), а не Zircolite (pinned pysigma-backend-sqlite компилирует
        # SQL для этих типов без учёта timespan и без state между batch'ами - см. докстринг
        # app/rules/rules_catalog.py). Фильтр ниже - только defense-in-depth на случай, если
        # какой-то будущий путь всё же протащит сюда correlation-запись (напр. built-in
        # рулсет, скомпилированный вне этого приложения) - дешёвый, безопасно оставить всегда.
        rules = [r for r in rules if not r.get("correlation")]
        core = ZircoliteCore(
            self.config_path,
            ProcessingConfig(db_location=":memory:", disable_progress=True, no_output=True),
        )
        try:
            core.load_ruleset_from_var(rules, None)
            total_events = core.run_streaming([events_path], input_type=input_type)
            core.execute_ruleset(
                "unused.json",  # не используется благодаря no_output=True
                keep_results=True,
                show_table=False,
                disable_progress=True,
            )
            results = core.full_results
            all_events = core.execute_select_query("SELECT * FROM logs")
        finally:
            core.close()

        elapsed = time.time() - t0
        return results, all_events, total_events, elapsed

    def run_batch(
        self,
        events_path: str,
        input_type: str = "json",
        ruleset_path: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, float]:
        """Прогоняет один файл событий через движок по ruleset_path (кэшируемый, компилируется
        через RulesetHandler один раз - см. _load_ruleset)."""
        ruleset_path = ruleset_path or self.default_ruleset_path
        handler = self._load_ruleset(ruleset_path)
        return self._run_core(events_path, input_type, handler.rulesets)

    def run_batch_with_rules(
        self,
        events_path: str,
        rules: list[dict[str, Any]],
        input_type: str = "json",
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, float]:
        """Как run_batch, но принимает уже готовый (отфильтрованный/объединённый) список
        скомпилированных правил напрямую - используется для "основного рулсета"
        (app/rules/main_ruleset.py), который собирается заново на каждый батч из разных источников
        и поэтому не подходит для обычного кэша _rulesets_cache (там кэш по одному пути к
        файлу). Компилировать тут нечего - правила уже скомпилированы на уровне rules_catalog."""
        return self._run_core(events_path, input_type, rules)

    def invalidate(self, ruleset_path: str) -> bool:
        """Сбрасывает кэш скомпилированного ruleset-а по пути. Нужно звать после add/delete
        кастомных .yml-правил (custom_rulesets/my_rules) и после удаления загруженного
        рулсета - иначе следующий /ingest/* с этим ruleset_path продолжит использовать
        старую скомпилированную версию из _rulesets_cache до рестарта процесса."""
        return self._rulesets_cache.pop(ruleset_path, None) is not None

    def health(self) -> dict[str, Any]:
        """Проверка для /health: ruleset по умолчанию грузится синхронно в __init__, поэтому
        если процесс вообще запустился - он уже в кэше (ошибка загрузки уронила бы старт
        сервиса, а не осталась незамеченной в runtime); rules_loaded == 0 - деградация."""
        handler = self._rulesets_cache.get(self.default_ruleset_path)
        rules_loaded = len(handler.rulesets) if handler else 0
        return {
            "status": "ok" if rules_loaded > 0 else "error",
            "ruleset": self.default_ruleset_path,
            "rules_loaded": rules_loaded,
            "cached_rulesets": len(self._rulesets_cache),
        }
