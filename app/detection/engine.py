"""
ZircoliteEngine - обёртка над библиотечным API Zircolite.

Ключевая идея (проверено тестом): RulesetHandler (загрузка + компиляция Sigma-правил
в SQL) должен создаваться ОДИН РАЗ при старте сервиса - это самая дорогая операция
(секунды на тысячи правил). На каждый батч событий создаём лёгкий ZircoliteCore
с in-memory SQLite и переиспользуем уже скомпилированный ruleset.
"""
from __future__ import annotations

import logging
import re
import sqlite3
import sys
import threading
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

logger = logging.getLogger(__name__)

# Тип досоздаваемой колонки - тот же, что Zircolite ставит по умолчанию полям событий
# (streaming.py:_ensure_columns_exist_cached), иначе сравнения в SQL правил вели бы себя иначе.
_MISSING_COLUMN_TYPE = "TEXT COLLATE NOCASE"
_NO_SUCH_COLUMN_RE = re.compile(r"no such column: (?:logs\.)?(.+)$")
# Предел итераций разбора одного SQL (по колонке за итерацию) - страховка от зацикливания.
_MAX_COLUMN_PROBES = 512
# Ошибка SQL правила пишется в лог не чаще раза за столько секунд на правило.
SQL_ERROR_LOG_INTERVAL = 600.0


class RuleColumnIndex:
    """
    Какие колонки таблицы `logs` нужны SQL правила - по мнению САМОГО SQLite, а не регэкспа.

    Zircolite строит таблицу флаша из полей пришедших событий. Правило, упоминающее поле, которого
    нет НИ В ОДНОМ событии флаша, падает с `no such column`, Zircolite глушит ошибку, и правило
    молча не срабатывает - в том числе на событиях, где его остальные условия выполнены (напр.
    `NOT (ParentImage LIKE ...)` во флаше из одних 4104). Регэксп по тексту SQL здесь ненадёжен
    (литералы, `LIKE`-шаблоны, функции), поэтому запрос готовится (`EXPLAIN`) на пустой таблице
    и недостающие колонки добавляются по одной, пока подготовка не пройдёт. Результат кэшируется
    по тексту SQL - разбор делается один раз на правило за жизнь процесса.
    """

    def __init__(self) -> None:
        self._cache: dict[str, frozenset[str]] = {}
        self._lock = threading.Lock()

    def columns_for(self, sql: str) -> frozenset[str]:
        cached = self._cache.get(sql)
        if cached is not None:
            return cached
        with self._lock:
            cached = self._cache.get(sql)
            if cached is None:
                cached = self._probe(sql)
                self._cache[sql] = cached
        return cached

    @staticmethod
    def _probe(sql: str) -> frozenset[str]:
        conn = sqlite3.connect(":memory:")
        try:
            # Функции, которые Zircolite регистрирует на своём соединении, - иначе подготовка
            # упадёт на "no such function" раньше, чем дойдёт до колонок.
            conn.create_function("regexp", 2, lambda x, y: 0)
            conn.execute("CREATE TABLE logs (row_id INTEGER PRIMARY KEY AUTOINCREMENT)")
            known: set[str] = {"row_id"}
            columns: set[str] = set()
            for _ in range(_MAX_COLUMN_PROBES):
                try:
                    conn.execute(f"EXPLAIN {sql}")
                    break
                except sqlite3.Error as exc:
                    m = _NO_SUCH_COLUMN_RE.search(str(exc))
                    if not m or m.group(1).lower() in known:
                        # Ошибка не про колонку (синтаксис и т.п.) - её покажет штатный прогон
                        # правила через _SiemCore.execute_select_query.
                        break
                    col = m.group(1)
                    known.add(col.lower())
                    columns.add(col)
                    conn.execute(f'ALTER TABLE logs ADD COLUMN "{col.replace(chr(34), chr(34) * 2)}"')
            return frozenset(columns)
        finally:
            conn.close()

    def missing_columns(self, rules: list[dict[str, Any]], existing: set[str]) -> list[str]:
        """Колонки, нужные правилам, которых нет среди `existing` (сравнение без учёта регистра,
        как у колонок SQLite)."""
        existing_lower = {c.lower() for c in existing}
        missing: dict[str, str] = {}
        for rule in rules:
            for sql in rule.get("rule") or []:
                if not isinstance(sql, str):
                    continue
                for col in self.columns_for(sql):
                    low = col.lower()
                    if low not in existing_lower:
                        missing.setdefault(low, col)
        return list(missing.values())


class _SiemCore(ZircoliteCore):
    """
    ZircoliteCore с двумя доработками, без правки внешнего клона Zircolite:

    - `add_missing_rule_columns` - досоздаёт колонки полей, упомянутых правилами, значением NULL
      (см. RuleColumnIndex);
    - ошибки SQL правил пишутся в лог WARNING с названием правила (штатный
      `execute_select_query` глушит их на уровне debug - мёртвые правила не видны).
    """

    def __init__(self, *args: Any, error_log_state: dict[str, float], **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._current_rule_title: str | None = None
        self._error_log_state = error_log_state

    def add_missing_rule_columns(self, index: RuleColumnIndex) -> int:
        if self.db_connection is None:
            return 0
        existing = set(self._get_table_columns())
        missing = index.missing_columns(self.ruleset or [], existing)
        cursor = self._get_cursor()
        for col in missing:
            cursor.execute(
                f'ALTER TABLE logs ADD COLUMN "{self.escape_identifier(col)}" {_MISSING_COLUMN_TYPE}'
            )
        if missing:
            self.db_connection.commit()
        return len(missing)

    def execute_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        self._current_rule_title = rule.get("title")
        try:
            return super().execute_rule(rule)
        finally:
            self._current_rule_title = None

    def execute_select_query(self, query: str) -> list[dict[str, Any]]:
        # Повторяет ZircoliteCore.execute_select_query (без rich-панели отладки) - нужна сама
        # ошибка, а родитель возвращает на неё тот же [], что и на пустой результат.
        if self.db_connection is None:
            return []
        try:
            cursor = self._get_cursor()
            cursor.execute(query)
            rows = cursor.fetchall()
        except sqlite3.Error as exc:
            self._log_sql_error(query, exc)
            return []
        if not rows:
            return []
        col_names = [d[0] for d in cursor.description]
        return [{k: v for k, v in zip(col_names, row, strict=True) if v is not None} for row in rows]

    def _log_sql_error(self, query: str, exc: sqlite3.Error) -> None:
        title = self._current_rule_title or "<вне правила>"
        now = time.monotonic()
        last = self._error_log_state.get(title)
        if last is not None and now - last < SQL_ERROR_LOG_INTERVAL:
            return
        self._error_log_state[title] = now
        logger.warning("ошибка SQL правила '%s': %s; запрос: %s", title, exc, query[:500])


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
        self._column_index = RuleColumnIndex()
        # Когда последний раз писали в лог ошибку SQL правила (по названию) - общий на все
        # прогоны, иначе троттлинг жил бы один флаш.
        self._sql_error_log_state: dict[str, float] = {}
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
            logger.info(
                "ruleset '%s' загружен за %.2fs (%s правил)",
                ruleset_path, elapsed, len(handler.rulesets),
            )
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
        core = _SiemCore(
            self.config_path,
            ProcessingConfig(db_location=":memory:", disable_progress=True, no_output=True),
            error_log_state=self._sql_error_log_state,
        )
        try:
            core.load_ruleset_from_var(rules, None)
            total_events = core.run_streaming([events_path], input_type=input_type)
            core.add_missing_rule_columns(self._column_index)
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
