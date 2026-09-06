"""
Регрессия на stored XSS в app/static/index.html.

Содержимое лога в SIEM полностью контролируется атакующим (имя пользователя, имя хоста, путь
процесса, командная строка), поэтому ЛЮБОЕ значение, пришедшее с сервера, обязано попадать в
разметку через escapeHtml/attr. Ловили: список алертов рендерил `${a.host}` и `${a.rule_title}`
сырыми, и событие с `Hostname` вида `<img src=x onerror=...>` выполняло JS в браузере аналитика
СРАЗУ при открытии вкладки «Алерты», без единого клика. Те же дыры были в карточке алерта,
карточке инцидента и карточке события.

Тест намеренно текстовый (JS-раннера в проекте нет): проверяет, что конкретные подстановки не
вернулись в сыром виде. Если переименовываешь переменную в шаблоне - поправь и список ниже.
"""
from __future__ import annotations

from pathlib import Path

import pytest

INDEX_HTML = Path(__file__).resolve().parent.parent / "app" / "static" / "index.html"

# Подстановки значений, пришедших из БД/лога, которые НЕ должны появляться в разметке сырыми.
FORBIDDEN_RAW = [
    # список алертов + карточка алерта
    "${a.host}",
    "${a.rule_title}",
    "${a.source_batch}",
    "${a.description}",
    # карточка события
    "${e.host}",
    "${e.source_batch}",
    # сущности (карточка алерта и карточка инцидента)
    '${(ent.users||[]).join(", ")}',
    '${(ent.src_ips||[]).join(", ")}',
    '${(ent.processes||[]).join(", ")}',
    '${(ent.users||[]).join(", ") || "—"}',
    '${(ent.src_ips||[]).join(", ") || "—"}',
    '${(ent.processes||[]).join(", ") || "—"}',
    # селектор источников (значение приходит из source_label / имени загруженного файла)
    "${b.source_batch}",
]


@pytest.fixture(scope="module")
def index_html() -> str:
    return INDEX_HTML.read_text(encoding="utf-8")


@pytest.mark.parametrize("snippet", FORBIDDEN_RAW)
def test_no_raw_interpolation_of_server_values(index_html: str, snippet: str):
    assert snippet not in index_html, (
        f"{snippet} подставляется в разметку без экранирования - оберни в escapeHtml() "
        f"(для значения атрибута - attr()). См. докстринг модуля."
    )


def test_escape_helpers_still_exist(index_html: str):
    """Сами хелперы на месте - иначе проверка выше проходила бы вхолостую."""
    assert "function escapeHtml(str)" in index_html
    assert "function attr(str)" in index_html


def test_matched_rules_chips_are_escaped(index_html: str):
    """Названия правил приходят в карточку события списком и раскладываются в чипы - каждый
    элемент экранируется отдельно (title кастомного правила пишет пользователь)."""
    assert '<span class="tech-tag">${escapeHtml(r)}</span>' in index_html
    assert '<span class="tech-tag">${r}</span>' not in index_html


def test_group_key_is_escaped_everywhere(index_html: str):
    """group_key инцидента (значение ключа группировки - имя хоста/пользователя/путь из лога,
    т.е. текст атакующего) показывается в списке инцидентов и в шапке карточки - обе
    подстановки обязаны идти через escapeHtml/attr."""
    assert "${groupKeyText(i.group_key)}" not in index_html
    assert "${groupKeyText(inc.group_key)}" not in index_html
    assert "${escapeHtml(groupKeyText(i.group_key))" in index_html
    assert "${escapeHtml(groupKeyText(inc.group_key))" in index_html
