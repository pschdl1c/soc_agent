"""
Тесты реестра потоковых источников (app/store.py: таблица sources + токен-аутентификация).
Гоняют настоящий Store на временной БД (фикстура `store` из conftest.py) - без HTTP-слоя.

Ключевое поведение, которое проверяем:
  - имя обязательно и уникально, оно же метка source_batch;
  - открытый токен отдаётся ОДИН раз при создании, в БД - только его sha256;
  - authenticate_source принимает верный токен активного источника и отвергает всё прочее
    (нет токена / чужой / выключенный источник / после перевыпуска / после удаления).
"""
from __future__ import annotations

import pytest


def test_create_returns_one_time_token_and_public_row(store):
    created = store.create_source("host01", "рабочая станция")
    assert created["name"] == "host01"
    assert created["description"] == "рабочая станция"
    assert created["enabled"] is True
    # открытый токен есть в ответе создания...
    token = created["token"]
    assert isinstance(token, str) and len(token) >= 32
    assert created["token_hint"] == token[-4:]
    # ...но больше нигде: ни в списке, ни в карточке нет ни token, ни token_sha256
    listed = store.list_sources()
    assert len(listed) == 1
    assert "token" not in listed[0] and "token_sha256" not in listed[0]
    assert store.get_source(created["source_id"]).keys() == listed[0].keys()


def test_name_is_required_and_unique(store):
    with pytest.raises(ValueError):
        store.create_source("   ", "")
    with pytest.raises(ValueError):
        store.create_source("bad/name", "")          # слэш недопустим (имя уходит в URL)
    store.create_source("dup", "")
    with pytest.raises(ValueError):
        store.create_source("dup", "другое описание")  # имя уже занято


def test_cyrillic_name_allowed(store):
    created = store.create_source("хост-01 прод", "")
    assert store.authenticate_source(created["token"])["name"] == "хост-01 прод"


def test_authenticate_accepts_only_valid_active_token(store):
    created = store.create_source("edge", "")
    token = created["token"]

    ok = store.authenticate_source(token)
    assert ok is not None and ok["name"] == "edge"
    assert ok["last_seen_at"] is not None          # первый приём проставляет last_seen_at

    assert store.authenticate_source(None) is None
    assert store.authenticate_source("") is None
    assert store.authenticate_source(token + "x") is None


def test_disabled_source_is_rejected(store):
    created = store.create_source("paused", "")
    token = created["token"]
    assert store.authenticate_source(token) is not None

    updated = store.update_source(created["source_id"], enabled=False)
    assert updated["enabled"] is False
    assert store.authenticate_source(token) is None      # выключенный - как будто токена нет

    store.update_source(created["source_id"], enabled=True)
    assert store.authenticate_source(token) is not None


def test_rotate_invalidates_old_token(store):
    created = store.create_source("rot", "")
    old = created["token"]
    new = store.rotate_source_token(created["source_id"])
    assert new is not None and new != old

    assert store.authenticate_source(old) is None
    assert store.authenticate_source(new)["name"] == "rot"
    assert store.get_source(created["source_id"])["token_hint"] == new[-4:]

    assert store.rotate_source_token("no-such-id") is None


def test_update_description_only_and_missing(store):
    created = store.create_source("d", "старое")
    updated = store.update_source(created["source_id"], description="новое")
    assert updated["description"] == "новое" and updated["enabled"] is True
    assert store.update_source("no-such-id", enabled=False) is None


def test_delete_source_revokes_but_keeps_id_semantics(store):
    created = store.create_source("gone", "")
    token = created["token"]
    assert store.delete_source(created["source_id"]) is True
    assert store.delete_source(created["source_id"]) is False
    assert store.authenticate_source(token) is None
    assert store.get_source(created["source_id"]) is None
    assert store.list_sources() == []
