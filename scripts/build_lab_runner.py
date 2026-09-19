"""Собирает самодостаточный раннер живых сценариев одним файлом: dist/run-lab-scenarios.ps1.

Читает lab: секции всех фикстур artifacts/content/<domain>/tests/*.yml (источник правды - git,
как и весь детект-контент, CLAUDE.md §9), классифицирует каждую строку и встраивает результат
JSON'ом (base64 от UTF-8, маркер `# @@EMBED:scenarios.json.b64@@`) в
dist/run-lab-scenarios.template.ps1 - тот же приём, что уже проверен на sysmonconfig.xml в
build_agent_installer.py. На ВМ копируется только dist/run-lab-scenarios.ps1 (результат сборки) -
он ничего не знает про git/YAML, только встроенные данные + HTTP к SIEM.

Источник (run-lab-scenarios.template.ps1) и результат (run-lab-scenarios.ps1) - в ОДНОЙ папке
(dist/, целиком в git, см. .gitignore) под РАЗНЫМИ именами. Раньше источник жил в deploy/windows/,
а результат - в dist/, но ОБА назывались run-lab-scenarios.ps1 - при ручном переносе на ВМ файлы
путали (копировали шаблон с пустым `$EmbeddedScenariosB64Parts` вместо собранного результата).
Суффикс `.template.ps1` - тоже страховка: такой файл не запустится по клику/копипасте имени не
глядя (не совпадает с тем, что просят в доках/выводе).

Base64, а не сырой UTF-8-литерал внутри here-string: живой прогон показал, что байты .ps1 на пути
к ВМ могут терять BOM/превращать CRLF в LF ДО того, как что-то из этого файла успевает выполниться
(чем именно на конкретной ВМ - не установлено и не важно: файл должен быть устойчив к этому сам по
себе). Без BOM PowerShell 5.1 читает скрипт в системной ANSI-кодировке - кириллица внутри JSON
(она у части lab-заметок, см. artifacts/content/*/tests/*.yml) ломала парсинг ДО первой строки
кода. Base64 - чистый ASCII, инвариантен к такой порче; сам шаблон run-lab-scenarios.ps1 тоже
ASCII-only (свои Write-Host/комментарии - на английском) по той же причине - парсер спотыкался не
только на JSON, но и на русских строках самого скрипта.

Классификация lab-строки (см. classify_line) - эвристика по тому, с чего строка начинается, а НЕ
разбор естественного языка: сначала снимается один из двух точных деструктивных префиксов
("Только на снимке ВМ:", "Откат:" - ровно эти встречаются в контенте сейчас, см. полный список
в истории обсуждения), затем остаток проверяется на "похоже на код" (командлет/утилита в начале
строки). Не похоже на код - строка целиком идёт как [NOTE] (печатается, не выполняется) - так
безопаснее для строк вида "Defender заблокирует: ... затем Add-MpPreference ..." (смешанные
заметка+код) и "Нужен второй хост..." (lateral), чем пытаться вычленить код внутри произвольного
предложения. Если контент обрастёт новыми lab-строками с другим устройством - новая строка просто
попадёт в [NOTE] (безопасный дефолт: показать, не выполнить), не потребует правки этого файла,
если только не появится СВОЙ новый деструктивный префикс (тогда добавить в DESTRUCTIVE_PREFIXES).

Запуск: uv run python scripts/build_lab_runner.py [--out dist/run-lab-scenarios.ps1]
"""
from __future__ import annotations

import argparse
import base64
import json
import re
from pathlib import Path
from typing import Any

import yaml
from content_lib import CONTENT_DIR, domain_dirs

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "dist" / "run-lab-scenarios.template.ps1"

# Порядок прогона доменов: спокойные/невидимые - сначала, потенциально деструктивные - в конце.
# Домен, которого нет в списке (новый домен в будущем), уходит в конец в алфавитном порядке -
# не теряется молча, просто не отсортирован осмысленно (см. build_scenarios).
DOMAIN_ORDER = [
    "recon", "auth", "execution", "persistence", "privesc",
    "credaccess", "evasion", "exfil", "lateral", "impact", "killchain",
]

# Ровно два деструктивных префикса встречаются в контенте на 2026-09-18 (см. докстринг). Снимаются
# ДО общей проверки "похоже на код" - остаток после них уже проверенно (вручную, при написании
# этого генератора) состоит из чистого кода без хвостовой прозы.
DESTRUCTIVE_PREFIXES = [
    re.compile(r"^Только на снимке ВМ:\s*"),
    re.compile(r"^Откат:\s*"),
]

# Начало строки, похожее на исполняемый код: командлет Verb-Noun, известная cmd-утилита, диапазон
# "N..M |", "foreach (", присваивание "$var = ...", вызов "& ...", прямой путь "C:\...".
_CODE_START_RE = re.compile(
    r"^("
    r"\$|"
    r"\d+\.\.\d+\s*\||"
    r"foreach\s*\(|"
    r"cmd\b|net\b|reg\b|sc\.exe\b|sc\b|schtasks\b|wevtutil\b|certutil\b|wmic\b|"
    # Живой прогон показал две строки-кода, уехавшие в [NOTE] из-за отсутствия их первого слова:
    # `powershell -Command "New-Service ..."` (SCE_Persist_Multiple_Mechanisms, третий механизм -
    # без него не взводился th_persist_autostart_changes) и `whoami; hostname; ipconfig /all; ...`
    # (SCE_TH_Recon_Discovery_Burst целиком уходил в SKIP). Заодно остальные интерпретаторы и
    # recon-утилиты, которыми сценарии начинают строки.
    r"powershell\b|pwsh\b|cscript\b|wscript\b|mshta\b|regsvr32\b|bitsadmin\b|msiexec\b|tar\b|"
    r"whoami\b|hostname\b|ipconfig\b|systeminfo\b|tasklist\b|quser\b|arp\b|netstat\b|nltest\b|"
    r"vssadmin\b|bcdedit\b|auditpol\b|cmdkey\b|vaultcmd\b|findstr\b|"
    r"rclone\.exe\b|curl\.exe\b|psexec\.exe\b|rundll32\.exe\b|"
    r"&\s|"
    # Ровно ОДИН литеральный бэкслеш: было `C:\\\\`, то есть регулярка требовала `C:\\`, и строка
    # вида `C:\Users\Public\w.exe` (запуск скачанного файла) молча уезжала в [NOTE] - сценарий
    # SCE_Exec_Download_Then_Execute никогда не замыкал свою цепочку и вечно давал ложный MISSING.
    r"C:\\|"
    r"[A-Z][A-Za-z]*-[A-Z][A-Za-z]*\b"
    r")"
)

# Незаполненный плейсхолдер (<win10-lab>, <pass>...) - строка НИКОГДА не идёт в RUN, даже если
# формально начинается с похожего на код токена: она рассчитана на ручную подстановку оператором
# (обычно вместе со вторым хостом), Invoke-Expression на буквальном "<...>" даст непредсказуемый
# результат разбора, а не осмысленную ошибку.
_PLACEHOLDER_RE = re.compile(r"<[^<>]+>")

_SECOND_HOST_MARKERS = ("второй хост", "второго хоста", "с хоста")


def classify_line(raw: str) -> dict[str, Any]:
    text = raw
    destructive = False
    for pat in DESTRUCTIVE_PREFIXES:
        if pat.match(text):
            text = pat.sub("", text, count=1)
            destructive = True
            break
    is_code = bool(_CODE_START_RE.match(text.strip())) and not _PLACEHOLDER_RE.search(text)
    return {
        # RUN - показываем и выполняем только сам код (без деструктивного префикса). NOTE -
        # показываем строку ЦЕЛИКОМ как есть (префикс - часть смысла заметки).
        "text": text.strip() if is_code else raw.strip(),
        "kind": "run" if is_code else "note",
        "destructive": destructive,
        "needs_second_host": any(m in raw.lower() for m in _SECOND_HOST_MARKERS),
    }


def lab_expected(doc: dict[str, Any]) -> list[str]:
    """Типы инцидентов, которые должна поднять ИМЕННО `lab:`-секция фикстуры.

    Не объединение всех кейсов: кейс `negative_*` одного сценария сплошь и рядом позитивен для
    СОСЕДНЕГО (у `SCE_Auth_BruteForce` негативный кейс ожидает `auth_account_bruteforce`), и такой
    тип живым прогоном не поднять — получался вечный ложный MISSING. Берём только позитивные кейсы,
    а где `lab:`-строка всё равно у́же любого из них (нужен второй хост, 7-Zip, композиция вручную)
    — фикстура задаёт список явно ключом `lab_expect`.
    """
    if "lab_expect" in doc:
        return sorted(set(doc["lab_expect"] or []))
    return sorted({
        t
        for c in doc["cases"]
        if str(c.get("name", "")).startswith("positive")
        for t in (c.get("expect_incidents") or [])
    })


def build_scenarios(content_dir: Path = CONTENT_DIR) -> list[dict[str, Any]]:
    order_idx = {d: i for i, d in enumerate(DOMAIN_ORDER)}
    scenarios: list[dict[str, Any]] = []
    for ddir in domain_dirs(content_dir):
        tests_dir = ddir / "tests"
        if not tests_dir.is_dir():
            continue
        for p in sorted(tests_dir.glob("*.yml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
            expected = lab_expected(doc)
            lines = [classify_line(str(line)) for line in (doc.get("lab") or [])]
            scenarios.append({
                "domain": ddir.name,
                "scenario": doc["scenario"],
                "expected": expected,
                "lines": lines,
                # Агрегаты уровня сценария - PS-раннер гейтит/пропускает по НИМ (destructive/
                # needs_second_host - если положить их только на строки, ConvertFrom-Json не даст
                # $sc.destructive, и гейт -ConfirmDestructive молча не сработает).
                "destructive": any(line["destructive"] for line in lines),
                "needs_second_host": any(line["needs_second_host"] for line in lines),
            })
    scenarios.sort(key=lambda s: (order_idx.get(s["domain"], len(DOMAIN_ORDER)), s["domain"], s["scenario"]))
    for i, s in enumerate(scenarios):
        s["order"] = i
    return scenarios


def build(out: Path) -> None:
    script = TEMPLATE.read_text(encoding="utf-8-sig")
    scenarios = build_scenarios()
    if not scenarios:
        raise SystemExit(f"в {CONTENT_DIR} не найдено ни одной фикстуры со сценарием")
    scenarios_json = json.dumps(scenarios, ensure_ascii=False, indent=None)
    # Base64, не сырой UTF-8-литерал: живой прогон показал, что байты .ps1 на пути к ВМ (антивирус/
    # предпросмотр/что-то ещё вне нашего контроля) могут терять BOM и превращать CRLF в LF -
    # PowerShell тогда читает файл в системной ANSI-кодировке, кириллица ломает парсинг ДО того, как
    # скрипт вообще начнёт выполняться. Base64 - чистый ASCII, инвариантен к любой такой порче;
    # тот же приём уже проверен на sysmonconfig.xml в build_agent_installer.py. Шаблон сам по себе
    # тоже ASCII-only (см. докстринг run-lab-scenarios.ps1) - кириллика остаётся только здесь.
    scenarios_b64 = base64.b64encode(scenarios_json.encode("utf-8")).decode("ascii")
    # Резать на короткие строки, а не писать одной простынёй ~40+ КБ: живой прогон дважды показал
    # порчу файла именно вокруг одной аномально длинной строки (сначала ломался парсинг из-за
    # потерянной BOM, после перехода на чистый ASCII - сам payload стал приходить пустым). Что
    # именно на пути к ВМ не переваривает длинные строки - не установлено, но раз паттерн
    # повторился дважды, не полагаемся на длину строки вообще: каждая строка ниже короче типичного
    # предела построчных текстовых фильтров (антивирус/буфер обмена/что угодно ещё).
    chunk_size = 200
    chunks = [scenarios_b64[i:i + chunk_size] for i in range(0, len(scenarios_b64), chunk_size)]

    replaced = False
    lines = []
    for line in script.splitlines():
        if "# @@EMBED:scenarios.json.b64@@" in line:
            lines.append("$EmbeddedScenariosB64Parts = @(")
            # PowerShell не терпит висячую запятую перед ")" в литерале массива - у последнего
            # чанка запятой быть не должно.
            lines.extend(f"    '{chunk}'," for chunk in chunks[:-1])
            lines.append(f"    '{chunks[-1]}'")
            lines.append(")")
            lines.append("$EmbeddedScenariosB64 = -join $EmbeddedScenariosB64Parts")
            replaced = True
        else:
            lines.append(line)
    if not replaced:
        raise SystemExit(f"в {TEMPLATE} не найден маркер # @@EMBED:scenarios.json.b64@@")

    out.parent.mkdir(parents=True, exist_ok=True)
    # BOM обязателен: Windows PowerShell 5.1 читает .ps1 без BOM в ANSI-кодировке, русский текст
    # (в т.ч. встроенные lab-строки с кириллицей) ломается. CRLF - родной перевод строки Windows.
    out.write_bytes("\r\n".join(lines).encode("utf-8-sig") + b"\r\n")

    manual = sum(1 for s in scenarios if not any(line["kind"] == "run" for line in s["lines"]) or s["needs_second_host"])
    destructive = sum(1 for s in scenarios if s["destructive"])
    print(f"{out} ({out.stat().st_size // 1024} КБ)")
    print(f"сценариев: {len(scenarios)}, только-заметка/второй хост: {manual}, деструктивных: {destructive}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "run-lab-scenarios.ps1")
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
