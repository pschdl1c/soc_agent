"""Собирает самодостаточный установщик агента одним файлом: dist/install-soc-agent.ps1.

Берёт dist/install-agent.ps1 и встраивает в него шаблон конфига Vector (dist/vector.toml) и конфиг
Sysmon (artifacts/content/telemetry/sysmonconfig.xml, gzip+base64) на место строк-маркеров
`# @@EMBED:<файл>@@`. На хост копируется только результат.

Источник (install-agent.ps1, vector.toml) и собранный результат (install-soc-agent.ps1) нарочно в
ОДНОЙ папке (dist/, целиком в git - см. .gitignore) и под РАЗНЫМИ именами: раньше источник жил в
deploy/windows/, а результат - в dist/, оба назывались run-lab-scenarios.ps1 (см. соседний
build_lab_runner.py) - при переносе на ВМ вручную путали, какой файл копировать. Здесь имена и так
разные (install-agent.ps1 vs install-soc-agent.ps1), коллизии не было - но папка та же, ради
единообразия с run-lab-scenarios.

Запуск: uv run python scripts/build_agent_installer.py [--out dist/install-soc-agent.ps1]
"""
from __future__ import annotations

import argparse
import base64
import gzip
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "dist" / "install-agent.ps1"
VECTOR_TOML = ROOT / "dist" / "vector.toml"
SYSMON_XML = ROOT / "artifacts" / "content" / "telemetry" / "sysmonconfig.xml"


def _here_string(text: str) -> str:
    """Single-quoted here-string PowerShell: без подстановок; закрывающий `'@` - в начале строки."""
    if any(line.startswith("'@") for line in text.splitlines()):
        raise ValueError("встраиваемый текст содержит строку, начинающуюся с '@ - сломает here-string")
    return "@'\n" + text.rstrip("\n") + "\n'@"


def build(out: Path) -> None:
    script = SOURCE.read_text(encoding="utf-8-sig")
    vector = VECTOR_TOML.read_text(encoding="utf-8")
    sysmon_b64 = base64.b64encode(gzip.compress(SYSMON_XML.read_bytes(), mtime=0)).decode("ascii")

    replaced = {"vector.toml": False, "sysmonconfig.xml": False}
    lines = []
    for line in script.splitlines():
        if "# @@EMBED:vector.toml@@" in line:
            lines.append("$EmbeddedVectorToml = " + _here_string(vector))
            replaced["vector.toml"] = True
        elif "# @@EMBED:sysmonconfig.xml@@" in line:
            lines.append(f"$EmbeddedSysmonConfigGzB64 = '{sysmon_b64}'")
            replaced["sysmonconfig.xml"] = True
        else:
            lines.append(line)
    missing = [name for name, ok in replaced.items() if not ok]
    if missing:
        raise SystemExit(f"в {SOURCE} не найдены маркеры: {', '.join(missing)}")

    out.parent.mkdir(parents=True, exist_ok=True)
    # BOM обязателен: Windows PowerShell 5.1 читает .ps1 без BOM в ANSI-кодировке, русский текст
    # ломает кавычки и скрипт не разбирается. CRLF - родной перевод строки для Windows.
    out.write_bytes("\r\n".join(lines).encode("utf-8-sig") + b"\r\n")
    print(f"{out} ({out.stat().st_size // 1024} КБ)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=ROOT / "dist" / "install-soc-agent.ps1")
    build(parser.parse_args().out)


if __name__ == "__main__":
    main()
