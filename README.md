# AI Security Review Agent

Небольшой локальный учебный проект: один Python-агент получает путь к Python-проекту, запускает Bandit через MCP, читает найденный файл, ищет рекомендации в локальной базе OWASP/CWE и возвращает проверяемый JSON-отчёт. Код проверяемого проекта агент не изменяет.

## Что нужно

- Python 3.11+
- [Ollama](https://docs.ollama.com/linux) с локальными моделями для tool calling и embeddings. Python-пакет `ollama` из `pyproject.toml` — только клиент; сам сервер устанавливается отдельно.

На Fedora пакет `ollama` может отсутствовать в репозиториях `dnf`. Используйте официальный установщик для Linux:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
```

Если установщик не запустил службу, выполните `ollama serve` в отдельном терминале. После запуска сервера загрузите модели:

```bash
ollama pull qwen3:4b
ollama pull all-minilm
```

Модели после загрузки работают локально. Если используется другая модель с поддержкой tool calling и structured output, задайте `SECURITY_REVIEW_MODEL`; модель для embeddings выбирается через `SECURITY_REVIEW_EMBED_MODEL`.

## Запуск

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/security-review examples/vulnerable_app --build-index --output review.json
```

Первый запуск с `--build-index` создаёт `knowledge/index.json` из шести коротких локальных заметок и embeddings. При следующих запусках этот флаг не нужен. Отчёт можно посмотреть в `review.json` или вывести в терминал, если убрать `--output`. Чтобы дополнительно запустить тесты проверяемого проекта, добавьте `--run-tests`. Этот результат относится к исходному коду: исправления ещё не применяются.

Демонстрационный проект содержит три находки: B602 (`shell=True`), B608 (строка SQL) и B506 (`yaml.load`). В отчёте для каждой находки будут severity и местоположение от Bandit, сопоставленный CWE, объяснение, рекомендация и URL использованных материалов. Поле `tests_status` показывает `not_run`, `passed`, `failed` или `error`.

```bash
.venv/bin/python -m pytest
```

## Устройство

- `src/security_review/agent.py` — один ограниченный цикл агента и мост между Ollama tool calling и MCP.
- `src/security_review/mcp_server.py` — четыре локальных MCP tools через stdio: `read_file`, `run_security_scan`, `search_security_docs`, `run_tests`.
- `src/security_review/scanner.py` — Bandit только для B602, B608 и B506.
- `src/security_review/rag.py` — разбиение заметок, embeddings Ollama, JSON-индекс и cosine retrieval без векторной БД.
- `src/security_review/models.py` — Pydantic-схема отчёта.
- `knowledge/sources/` — шесть коротких заметок с исходными ссылками OWASP/CWE.

MCP-сервер получает корень проверяемого проекта от CLI. Чтение ограничено файлами внутри этого корня; Bandit и pytest запускаются фиксированными командами без shell. `run_tests` доступен только при `--run-tests`. У вызовов установлены пределы времени, у числа обрабатываемых находок — предел. Файлы проекта и материалы базы знаний передаются модели как данные, а не как инструкции.

В MVP нет применения patch, UI, облака, CI или обучения собственной модели. Bandit даёт предупреждения для проверки человеком; отчёт не утверждает, что каждый результат является доказанной уязвимостью.
