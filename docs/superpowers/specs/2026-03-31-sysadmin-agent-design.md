# AgenSysAdmin — MCP-сервер для системного администрирования

## Обзор

Python MCP-сервер, который позволяет Claude Code управлять удалёнными Linux-серверами (Ubuntu/Debian) через SSH. Монолитная архитектура с модульной внутренней структурой. Гибридный подход к tools: готовые инструменты для типовых операций + `execute_command` для произвольных команд.

## Milestone 1 — Ядро + Мониторинг

Первый этап: SSH-подключение, конфигурация серверов и базовый набор tools для мониторинга.

### Структура проекта

```
agensysadmin/
├── src/
│   ├── server.py          # MCP сервер, точка входа
│   ├── ssh_manager.py     # Управление SSH-соединениями
│   ├── config.py          # Загрузка конфигурации
│   └── tools/
│       ├── monitoring.py  # check_services, system_info, disk_usage...
│       └── general.py     # execute_command (произвольные команды)
├── servers.yaml           # Конфигурация серверов
├── .env                   # Секреты (пути к ключам, пароли)
├── pyproject.toml
└── README.md
```

### Компоненты

#### SSH Manager (`ssh_manager.py`)

Пул SSH-соединений через paramiko:
- Подключается по запросу, кэширует активное соединение
- Автоматически переподключается при обрыве
- Берёт креды из конфига + .env
- Таймаут подключения: 10 сек (настраиваемо)
- Таймаут выполнения команды: 30 сек (настраиваемо)
- Логика подключения: сначала SSH-ключ (если указан), затем пароль

#### Config (`config.py`)

Загружает два источника:
- `servers.yaml` — хосты, порты, юзеры, алиасы, роли серверов
- `.env` — пути к SSH-ключам, пароли (через python-dotenv)

#### Конфигурация серверов

**servers.yaml:**
```yaml
servers:
  prod:
    host: 192.168.1.10
    port: 22
    user: admin
    key_env: PROD_SSH_KEY_PATH

  staging:
    host: 192.168.1.20
    port: 2222
    user: deploy
    key_env: STAGING_SSH_KEY_PATH
```

**.env:**
```
PROD_SSH_KEY_PATH=/home/user/.ssh/prod_key
STAGING_SSH_KEY_PATH=/home/user/.ssh/staging_key
# PROD_SSH_PASSWORD=secret
```

### MCP Tools

Каждый tool принимает `server` (алиас или хост) как обязательный параметр.

| Tool | Параметры | Описание |
|------|-----------|----------|
| `list_servers` | — | Список настроенных серверов и их статус (доступен/нет) |
| `system_info` | `server` | OS, uptime, CPU, RAM, swap, load average |
| `disk_usage` | `server` | Использование дисков и файловых систем |
| `check_services` | `server`, `services` (опц.) | Статус systemd-сервисов |
| `check_ports` | `server` | Открытые порты и слушающие процессы |
| `process_list` | `server`, `sort_by` (cpu/memory) | Топ процессов по CPU/RAM |
| `execute_command` | `server`, `command`, `timeout` (опц., сек) | Произвольная команда, возвращает `{stdout, stderr, exit_code, duration_ms}` |

### MCP интеграция

Сервер регистрируется в Claude Code:

```json
{
  "mcpServers": {
    "sysadmin": {
      "command": "python",
      "args": ["-m", "agensysadmin.server"],
      "cwd": "D:/AI/AgenSysAdmin"
    }
  }
}
```

### Примеры использования

- *"Проверь что nginx работает на prod"* → `check_services(server="prod", services=["nginx"])`
- *"Что жрёт память на staging?"* → `process_list(server="staging", sort_by="memory")`
- *"Поставь htop на prod"* → `execute_command(server="prod", command="sudo apt install -y htop")`

### Зависимости

- `mcp` — MCP SDK для Python
- `paramiko` — SSH-клиент
- `pyyaml` — парсинг YAML
- `python-dotenv` — загрузка .env

## Будущие Milestone'ы

| Milestone | Домен | Ключевые tools |
|-----------|-------|----------------|
| 2 | Установка/настройка | `install_package`, `manage_service`, `edit_config` |
| 3 | Docker | `docker_ps`, `docker_logs`, `docker_compose_up` |
| 4 | Безопасность | `security_audit`, `check_updates`, `firewall_status` |
| 5 | Бэкапы | `create_backup`, `list_backups`, `check_cron` |
| 6 | Отчёты | `generate_report` (markdown/PDF) |

Каждый milestone — отдельный цикл spec → plan → implementation.
