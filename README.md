# eBPF Monitor

Мониторинг системных вызовов `execve` и `openat` через eBPF с экспортом метрик в Prometheus и визуализацией в Grafana.



**eBPF Monitor** — система наблюдаемости, которая:

- прикрепляется к tracepoints `sys_enter_execve` и `sys_enter_openat` в ядре Linux;
- передаёт события из ядра в user-space через `BPF_MAP_TYPE_RINGBUF`;
- агрегирует события в счётчики Prometheus;
- отдаёт метрики по HTTP через самописный epoll-сервер;
- визуализирует данные в Grafana.


## Возможности

- Мониторинг `execve` и `openat`
- Классификация событий: root, sudo, обычные пользователи
- Детектирование открытия `/etc/shadow`, `/etc/sudoers`, `/etc/passwd`
- Метрики в формате Prometheus
- Готовый дашборд Grafana
- Два режима логирования: базовый и расширенный
- Статически слинкованный бинарник — работает на любом Linux без пересборки



## Архитектура
```
┌────────────────────────────────────────────────────────┐
│                     KERNEL SPACE                       │
│                                                        │
│  ┌─────────────────────┐ ┌─────────────────────┐       │
│  │ tracepoint:         │ │ tracepoint:         │       │
│  │ sys_enter_execve    │ │ sys_enter_openat    │       │
│  └──────────┬──────────┘ └──────────┬──────────┘       │
│             │                       │                  │
│             ▼                       ▼                  │
│  ┌───────────────────────────────────────────────────┐ │
│  │ monitor.bpf.c (eBPF program)                      │ │
│  │ handle_execve() / handle_openat()                 │ │
│  │ заполняет struct event_data                       │ │
│  └───────────────────────┬───────────────────────────┘ │
│                          │                             │
│                          ▼                             │
│  ┌───────────────────────────────────────────────────┐ │
│  │ BPF_MAP_TYPE_RINGBUF "rb" (8 Mb)                  │ │
│  └───────────────────────┬───────────────────────────┘ │
└──────────────────────────┼─────────────────────────────┘
                           │ epoll-уведомление
                           ▼
┌───────────────────────────────────────────────────────────────────┐
│                       USER SPACE                                  │
│                                                                   │
│ ┌───────────────────────────────────────────────────────────────┐ │
│ │                     main.cpp                                  │ │
│ │ 1. monitor_bpf__open() → __load() → __attach()                │ │
│ │ 2. ring_buffer__new(skel->maps.rb, handle_event, ...)         │ │
│ │ 3. ring_buffer__poll() → handle_event()                       │ │
│ │ 4. обновление atomic-счётчиков + console_log()                │ │
│ └─────────────────────────┬─────────────────────────────────────┘ │
│                           │                                       │
│                           ▼                                       │
│ ┌───────────────────────────────────────────────────────────────┐ │
│ │ prometheus-exporter.cpp                                       │ │
│ │ epoll-сервер на порту 8080                                    │ │
│ │ GET /metrics → Prometheus text exposition                     │ │
│ └──────────────────────────┬────────────────────────────────────┘ │
└────────────────────────────┼──────────────────────────────────────┘
                             │ HTTP scrape (раз в 15 сек)
                             ▼
             ┌──────────────────────────────┐
             │       Prometheus :9090       │
             └──────────────┬───────────────┘
                            │ PromQL
                            ▼
             ┌──────────────────────────────┐
             │       Grafana :3000          │
             └──────────────────────────────┘
```


### 1. Ядерный модуль — `monitor.bpf.c`

| Свойство | Значение |
|---|---|
| Язык | C (BPF-диалект, без libc) |
| Живёт | В ядре Linux (ring 0) |
| Хуки | `tracepoint/syscalls/sys_enter_execve`, `tracepoint/syscalls/sys_enter_openat` |
| Map | `BPF_MAP_TYPE_RINGBUF`, 256 KB |


### 2. User-space агент — `main.cpp` + `app_context.cpp`

| Свойство | Значение |
|---|---|
| Язык | C++17 |
| Библиотеки | `libbpf` |
| Задачи | Загрузка BPF, attach, чтение ringbuf, обновление метрик |


### 3. Prometheus-экспортер — `prometheus-exporter.h/.cpp`

| Свойство | Значение |
|---|---|
| Язык | C++17 |
| Транспорт | Сырые сокеты + `epoll` |
| Порт | 8080 |
| Эндпоинт | `GET /metrics` |


## Структура проекта
```
ebpf-monitor/
├── CMakeLists.txt # сборка BPF + user-space
├── Dockerfile # multi-stage сборка
├── docker-compose.yml # agent + prometheus + grafana
├── prometheus.yml # конфиг Prometheus
├── README.md
├── build/ # артефакты, не отслеживается
│
├── grafana/
│ ├── dashboards/
│ │ ├── dashboards.yml
│ │ └── ebpf_dashboard.json
│ └── datasources/
│ └── datasource.yml
│
└── src/
    ├── common.h # общая структура event_data
    ├── monitor.bpf.c # eBPF-программа
    ├── main.cpp # точка входа
    ├── app_context.h
    ├── app_context.cpp
    ├── prometheus-exporter.h
    ├── prometheus-exporter.cpp
    └── vmlinux.h # генерируется
```

### Генерируемые файлы

| Файл | Кто генерирует | Как |
|---|---|---|
| `vmlinux.h` | `bpftool` | `bpftool btf dump file /sys/kernel/btf/vmlinux format c` |
| `monitor.bpf.o` | `clang` | `clang -target bpf -c monitor.bpf.c` |
| `monitor.skel.h` | `bpftool` | `bpftool gen skeleton monitor.bpf.o` |


## Метрики

| Метрика Prometheus | Поле в коде | Тип | Что считает |
|---|---|---|---|
| `ebpf_exec_total` | `metrics_exec_total` | counter | Все `execve` |
| `ebpf_open_total` | `metrics_open_total` | counter | Все `openat` |
| `ebpf_sudo_actions_total` | `metrics_sudo_actions` | counter | Запуск `sudo` |
| `ebpf_root_actions_total` | `metrics_root_actions` | counter | Действия с `uid==0` |
| `ebpf_sensitive_files_opened_total` | `sensitive_files_opened` | counter | Открытия `/etc/shadow`, `/etc/sudoers`, `/etc/passwd` |

### Логика классификации

**EVENT_EXEC:**
```
exec_total++
if uid == 0: root_actions++; log("[ROOT EXEC]")
elif path in {/usr/bin/sudo, /bin/sudo}: sudo_actions++; log("[SUDO ACTION EXEC]")
elif extended_logs: log("[EXEC]")
```

**EVENT_OPEN:**
```
open_total++
if path in {/etc/shadow, /etc/sudoers, /etc/passwd}:
sensitive_files_opened++; log("[SENSITIVE FILE OPEN]") # всегда
elif uid == 0:
root_actions++; log("[ROOT OPEN]") # всегда
elif extended_logs:
log("[OPEN]")
```

### Пример `/metrics`
```
HELP ebpf_exec_total Total number of execve syscalls
TYPE ebpf_exec_total counter
ebpf_exec_total 1523

HELP ebpf_open_total Total number of openat syscalls
TYPE ebpf_open_total counter
ebpf_open_total 89271

HELP ebpf_sudo_actions_total Total sudo invocations
TYPE ebpf_sudo_actions_total counter
ebpf_sudo_actions_total 4

HELP ebpf_root_actions_total Total actions by root
TYPE ebpf_root_actions_total counter
ebpf_root_actions_total 312

HELP ebpf_sensitive_files_opened_total Sensitive files opened
TYPE ebpf_sensitive_files_opened_total counter
ebpf_sensitive_files_opened_total 2

```


##  Формат события

`src/common.h` — включается и в `monitor.bpf.c`, и в `main.cpp`. Layout должен совпадать побайтово.

```c
#ifndef __COMMON_H
#define __COMMON_H

#define MAX_PATH_LEN  200
#define MAX_ARGS_LEN  64

enum event_type {
    EVENT_EXEC,
    EVENT_OPEN
};

struct event_data {
    unsigned int    pid;
    unsigned int    uid;
    enum event_type type;
    char            path[MAX_PATH_LEN];
    char            args[MAX_ARGS_LEN];
};

#endif
```
Размер: 4 + 4 + 4 + 200 + 64 = 276 байт. При ringbuf 8Mb(8 * 1024 * 1024) помещается 8388608 / (276 + 8) ≈ 29 537 событий одновременно.

## Сборка

```
┌──────────────────────────┐
│ /sys/kernel/btf/vmlinux  │
└────────────┬─────────────┘
             │ bpftool btf dump
             ▼
      ┌──────────────┐
      │  vmlinux.h   │
      └──────┬───────┘
             │ #include
             ▼
┌──────────────────────────┐            ┌───────────────────┐
│ src/monitor.bpf.c        │──clang─ ▶ │ monitor.bpf.o     │
└──────────────────────────┘  -target   │ (BPF bytecode)    │
                                bpf     └────────┬──────────┘
                                              │ bpftool gen skeleton
                                              ▼
                                     ┌──────────────────┐
                                     │ monitor.skel.h   │
                                     └────────┬─────────┘
                                              │ #include
                                              ▼
┌──────────────────────────────────────────────────────────┐
│ src/main.cpp + app_context.cpp + prometheus-exporter.cpp │
└──────────────────────────┬───────────────────────────────┘
                           │ g++ -std=c++17
                           │ -lbpf -lelf -lz
                           ▼
                  ┌──────────────────┐
                  │  ebpf-monitor    │
                  │  (executable)    │
                  └──────────────────┘
```
### Этапы

vmlinux.h — BTF-дамп из ядра. Генерируется один раз:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
monitor.bpf.o — компиляция BPF:

```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I. -c src/monitor.bpf.c -o monitor.bpf.o
```
monitor.skel.h — генерация скелета:

```bash
bpftool gen skeleton monitor.bpf.o > monitor.skel.h
```
Линковка user-space:

```bash
g++ -std=c++17 src/main.cpp src/app_context.cpp src/prometheus-exporter.cpp \
    -I. -lbpf -lelf -lz -o ebpf-monitor
```

### В проекте сборка автоматизирована двумя способами:

A. Локальная сборка через CMake (для разработки)
Используется, когда вы активно меняете код. docker-compose.yml собирает agent через Dockerfile, но Dockerfile использует те же шаги, что и CMake, только вручную.

B. Готовый статический бинарник (для переносимости)
Dockerfile собирает статически слинкованный ebpf-monitor на Alpine.
- не зависит от glibc/musl хоста;
- работает на любом Linux с подходящим ядром;
- не требует пересборки на каждом сервере.

Бинарник тащит с собой libbpf/libelf/zlib, не зависит от хостовых .so. На сервере с другим дистрибутивом (Ubuntu, Debian, RHEL) достаточно скопировать файл — он запустится.

Команды для компиляции такого бинарника:

```bash
docker build . -t ebpf-build

docker create --name ebpf-build ebpf-build

docker cp ebpf-build:/app/ebpf-monitor ./

docker rm ebpf-build
```


## Запуск мониторинга

```bash
docker compose up -d
```

| Сервис | Порт | Что делает |
|---|---|---|
| agent | 8080 | `eBPF-монитор + экспортер` |
| prometheus | 9090 | `скрейпит agent:8080/metrics` |
| grafana | 3000 | `визуализация` |


### Доступ:

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3000 (admin/admin)
- Метрики: http://localhost:8080/metrics


## Почему epoll, а не поток на клиента
`prometheus_endpoint()` использует `epoll` вместо `std::thread(handle_client, fd).detach()`.


>Поток на клиента
```
accept() → std::thread(handle_client, cfd).detach()
```
Стек: 8 MB на поток по умолчанию. 1000 клиентов = 8 GB виртуальной памяти.Переключение контекста: ядро переключает регистры, TLB, стек ядра. Микросекунды на каждое.Планировщик: 1000 потоков конкурируют за CPU. Переключения происходят постоянно, даже когда данных нет. Создание/уничтожение: `pthread_create = syscall clone + аллокация стека`. Дорого для коротких соединений.

>epoll

Один поток обслуживает N соединений. Память — только структуры epitem (~200 байт на fd). Нет переключений контекста, пока нет данных. `O(1)` на готовое событие: ядро само отслеживает готовность, `epoll_wait()` возвращает только активные fd. Создание/удаление — `epoll_ctl(ADD/DEL)`, дешёвая операция.

В контексте Prometheus:
Prometheus скрейпит раз в 15 секунд, соединение живёт миллисекунды. Если на каждого — поток: за 5 секунд создаётся и уничтожается, при нескольких таргетах с одного Prometheus — постоянная нагрузка на планировщик.

С epoll: соединение принимается, обслуживается, закрывается в том же потоке, нет pthread_create/join, память и CPU — минимальны.

## Логирование
`AppContext::console_log(bool always, const char* tag, pid, uid, path, args)`

|Режим	| Флаг	| Что пишет |
|---|---|---|
|Базовый|extended_logs = false|[ROOT *], [SUDO ACTION EXEC], [SENSITIVE FILE OPEN]
|Расширенный|extended_logs = true|Все события, включая [EXEC] и [OPEN]


Включение: указазать `extended_logs = true` в `app_context.h`

Пример:

```
[ROOT EXEC]            pid=1234 uid=0    path=/usr/bin/apt args=update
[SUDO ACTION EXEC]     pid=5678 uid=1000 path=/usr/bin/sudo args=-l
[SENSITIVE FILE OPEN]  pid=9999 uid=0    path=/etc/shadow args=none
[EXEC]                 pid=1111 uid=1000 path=/bin/ls args=-la /tmp
```

## Требования
- Ядро Linux 5.8+ (BPF_MAP_TYPE_RINGBUF)
- BTF: /sys/kernel/btf/vmlinux
- CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_JIT=y
- Пользователь `root` или capabilities `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`
- Docker 20.10+, Docker Compose 2.x