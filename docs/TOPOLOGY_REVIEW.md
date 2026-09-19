# IPv4 Traffic Topology / Throttle — implementation review

Дата ревью: 2026-09-19.

## Что реализовано

- Автоматическая группировка наблюдаемых IPv4 source-адресов по префиксу; по умолчанию `/24`. Никакого списка команд для обнаружения групп не требуется.
- Внутри каждой группы сохраняются отдельные source-IP. Для групп и источников считаются wire packets/bytes и скользящие PPS/bit/s.
- Учет выполняется до основного L4 decoder и service allow-list, поэтому off-service, fragmented и malformed-L4 IPv4 спам не исчезает из Topology только из-за того, что Bazalt его дальше не анализирует как поток.
- Capture worker накапливает счетчики локально и примерно раз в 250 мс сливает batch в общую таблицу; глобального lock/atomic update для topology на каждый пакет нет.
- Source state ограничен `BAZALT_TOPOLOGY_MAX_SOURCES` (по умолчанию 65536). Новые source-IP после насыщения попадают в aggregate overflow, а не раздувают память.
- API/UI snapshot дополнительно ограничен 256 наиболее активными группами и 2048 source-строками. Полные aggregate rates/totals и исходная cardinality сохраняются, truncation явно отражен в ответе/UI.
- Группировка, string-formatting и сортировка snapshot выполняются после освобождения общего topology lock.
- Реальный throttle сделан отдельным XDP enforcement plane. Drop выполняется в kernel до обычной сетевой обработки, а не просто скрывает пакет от анализатора Bazalt.
- XDP использует IPv4 LPM trie: group rule и individual source rule могут сосуществовать; более специфичный source rule имеет приоритет.
- `drop_percent=1..100` реализован как вероятностный packet drop. `100%` — полный block.
- Правила поддерживают TTL или режим until disabled, имеют kernel seen/drop counters и bounded in-memory audit.
- Control-plane операции set/clear/expire сериализованы, чтобы истечение старого правила не могло удалить одновременно установленную замену.
- По умолчанию API не позволяет throttle CIDR шире автоматической topology-группы. При `/24` нельзя случайно установить `/16`, `/8` или `/0` penalty.
- В AF_XDP режиме Bazalt запрещает использовать один и тот же интерфейс для capture XSK и throttle attachment.

## Оценка архитектуры

### Сильные стороны

1. **Hot path не превращен в UI accounting path.** Основная стоимость на пакет — легкий Ethernet/VLAN/IPv4 source parse и update worker-local hash map. Это значительно безопаснее, чем общий concurrent map/lock на каждом frame.
2. **Accounting считает wire traffic.** Для topology используется `frame.wire_len`, а не application payload, поэтому BPS ближе к тому, что реально нагружает линк.
3. **Enforcement расположен правильно.** Percentage throttle реализован как настоящий XDP drop. Если бы пакет отбрасывался только после capture внутри Rust, участник не получал бы сетевого penalty.
4. **Память bounded на двух уровнях.** Ограничена как cardinality backend-state, так и объем JSON/UI snapshot. Это важно именно для функции, которая будет наблюдать packet-spam и spoofed-source floods.
5. **Опасные широкие правила ограничены.** UI работает с auto-group `/24` и source `/32`, а API не дает случайно выйти выше group scope.
6. **Control plane и kernel state обновляются последовательно.** Исправлена race между TTL expiry и replacement rule.
7. **Topology и enforcement разделены.** Bazalt может продолжать показывать topology вообще без настроенного drop-интерфейса; неверная конфигурация enforcement не маскируется как рабочая.

### Оставшиеся риски / что еще требуется проверить на целевой машине

1. В текущем artifact environment отсутствуют `cargo`, `rustc`, `rustfmt` и `clippy`, поэтому полный Rust compile/test/clippy gate здесь выполнить невозможно. Source verification намеренно останавливается на этом mandatory gate.
2. У установленного clang отсутствует BPF backend, поэтому `clang -target bpf` и kernel verifier/load здесь не проверены. Host-C syntax `native/throttle.bpf.c` проходит с `-Wall -Wextra -Werror`.
3. Нужен destructive integration test на disposable veth: `/32` и `/24` rules на 25/50/100%, TTL expiry, `/24 + /32` longest-prefix precedence, counters и отсутствие влияния на management/capture interface.
4. При очень большом числе tracked sources snapshot все еще проходит по всей bounded таблице (максимум 65536) для вычисления rates перед top-K trimming. Это сознательный компромисс: memory/UI bounded, но при экстремальном spoof flood стоит измерить snapshot CPU и при необходимости перейти на sharded heavy-hitter structure.
5. Rule stats сейчас обновляются атомиками в LPM value. Это просто и корректно, но на очень высоком PPS одного penalized source может стать cache-contention point. Если soak покажет заметную цену, следующий шаг — per-CPU stats map с rule id.
6. Audit и active rulebook живут в памяти процесса. При restart XDP link закрывается и penalty исчезает — это fail-safe поведение, но durable operator audit при необходимости лучше хранить отдельно.
7. Автоматическая `/24` группировка выводит сетевую структуру, но не может сама достоверно понять роль `Jury`/`Team` только по IP. Роли/labels лучше делать необязательным presentation-layer mapping, не меняя автоматическое обнаружение.

## Выполненные проверки

Пройдены:

- `python3 -m py_compile scripts/*.py`
- fixture generation + `scripts/verify_fixture.py`
- `scripts/static_verify.py`
- `scripts/verify_v04_hotpath.py`
- `node --check frontend/app.js`
- `bash -n scripts/smoke.sh`
- `bash -n scripts/verify_source.sh`
- YAML parse `docker-compose.yml`
- `clang -Wall -Wextra -Werror -fsyntax-only native/throttle.bpf.c`
- syntax pass `native/throttle.c` с временными mock libbpf declarations (это проверка C-синтаксиса, не ABI/API compatibility).

Не пройдены не из-за найденной ошибки, а из-за отсутствия toolchain в окружении:

- `cargo fmt --check`
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo test --all-features`
- `cargo build --release --all-features`
- actual `clang -target bpf` + kernel XDP verifier/load.

До production/deployment acceptance feature следует считать **implementation-complete, source-gate checked, but native-gate pending**.
