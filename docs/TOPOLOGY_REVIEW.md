# IPv4 Traffic Topology / Throttle — implementation review

Дата ревью: 2026-09-19.

## Что реализовано

- Автоматическая группировка наблюдаемых IPv4 source-адресов по префиксу; по умолчанию `/24`. Никакого списка команд для обнаружения групп не требуется.
- Внутри каждой группы сохраняются отдельные source-IP. Для групп и источников считаются wire packets/bytes и скользящие PPS/bit/s.
- Учет выполняется только после directional service-destination проверки: off-service traffic не попадает в Topology/participant statistics. Обычный off-service IPv4 отсеивается ещё лёгким pre-decode classifier; fragments/tunnels проходят bounded decoder и учитываются только если итоговый destination port настроен как сервис.
- Capture worker накапливает счетчики локально и примерно раз в 250 мс сливает batch в общую таблицу; глобального lock/atomic update для topology на каждый пакет нет.
- Source state ограничен `BAZALT_TOPOLOGY_MAX_SOURCES` (по умолчанию 65536). Новые source-IP после насыщения попадают в aggregate overflow, а не раздувают память.
- API/UI snapshot дополнительно ограничен 256 наиболее активными группами и 2048 source-строками. Полные aggregate rates/totals и исходная cardinality сохраняются, truncation явно отражен в ответе/UI.
- Группировка, string-formatting и сортировка snapshot выполняются после освобождения общего topology lock.
- Реальный throttle сделан отдельным XDP enforcement plane. Drop выполняется в kernel до обычной сетевой обработки, а не просто скрывает пакет от анализатора Bazalt.
- XDP использует IPv4 LPM trie: group rule и individual source rule могут сосуществовать; более специфичный source rule имеет приоритет.
- `drop_percent=1..100` реализован как вероятностный packet drop. `100%` — полный block.
- Правила всегда имеют конечный TTL (1–3600 секунд), kernel seen/drop counters и bounded in-memory audit; бессрочный drop намеренно запрещён.
- Control-plane операции set/clear/expire сериализованы, чтобы истечение старого правила не могло удалить одновременно установленную замену.
- По умолчанию API не позволяет throttle CIDR шире автоматической topology-группы. При `/24` нельзя случайно установить `/16`, `/8` или `/0` penalty.
- `BAZALT_EARLY_PORT_FILTER=true` совместим с новой семантикой и используется по умолчанию как backend-оптимизация; userspace service gate остаётся authoritative.
- Active Rules выводит live matched/drop rate по дельтам kernel counters, поэтому pre-drop давление остаётся видимым после применения throttle.
- Same-interface enforcement поддерживается: throttle XDP остаётся единственным владельцем ingress hook, а запрошенный AF_XDP capture автоматически заменяется на пассивный libpcap. При passive capture кадры с source MAC самого интерфейса не входят в Topology, поэтому исходящий трафик хоста не искажает список отправителей.
- Native-XDP путь использует BPF link, поэтому attachment следует lifetime процесса. Если BPF-link attach недоступен, используется netlink fallback: он может остаться native или перейти в generic/SKB с защитой `UPDATE_IF_NOEXIST` и проверкой собственного program id при detach.
- Правила не могут быть бессрочными: TTL только 1–3600 секунд и проверяется в kernel. Active Rules отображаются отдельно от текущих source nodes, поэтому 100% block нельзя потерять из UI после истечения topology source TTL.

## Оценка архитектуры

### Сильные стороны

1. **Hot path не превращен в UI accounting path.** Обычный off-service IPv4 сначала проходит дешёвый Ethernet/VLAN/IPv4+port classifier и отбрасывается до полного decoder. Для принятого service packet Topology обновляет только worker-local hash map после единого `packet_scope` snapshot; общего concurrent map/lock на каждом frame нет.
2. **Accounting считает service-directed wire traffic.** Для принятого packet используется `packet.wire_len`, а не application payload, поэтому BPS отражает wire bytes именно трафика на добавленные порты.
3. **Enforcement расположен правильно.** Percentage throttle реализован как настоящий XDP drop. Если бы пакет отбрасывался только после capture внутри Rust, участник не получал бы сетевого penalty.
4. **Память bounded на двух уровнях.** Ограничена как cardinality backend-state, так и объем JSON/UI snapshot. Это важно именно для функции, которая будет наблюдать packet-spam и spoofed-source floods.
5. **Опасные широкие правила ограничены.** UI работает с auto-group `/24` и source `/32`, а API не дает случайно выйти выше group scope.
6. **Control plane и kernel state обновляются последовательно.** Исправлена race между TTL expiry и replacement rule.
7. **Topology и enforcement разделены логически и используют один ingress при включённом enforcement.** Bazalt может показывать topology без enforcement; при включенном same-interface throttle XDP отвечает только за drop/pass, а capture остаётся пассивным и не конкурирует за XDP hook.

### Оставшиеся риски / что еще требуется проверить на целевой машине

1. В текущем artifact environment отсутствуют `cargo`, `rustc`, `rustfmt` и `clippy`, поэтому полный Rust compile/test/clippy gate здесь выполнить невозможно. Source verification намеренно останавливается на этом mandatory gate.
2. У установленного clang отсутствует BPF backend, поэтому `clang -target bpf` и kernel verifier/load здесь не проверены. Host-C syntax `native/throttle.bpf.c` проходит с `-Wall -Wextra -Werror`.
3. Нужен destructive integration test на disposable veth в same-interface режиме: XDP throttle + passive capture на одном ingress, `/32` и `/24` rules на 25/50/100%, TTL expiry, `/24 + /32` longest-prefix precedence и сверка kernel counters с фактически прошедшим трафиком.
4. При очень большом числе tracked sources snapshot все еще проходит по всей bounded таблице (максимум 65536) для вычисления rates перед top-K trimming. Это сознательный компромисс: memory/UI bounded, но при экстремальном spoof flood стоит измерить snapshot CPU и при необходимости перейти на sharded heavy-hitter structure.
5. Rule stats сейчас обновляются атомиками в LPM value. Это просто и корректно, но на очень высоком PPS одного penalized source может стать cache-contention point. Если soak покажет заметную цену, следующий шаг — per-CPU stats map с rule id.
6. Audit и active rulebook живут в памяти процесса. На native BPF-link пути restart/crash снимает attachment. На любом netlink fallback жёсткий `SIGKILL` может оставить сам XDP program прикреплённым; mandatory kernel TTL гарантирует прекращение drop, но pass-only attachment способен потребовать ручного detach перед restart. Это оставшийся lifecycle gap, который лучше закрыть stale-owner recovery/heartbeat в следующем hardening шаге. Durable operator audit при необходимости тоже лучше хранить отдельно.
7. Автоматическая `/24` группировка выводит сетевую структуру, но не может сама достоверно понять роль `Jury`/`Team` только по IP. Роли/labels лучше делать необязательным presentation-layer mapping, не меняя автоматическое обнаружение.
8. Для обычного unfragmented IPv4 один wire packet соответствует одному Topology packet. Для IP fragmentation Topology сейчас учитывает завершённый reassembled service datagram как один packet с агрегированным `wire_len`; незавершённые fragment sets остаются только в capture/fragment health metrics. Это bounded и не пропускает их в L7, но при специально фрагментированном packet-spam PPS может быть занижен. Если такой adversarial режим важен, следующий hardening — fragment-aware service visibility/counter state, который считает физические fragments после того, как первый fragment связал datagram с service port.

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

Не пройдены не из-за найденной ошибки, а из-за отсутствия toolchain в окружении:

- `cargo fmt --check`
- `cargo clippy --all-features --all-targets -- -D warnings`
- `cargo test --all-features`
- `cargo build --release --all-features`
- actual `clang -target bpf` + kernel XDP verifier/load.

До production/deployment acceptance feature следует считать **implementation-complete, source-gate checked, but native-gate pending**.
