# Code Review — lab-9 / T2: перенацеливание диспетчера `Main` на ElGamal

**Дата:** 2026-10-18
**Область:** `src/main/java/io/allitov/Main.java` (единственный изменённый отслеживаемый файл)
**План:** `opencode-plans/lab-9.md`, задача T2 (решение Q1 — «заменить на lab-9»)
**Правила:** файл `java-rules.md` в репозитории отсутствует (проверено glob-поиском по `**/java-rules.md`) — проверка выполнена по чек-листу задачи и стандартным правилам Java-ревью.

---

## 1. Проверка области изменения (git-доказательства)

Вывод `git status --short` (до стейджинга):

```
 M opencode-plans/lab-9.md          ← bookkeeping оркестратора (разрешено условием)
 M src/main/java/io/allitov/Main.java   ← единственный изменённый отслеживаемый файл (цель T2)
?? src/main/java/io/allitov/ElGamal.java ← единственный новый НЕотслеживаемый ИСХОДНЫЙ файл (T1, уже PASS-reviewed)
?? .opencode/commands/, README.md, gifka.gif, input.txt, output*.gif/txt, output_sign.txt, reviews/
```

- (a) Единственный изменённый отслеживаемый файл — `Main.java`; `opencode-plans/lab-9.md` разрешён как bookkeeping. **Условие выполнено.**
- (b) Единственный новый неотслеживаемый **исходный** файл — `ElGamal.java`; прочие untracked-записи — данные/README/артефакты ревью, не исходники. **Условие выполнено.**
- `git diff --staged -- src/main/java/io/allitov/Main.java` (после `git add`): 11 вставок / 11 удалений, один файл.

---

## 2. Маршрутизация (check #1) — сверка с реальными сигнатурами `ElGamal`

Фактические сигнатуры (ElGamal.java, класс `@UtilityClass`, `static` добавляется Lombok'ом):

| Метод | Объявление | Вызов в Main |
|---|---|---|
| `generateKeys()` | `public long[] generateKeys() throws IOException` (ElGamal.java:43), возвращает **{p, g, Cb, Db}** (javadoc :40) | Main.java:104–105 |
| `sign` | `public void sign(Path input, Path output, long p, long g, long cb) throws IOException` (ElGamal.java:72) | Main.java:53 |
| `signAttached` | `... long p, long g, long cb ...` (ElGamal.java:96) | Main.java:65 |
| `verify` | `public boolean verify(Path input, Path signature, long p, long g, long db) throws IOException` (ElGamal.java:122) | Main.java:81–82 |
| `verifyAttached` | `public boolean verifyAttached(Path input, long p, long g, long db) throws IOException` (ElGamal.java:149) | Main.java:98 |

- **sign / sign-attached:** `keys = {p, g, cb}` (manual: Main.java:109–112) → `sign(input, output, keys[0]=p, keys[1]=g, keys[2]=cb)` — порядок совпадает. ✅
- **verify / verify-attached:** `keys = {p, g, db}` (`readVerificationKeys`, Main.java:119–124) → `verify(input, signature, p, g, db)` / `verifyAttached(input, p, g, db)` — порядок совпадает. ✅
- **Random-режим:** `ElGamal.generateKeys()` возвращает `{p, g, Cb, Db}`; берутся индексы `{0, 1, 2}` = `{p, g, Cb}` (Main.java:105) — Db корректно отброшен (Db для подписи не нужен). ✅
- Инверсии p↔g, cb↔db, подпись↔публичный ключ — **не обнаружены**.

## 3. CLI-контракт (check #2)

Строки ниже не менялись (контекст диффа) — сверены полным прочтением файла:

- USAGE при пустых аргументах (Main.java:27–29) и неизвестной команде (`default -> log.error(USAGE)`, :38). ✅
- Диспетчеризация по `args[0]`: `switch` с 4 командами (Main.java:33–39). ✅
- Арность 4/4/4/3 с per-command usage-сообщениями: Main.java:46–49, 58–61, 70–73, 87–90. ✅
- Режим sign: `random` → generateKeys; `manual` → подсказки `Enter p/g/Cb:`; иначе `log.error("Signing mode must be manual or random")` + `return null` (Main.java:103–116, `keys != null` guard на :52/:64). ✅
- verify — только manual: `!"manual".equals(args[3])` / `args[2]` → `"Verification mode must be manual"` (Main.java:75–78, 92–95). ✅
- Логи результата: `"Signature is {}"` / `"Attached signature is {}"` с `valid ? "valid" : "invalid"` (Main.java:83, :99). ✅
- Общий catch `(IOException | IllegalArgumentException | NoSuchElementException)` → `log.error("Operation failed: {}", e.getMessage())` (Main.java:40–42). ✅
- Только SLF4J (`@Slf4j`), сообщения на английском, `System.out` отсутствует (полное чтение файла, 130 строк). ✅
- «Полный набор ключей залогирован» в random-режиме: обеспечивается внутри `IlGamal.generateKeys()` — `log.info("Generated ElGamal parameters: p = {}, g = {}, Cb = {}, Db = {}", ...)` (IlGamal.java:39) — тот же паттерн, что в lab-8; `readSigningKeys` в lab-8 ключи тоже не логировал. ✅

## 4. Отклонение сигнатуры (check #3)

- `private long[] readSigningKeys(String mode) throws IOException` (Main.java:102) — **единственное** изменение сигнатуры; навязано `ElGamal.generateKeys() throws IOException` (ElGamal.java:43), тогда как старый `RSA.generateKeys()` throws не имел.
- Вызывающие `signFile` (Main.java:45) и `signAttachedFile` (:57) уже объявляли `throws IOException` в lab-8 — исключение доходит до общего catch в `run()`. Поток ошибок не нарушен. ✅
- `readVerificationKeys` (Main.java:119) без `throws` — не менялся; `verify/verifyAttached` вызываются прямо в методах, уже объявляющих `throws IOException`. Прочих дрейфов сигнатур в диффе нет. ✅

## 5. Лишние изменения (check #4)

- Grep по `rsa|RSA|\bq\b` в Main.java — совпадений нет: ссылок на RSA не осталось, «мёртвых» импортов нет (импорты Main.java:3–9 — lombok, IOException, Path, NoSuchElementException, Scanner; все используются).
- Устаревших комментариев про `q` нет; переименовано только `q → g` (:110, :121). Дифф не содержит ничего вне мандата.

## 6. Консистентность top-level vs вложенный Main (check #5)

Вложенный `private final class Main` в ElGamal.java:365–480 структурно идентичен: те же 4 команды, арности, режимы, catch, порядки ключей. Известное косметическое отличие (по вводным — не основание для FAIL): random-режим top-level вызывает `ElGamal.generateKeys()` (Main.java:104, с `throws IOException`), вложенный — `IlGamal.generateKeys()` (ElGamal.java:454, без throws, поэтому `readSigningKeys` вложенного :452 без `throws`). Делегирование функционально идентично (ElGamal.java:43–45 → IlGamal). **Отмечено, не штрафуется.**

## 7. Сборка (check #6)

```
./gradlew compileJava --rerun-tasks  → > Task :compileJava, BUILD SUCCESSFUL, 2 actionable tasks: 2 executed
./gradlew compileJava               → BUILD SUCCESSFUL (UP-TO-DATE по текущим исходникам)
```

Сборка зелёная. (Разово инструмент-обёртка показал «Exited with code 1» — артефакт пайпа stderr-предупреждения JVM через `Select-Object`; два прямых запуска дали BUILD SUCCESSFUL.)

---

## Находки

| Серьёзность | Место | Описание | Требуемые исправления |
|---|---|---|---|
| blocker | — | не обнаружено | — |
| major | — | не обнаружено | — |
| minor | — | не обнаружено | — |
| nit (заметка) | src/main/java/io/allitov/Main.java:104 vs ElGamal.java:454 | top-level random использует `ElGamal.generateKeys()`, вложенный — `IlGamal.generateKeys()`; функционально идентичное делегирование, известное косметическое расхождение | исправление не требуется |
| nit (заметка) | reviews — | `java-rules.md` в репозитории отсутствует; проверка велась по чек-листу задачи | создать/положить файл правил для будущих ревью (вне рамок T2) |

---

## Вердикт

**PASS** — блокеров и мажоров нет. Изменение точно соответствует мандату T2: диспетчер `Main` перенацелен с RSASign на ElGamal при полном сохранении CLI-контракта lab-8; порядки ключей (p, g, cb) / (p, g, db) сверены с фактическими сигнатурами `ElGamal`; единственное отклонение сигнатуры (`readSigningKeys throws IOException`) обосновано и корректно пробрасывается в общий catch; лишних изменений нет; `gradlew compileJava` — зелёный.
