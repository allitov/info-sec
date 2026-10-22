# Plan contract: lab-9

> Disk source of truth. Re-read before each decision and after any compaction.

**Goal:** Реализовать ЭЦП Эль-Гамаля (tasks/lab-9.md): новый утилитный класс `ElGamal` в пакете `io.allitov` — подпись любого файла (отдельным файлом подписи И присоединённой — оба варианта, как в lab-8) и проверка подписи. SHA-256 хеш подписывается побайтово: каждый байт h — пара (a, b) при одних и тех же ключах {p, g, Cb, Db}, переиспользуемых из `IlGamal.generateKeys()/createKeys()`. CLI зеркалирует `RSASign` (`sign|sign-attached|verify|verify-attached`, режим `manual|random`); тесты зеркалируют `RSASignTest`/`IlGamalTest`. Критерий готовности: `gradlew test` зелёный включая новый `ElGamalTest`; round-trip «подпись → проверка = true», любая модификация файла или подписи → false.

**active:** —

## open_questions

- [x] Q1: Точка входа `Main.java` (gradle entry, сейчас диспетчер lab-8 RSASign): заменить диспетчер на команды lab-9 (ElGamal), или объединить оба набора под неймспейсами (rsa-* / elgamal-*), или не трогать `Main` (CLI живёт во вложенном `Main` класса `ElGamal`, но тогда недоступен через `gradlew run`) — answer: **Заменить на lab-9**: Main диспетчит те же 4 команды, но через `ElGamal`.
- [x] Q2: Варианты подписи: делать оба (detached + attached, как в lab-8 RSASign) или только один? — answer: **Оба** (detached + attached), полное зеркало lab-8.

## backlog

- [x] **T1** — Класс `ElGamal`: ядро ЭЦП + вложенный CLI
    - **agent:** coder
    - **inputs:**
        - Создать `src/main/java/io/allitov/ElGamalSign.java`, `@Slf4j @UtilityClass public class ElGamalSign` (Lombok-паттерн проекта; поля без ключевого слова `static` — `@UtilityClass` статизирует сам). Java 25.
        - **Публичный API (зеркало RSASign, `src/main/java/io/allitov/RSASign.java:45-120`):**
            - `public long[] generateKeys()` — делегирует `IlGamal.generateKeys()` (вернёт `{p, g, Cb, Db}`; p = простое из `CryptoUtils.randomLargePrime()` в [1e9, 2e9), g — наименьший первообразный корень, Cb ∈ [1, p−2], Db = g^Cb mod p).
            - `public long[] createKeys(long p, long g, long cb)` — делегирует `IlGamal.createKeys(p, g, cb)` (валидирует p ∈ [257, 3_037_000_000] + `CryptoUtils.ferma`, g — первообразный корень, Cb ∈ [1, p−2]; бросает IllegalArgumentException).
            - `public void sign(Path input, Path output, long p, long g, long cb) throws IOException` — отсоединённая подпись.
            - `public void signAttached(Path input, Path output, long p, long g, long cb) throws IOException` — 512-байтная подпись префиксом, затем контент (`transferTo`, как RSASign.java:77-78).
            - `public boolean verify(Path input, Path signature, long p, long g, long db) throws IOException`.
            - `public boolean verifyAttached(Path input, long p, long g, long db) throws IOException`.
        - **Математика подписи одного байта h (h = hashByte & 0xFF, 0..255):**
            1. `k`: повторять `RANDOM.nextLong(1, p - 1)` (диапазон [1, p−2]), пока `CryptoUtils.gcdSimple(k, p - 1) != 1` (репликация private `IlGamal.randomSessionKey`, IlGamal.java:175-182).
            2. `a = CryptoUtils.pow(g, k, p)`.
            3. `b` — ТОЛЬКО через BigInteger (в IlGamal/CryptoUtils нет BigInteger; прецедент — приватный `power`/`modularInverse` в RSA/RSASign): `b = BigInteger.valueOf(k).modInverse(BigInteger.valueOf(p - 1)).multiply(BigInteger.valueOf(h).subtract(BigInteger.valueOf(cb).multiply(BigInteger.valueOf(a)))).mod(BigInteger.valueOf(p - 1)).longValueExact()`. `.mod()` BigInteger всегда неотрицателен — НЕ использовать `%` для отрицательных. Если `b == 0` — выбрать новый k и пересчитать пару (b=0 вырожден; вероятность ~1/(p−1), retry без счётчика).
        - **Проверка пары (a, b) для байта h:** валидность диапазонов (зеркало `IlGamal.validateCiphertextPart` / `RSASign.readSignature`): `1 <= a <= p-1` и `0 <= b <= p-2`; невалидно → подпись целиком `false` (не исключение). Уравнение: `CryptoUtils.pow(g, h, p) == (CryptoUtils.pow(db, a, p) * CryptoUtils.pow(a, b, p)) % p`. Переполнение безопасно: остатки < p ≤ 3_037_000_000 (MAX_MODULUS), произведение ≤ (p−1)² ≈ 9.2233e18 < Long.MAX_VALUE.
        - **Валидация ключей на sign-стороне:** реплицировать 3 приватные проверки (у RSASign свои — RSASign.java:225-243): p — простое в диапазоне + ferma; g — первообразный корень (логика `isPrimitiveRoot`, IlGamal.java:153-173: разложить p−1 пробным делением, для каждого простого фактора f проверить `CryptoUtils.pow(g, (p-1)/f, p) != 1`); Cb ∈ [1, p−2]. На verify-стороне: p, g — те же проверки, Db ∈ [2, p−1]. Все нарушения — IllegalArgumentException.
        - **Приватные хелперы (реплицировать, НЕ трогая чужие классы):** `digest(Path)` + `digestRemaining(InputStream)` — SHA-256 через JCE `MessageDigest`, буфер `byte[8192]`, проверка длины 32 (RSASign.java:193-217); `writeLong(OutputStream, long)` — 8 байт big-endian (IlGamal.java:215-219); `readLong(byte[], int)` (IlGamal.java:221-228); `readFully(InputStream, byte[])` (IlGamal.java:230-242).
        - **Формат на диске:** detached = ровно 32 × (a: 8B BE, b: 8B BE) = **512 байт**; короче или длиннее → `verify` = false. attached = 512-байтный префикс + контент; файл < 512 байт → false.
        - **Вложенный CLI** `@UtilityClass private final class Main` — зеркало RSASign.Main (RSASign.java:274-391): поля `SCANNER = new Scanner(System.in)`, `USAGE`; package-private `void main(String[] args)`; диспетчер: `sign` (4 аргумента: input, output, mode), `sign-attached` (4), `verify` (4: input, signature, mode), `verify-attached` (3: input, mode); неверное число аргументов → log.error(USAGE). Режим `random` для sign → `IlGamal.generateKeys()`, взять {p, g, Cb}, залогировать все ключи; `manual` → `readLong("p"/"g"/"Cb")` с подсказками `log.info("Enter {}:", name)`. verify — только `manual` (p, g, Db); иначе `log.error("Verification mode must be manual")`. Общий catch `(IOException | IllegalArgumentException | NoSuchElementException)` → `log.error("Operation failed: {}", e.getMessage())`. Сообщения в стиле RSASign: «Signing file {} with a separate signature file {}», «File signed successfully: {}», «Signature is {}», valid ? "valid" : "invalid" — на английском.
        - **Запрет на рефакторинг соседей:** НЕ выносить дублирующиеся хелперы в CryptoUtils, НЕ менять IlGamal/RSA/RSASign/Main. Триплликация readLong/writeLong — устоявшийся стиль репозитория.
        - Контекст: проект — Gradle Kotlin DSL, `gradlew compileJava` для проверки сборки; тестов для ElGamal ещё нет (их пишет T3).
    - **deps:** []
    - **acceptance:** `gradlew compileJava` проходит; класс содержит все 6 публичных методов с точными сигнатурами выше; вложенный `Main` диспетчирует 4 команды; ни один существующий файл не изменён.
    - **description:** Создать `ElGamal.java` целиком по спецификации в inputs (ядро sign/verify + формат файла + валидаторы + вложенный CLI). Одним атомарным файлом.
    - **touched:** src/main/java/io/allitov/ElGamal.java (новый файл; ревью: reviews/lab-9-t1.code-review.md, PASS)
- [x] **T2** — Точка входа lab-9 (решение по Q1)
    - **agent:** coder
    - **inputs:**
        - `src/main/java/io/allitov/Main.java` (130 строк) — gradle entry (`build.gradle.kts:29`, mainClass `io.allitov.Main`, `standardInput = System.in`). Сейчас — полный дубликат диспетчера RSASign.Main: команды `sign|sign-attached|verify|verify-attached`, вызовы RSASign на строках 53/65/81/98. Внешних callers нет (только mainClass) — изменение безопасно.
        - **Решение Q1 — «заменить на lab-9»:** переписать диспетчер Main на те же 4 команды (`sign`, `sign-attached`, `verify`, `verify-attached`, те же счётчики аргументов 4/4/4/3), но с вызовами `ElGamal.sign/signAttached/verify/verifyAttached`; чтение ключей: sign `random` → `IlGamal.generateKeys()` {p, g, Cb}; `manual` → p, g, Cb; verify `manual` → p, g, Db. Тело копируется из текущего Main с заменой p, q → p, g.
    - **deps:** [T1]
    - **acceptance:** `gradlew compileJava` проходит; `gradlew run --args="..."` с командами `sign` / `sign-attached` / `verify` / `verify-attached` диспетчит в `ElGamal`; поведение соответствует прежнему контракту CLI (те же аргументы, режим manual|random).
    - **description:** Переписать диспетчер `Main` на команды lab-9 (вызовы `ElGamal`), решение Q1.
    - **touched:** src/main/java/io/allitov/Main.java (ретаргет RSASign→ElGamal; ревью: reviews/lab-9-t2.code-review.md, PASS)
- [x] **T3** — Тесты `ElGamalTest`
    - **agent:** tester
    - **inputs:**
        - Создать `src/test/java/io/allitov/ElGamalTest.java`, зеркало `src/test/java/io/allitov/RSASignTest.java` (448 строк) в конвенциях `IlGamalTest.java`: JUnit 5 Jupiter + AssertJ, класс `@DisplayName("Электронная подпись Эль-Гамаля")`, `@TempDir Path tempDir` поле, `@Nested`-классы `GenerateKeys`, `CreateKeys`, `Sign`, `SignAttached`, `Verify`, `VerifyAttached` — все с русскими `@DisplayName`.
        - **Фиксированный вектор:** p = 1009, g = 11 (11 — первообразный корень 1009), Cb = 168, Db = 11^168 mod 1009 (вычислить хелпером через `BigInteger.modPow`, захардкодить ожидание). Корректность вектора доказывается самим тестом: позитивный `CreateKeys` (createKeys принимает p, g, Cb) упадёт, если вектор неверен. Диапазон ключей p > 256 соблюдён (как P=257 в RSASignTest).
        - **Отличие от RSA — подпись рандомизирована:** бинарное сравнение с эталоном (как `shouldCreateDetachedSignature`) НЕ работает. Вместо этого Sign-тесты: (1) размер detached-файла = 512 байт; (2) round-trip: `verify(input, sig, p, g, Db)` == true; (3) с чужим ключом (Cb+1 → другой Db... фактически подписать с другим cb и проверять с исходным Db) == false; (4) независимая математическая проверка: прочитать 32 пары (a, b) из файла, для каждого i проверить `CryptoUtils.pow(g, digest[i]&0xFF, p) == (CryptoUtils.pow(Db, a, p) * CryptoUtils.pow(a, b, p)) % p`.
        - **Детерминированный хелпер для Verify-тестов** (аналог `expectedSignature()`): вычислить SHA-256 файла, для каждого байта построить валидную пару (a, b) с ФИКСИРОВАННЫМ k (например k = 25: 1008 = 2^4·3^2·7, gcd(25, 1008) = 1): a = BigInteger.valueOf(g).modPow(k, p), b = k^{-1}·(h − Cb·a) mod (p−1) через `BigInteger.modInverse`/`mod`; если какой-то b == 0 — увеличивать k на 2, ПРОПУСКАЯ k с gcd(k, p−1) != 1 (например 27 делится на 3 — не инвертируется), и пересчитывать все пары заново. Записать пары big-endian (хелпер `createSignatureBlock(OutputStream, long a, long b)` или аналог `createEncryptedBlock` из RSASignTest:415-447).
        - **Инвентарь тестов (зеркало RSASignTest):**
            - `GenerateKeys` (стиль IlGamalTest:34, `@RepeatedTest(10)`): p простое (ferma) в [1e9, 2e9); g ∈ [2, p−2] и `CryptoUtils.pow(g, p - 1, p) == 1`; Cb ∈ [1, p−2]; Db ∈ [2, p−1]; Db == `CryptoUtils.pow(g, Cb, p)`.
            - `CreateKeys`: позитивный (вектор), отклонение невалидного p (не простое / вне диапазона, сообщение содержит "prime"), невалидного g (не первообразный корень, например g = 2 для p = 1009 — 2 НЕ первообразный корень 1009, сообщение содержит "g"), невалидного Cb (0 или ≥ p−1, сообщение содержит "Cb"). `@ParameterizedTest` + `@CsvSource`.
            - `Sign`: round-trip true; размер 512; пустой файл (SHA-256 пустого — тоже 32 байта, всё работает); сгенерированные ключи (`IlGamal.generateKeys()`); независимая проверка уравнения; отклонение невалидных p/g/Cb.
            - `SignAttached`: контент = 512-байтный префикс + исходные байты (assert через `hasBinaryContent` со склеенным массивом); round-trip `verifyAttached` true; пустой файл; невалидный Cb → IAE.
            - `Verify`: принимает валидную (хелпер выше); отвергает модифицированный файл (переписать контент); модифицированную подпись (инвертировать байт в последнем лонге); подпись другого ключа; невалидные параметры → IAE (`@CsvSource`); укороченный файл подписи (например 3 байта) → false; лишний байт (513) → false; невалидные значения a/b в файле (a = 0, b = p−1, b > p−2, отрицательное) → false.
            - `VerifyAttached`: принимает валидную; отвергает модифицированные данные (флип последнего байта контента) и подписи (флип байта 7 = b первой пары); файл короче 512 → false; невалидные параметры → IAE.
            - Отсутствующий входной файл → `NoSuchFileException` (стиль IlGamalTest).
        - Тесты НЕ обращаются к приватам `ElGamal` — только публичный API и файлы. Поверх `ElGamal`, `IlGamal`, `CryptoUtils` (обе публичные утилиты доступны).
    - **deps:** [T1]
    - **acceptance:** `gradlew test` зелёный: все новые тесты ElGamalTest проходят, существующие тесты (RSASignTest, IlGamalTest, RSATest, ShamirTest, VernamTest) не сломаны. Отчёт тестера: перечень написанных тестов + результат прогона.
    - **description:** Написать ElGamalTest по инвентарю в inputs, прогнать полный `gradlew test`.
    - **touched:** src/test/java/io/allitov/ElGamalTest.java (новый файл, 70 тестов; ревью: reviews/lab-9-t3.test-review.md, PASS)

## Заметки планировщика (контекст разведки)

- Проверка deps: T1 [] → T2 [T1], T3 [T1] — ациклично, все id существуют.
- Обзор: Gradle 9.6 (Kotlin DSL), Java 25, Lombok (freefair 9.5.0), log4j2/slf4j, JUnit BOM 6 + AssertJ 3.27.7, mainClass `io.allitov.Main`. Пакет один — `io.allitov`.
- lab-9 (tasks/lab-9.md) формулировкой совпадает с lab-8 (RSASign), отличается алгоритмом и классом; хеш ≥ MD5 — берём SHA-256 (устоявшийся выбор проекта, JCE).
- Ловушки, учтённые в T1/T3: `CryptoUtils.gcd` возвращает ненормализованный коэффициент и меняет аргументы местами (потому в T1 выбран `BigInteger.modInverse`); `CryptoUtils.pow` переполняется при p > ~3.037e9 (потому тот же MAX_MODULUS); `%` в Java для отрицательных даёт отрицательное (потому `.mod()` BigInteger / floorMod-семантика).
