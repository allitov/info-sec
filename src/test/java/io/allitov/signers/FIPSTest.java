package io.allitov.signers;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import io.allitov.common.CryptoUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Электронная подпись FIPS 186 (DSA)")
class FIPSTest {

    private static final long P = 1543L;
    private static final long Q = 257L;
    private static final long G = 64L;
    private static final long CB = 65L;
    private static final long DB = BigInteger.valueOf(G)
            .modPow(BigInteger.valueOf(CB), BigInteger.valueOf(P))
            .longValueExact();
    private static final int SIGNATURE_BYTES = 32 * 2 * Long.BYTES;
    private static final int HASH_BYTES = 32;
    private static final long INITIAL_SESSION_KEY = 25L;
    private static final byte[] SAMPLE = {1, 2, 3};

    @TempDir
    Path tempDir;

    @Nested
    @DisplayName("Генерация ключей")
    class GenerateKeys {

        @RepeatedTest(value = 10)
        @DisplayName("Генерирует корректные параметры подписи")
        void shouldGenerateValidParameters() {
            long[] keys = FIPS.generateKeys();
            long p = keys[0];
            long q = keys[1];
            long g = keys[2];
            long cb = keys[3];
            long db = keys[4];

            assertThat(q).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(CryptoUtils.ferma(q)).isTrue();
            assertThat(p).isBetween(2 * q + 1, 3_037_000_000L);
            assertThat(CryptoUtils.ferma(p)).isTrue();
            assertThat((p - 1) % q).isZero();
            assertThat(g).isBetween(2L, p - 2);
            assertThat(CryptoUtils.pow(g, q, p)).isOne();
            assertThat(cb).isBetween(1L, q - 1);
            assertThat(db).isEqualTo(CryptoUtils.pow(g, cb, p));
        }
    }

    @Nested
    @DisplayName("Вычисление ключей")
    class CreateKeys {

        @Test
        @DisplayName("Вычисляет открытый ключ Db по фиксированному вектору параметров")
        void shouldCalculatePublicKey() {
            long[] keys = FIPS.createKeys(P, Q, G, CB);

            assertThat(keys[0]).isEqualTo(P);
            assertThat(keys[1]).isEqualTo(Q);
            assertThat(keys[2]).isEqualTo(G);
            assertThat(keys[3]).isEqualTo(CB);
            assertThat(keys[4]).isEqualTo(DB);
        }

        @ParameterizedTest
        @CsvSource({
                "1, 257, 64, 65",
                "256, 257, 64, 65",
                "1542, 257, 64, 65",
                "3037000001, 257, 64, 65"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long q, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.createKeys(p, q, g, cb))
                    .withMessageContaining("p");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 2, 64, 65",
                "1543, 514, 64, 65",
                "1543, 771, 64, 65",
                "3079, 257, 64, 65"
        })
        @DisplayName("Отклоняет q, не являющееся простым делителем p - 1")
        void shouldRejectInvalidSubgroup(long p, long q, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.createKeys(p, q, g, cb))
                    .withMessageContaining("q");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 257, 1, 65",
                "1543, 257, 1543, 65",
                "1543, 257, 1542, 65",
                "1543, 257, 2, 65"
        })
        @DisplayName("Отклоняет g, не удовлетворяющее g^q mod p = 1")
        void shouldRejectInvalidGenerator(long p, long q, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.createKeys(p, q, g, cb))
                    .withMessageContaining("g ");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 257, 64, 0",
                "1543, 257, 64, 257",
                "1543, 257, 64, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.createKeys(p, q, g, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("Подпись отдельным файлом")
    class Sign {

        @Test
        @DisplayName("Создаёт отдельный файл подписи из 512 байт, проверяемый открытым ключом")
        void shouldCreateDetachedSignature() throws IOException {
            byte[] source = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");

            FIPS.sign(input, signature, P, Q, G, CB);

            assertThat(Files.size(signature)).isEqualTo(SIGNATURE_BYTES);
            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись для пустого файла")
        void shouldSignEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signature = tempDir.resolve("empty.bin.sig");

            FIPS.sign(input, signature, P, Q, G, CB);

            assertThat(Files.size(signature)).isEqualTo(SIGNATURE_BYTES);
            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись, проверяемую сгенерированными ключами")
        void shouldSignWithGeneratedKeys() throws IOException {
            byte[] source = "any binary content".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");
            long[] keys = FIPS.generateKeys();

            FIPS.sign(input, signature, keys[0], keys[1], keys[2], keys[3]);

            assertThat(FIPS.verify(input, signature, keys[0], keys[1], keys[2], keys[4])).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись, удовлетворяющую уравнению проверки FIPS 186")
        void shouldSatisfyVerificationEquation() throws IOException {
            byte[] source = {7, 34, 0, -1, -128, 126};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");

            FIPS.sign(input, signature, P, Q, G, CB);

            byte[] digest = sha256(source);
            byte[] signatureBytes = Files.readAllBytes(signature);
            assertThat(signatureBytes).hasSize(SIGNATURE_BYTES);
            for (int index = 0; index < HASH_BYTES; index++) {
                long r = readLong(signatureBytes, 2 * index * Long.BYTES);
                long s = readLong(signatureBytes, (2 * index + 1) * Long.BYTES);
                long h = digest[index] & 0xFF;
                long w = CryptoUtils.pow(s, Q - 2, Q);
                long u1 = h * w % Q;
                long u2 = r * w % Q;
                assertThat((CryptoUtils.pow(G, u1, P) * CryptoUtils.pow(DB, u2, P)) % P % Q)
                        .as("пара подписи №%d", index)
                        .isEqualTo(r);
            }
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.sig");

            assertThatThrownBy(() -> FIPS.sign(input, output, P, Q, G, CB))
                    .isInstanceOf(NoSuchFileException.class);
        }

        @ParameterizedTest
        @CsvSource({
                "1, 257, 64, 65",
                "256, 257, 64, 65",
                "1542, 257, 64, 65"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long q, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.sign(input, output, p, q, g, cb))
                    .withMessageContaining("p");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 2, 64, 65",
                "1543, 514, 64, 65",
                "3079, 257, 64, 65"
        })
        @DisplayName("Отклоняет q, не являющееся простым делителем p - 1")
        void shouldRejectInvalidSubgroup(long p, long q, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.sign(input, output, p, q, g, cb))
                    .withMessageContaining("q");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 257, 1542, 65",
                "1543, 257, 1543, 65"
        })
        @DisplayName("Отклоняет g, не удовлетворяющее g^q mod p = 1")
        void shouldRejectInvalidGenerator(long p, long q, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.sign(input, output, p, q, g, cb))
                    .withMessageContaining("g ");
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 257, 64, 0",
                "1543, 257, 64, 257",
                "1543, 257, 64, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.sign(input, output, p, q, g, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("Встроенная подпись")
    class SignAttached {

        @Test
        @DisplayName("Записывает подпись перед содержимым подписываемого файла")
        void shouldWriteSignatureBeforeContent() throws IOException {
            byte[] source = {10, 20, 30, 40, 50, 60, 70, 80};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");

            FIPS.signAttached(input, signed, P, Q, G, CB);

            byte[] actual = Files.readAllBytes(signed);
            assertThat(actual).hasSize(SIGNATURE_BYTES + source.length);
            byte[] expected = new byte[SIGNATURE_BYTES + source.length];
            System.arraycopy(actual, 0, expected, 0, SIGNATURE_BYTES);
            System.arraycopy(source, 0, expected, SIGNATURE_BYTES, source.length);
            assertThat(signed).hasBinaryContent(expected);
        }

        @Test
        @DisplayName("Создаёт подписанный файл, проверяемый сгенерированными ключами")
        void shouldSignAttachedWithGeneratedKeys() throws IOException {
            byte[] source = "attached signature content".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");
            long[] keys = FIPS.generateKeys();

            FIPS.signAttached(input, signed, keys[0], keys[1], keys[2], keys[3]);

            assertThat(FIPS.verifyAttached(signed, keys[0], keys[1], keys[2], keys[4])).isTrue();
        }

        @Test
        @DisplayName("Создаёт подписанный файл для пустого исходного файла")
        void shouldSignAttachedEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signed = tempDir.resolve("empty.signed.bin");

            FIPS.signAttached(input, signed, P, Q, G, CB);

            assertThat(Files.size(signed)).isEqualTo(SIGNATURE_BYTES);
            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isTrue();
        }

        @ParameterizedTest
        @CsvSource({
                "1543, 257, 64, 0",
                "1543, 257, 64, 257",
                "1543, 257, 64, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.signed.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.signAttached(input, output, p, q, g, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("Проверка отдельной подписи")
    class Verify {

        @Test
        @DisplayName("Подтверждает корректную отдельную подпись")
        void shouldAcceptValidSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = createSignatureFile(tempDir.resolve("input.bin.sig"), SAMPLE);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isTrue();
        }

        @ParameterizedTest
        @MethodSource("provideModifiedContents")
        @DisplayName("Отклоняет подпись после изменения подписанного файла")
        void shouldRejectModifiedFile(byte[] modified) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            FIPS.sign(input, signature, P, Q, G, CB);
            Files.write(input, modified);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок подписи")
        void shouldRejectModifiedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            FIPS.sign(input, signature, P, Q, G, CB);
            byte[] modified = Files.readAllBytes(signature);
            modified[SIGNATURE_BYTES - 1] ^= 1;
            Files.write(signature, modified);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет подпись, созданную другим секретным ключом")
        void shouldRejectSignatureOfDifferentKey() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");

            FIPS.sign(input, signature, P, Q, G, CB + 1);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 257, 64, 438",
                "1543, 2, 64, 438",
                "1543, 257, 1, 438",
                "1543, 257, 1542, 438",
                "1543, 257, 64, 0",
                "1543, 257, 64, 1543"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long q, long g, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            FIPS.sign(input, signature, P, Q, G, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.verify(input, signature, p, q, g, db));
        }

        @Test
        @DisplayName("Возвращает false для неполного файла подписи")
        void shouldReturnFalseForTruncatedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path truncated = createFile(tempDir.resolve("truncated.sig"), new byte[] {1, 2, 3});

            assertThat(FIPS.verify(input, truncated, P, Q, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Возвращает false для файла подписи с лишними байтами")
        void shouldReturnFalseForSignatureWithExtraBytes() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            FIPS.sign(input, signature, P, Q, G, CB);
            byte[] extra = new byte[SIGNATURE_BYTES + 1];
            extra[extra.length - 1] = 1;
            Files.write(signature, extra);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isFalse();
        }

        @ParameterizedTest
        @MethodSource("provideInvalidSignatureValues")
        @DisplayName("Возвращает false при значениях r или s вне допустимого диапазона")
        void shouldReturnFalseForInvalidSignatureValues(long r, long s) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = createCorruptedSignatureFile(tempDir.resolve("invalid.sig"), r, s);

            assertThat(FIPS.verify(input, signature, P, Q, G, DB)).isFalse();
        }

        static Stream<Arguments> provideModifiedContents() {
            return Stream.of(
                    Arguments.of((Object) new byte[] {1, 2, 4}),
                    Arguments.of((Object) new byte[] {1, 2, 3, 4}),
                    Arguments.of((Object) new byte[] {1, 2}),
                    Arguments.of((Object) new byte[0])
            );
        }

        static Stream<Arguments> provideInvalidSignatureValues() {
            return Stream.of(
                    Arguments.of(0L, 1L),
                    Arguments.of(-1L, 1L),
                    Arguments.of(Q, 1L),
                    Arguments.of(1L, 0L),
                    Arguments.of(1L, Q),
                    Arguments.of(1L, -1L)
            );
        }
    }

    @Nested
    @DisplayName("Проверка встроенной подписи")
    class VerifyAttached {

        @Test
        @DisplayName("Подтверждает корректную встроенную подпись")
        void shouldAcceptValidAttachedSignature() throws IOException {
            byte[] source = "content with attached signature".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");
            FIPS.signAttached(input, signed, P, Q, G, CB);

            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Подтверждает встроенную подпись, построенную независимо от signAttached")
        void shouldAcceptIndependentlyBuiltAttachedSignature() throws IOException {
            byte[] source = {5, 4, 3, 2, 1};
            Path signed = createSignedFile(tempDir.resolve("built.signed.bin"), source);

            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Отклоняет подписанный файл после изменения данных")
        void shouldRejectModifiedData() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            FIPS.signAttached(input, signed, P, Q, G, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[modified.length - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок встроенной подписи")
        void shouldRejectModifiedAttachedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            FIPS.signAttached(input, signed, P, Q, G, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[Long.BYTES - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 257, 64, 438",
                "1543, 2, 64, 438",
                "1543, 257, 1, 438",
                "1543, 257, 64, 1543"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long q, long g, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            FIPS.signAttached(input, signed, P, Q, G, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> FIPS.verifyAttached(signed, p, q, g, db));
        }

        @Test
        @DisplayName("Возвращает false для файла короче встроенной подписи")
        void shouldReturnFalseForFileShorterThanSignature() throws IOException {
            Path signed = createFile(tempDir.resolve("short.signed.bin"), new byte[] {1, 2, 3});

            assertThat(FIPS.verifyAttached(signed, P, Q, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path signed = tempDir.resolve("missing.signed.bin");

            assertThatThrownBy(() -> FIPS.verifyAttached(signed, P, Q, G, DB))
                    .isInstanceOf(NoSuchFileException.class);
        }
    }

    private static Path createFile(Path path, byte[] content) throws IOException {
        Files.write(path, content);
        return path;
    }

    private static Path createSignatureFile(Path path, byte[] content) throws IOException {
        return createFile(path, expectedSignature(content));
    }

    private static Path createSignedFile(Path path, byte[] content) throws IOException {
        byte[] signature = expectedSignature(content);
        byte[] signed = new byte[signature.length + content.length];
        System.arraycopy(signature, 0, signed, 0, signature.length);
        System.arraycopy(content, 0, signed, signature.length, content.length);
        return createFile(path, signed);
    }

    private static Path createCorruptedSignatureFile(Path path, long r, long s) throws IOException {
        byte[] signature = expectedSignature(SAMPLE);
        writeLong(signature, 0, r);
        writeLong(signature, Long.BYTES, s);
        return createFile(path, signature);
    }

    private static byte[] expectedSignature(byte[] source) {
        byte[] digest = sha256(source);
        long k = INITIAL_SESSION_KEY;
        long[][] pairs = signaturePairs(digest, k);
        while (hasZeroValue(pairs)) {
            k = nextSessionKey(k);
            pairs = signaturePairs(digest, k);
        }

        byte[] signature = new byte[SIGNATURE_BYTES];
        for (int index = 0; index < pairs.length; index++) {
            writeLong(signature, 2 * index * Long.BYTES, pairs[index][0]);
            writeLong(signature, (2 * index + 1) * Long.BYTES, pairs[index][1]);
        }

        return signature;
    }

    private static long[][] signaturePairs(byte[] digest, long k) {
        long[][] pairs = new long[HASH_BYTES][2];
        BigInteger q = BigInteger.valueOf(Q);
        BigInteger cb = BigInteger.valueOf(CB);
        for (int index = 0; index < HASH_BYTES; index++) {
            long h = digest[index] & 0xFF;
            BigInteger r = BigInteger.valueOf(G)
                    .modPow(BigInteger.valueOf(k), BigInteger.valueOf(P))
                    .mod(q);
            BigInteger s = BigInteger.valueOf(k).modInverse(q)
                    .multiply(cb.multiply(r).add(BigInteger.valueOf(h)))
                    .mod(q);
            pairs[index][0] = r.longValueExact();
            pairs[index][1] = s.longValueExact();
        }

        return pairs;
    }

    private static long nextSessionKey(long k) {
        return k + 1;
    }

    private static boolean hasZeroValue(long[][] pairs) {
        for (long[] pair : pairs) {
            if (pair[0] == 0 || pair[1] == 0) {
                return true;
            }
        }

        return false;
    }

    private static void writeLong(byte[] target, int offset, long value) {
        for (int index = 0; index < Long.BYTES; index++) {
            target[offset + index] = (byte) (value >>> (Long.SIZE - Byte.SIZE * (index + 1)));
        }
    }

    private static long readLong(byte[] source, int offset) {
        long value = 0;
        for (int index = offset; index < offset + Long.BYTES; index++) {
            value = (value << Byte.SIZE) | (source[index] & 0xFF);
        }

        return value;
    }

    private static byte[] sha256(byte[] source) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(source);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }
}
