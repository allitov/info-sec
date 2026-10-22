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

@DisplayName("Электронная подпись Эль-Гамаля")
class ElGamalTest {

    private static final long P = 1009L;
    private static final long G = 11L;
    private static final long CB = 168L;
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
        void shouldGenerateValidParameters() throws IOException {
            long[] keys = ElGamal.generateKeys();
            long p = keys[0];
            long g = keys[1];
            long cb = keys[2];
            long db = keys[3];

            assertThat(p).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(CryptoUtils.ferma(p)).isTrue();
            assertThat(g).isBetween(2L, p - 2);
            assertThat(CryptoUtils.pow(g, p - 1, p)).isOne();
            assertThat(cb).isBetween(1L, p - 2);
            assertThat(db).isBetween(2L, p - 1);
            assertThat(db).isEqualTo(CryptoUtils.pow(g, cb, p));
        }
    }

    @Nested
    @DisplayName("Вычисление ключей")
    class CreateKeys {

        @Test
        @DisplayName("Вычисляет открытый ключ Db по фиксированному вектору параметров")
        void shouldCalculatePublicKey() throws IOException {
            long[] keys = ElGamal.createKeys(P, G, CB);

            assertThat(keys[0]).isEqualTo(P);
            assertThat(keys[1]).isEqualTo(G);
            assertThat(keys[2]).isEqualTo(CB);
            assertThat(keys[3]).isEqualTo(DB);
        }

        @ParameterizedTest
        @CsvSource({
                "1, 11, 168",
                "256, 11, 168",
                "1008, 11, 168",
                "3037000001, 11, 168"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.createKeys(p, g, cb))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "1009, 1, 168",
                "1009, 2, 168",
                "1009, 1009, 168"
        })
        @DisplayName("Отклоняет g, не являющийся первообразным корнем")
        void shouldRejectInvalidGenerator(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.createKeys(p, g, cb))
                    .withMessageContaining("g");
        }

        @ParameterizedTest
        @CsvSource({
                "1009, 11, 0",
                "1009, 11, 1008",
                "1009, 11, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.createKeys(p, g, cb))
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

            ElGamal.sign(input, signature, P, G, CB);

            assertThat(Files.size(signature)).isEqualTo(SIGNATURE_BYTES);
            assertThat(ElGamal.verify(input, signature, P, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись для пустого файла")
        void shouldSignEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signature = tempDir.resolve("empty.bin.sig");

            ElGamal.sign(input, signature, P, G, CB);

            assertThat(Files.size(signature)).isEqualTo(SIGNATURE_BYTES);
            assertThat(ElGamal.verify(input, signature, P, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись, проверяемую сгенерированными ключами")
        void shouldSignWithGeneratedKeys() throws IOException {
            byte[] source = "any binary content".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");
            long[] keys = ElGamal.generateKeys();

            ElGamal.sign(input, signature, keys[0], keys[1], keys[2]);

            assertThat(ElGamal.verify(input, signature, keys[0], keys[1], keys[3])).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись, удовлетворяющую уравнению проверки Эль-Гамаля")
        void shouldSatisfyVerificationEquation() throws IOException {
            byte[] source = {7, 34, 0, -1, -128, 126};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");

            ElGamal.sign(input, signature, P, G, CB);

            byte[] digest = sha256(source);
            byte[] signatureBytes = Files.readAllBytes(signature);
            assertThat(signatureBytes).hasSize(SIGNATURE_BYTES);
            for (int index = 0; index < HASH_BYTES; index++) {
                long a = readLong(signatureBytes, 2 * index * Long.BYTES);
                long b = readLong(signatureBytes, (2 * index + 1) * Long.BYTES);
                long h = digest[index] & 0xFF;
                assertThat((CryptoUtils.pow(DB, a, P) * CryptoUtils.pow(a, b, P)) % P)
                        .as("пара подписи №%d", index)
                        .isEqualTo(CryptoUtils.pow(G, h, P));
            }
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.sig");

            assertThatThrownBy(() -> ElGamal.sign(input, output, P, G, CB))
                    .isInstanceOf(NoSuchFileException.class);
        }

        @ParameterizedTest
        @CsvSource({
                "1, 11, 168",
                "256, 11, 168",
                "1008, 11, 168",
                "3037000001, 11, 168"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.sign(input, output, p, g, cb))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "1009, 1, 168",
                "1009, 2, 168",
                "1009, 1009, 168"
        })
        @DisplayName("Отклоняет g, не являющийся первообразным корнем")
        void shouldRejectInvalidGenerator(long p, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.sign(input, output, p, g, cb))
                    .withMessageContaining("g");
        }

        @ParameterizedTest
        @CsvSource({
                "1009, 11, 0",
                "1009, 11, 1008",
                "1009, 11, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.sign(input, output, p, g, cb))
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

            ElGamal.signAttached(input, signed, P, G, CB);

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
            long[] keys = ElGamal.generateKeys();

            ElGamal.signAttached(input, signed, keys[0], keys[1], keys[2]);

            assertThat(ElGamal.verifyAttached(signed, keys[0], keys[1], keys[3])).isTrue();
        }

        @Test
        @DisplayName("Создаёт подписанный файл для пустого исходного файла")
        void shouldSignAttachedEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signed = tempDir.resolve("empty.signed.bin");

            ElGamal.signAttached(input, signed, P, G, CB);

            assertThat(Files.size(signed)).isEqualTo(SIGNATURE_BYTES);
            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isTrue();
        }

        @ParameterizedTest
        @CsvSource({
                "1009, 11, 0",
                "1009, 11, 1008",
                "1009, 11, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long g, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.signed.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.signAttached(input, output, p, g, cb))
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

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isTrue();
        }

        @ParameterizedTest
        @MethodSource("provideModifiedContents")
        @DisplayName("Отклоняет подпись после изменения подписанного файла")
        void shouldRejectModifiedFile(byte[] modified) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            ElGamal.sign(input, signature, P, G, CB);
            Files.write(input, modified);

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок подписи")
        void shouldRejectModifiedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            ElGamal.sign(input, signature, P, G, CB);
            byte[] modified = Files.readAllBytes(signature);
            modified[SIGNATURE_BYTES - 1] ^= 1;
            Files.write(signature, modified);

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет подпись, созданную другим секретным ключом")
        void shouldRejectSignatureOfDifferentKey() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");

            ElGamal.sign(input, signature, P, G, CB + 1);

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 11, 375",
                "1009, 2, 375",
                "1009, 11, 1",
                "1009, 11, 1009"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long g, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            ElGamal.sign(input, signature, P, G, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.verify(input, signature, p, g, db));
        }

        @Test
        @DisplayName("Возвращает false для неполного файла подписи")
        void shouldReturnFalseForTruncatedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path truncated = createFile(tempDir.resolve("truncated.sig"), new byte[] {1, 2, 3});

            assertThat(ElGamal.verify(input, truncated, P, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Возвращает false для файла подписи с лишними байтами")
        void shouldReturnFalseForSignatureWithExtraBytes() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = tempDir.resolve("input.bin.sig");
            ElGamal.sign(input, signature, P, G, CB);
            byte[] extra = new byte[SIGNATURE_BYTES + 1];
            extra[extra.length - 1] = 1;
            Files.write(signature, extra);

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isFalse();
        }

        @ParameterizedTest
        @MethodSource("provideInvalidSignatureValues")
        @DisplayName("Возвращает false при значениях a или b вне допустимого диапазона")
        void shouldReturnFalseForInvalidSignatureValues(long a, long b) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signature = createCorruptedSignatureFile(tempDir.resolve("invalid.sig"), a, b);

            assertThat(ElGamal.verify(input, signature, P, G, DB)).isFalse();
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
                    Arguments.of(1L, P - 1),
                    Arguments.of(1L, P),
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
            ElGamal.signAttached(input, signed, P, G, CB);

            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Подтверждает встроенную подпись, построенную независимо от signAttached")
        void shouldAcceptIndependentlyBuiltAttachedSignature() throws IOException {
            byte[] source = {5, 4, 3, 2, 1};
            Path signed = createSignedFile(tempDir.resolve("built.signed.bin"), source);

            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isTrue();
        }

        @Test
        @DisplayName("Отклоняет подписанный файл после изменения данных")
        void shouldRejectModifiedData() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            ElGamal.signAttached(input, signed, P, G, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[modified.length - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок встроенной подписи")
        void shouldRejectModifiedAttachedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            ElGamal.signAttached(input, signed, P, G, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[Long.BYTES - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 11, 375",
                "1009, 2, 375",
                "1009, 11, 1",
                "1009, 11, 1009"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long g, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), SAMPLE);
            Path signed = tempDir.resolve("input.signed.bin");
            ElGamal.signAttached(input, signed, P, G, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> ElGamal.verifyAttached(signed, p, g, db));
        }

        @Test
        @DisplayName("Возвращает false для файла короче встроенной подписи")
        void shouldReturnFalseForFileShorterThanSignature() throws IOException {
            Path signed = createFile(tempDir.resolve("short.signed.bin"), new byte[] {1, 2, 3});

            assertThat(ElGamal.verifyAttached(signed, P, G, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path signed = tempDir.resolve("missing.signed.bin");

            assertThatThrownBy(() -> ElGamal.verifyAttached(signed, P, G, DB))
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

    private static Path createCorruptedSignatureFile(Path path, long a, long b) throws IOException {
        byte[] signature = expectedSignature(SAMPLE);
        writeLong(signature, 0, a);
        writeLong(signature, Long.BYTES, b);
        return createFile(path, signature);
    }

    private static byte[] expectedSignature(byte[] source) {
        byte[] digest = sha256(source);
        long k = INITIAL_SESSION_KEY;
        long[][] pairs = signaturePairs(digest, k);
        while (hasZeroCoefficient(pairs)) {
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
        for (int index = 0; index < HASH_BYTES; index++) {
            long h = digest[index] & 0xFF;
            BigInteger a = BigInteger.valueOf(G).modPow(BigInteger.valueOf(k), BigInteger.valueOf(P));
            BigInteger b = BigInteger.valueOf(k)
                    .modInverse(BigInteger.valueOf(P - 1))
                    .multiply(BigInteger.valueOf(h).subtract(BigInteger.valueOf(CB).multiply(a)))
                    .mod(BigInteger.valueOf(P - 1));
            pairs[index][0] = a.longValueExact();
            pairs[index][1] = b.longValueExact();
        }

        return pairs;
    }

    private static long nextSessionKey(long k) {
        k += 2;
        while (CryptoUtils.gcdSimple(k, P - 1) != 1) {
            k += 2;
        }

        return k;
    }

    private static boolean hasZeroCoefficient(long[][] pairs) {
        for (long[] pair : pairs) {
            if (pair[1] == 0) {
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
