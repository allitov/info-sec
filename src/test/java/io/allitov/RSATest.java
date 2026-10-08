package io.allitov;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.stream.Stream;

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

@DisplayName("Шифр RSA")
class RSATest {

    private static final long P = 257L;
    private static final long Q = 263L;
    private static final long DB = 7L;
    private static final long CB = 38327L;
    private static final long N = 67591L;

    @Nested
    @DisplayName("generateKeys")
    class GenerateKeys {

        @RepeatedTest(value = 10)
        @DisplayName("Генерирует разные простые числа и взаимно обратные ключи")
        void shouldGenerateValidParameters() {
            long[] keys = RSA.generateKeys();
            long p = keys[0];
            long q = keys[1];
            long n = keys[2];
            long cb = keys[3];
            long db = keys[4];
            long phi = (p - 1) * (q - 1);

            assertThat(p).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(q).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(p).isNotEqualTo(q);
            assertThat(CryptoUtils.ferma(p)).isTrue();
            assertThat(CryptoUtils.ferma(q)).isTrue();
            assertThat(n).isEqualTo(p * q);
            assertThat(db).isBetween(2L, phi - 1);
            assertThat(cb).isBetween(1L, phi - 1);
            assertThat(CryptoUtils.gcdSimple(db, phi)).isOne();
            assertThat(multiplyMod(cb, db, phi)).isOne();
        }
    }

    @Nested
    @DisplayName("createKeys")
    class CreateKeys {

        @ParameterizedTest
        @CsvSource({
                "257, 263, 7",
                "1009, 1013, 5"
        })
        @DisplayName("Вычисляет секретный ключ Cb, обратный открытому ключу Db")
        void shouldCalculateSecretKey(long p, long q, long db) {
            long[] keys = RSA.createKeys(p, q, db);
            long phi = (p - 1) * (q - 1);

            assertThat(keys[0]).isEqualTo(p);
            assertThat(keys[1]).isEqualTo(q);
            assertThat(keys[2]).isEqualTo(p * q);
            assertThat(keys[3]).isBetween(1L, phi - 1);
            assertThat(keys[4]).isEqualTo(db);
            assertThat(multiplyMod(keys[3], db, phi)).isOne();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 263, 7",
                "256, 263, 7",
                "300, 263, 7",
                "3037000001, 263, 7"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidP(long p, long q, long db) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.createKeys(p, q, db))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 1, 7",
                "257, 256, 7",
                "257, 300, 7",
                "257, 3037000001, 7"
        })
        @DisplayName("Отклоняет неподходящее простое число q")
        void shouldRejectInvalidQ(long p, long q, long db) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.createKeys(p, q, db))
                    .withMessageContaining("prime");
        }

        @Test
        @DisplayName("Отклоняет одинаковые простые числа p и q")
        void shouldRejectEqualPrimes() {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.createKeys(P, P, DB))
                    .withMessageContaining("different");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 263, 1",
                "257, 263, 2",
                "257, 263, 131",
                "257, 263, 67072"
        })
        @DisplayName("Отклоняет Db вне допустимого диапазона или не взаимно простое с (p - 1)(q - 1)")
        void shouldRejectInvalidDb(long p, long q, long db) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.createKeys(p, q, db))
                    .withMessageContaining("Db");
        }
    }

    @Nested
    @DisplayName("encrypt")
    class Encrypt {

        @TempDir
        Path tempDir;

        @Test
        @DisplayName("Шифрует произвольные байты блоками по восемь байт")
        void shouldEncryptArbitraryBytes() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path output = tempDir.resolve("encrypted.bin");

            RSA.encrypt(input, output, P, Q, DB);

            assertThat(output).exists();
            assertThat(Files.size(output)).isEqualTo(source.length * Long.BYTES);
            assertThat(Files.readAllBytes(output)).isNotEqualTo(source);
        }

        @ParameterizedTest
        @CsvSource({
                "256, 263, 7",
                "257, 300, 7",
                "3037000001, 263, 7",
                "257, 3037000001, 7"
        })
        @DisplayName("Отклоняет неподходящие простые числа p или q")
        void shouldRejectInvalidPrimes(long p, long q, long db) throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.encrypt(input, output, p, q, db))
                    .withMessageContaining("prime");
        }

        @Test
        @DisplayName("Отклоняет одинаковые простые числа p и q")
        void shouldRejectEqualPrimes() throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.encrypt(input, output, P, P, DB))
                    .withMessageContaining("different");
        }

        @ParameterizedTest
        @MethodSource("provideInvalidPublicKeys")
        @DisplayName("Отклоняет Db вне допустимого диапазона или не взаимно простое с (p - 1)(q - 1)")
        void shouldRejectInvalidDb(long db) throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.encrypt(input, output, P, Q, db))
                    .withMessageContaining("Db");
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.bin");

            assertThatThrownBy(() -> RSA.encrypt(input, output, P, Q, DB))
                    .isInstanceOf(NoSuchFileException.class);
        }

        static Stream<Arguments> provideInvalidPublicKeys() {
            return Stream.of(
                    Arguments.of(1L),
                    Arguments.of(2L),
                    Arguments.of(131L),
                    Arguments.of(67072L),
                    Arguments.of(-1L)
            );
        }
    }

    @Nested
    @DisplayName("decrypt")
    class Decrypt {

        @TempDir
        Path tempDir;

        @Test
        @DisplayName("Восстанавливает произвольные байты после шифрования")
        void shouldRestoreEncryptedFile() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42, 7};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");

            RSA.encrypt(input, encrypted, P, Q, DB);
            RSA.decrypt(encrypted, restored, P, Q, CB);

            assertThat(restored).hasBinaryContent(source);
        }

        @Test
        @DisplayName("Восстанавливает файл, зашифрованный сгенерированными ключами")
        void shouldRestoreFileEncryptedWithGeneratedKeys() throws IOException {
            byte[] source = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");
            long[] keys = RSA.generateKeys();

            RSA.encrypt(input, encrypted, keys[0], keys[1], keys[4]);
            RSA.decrypt(encrypted, restored, keys[0], keys[1], keys[3]);

            assertThat(restored).hasBinaryContent(source);
        }

        @Test
        @DisplayName("Корректно обрабатывает пустой файл")
        void shouldRestoreEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");

            RSA.encrypt(input, encrypted, P, Q, DB);
            RSA.decrypt(encrypted, restored, P, Q, CB);

            assertThat(encrypted).isEmptyFile();
            assertThat(restored).isEmptyFile();
        }

        @ParameterizedTest
        @CsvSource({
                "257, 263, 0",
                "257, 263, 67072",
                "257, 263, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("encrypted.bin"), new byte[Long.BYTES]);
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.decrypt(input, output, p, q, cb))
                    .withMessageContaining("Cb");
        }

        @Test
        @DisplayName("Отклоняет неполный 64-битный блок шифртекста")
        void shouldRejectIncompleteEncryptedBlock() throws IOException {
            Path input = createFile(tempDir.resolve("invalid.bin"), new byte[] {1, 2, 3, 4, 5});
            Path output = tempDir.resolve("output.bin");

            assertThatThrownBy(() -> RSA.decrypt(input, output, P, Q, CB))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("incomplete");
        }

        @ParameterizedTest
        @MethodSource("provideInvalidCiphertextValues")
        @DisplayName("Отклоняет значения шифртекста вне диапазона [0, n - 1]")
        void shouldRejectInvalidCiphertextValues(long value) throws IOException {
            Path input = createEncryptedBlock(tempDir.resolve("invalid.bin"), value);
            Path output = tempDir.resolve("output.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSA.decrypt(input, output, P, Q, CB))
                    .withMessageContaining("range");
        }

        static Stream<Arguments> provideInvalidCiphertextValues() {
            return Stream.of(
                    Arguments.of(N),
                    Arguments.of(-1L),
                    Arguments.of(Long.MAX_VALUE)
            );
        }
    }

    private static Path createFile(Path path, byte[] content) throws IOException {
        Files.write(path, content);
        return path;
    }

    private static Path createEncryptedBlock(Path path, long value) throws IOException {
        byte[] block = new byte[Long.BYTES];
        for (int index = 0; index < Long.BYTES; index++) {
            block[index] = (byte) (value >>> (Long.SIZE - Byte.SIZE * (index + 1)));
        }

        return createFile(path, block);
    }

    private static BigInteger multiplyMod(long first, long second, long modulus) {
        return BigInteger.valueOf(first)
                .multiply(BigInteger.valueOf(second))
                .mod(BigInteger.valueOf(modulus));
    }
}
