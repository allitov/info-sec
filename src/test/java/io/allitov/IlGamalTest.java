package io.allitov;

import java.io.IOException;
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

@DisplayName("Шифр Эль-Гамаля")
class IlGamalTest {

    private static final long PRIME = 257L;
    private static final long GENERATOR = 3L;
    private static final long SECRET_KEY = 5L;

    @Nested
    @DisplayName("generateKeys")
    class GenerateKeys {

        @RepeatedTest(value = 10)
        @DisplayName("Генерирует корректные параметры шифрования")
        void shouldGenerateValidParameters() {
            long[] keys = IlGamal.generateKeys();
            long p = keys[0];
            long g = keys[1];
            long cb = keys[2];
            long db = keys[3];

            assertThat(p).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(CryptoUtils.ferma(p)).isTrue();
            assertThat(g).isBetween(2L, p - 2);
            assertThat(CryptoUtils.pow(g, p - 1, p)).isOne();
            assertThat(cb).isBetween(1L, p - 2);
            assertThat(db).isBetween(1L, p - 1);
            assertThat(db).isEqualTo(CryptoUtils.pow(g, cb, p));
        }
    }

    @Nested
    @DisplayName("createKeys")
    class CreateKeys {

        @ParameterizedTest
        @CsvSource({
                "257, 3, 5",
                "1019, 2, 7"
        })
        @DisplayName("Вычисляет открытый ключ Db по секретному ключу Cb")
        void shouldCalculatePublicKey(long p, long g, long cb) {
            long[] keys = IlGamal.createKeys(p, g, cb);

            assertThat(keys[0]).isEqualTo(p);
            assertThat(keys[1]).isEqualTo(g);
            assertThat(keys[2]).isEqualTo(cb);
            assertThat(keys[3]).isEqualTo(CryptoUtils.pow(g, cb, p));
        }

        @ParameterizedTest
        @CsvSource({
                "1, 3, 5",
                "256, 3, 5",
                "300, 3, 5",
                "3_037_000_001, 3, 5"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.createKeys(p, g, cb))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 1, 5",
                "257, 4, 5",
                "257, 257, 5"
        })
        @DisplayName("Отклоняет g, не являющийся первообразным корнем")
        void shouldRejectInvalidGenerator(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.createKeys(p, g, cb))
                    .withMessageContaining("g");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 3, 0",
                "257, 3, 256",
                "257, 3, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long g, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.createKeys(p, g, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("encrypt")
    class Encrypt {

        @TempDir
        Path tempDir;

        @Test
        @DisplayName("Шифрует произвольные байты блоками по шестнадцать байт")
        void shouldEncryptArbitraryBytes() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path output = tempDir.resolve("encrypted.bin");
            long[] keys = IlGamal.createKeys(PRIME, GENERATOR, SECRET_KEY);

            IlGamal.encrypt(input, output, keys[0], keys[1], keys[3]);

            assertThat(output).exists();
            assertThat(Files.size(output)).isEqualTo(source.length * 2 * Long.BYTES);
            assertThat(Files.readAllBytes(output)).isNotEqualTo(source);
        }

        @ParameterizedTest
        @MethodSource("provideInvalidPublicKeys")
        @DisplayName("Отклоняет Db вне допустимого диапазона")
        void shouldRejectInvalidPublicKey(long db) throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.encrypt(input, output, PRIME, GENERATOR, db))
                    .withMessageContaining("Db");
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.bin");
            long[] keys = IlGamal.createKeys(PRIME, GENERATOR, SECRET_KEY);

            assertThatThrownBy(() -> IlGamal.encrypt(input, output, keys[0], keys[1], keys[3]))
                    .isInstanceOf(NoSuchFileException.class);
        }

        static Stream<Arguments> provideInvalidPublicKeys() {
            return Stream.of(
                    Arguments.of(1L),
                    Arguments.of(0L),
                    Arguments.of(257L),
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
            long[] keys = IlGamal.createKeys(PRIME, GENERATOR, SECRET_KEY);

            IlGamal.encrypt(input, encrypted, keys[0], keys[1], keys[3]);
            IlGamal.decrypt(encrypted, restored, keys[0], keys[2]);

            assertThat(restored).hasBinaryContent(source);
        }

        @Test
        @DisplayName("Корректно обрабатывает пустой файл")
        void shouldRestoreEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");
            long[] keys = IlGamal.createKeys(PRIME, GENERATOR, SECRET_KEY);

            IlGamal.encrypt(input, encrypted, keys[0], keys[1], keys[3]);
            IlGamal.decrypt(encrypted, restored, keys[0], keys[2]);

            assertThat(encrypted).isEmptyFile();
            assertThat(restored).isEmptyFile();
        }

        @ParameterizedTest
        @CsvSource({
                "257, 0",
                "257, 256",
                "257, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("encrypted.bin"), new byte[2 * Long.BYTES]);
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.decrypt(input, output, p, cb))
                    .withMessageContaining("Cb");
        }

        @Test
        @DisplayName("Отклоняет неполный 128-битный блок шифртекста")
        void shouldRejectIncompleteEncryptedBlock() throws IOException {
            Path input = createFile(tempDir.resolve("invalid.bin"), new byte[] {1, 2, 3, 4, 5});
            Path output = tempDir.resolve("output.bin");

            assertThatThrownBy(() -> IlGamal.decrypt(input, output, PRIME, SECRET_KEY))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("incomplete");
        }

        @ParameterizedTest
        @MethodSource("provideInvalidCiphertextBlocks")
        @DisplayName("Отклоняет недопустимые значения r или e в блоке")
        void shouldRejectInvalidCiphertextValues(long r, long encrypted) throws IOException {
            Path input = createEncryptedBlock(tempDir.resolve("invalid.bin"), r, encrypted);
            Path output = tempDir.resolve("output.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> IlGamal.decrypt(input, output, PRIME, SECRET_KEY))
                    .withMessageContaining("range");
        }

        static Stream<Arguments> provideInvalidCiphertextBlocks() {
            return Stream.of(
                    Arguments.of(0L, 1L),
                    Arguments.of(257L, 1L),
                    Arguments.of(1L, 258L)
            );
        }
    }

    private static Path createFile(Path path, byte[] content) throws IOException {
        Files.write(path, content);
        return path;
    }

    private static Path createEncryptedBlock(Path path, long r, long encrypted) throws IOException {
        byte[] block = new byte[2 * Long.BYTES];
        for (int index = 0; index < Long.BYTES; index++) {
            block[index] = (byte) (r >>> (Long.SIZE - Byte.SIZE * (index + 1)));
            block[Long.BYTES + index] = (byte) (encrypted >>> (Long.SIZE - Byte.SIZE * (index + 1)));
        }

        return createFile(path, block);
    }
}
