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

@DisplayName("Шифр Вернама")
class VernamTest {

    private static final long KEY = 0x1234567890ABCDEFL;

    @Nested
    @DisplayName("generateKey")
    class GenerateKeys {

        @RepeatedTest(value = 20)
        @DisplayName("Генерирует положительный ключ методом Диффи-Хеллмана")
        void shouldGeneratePositiveKey() {
            long key = Vernam.generateKey();

            assertThat(key).isPositive().isLessThan(2_000_000_000L);
        }

        @ParameterizedTest
        @CsvSource({
                "23, 5, 6, 15, 2",
                "23, 7, 3, 5, 14"
        })
        @DisplayName("Вычисляет общий ключ Диффи-Хеллмана для заданных параметров")
        void shouldCalculateSharedKey(long p, long g, long xa, long xb, long expected) {
            assertThat(Vernam.generateKey(p, g, xa, xb)).isEqualTo(expected);
        }

        @ParameterizedTest
        @MethodSource("provideInvalidDiffieHellmanParameters")
        @DisplayName("Отклоняет некорректные параметры Диффи-Хеллмана")
        void shouldRejectInvalidParameters(long p, long g, long xa, long xb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Vernam.generateKey(p, g, xa, xb));
        }

        static Stream<Arguments> provideInvalidDiffieHellmanParameters() {
            return Stream.of(
                    Arguments.of(4L, 5L, 6L, 15L),
                    Arguments.of(23L, 1L, 6L, 15L),
                    Arguments.of(23L, 24L, 6L, 15L),
                    Arguments.of(23L, 5L, 1L, 15L),
                    Arguments.of(23L, 5L, 6L, 23L)
            );
        }
    }

    @Nested
    @DisplayName("encrypt")
    class Encrypt {

        @TempDir
        Path tempDir;

        @Test
        @DisplayName("Шифрует произвольные байты операцией XOR с байтами ключа")
        void shouldEncryptArbitraryBytes() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42, 7};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path output = tempDir.resolve("encrypted.bin");

            Vernam.encrypt(input, output, KEY);

            assertThat(output).exists();
            assertThat(Files.readAllBytes(output)).isEqualTo(xorWithKey(source));
        }

        @Test
        @DisplayName("Повторное шифрование тем же ключом восстанавливает исходный файл")
        void shouldRestoreFileWhenEncryptedTwice() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");

            Vernam.encrypt(input, encrypted, KEY);
            Vernam.encrypt(encrypted, restored, KEY);

            assertThat(restored).hasBinaryContent(source);
        }

        @Test
        @DisplayName("Создаёт пустой файл для пустого входного файла")
        void shouldEncryptEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path output = tempDir.resolve("encrypted.bin");

            Vernam.encrypt(input, output, KEY);

            assertThat(output).exists().isEmptyFile();
        }

        @ParameterizedTest
        @CsvSource({
                "0",
                "-1"
        })
        @DisplayName("Отклоняет неположительный ключ")
        void shouldRejectInvalidKey(long key) throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Vernam.encrypt(input, output, key))
                    .withMessageContaining("positive");
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.bin");

            assertThatThrownBy(() -> Vernam.encrypt(input, output, KEY))
                    .isInstanceOf(NoSuchFileException.class);
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

            Vernam.encrypt(input, encrypted, KEY);
            Vernam.decrypt(encrypted, restored, KEY);

            assertThat(restored).hasBinaryContent(source);
        }

        @Test
        @DisplayName("Восстанавливает пустой файл")
        void shouldRestoreEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");

            Vernam.encrypt(input, encrypted, KEY);
            Vernam.decrypt(encrypted, restored, KEY);

            assertThat(restored).isEmptyFile();
        }

        @ParameterizedTest
        @CsvSource({
                "0",
                "-1"
        })
        @DisplayName("Отклоняет неположительный ключ")
        void shouldRejectInvalidKey(long key) throws IOException {
            Path input = createFile(tempDir.resolve("encrypted.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Vernam.decrypt(input, output, key))
                    .withMessageContaining("positive");
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.bin");

            assertThatThrownBy(() -> Vernam.decrypt(input, output, KEY))
                    .isInstanceOf(NoSuchFileException.class);
        }
    }

    private static byte[] xorWithKey(byte[] source) {
        byte[] keyBytes = new byte[Long.BYTES];
        for (int i = 0; i < Long.BYTES; i++) {
            keyBytes[i] = (byte) (KEY >>> (Long.SIZE - (i + 1) * Byte.SIZE));
        }

        byte[] result = new byte[source.length];
        for (int i = 0; i < source.length; i++) {
            result[i] = (byte) (source[i] ^ keyBytes[i % Long.BYTES]);
        }

        return result;
    }

    private static Path createFile(Path path, byte[] content) throws IOException {
        Files.write(path, content);
        return path;
    }
}