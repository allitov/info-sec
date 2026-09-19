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

@DisplayName("Шифр Шамира")
class ShamirTest {

    private static final long PRIME = 257L;
    private static final long CA = 47L;
    private static final long CB = 97L;

    @Nested
    @DisplayName("generateKeys")
    class GenerateKeys {

        @RepeatedTest(value = 20)
        @DisplayName("Генерирует простое p и взаимно обратные пары ключей")
        void shouldGenerateValidInverseKeys() {
            long[] keys = Shamir.generateKeys();
            long p = keys[0];
            long ca = keys[1];
            long da = keys[2];
            long cb = keys[3];
            long db = keys[4];
            long modulus = p - 1;

            assertThat(p).isBetween(1_000_000_000L, 1_999_999_999L);
            assertThat(CryptoUtils.ferma(p)).isTrue();
            assertThat(ca).isPositive().isLessThan(modulus);
            assertThat(cb).isPositive().isLessThan(modulus);
            assertThat(da).isPositive().isLessThan(modulus);
            assertThat(db).isPositive().isLessThan(modulus);
            assertThat((ca * da) % modulus).isOne();
            assertThat((cb * db) % modulus).isOne();
            assertThat(CryptoUtils.gcdSimple(ca, modulus)).isOne();
            assertThat(CryptoUtils.gcdSimple(cb, modulus)).isOne();
        }
    }

    @Nested
    @DisplayName("createKeys")
    class CreateKeys {

        @ParameterizedTest
        @CsvSource({
                "257, 47, 97",
                "1009, 5, 101"
        })
        @DisplayName("Вычисляет закрытые ключи, обратные открытым ключам по модулю p - 1")
        void shouldCalculateInverseKeys(long p, long ca, long cb) {
            long[] keys = Shamir.createKeys(p, ca, cb);
            long modulus = p - 1;

            assertThat(keys[0]).isEqualTo(p);
            assertThat(keys[1]).isEqualTo(ca);
            assertThat(keys[2]).isPositive().isLessThan(modulus);
            assertThat(keys[3]).isEqualTo(cb);
            assertThat(keys[4]).isPositive().isLessThan(modulus);
            assertThat((keys[1] * keys[2]) % modulus).isOne();
            assertThat((keys[3] * keys[4]) % modulus).isOne();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 47, 97",
                "256, 47, 97",
                "300, 47, 97",
                "3_037_000_001, 47, 97"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidPrime(long p, long ca, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.createKeys(p, ca, cb))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 1, 97",
                "257, 2, 97",
                "257, 256, 97"
        })
        @DisplayName("Отклоняет Ca, не взаимно простое с p - 1")
        void shouldRejectInvalidCa(long p, long ca, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.createKeys(p, ca, cb))
                    .withMessageContaining("Ca");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 47, 1",
                "257, 47, 2",
                "257, 47, 256"
        })
        @DisplayName("Отклоняет Cb, не взаимно простое с p - 1")
        void shouldRejectInvalidCb(long p, long ca, long cb) {
            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.createKeys(p, ca, cb))
                    .withMessageContaining("Cb");
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
            long[] keys = Shamir.createKeys(PRIME, CA, CB);

            Shamir.encrypt(input, output, keys[0], keys[1], keys[3], keys[2]);

            assertThat(output).exists();
            assertThat(Files.size(output)).isEqualTo(source.length * Long.BYTES);
            assertThat(Files.readAllBytes(output)).isNotEqualTo(source);
        }

        @ParameterizedTest
        @MethodSource("provideInvalidPrivateExponents")
        @DisplayName("Отклоняет Da вне допустимого диапазона")
        void shouldRejectInvalidDa(long da) throws IOException {
            Path input = createFile(tempDir.resolve("source.bin"), new byte[] {1, 2, 3});
            Path output = tempDir.resolve("result.bin");
            long[] keys = Shamir.createKeys(PRIME, CA, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.encrypt(input, output, keys[0], keys[1], keys[3], da))
                    .withMessageContaining("Da");
        }

        @Test
        @DisplayName("Отклоняет отсутствующий входной файл")
        void shouldRejectMissingInputFile() {
            Path input = tempDir.resolve("missing.bin");
            Path output = tempDir.resolve("output.bin");
            long[] keys = Shamir.createKeys(PRIME, CA, CB);

            assertThatThrownBy(() -> Shamir.encrypt(input, output, keys[0], keys[1], keys[3], keys[2]))
                    .isInstanceOf(NoSuchFileException.class);
        }

        static Stream<Arguments> provideInvalidPrivateExponents() {
            return Stream.of(
                    Arguments.of(0L),
                    Arguments.of(256L),
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
        @DisplayName("Восстанавливает произвольные байты после полного цикла шифрования")
        void shouldRestoreEncryptedFile() throws IOException {
            byte[] source = {0, 1, 2, 127, -128, -2, -1, 42, 7};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path encrypted = tempDir.resolve("encrypted.bin");
            Path restored = tempDir.resolve("restored.bin");
            long[] keys = Shamir.createKeys(PRIME, CA, CB);

            Shamir.encrypt(input, encrypted, keys[0], keys[1], keys[3], keys[2]);
            Shamir.decrypt(encrypted, restored, keys[0], keys[4]);

            assertThat(restored).hasBinaryContent(source);
        }

        @ParameterizedTest
        @MethodSource("provideInvalidDbValues")
        @DisplayName("Отклоняет Db вне допустимого диапазона")
        void shouldRejectInvalidDb(long db) throws IOException {
            Path input = createFile(tempDir.resolve("encrypted.bin"), new byte[Long.BYTES]);
            Path output = tempDir.resolve("result.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.decrypt(input, output, PRIME, db))
                    .withMessageContaining("Db");
        }

        @Test
        @DisplayName("Отклоняет неполный 64-битный блок шифртекста")
        void shouldRejectIncompleteEncryptedBlock() throws IOException {
            Path input = createFile(tempDir.resolve("invalid.bin"), new byte[] {1, 2, 3, 4, 5});
            Path output = tempDir.resolve("output.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> Shamir.decrypt(input, output, PRIME, 1L))
                    .withMessageContaining("incomplete");
        }

        static Stream<Arguments> provideInvalidDbValues() {
            return Stream.of(
                    Arguments.of(0L),
                    Arguments.of(256L),
                    Arguments.of(-1L)
            );
        }
    }

    private static Path createFile(Path path, byte[] content) throws IOException {
        Files.write(path, content);
        return path;
    }
}
