package io.allitov;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

@DisplayName("Электронная подпись RSA")
class RSASignTest {

    private static final long P = 257L;
    private static final long Q = 263L;
    private static final long DB = 7L;
    private static final long CB = 38327L;
    private static final long N = 67591L;
    private static final int SIGNATURE_BYTES = 32 * Long.BYTES;

    @TempDir
    Path tempDir;

    @Nested
    @DisplayName("sign")
    class Sign {

        @Test
        @DisplayName("Создаёт отдельный файл подписи из 32 подписанных байтов SHA-256")
        void shouldCreateDetachedSignature() throws IOException {
            byte[] source = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");

            RSASign.sign(input, signature, P, Q, CB);

            assertThat(signature).hasBinaryContent(expectedSignature(source));
        }

        @Test
        @DisplayName("Создаёт подпись для пустого файла")
        void shouldSignEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signature = tempDir.resolve("empty.bin.sig");

            RSASign.sign(input, signature, P, Q, CB);

            assertThat(signature).hasBinaryContent(expectedSignature(new byte[0]));
            assertThat(RSASign.verify(input, signature, P, Q, DB)).isTrue();
        }

        @Test
        @DisplayName("Создаёт подпись, проверяемую сгенерированными ключами")
        void shouldSignWithGeneratedKeys() throws IOException {
            byte[] source = "any binary content".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");
            long[] keys = RSA.generateKeys();

            RSASign.sign(input, signature, keys[0], keys[1], keys[3]);

            assertThat(RSASign.verify(input, signature, keys[0], keys[1], keys[4])).isTrue();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 263, 38327",
                "256, 263, 38327",
                "3037000001, 263, 38327"
        })
        @DisplayName("Отклоняет неподходящее простое число p")
        void shouldRejectInvalidP(long p, long q, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.sign(input, output, p, q, cb))
                    .withMessageContaining("prime");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 1, 38327",
                "257, 256, 38327",
                "257, 3037000001, 38327"
        })
        @DisplayName("Отклоняет неподходящее простое число q")
        void shouldRejectInvalidQ(long p, long q, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.sign(input, output, p, q, cb))
                    .withMessageContaining("prime");
        }

        @Test
        @DisplayName("Отклоняет одинаковые простые числа p и q")
        void shouldRejectEqualPrimes() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.sign(input, output, P, P, CB))
                    .withMessageContaining("different");
        }

        @ParameterizedTest
        @CsvSource({
                "257, 263, 0",
                "257, 263, 67072",
                "257, 263, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.sig");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.sign(input, output, p, q, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("signAttached")
    class SignAttached {

        @Test
        @DisplayName("Записывает подпись перед содержимым подписываемого файла")
        void shouldWriteSignatureBeforeContent() throws IOException {
            byte[] source = {10, 20, 30, 40, 50, 60, 70, 80};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");

            RSASign.signAttached(input, signed, P, Q, CB);

            byte[] expected = new byte[SIGNATURE_BYTES + source.length];
            byte[] signature = expectedSignature(source);
            System.arraycopy(signature, 0, expected, 0, signature.length);
            System.arraycopy(source, 0, expected, signature.length, source.length);
            assertThat(signed).hasBinaryContent(expected);
        }

        @Test
        @DisplayName("Создаёт подписанный файл, проверяемый сгенерированными ключами")
        void shouldSignAttachedWithGeneratedKeys() throws IOException {
            byte[] source = "attached signature content".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");
            long[] keys = RSA.generateKeys();

            RSASign.signAttached(input, signed, keys[0], keys[1], keys[3]);

            assertThat(RSASign.verifyAttached(signed, keys[0], keys[1], keys[4])).isTrue();
        }

        @Test
        @DisplayName("Создаёт подписанный файл для пустого исходного файла")
        void shouldSignAttachedEmptyFile() throws IOException {
            Path input = createFile(tempDir.resolve("empty.bin"), new byte[0]);
            Path signed = tempDir.resolve("empty.signed.bin");

            RSASign.signAttached(input, signed, P, Q, CB);

            assertThat(signed).hasBinaryContent(expectedSignature(new byte[0]));
            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isTrue();
        }

        @ParameterizedTest
        @CsvSource({
                "257, 263, 0",
                "257, 263, 67072",
                "257, 263, -1"
        })
        @DisplayName("Отклоняет Cb вне допустимого диапазона")
        void shouldRejectInvalidSecretKey(long p, long q, long cb) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1});
            Path output = tempDir.resolve("output.signed.bin");

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.signAttached(input, output, p, q, cb))
                    .withMessageContaining("Cb");
        }
    }

    @Nested
    @DisplayName("verify")
    class Verify {

        @Test
        @DisplayName("Подтверждает корректную отдельную подпись")
        void shouldAcceptValidSignature() throws IOException {
            byte[] source = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isTrue();
        }

        @ParameterizedTest
        @MethodSource("provideModifiedContents")
        @DisplayName("Отклоняет подпись после изменения подписанного файла")
        void shouldRejectModifiedFile(byte[] modified) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB);
            Files.write(input, modified);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок подписи")
        void shouldRejectModifiedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB);
            byte[] modified = Files.readAllBytes(signature);
            modified[Long.BYTES - 1] ^= 1;
            Files.write(signature, modified);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет подпись, созданную другим секретным ключом")
        void shouldRejectSignatureOfDifferentKey() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB + 1);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 263, 7",
                "257, 1, 7",
                "257, 263, 1",
                "257, 263, 131",
                "257, 263, 67072"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long q, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.verify(input, signature, p, q, db));
        }

        @Test
        @DisplayName("Возвращает false для неполного 64-битного блока подписи")
        void shouldReturnFalseForIncompleteSignatureBlock() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path incomplete = createFile(tempDir.resolve("incomplete.sig"), new byte[] {1, 2, 3});

            assertThat(RSASign.verify(input, incomplete, P, Q, DB)).isFalse();
        }

        @Test
        @DisplayName("Возвращает false для файла подписи с лишними байтами")
        void shouldReturnFalseForSignatureWithExtraBytes() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = tempDir.resolve("input.bin.sig");
            RSASign.sign(input, signature, P, Q, CB);
            byte[] extra = new byte[SIGNATURE_BYTES + 1];
            extra[extra.length - 1] = 1;
            Files.write(signature, extra);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isFalse();
        }

        @ParameterizedTest
        @MethodSource("provideInvalidSignatureValues")
        @DisplayName("Возвращает false при значениях подписи вне диапазона [0, n - 1]")
        void shouldReturnFalseForInvalidSignatureValues(long value) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signature = createEncryptedBlock(tempDir.resolve("invalid.sig"), value);

            assertThat(RSASign.verify(input, signature, P, Q, DB)).isFalse();
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
                    Arguments.of(N),
                    Arguments.of(-1L),
                    Arguments.of(Long.MAX_VALUE)
            );
        }
    }

    @Nested
    @DisplayName("verifyAttached")
    class VerifyAttached {

        @Test
        @DisplayName("Подтверждает корректную встроенную подпись")
        void shouldAcceptValidAttachedSignature() throws IOException {
            byte[] source = "content with attached signature".getBytes();
            Path input = createFile(tempDir.resolve("input.bin"), source);
            Path signed = tempDir.resolve("input.signed.bin");
            RSASign.signAttached(input, signed, P, Q, CB);

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isTrue();
        }

        @Test
        @DisplayName("Отклоняет подписанный файл после изменения данных")
        void shouldRejectModifiedData() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signed = tempDir.resolve("input.signed.bin");
            RSASign.signAttached(input, signed, P, Q, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[modified.length - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isFalse();
        }

        @Test
        @DisplayName("Отклоняет изменённый блок встроенной подписи")
        void shouldRejectModifiedAttachedSignature() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signed = tempDir.resolve("input.signed.bin");
            RSASign.signAttached(input, signed, P, Q, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[Long.BYTES - 1] ^= 1;
            Files.write(signed, modified);

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isFalse();
        }

        @ParameterizedTest
        @CsvSource({
                "1, 263, 7",
                "257, 1, 7",
                "257, 263, 1",
                "257, 263, 131",
                "257, 263, 67072"
        })
        @DisplayName("Отклоняет неподходящие параметры проверки")
        void shouldRejectInvalidParameters(long p, long q, long db) throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signed = tempDir.resolve("input.signed.bin");
            RSASign.signAttached(input, signed, P, Q, CB);

            assertThatIllegalArgumentException()
                    .isThrownBy(() -> RSASign.verifyAttached(signed, p, q, db));
        }

        @Test
        @DisplayName("Возвращает false для файла короче встроенной подписи")
        void shouldReturnFalseForFileShorterThanSignature() throws IOException {
            Path signed = createFile(tempDir.resolve("short.signed.bin"), new byte[] {1, 2, 3});

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isFalse();
        }

        @Test
        @DisplayName("Возвращает false при изменении байта встроенной подписи вне диапазона n")
        void shouldReturnFalseWhenSignatureValueLeavesValidRange() throws IOException {
            Path input = createFile(tempDir.resolve("input.bin"), new byte[] {1, 2, 3});
            Path signed = tempDir.resolve("input.signed.bin");
            RSASign.signAttached(input, signed, P, Q, CB);
            byte[] modified = Files.readAllBytes(signed);
            modified[0] ^= (byte) 0xFF;
            Files.write(signed, modified);

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isFalse();
        }

        @ParameterizedTest
        @MethodSource("provideInvalidSignatureValues")
        @DisplayName("Возвращает false при значениях встроенной подписи вне диапазона [0, n - 1]")
        void shouldReturnFalseForInvalidSignatureValues(long value) throws IOException {
            Path signed = createEncryptedBlock(tempDir.resolve("invalid.signed.bin"), value);

            assertThat(RSASign.verifyAttached(signed, P, Q, DB)).isFalse();
        }

        static Stream<Arguments> provideInvalidSignatureValues() {
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

    private static byte[] expectedSignature(byte[] source) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(source);
            byte[] signature = new byte[digest.length * Long.BYTES];
            for (int index = 0; index < digest.length; index++) {
                long value = BigInteger.valueOf(digest[index] & 0xFF)
                        .modPow(BigInteger.valueOf(CB), BigInteger.valueOf(N))
                        .longValueExact();
                for (int offset = 0; offset < Long.BYTES; offset++) {
                    signature[index * Long.BYTES + offset] =
                            (byte) (value >>> (Long.SIZE - Byte.SIZE * (offset + 1)));
                }
            }

            return signature;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
    }
}
