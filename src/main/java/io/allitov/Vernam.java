package io.allitov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Implements file encryption and decryption with the Vernam cipher.
 * The key K can be generated using the Diffie-Hellman method.
 */
@Slf4j
@UtilityClass
public class Vernam {

    private final int BUFFER_SIZE = 8192;

    /**
     * Generates a Vernam key K using the Diffie-Hellman method
     * with randomly generated parameters p, g, Xa and Xb.
     *
     * @return shared secret key K
     */
    public long generateKey() {
        long key = CryptoUtils.diffieHellmanRandom();

        log.info("Generated Vernam key K = {}", key);

        return key;
    }

    /**
     * Generates a Vernam key K using the Diffie-Hellman method:
     *     Ya = g^Xa mod p, Yb = g^Xb mod p
     *     K = Yb^Xa mod p = Ya^Xb mod p
     *
     * @param p large prime number
     * @param g primitive root modulo p
     * @param xa secret exponent of subscriber A
     * @param xb secret exponent of subscriber B
     * @return shared secret key K
     */
    public long generateKey(long p, long g, long xa, long xb) {
        long key = CryptoUtils.diffieHellman(p, g, xa, xb);

        log.info("Calculated Vernam key K = {}", key);

        return key;
    }

    /**
     * Encrypts every byte of a file by applying XOR with the key bytes.
     *
     * @param input path to the source file
     * @param output path to the encrypted file
     * @param key shared secret key K
     * @throws IOException if a file cannot be read or written
     */
    public void encrypt(Path input, Path output, long key) throws IOException {
        validateKey(key);

        log.info("Encrypting file {} to {}", input, output);

        transform(input, output, keyBytes(key));

        log.info("File encrypted successfully: {}", output);
    }

    /**
     * Decrypts a file produced by {@link #encrypt(Path, Path, long)}.
     *
     * @param input path to the encrypted file
     * @param output path to the restored file
     * @param key shared secret key K
     * @throws IOException if a file cannot be read or written
     */
    public void decrypt(Path input, Path output, long key) throws IOException {
        validateKey(key);

        log.info("Decrypting file {} to {}", input, output);

        transform(input, output, keyBytes(key));

        log.info("File decrypted successfully: {}", output);
    }

    private void validateKey(long key) {
        if (key <= 0) {
            throw new IllegalArgumentException("Key must be a positive number");
        }
    }

    private byte[] keyBytes(long key) {
        byte[] bytes = new byte[Long.BYTES];
        for (int i = 0; i < Long.BYTES; i++) {
            bytes[i] = (byte) (key >>> (Long.SIZE - (i + 1) * Byte.SIZE));
        }

        return bytes;
    }

    private void transform(Path input, Path output, byte[] keyBytes) throws IOException {
        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            long processed = 0;
            int read;
            while ((read = reader.read(buffer)) != -1) {
                for (int i = 0; i < read; i++) {
                    buffer[i] ^= keyBytes[(int) ((processed + i) % Long.BYTES)];
                }

                writer.write(buffer, 0, read);
                processed += read;
            }
        }
    }
}