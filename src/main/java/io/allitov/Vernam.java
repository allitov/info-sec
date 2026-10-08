package io.allitov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Scanner;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Implements file encryption and decryption with the Vernam cipher.
 * The key K can be generated using the Diffie-Hellman method.
 */
@Slf4j
@UtilityClass
public class Vernam {

    private final Scanner SCANNER = new Scanner(System.in);

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

    private void run(String[] args) {
        if (args.length != 4) {
            log.error("Usage: encrypt <input> <output> manual|random, decrypt <input> <output> manual, "
                    + "vernam-encrypt <input> <output> manual|random or vernam-decrypt <input> <output> manual");
            return;
        }

        Path input = Path.of(args[1]);
        Path output = Path.of(args[2]);

        try {
            switch (args[0]) {
                case "encrypt" -> encryptFile(input, output, args[3]);
                case "decrypt" -> decryptFile(input, output, args[3]);
                case "vernam-encrypt" -> vernamEncryptFile(input, output, args[3]);
                case "vernam-decrypt" -> vernamDecryptFile(input, output, args[3]);
                default -> log.error("Operation must be encrypt, decrypt, vernam-encrypt or vernam-decrypt");
            }
        } catch (IOException | IllegalArgumentException | NoSuchElementException e) {
            log.error("Operation failed: {}", e.getMessage());
        }
    }

    private void encryptFile(Path input, Path output, String mode) throws IOException {
        long[] keys;
        if ("random".equals(mode)) {
            keys = Shamir.generateKeys();
        } else if ("manual".equals(mode)) {
            long p = readLong("p");
            long ca = readLong("Ca");
            long cb = readLong("Cb");
            keys = Shamir.createKeys(p, ca, cb);
        } else {
            log.error("Encryption mode must be manual or random");
            return;
        }

        Shamir.encrypt(input, output, keys[0], keys[1], keys[3], keys[2]);
    }

    private void decryptFile(Path input, Path output, String mode) throws IOException {
        if (!"manual".equals(mode)) {
            log.error("Decryption mode must be manual");
            return;
        }

        long p = readLong("p");
        long db = readLong("Db");
        Shamir.decrypt(input, output, p, db);
    }

    private void vernamEncryptFile(Path input, Path output, String mode) throws IOException {
        if ("random".equals(mode)) {
            Vernam.encrypt(input, output, Vernam.generateKey());
        } else if ("manual".equals(mode)) {
            long p = readLong("p");
            long g = readLong("g");
            long xa = readLong("Xa");
            long xb = readLong("Xb");
            Vernam.encrypt(input, output, Vernam.generateKey(p, g, xa, xb));
        } else {
            log.error("Encryption mode must be manual or random");
        }
    }

    private void vernamDecryptFile(Path input, Path output, String mode) throws IOException {
        if (!"manual".equals(mode)) {
            log.error("Decryption mode must be manual");
            return;
        }

        long key = readLong("K");
        Vernam.decrypt(input, output, key);
    }

    private long readLong(String name) {
        log.info("Enter {}:", name);
        return SCANNER.nextLong();
    }
}