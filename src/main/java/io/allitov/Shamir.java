package io.allitov;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;

/**
 * Implements file encryption and decryption with the Shamir three-pass protocol.
 */
@Slf4j
@UtilityClass
public class Shamir {

    private final Random RANDOM = new Random();
    private final long MIN_PRIME = 257L;
    private final long MAX_MODULUS = 3_037_000_000L;

    /**
     * Generates all parameters required by the Shamir cipher.
     *
     * @return keys in the order p, Ca, Da, Cb, Db
     */
    public long[] generateKeys() {
        long p = CryptoUtils.randomLargePrime();
        long modulus = p - 1;
        long ca = randomCoprime(modulus);
        long cb = randomCoprime(modulus);
        long da = modularInverse(ca, modulus);
        long db = modularInverse(cb, modulus);

        log.info("Generated Shamir parameters: p = {}, Ca = {}, Da = {}, Cb = {}, Db = {}",
                p, ca, da, cb, db);

        return new long[] {p, ca, da, cb, db};
    }

    /**
     * Calculates private exponents for prime p and public exponents Ca and Cb.
     *
     * @param p prime modulus
     * @param ca first public exponent
     * @param cb second public exponent
     * @return keys in the order p, Ca, Da, Cb, Db
     */
    public long[] createKeys(long p, long ca, long cb) {
        validatePrime(p);
        validatePublicExponent(ca, p, "Ca");
        validatePublicExponent(cb, p, "Cb");

        long modulus = p - 1;
        long da = modularInverse(ca, modulus);
        long db = modularInverse(cb, modulus);

        log.info("Calculated Shamir parameters: p = {}, Ca = {}, Da = {}, Cb = {}, Db = {}",
                p, ca, da, cb, db);

        return new long[] {p, ca, da, cb, db};
    }

    /**
     * Encrypts every byte of a file by applying the Shamir exponents Ca, Cb and Da.
     *
     * @param input path to the source file
     * @param output path to the encrypted file
     * @param p prime modulus
     * @param ca first public exponent
     * @param cb second public exponent
     * @param da first private exponent
     * @throws IOException if a file cannot be read or written
     */
    public void encrypt(Path input, Path output, long p, long ca, long cb, long da)
            throws IOException {
        validatePrime(p);
        validatePublicExponent(ca, p, "Ca");
        validatePublicExponent(cb, p, "Cb");
        validatePrivateExponent(da, ca, p, "Da");

        log.info("Encrypting file {} to {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            int value;
            while ((value = reader.read()) != -1) {
                long first = CryptoUtils.pow(value, ca, p);
                long second = CryptoUtils.pow(first, cb, p);
                long encrypted = CryptoUtils.pow(second, da, p);
                writeLong(writer, encrypted);
            }
        }

        log.info("File encrypted successfully: {}", output);
    }

    /**
     * Decrypts a file produced by {@link #encrypt(Path, Path, long, long, long, long)}.
     *
     * @param input path to the encrypted file
     * @param output path to the restored file
     * @param p prime modulus
     * @param db second private exponent
     * @throws IOException if a file cannot be read or written
     */
    public void decrypt(Path input, Path output, long p, long db) throws IOException {
        validatePrime(p);
        validateExponent(db, p, "Db");

        log.info("Decrypting file {} to {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            byte[] block = new byte[Long.BYTES];
            while (true) {
                int read = readFully(reader, block);
                if (read == 0) {
                    break;
                }

                if (read != Long.BYTES) {
                    throw new IllegalArgumentException("Encrypted file contains an incomplete 64-bit block");
                }

                long encrypted = readLong(block);
                writer.write(Math.toIntExact(CryptoUtils.pow(encrypted, db, p)));
            }
        }

        log.info("File decrypted successfully: {}", output);
    }

    private long randomCoprime(long modulus) {
        long candidate = RANDOM.nextLong(2, modulus);
        while (CryptoUtils.gcdSimple(candidate, modulus) != 1) {
            candidate = RANDOM.nextLong(2, modulus);
        }

        return candidate;
    }

    private long modularInverse(long exponent, long modulus) {
        List<Long> bezout = CryptoUtils.gcd(exponent, modulus);
        return (bezout.getLast() % modulus + modulus) % modulus;
    }

    private void validatePrime(long p) {
        if (p < MIN_PRIME || p > MAX_MODULUS || !CryptoUtils.ferma(p)) {
            throw new IllegalArgumentException("p must be a prime number greater than 256 and suitable for long modular arithmetic");
        }
    }

    private void validatePublicExponent(long exponent, long p, String name) {
        validateExponent(exponent, p, name);
        long modulus = p - 1;
        if (exponent <= 1 || CryptoUtils.gcdSimple(exponent, modulus) != 1) {
            throw new IllegalArgumentException(name + " must be coprime with p - 1 and be in the range [2, p - 2]");
        }
    }

    private void validatePrivateExponent(long exponent, long pairExponent, long p, String name) {
        validateExponent(exponent, p, name);
        long modulus = p - 1;
        if ((exponent * pairExponent) % modulus != 1) {
            throw new IllegalArgumentException(name + " must be the modular inverse of its paired exponent modulo p - 1");
        }
    }

    private void validateExponent(long exponent, long p, String name) {
        long modulus = p - 1;
        if (exponent <= 0 || exponent >= modulus) {
            throw new IllegalArgumentException(name + " must be in the range [1, p - 2]");
        }
    }

    private void writeLong(OutputStream output, long value) throws IOException {
        for (int shift = Long.SIZE - Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
            output.write((int) (value >>> shift));
        }
    }

    private long readLong(byte[] block) {
        long value = 0;
        for (byte current : block) {
            value = (value << Byte.SIZE) | (current & 0xFF);
        }

        return value;
    }

    private int readFully(InputStream input, byte[] buffer) throws IOException {
        int offset = 0;
        while (offset < buffer.length) {
            int read = input.read(buffer, offset, buffer.length - offset);
            if (read == -1) {
                break;
            }

            offset += read;
        }

        return offset;
    }

    @UtilityClass
    private final class Main {
        private final Scanner SCANNER = new Scanner(System.in);

        void main(String[] args) {
            run(args);
        }

        private void run(String[] args) {
            if (args.length != 4) {
                log.error("Usage: encrypt <input> <output> manual|random or decrypt <input> <output> manual");
                return;
            }

            Path input = Path.of(args[1]);
            Path output = Path.of(args[2]);

            try {
                switch (args[0]) {
                    case "encrypt" -> encryptFile(input, output, args[3]);
                    case "decrypt" -> decryptFile(input, output, args[3]);
                    default -> log.error("Operation must be encrypt or decrypt");
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

        private long readLong(String name) {
            log.info("Enter {}:", name);
            return SCANNER.nextLong();
        }
    }
}
