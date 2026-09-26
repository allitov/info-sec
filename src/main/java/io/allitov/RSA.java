package io.allitov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Implements file encryption and decryption with the RSA cipher.
 */
@Slf4j
@UtilityClass
public class RSA {

    private final Random RANDOM = new Random();
    private final long MIN_PRIME = 257L;
    private final long MAX_PRIME = 3_037_000_000L;

    /**
     * Generates all parameters required by the RSA cipher.
     *
     * @return keys in the order p, q, n, Cb, Db
     */
    public long[] generateKeys() {
        long p = CryptoUtils.randomLargePrime();
        long q = randomDifferentPrime(p);
        long n = p * q;
        long phi = (p - 1) * (q - 1);
        long db = randomCoprime(phi);
        long cb = modularInverse(db, phi);

        log.info("Generated RSA parameters: p = {}, q = {}, n = {}, Cb = {}, Db = {}",
                p, q, n, cb, db);

        return new long[] {p, q, n, cb, db};
    }

    /**
     * Calculates the secret key for primes p and q and the public key Db.
     *
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param db public key
     * @return keys in the order p, q, n, Cb, Db
     */
    public long[] createKeys(long p, long q, long db) {
        validatePrimes(p, q);
        long phi = (p - 1) * (q - 1);
        validatePublicKey(db, phi);

        long n = p * q;
        long cb = modularInverse(db, phi);

        log.info("Calculated RSA parameters: p = {}, q = {}, n = {}, Cb = {}, Db = {}",
                p, q, n, cb, db);

        return new long[] {p, q, n, cb, db};
    }

    /**
     * Encrypts every byte of a file with the RSA public key Db.
     *
     * @param input path to the source file
     * @param output path to the encrypted file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param db public key
     * @throws IOException if a file cannot be read or written
     */
    public void encrypt(Path input, Path output, long p, long q, long db) throws IOException {
        validatePrimes(p, q);
        long phi = (p - 1) * (q - 1);
        validatePublicKey(db, phi);
        long n = p * q;

        log.info("Encrypting file {} to {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            int value;
            while ((value = reader.read()) != -1) {
                writeLong(writer, power(value, db, n));
            }
        }

        log.info("File encrypted successfully: {}", output);
    }

    /**
     * Decrypts a file produced by {@link #encrypt(Path, Path, long, long, long)}.
     *
     * @param input path to the encrypted file
     * @param output path to the restored file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void decrypt(Path input, Path output, long p, long q, long cb) throws IOException {
        validatePrimes(p, q);
        long phi = (p - 1) * (q - 1);
        validateSecretKey(cb, phi);
        long n = p * q;

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
                validateCiphertext(encrypted, n);

                long value = power(encrypted, cb, n);
                if (value > 255) {
                    throw new IllegalArgumentException("Decrypted value is not a valid byte");
                }

                writer.write((int) value);
            }
        }

        log.info("File decrypted successfully: {}", output);
    }

    private long randomDifferentPrime(long p) {
        long q = CryptoUtils.randomLargePrime();
        while (q == p) {
            q = CryptoUtils.randomLargePrime();
        }

        return q;
    }

    private long randomCoprime(long modulus) {
        long candidate = RANDOM.nextLong(2, modulus);
        while (CryptoUtils.gcdSimple(candidate, modulus) != 1) {
            candidate = RANDOM.nextLong(2, modulus);
        }

        return candidate;
    }

    private long modularInverse(long value, long modulus) {
        return BigInteger.valueOf(value)
                .modInverse(BigInteger.valueOf(modulus))
                .longValueExact();
    }

    private long power(long base, long exponent, long modulus) {
        return BigInteger.valueOf(base)
                .modPow(BigInteger.valueOf(exponent), BigInteger.valueOf(modulus))
                .longValueExact();
    }

    private void validatePrimes(long p, long q) {
        validatePrime(p, "p");
        validatePrime(q, "q");
        if (p == q) {
            throw new IllegalArgumentException("p and q must be different prime numbers");
        }
    }

    private void validatePrime(long value, String name) {
        if (value < MIN_PRIME || value > MAX_PRIME || !CryptoUtils.ferma(value)) {
            throw new IllegalArgumentException(name + " must be a prime number greater than 256 and suitable for long modular arithmetic");
        }
    }

    private void validatePublicKey(long db, long phi) {
        if (db < 2 || db >= phi || CryptoUtils.gcdSimple(db, phi) != 1) {
            throw new IllegalArgumentException("Db must be coprime with (p - 1)(q - 1) and be in the range [2, (p - 1)(q - 1) - 1]");
        }
    }

    private void validateSecretKey(long cb, long phi) {
        if (cb < 1 || cb >= phi) {
            throw new IllegalArgumentException("Cb must be in the range [1, (p - 1)(q - 1) - 1]");
        }
    }

    private void validateCiphertext(long value, long n) {
        if (value < 0 || value >= n) {
            throw new IllegalArgumentException("Encrypted value must be in the range [0, n - 1]");
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
}
