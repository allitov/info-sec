package io.allitov;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Implements file encryption and decryption with the ElGamal cipher.
 */
@Slf4j
@UtilityClass
public class IlGamal {

    private final Random RANDOM = new Random();
    private final long MIN_PRIME = 257L;
    private final long MAX_MODULUS = 3_037_000_000L;

    /**
     * Generates parameters required by the ElGamal cipher.
     *
     * @return keys in the order p, g, Cb, Db
     */
    public long[] generateKeys() {
        long p = CryptoUtils.randomLargePrime();
        long g = randomPrimitiveRoot(p);
        long cb = RANDOM.nextLong(1, p - 1);
        long db = CryptoUtils.pow(g, cb, p);

        log.info("Generated ElGamal parameters: p = {}, g = {}, Cb = {}, Db = {}", p, g, cb, db);

        return new long[] {p, g, cb, db};
    }

    /**
     * Calculates the public key for prime modulus p, generator g and secret key Cb.
     *
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param cb secret key
     * @return keys in the order p, g, Cb, Db
     */
    public long[] createKeys(long p, long g, long cb) {
        validatePrime(p);
        validateGenerator(g, p);
        validateSecretKey(cb, p);

        long db = CryptoUtils.pow(g, cb, p);
        log.info("Calculated ElGamal parameters: p = {}, g = {}, Cb = {}, Db = {}", p, g, cb, db);

        return new long[] {p, g, cb, db};
    }

    /**
     * Encrypts every byte of a file with the ElGamal public key Db.
     *
     * @param input path to the source file
     * @param output path to the encrypted file
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param db public key
     * @throws IOException if a file cannot be read or written
     */
    public void encrypt(Path input, Path output, long p, long g, long db) throws IOException {
        validatePrime(p);
        validateGenerator(g, p);
        validatePublicKey(db, p);

        log.info("Encrypting file {} to {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            int value;
            while ((value = reader.read()) != -1) {
                long sessionKey = randomSessionKey(p);
                long r = CryptoUtils.pow(g, sessionKey, p);
                long mask = CryptoUtils.pow(db, sessionKey, p);
                long encrypted = (value * mask) % p;

                writeLong(writer, r);
                writeLong(writer, encrypted);
            }
        }

        log.info("File encrypted successfully: {}", output);
    }

    /**
     * Decrypts a file produced by {@link #encrypt(Path, Path, long, long, long)}.
     *
     * @param input path to the encrypted file
     * @param output path to the restored file
     * @param p prime modulus
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void decrypt(Path input, Path output, long p, long cb) throws IOException {
        validatePrime(p);
        validateSecretKey(cb, p);

        log.info("Decrypting file {} to {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            byte[] block = new byte[2 * Long.BYTES];
            while (true) {
                int read = readFully(reader, block);
                if (read == 0) {
                    break;
                }

                if (read != block.length) {
                    throw new IllegalArgumentException("Encrypted file contains an incomplete 128-bit block");
                }

                long r = readLong(block, 0);
                long encrypted = readLong(block, Long.BYTES);
                validateCiphertextPart(r, p, "r");
                validateCiphertextPart(encrypted, p, "e");

                long inverseMask = CryptoUtils.pow(r, p - 1 - cb, p);
                long value = (encrypted * inverseMask) % p;
                if (value > 255) {
                    throw new IllegalArgumentException("Decrypted value is not a valid byte");
                }

                writer.write((int) value);
            }
        }

        log.info("File decrypted successfully: {}", output);
    }

    private long randomPrimitiveRoot(long p) {
        for (long candidate = 2; candidate < p; candidate++) {
            if (isPrimitiveRoot(candidate, p)) {
                return candidate;
            }
        }

        throw new IllegalArgumentException("Primitive root modulo p is not found");
    }

    private boolean isPrimitiveRoot(long g, long p) {
        if (g <= 1 || g >= p) {
            return false;
        }

        long groupOrder = p - 1;
        long remaining = groupOrder;
        for (long factor = 2; factor * factor <= remaining; factor++) {
            if (remaining % factor == 0) {
                if (CryptoUtils.pow(g, groupOrder / factor, p) == 1) {
                    return false;
                }

                while (remaining % factor == 0) {
                    remaining /= factor;
                }
            }
        }

        return remaining <= 1 || CryptoUtils.pow(g, groupOrder / remaining, p) != 1;
    }

    private long randomSessionKey(long p) {
        long candidate = RANDOM.nextLong(1, p - 1);
        while (CryptoUtils.gcdSimple(candidate, p - 1) != 1) {
            candidate = RANDOM.nextLong(1, p - 1);
        }

        return candidate;
    }

    private void validatePrime(long p) {
        if (p < MIN_PRIME || p > MAX_MODULUS || !CryptoUtils.ferma(p)) {
            throw new IllegalArgumentException("p must be a prime number greater than 256 and suitable for long modular arithmetic");
        }
    }

    private void validateGenerator(long g, long p) {
        if (!isPrimitiveRoot(g, p)) {
            throw new IllegalArgumentException("g must be a primitive root modulo p");
        }
    }

    private void validateSecretKey(long cb, long p) {
        if (cb < 1 || cb > p - 2) {
            throw new IllegalArgumentException("Cb must be in the range [1, p - 2]");
        }
    }

    private void validatePublicKey(long db, long p) {
        if (db < 2 || db > p - 1) {
            throw new IllegalArgumentException("Db must be in the range [2, p - 1]");
        }
    }

    private void validateCiphertextPart(long value, long p, String name) {
        long minValue = "r".equals(name) ? 1 : 0;
        if (value < minValue || value > p - 1) {
            throw new IllegalArgumentException(name + " must be in the range [" + minValue + ", p - 1]");
        }
    }

    private void writeLong(OutputStream output, long value) throws IOException {
        for (int shift = Long.SIZE - Byte.SIZE; shift >= 0; shift -= Byte.SIZE) {
            output.write((int) (value >>> shift));
        }
    }

    private long readLong(byte[] block, int offset) {
        long value = 0;
        for (int index = offset; index < offset + Long.BYTES; index++) {
            value = (value << Byte.SIZE) | (block[index] & 0xFF);
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
