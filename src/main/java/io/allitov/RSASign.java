package io.allitov;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;
import java.util.Scanner;

/**
 * Implements file signing and signature verification with the RSA digital signature algorithm.
 *
 * <p>The SHA-256 hash of a file is treated as a byte array. Every hash byte is signed
 * separately with the same RSA parameters. A signature can be stored either in a separate
 * file or in the signed file itself (signature bytes are written before the file content).</p>
 */
@Slf4j
@UtilityClass
public class RSASign {

    private final String HASH_ALGORITHM = "SHA-256";
    private final int HASH_LENGTH = 32;
    private final int BUFFER_SIZE = 8192;
    private final long MIN_PRIME = 257L;
    private final long MAX_PRIME = 3_037_000_000L;

    /**
     * Signs the SHA-256 hash of a file with the RSA secret key Cb and stores
     * the signature in a separate file.
     *
     * @param input path to the source file
     * @param output path to the signature file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void sign(Path input, Path output, long p, long q, long cb) throws IOException {
        long n = prepareSigning(p, q, cb);
        byte[] digest = digest(input);

        log.info("Signing file {} with a separate signature file {}", input, output);

        try (OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, cb, n);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Signs the SHA-256 hash of a file with the RSA secret key Cb and stores
     * the signature in the signed file itself before the file content.
     *
     * @param input path to the source file
     * @param output path to the signed file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void signAttached(Path input, Path output, long p, long q, long cb) throws IOException {
        long n = prepareSigning(p, q, cb);
        byte[] digest = digest(input);

        log.info("Signing file {} with an attached signature {}", input, output);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, cb, n);
            reader.transferTo(writer);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Verifies a detached RSA signature of a file with the RSA public key Db.
     *
     * @param input path to the signed file
     * @param signature path to the signature file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if a file cannot be read
     */
    public boolean verify(Path input, Path signature, long p, long q, long db) throws IOException {
        long n = RSA.createKeys(p, q, db)[2];
        byte[] digest = digest(input);

        log.info("Verifying detached signature {} for file {}", signature, input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(signature)) {
            valid = matchesSignature(reader, digest, db, n);
        }

        log.info("Detached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    /**
     * Verifies an attached RSA signature stored in the first bytes of the signed file.
     *
     * @param input path to the signed file
     * @param p first prime factor of the modulus
     * @param q second prime factor of the modulus
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if the file cannot be read
     */
    public boolean verifyAttached(Path input, long p, long q, long db) throws IOException {
        long n = RSA.createKeys(p, q, db)[2];

        log.info("Verifying attached signature in file {}", input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(input)) {
            long[] signature = readSignature(reader, n);
            if (signature == null) {
                valid = false;
            } else {
                byte[] digest = digestRemaining(reader);
                valid = matches(signature, digest, db, n);
            }
        }

        log.info("Attached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    private long prepareSigning(long p, long q, long cb) {
        validatePrimes(p, q);
        long phi = (p - 1) * (q - 1);
        validateSecretKey(cb, phi);

        return p * q;
    }

    private void writeSignature(OutputStream output, byte[] digest, long cb, long n)
            throws IOException {
        for (byte hashByte : digest) {
            writeLong(output, power(hashByte & 0xFF, cb, n));
        }
    }

    private boolean matchesSignature(InputStream input, byte[] digest, long db, long n)
            throws IOException {
        long[] signature = readSignature(input, n);
        if (signature == null || input.read() != -1) {
            return false;
        }

        return matches(signature, digest, db, n);
    }

    private boolean matches(long[] signature, byte[] digest, long db, long n) {
        for (int index = 0; index < HASH_LENGTH; index++) {
            if (power(signature[index], db, n) != (digest[index] & 0xFF)) {
                return false;
            }
        }

        return true;
    }

    private long[] readSignature(InputStream input, long n) throws IOException {
        byte[] block = new byte[Long.BYTES];
        long[] signature = new long[HASH_LENGTH];
        for (int index = 0; index < HASH_LENGTH; index++) {
            int read = readFully(input, block);
            if (read != Long.BYTES) {
                return null;
            }

            signature[index] = readLong(block);
            if (signature[index] < 0 || signature[index] >= n) {
                return null;
            }
        }

        return signature;
    }

    private byte[] digest(Path input) throws IOException {
        try (InputStream reader = Files.newInputStream(input)) {
            return digestRemaining(reader);
        }
    }

    private byte[] digestRemaining(InputStream input) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
            byte[] buffer = new byte[BUFFER_SIZE];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }

            byte[] result = digest.digest();
            if (result.length != HASH_LENGTH) {
                throw new IllegalStateException("SHA-256 digest has an unexpected length");
            }

            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is not available", e);
        }
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

    private void validateSecretKey(long cb, long phi) {
        if (cb < 1 || cb >= phi) {
            throw new IllegalArgumentException("Cb must be in the range [1, (p - 1)(q - 1) - 1]");
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
        private final String USAGE = "Usage: sign <input> <signature> manual|random, "
                + "sign-attached <input> <output> manual|random, "
                + "verify <input> <signature> manual or verify-attached <input> manual";

        void main(String[] args) {
            run(args);
        }

        private void run(String[] args) {
            if (args.length == 0) {
                log.error(USAGE);
                return;
            }

            try {
                switch (args[0]) {
                    case "sign" -> signFile(args);
                    case "sign-attached" -> signAttachedFile(args);
                    case "verify" -> verifyFile(args);
                    case "verify-attached" -> verifyAttachedFile(args);
                    default -> log.error(USAGE);
                }
            } catch (IOException | IllegalArgumentException | NoSuchElementException e) {
                log.error("Operation failed: {}", e.getMessage());
            }
        }

        private void signFile(String[] args) throws IOException {
            if (args.length != 4) {
                log.error("Usage: sign <input> <signature> manual|random");
                return;
            }

            long[] keys = readSigningKeys(args[3]);
            if (keys != null) {
                RSASign.sign(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2]);
            }
        }

        private void signAttachedFile(String[] args) throws IOException {
            if (args.length != 4) {
                log.error("Usage: sign-attached <input> <output> manual|random");
                return;
            }

            long[] keys = readSigningKeys(args[3]);
            if (keys != null) {
                RSASign.signAttached(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2]);
            }
        }

        private void verifyFile(String[] args) throws IOException {
            if (args.length != 4) {
                log.error("Usage: verify <input> <signature> manual");
                return;
            }

            if (!"manual".equals(args[3])) {
                log.error("Verification mode must be manual");
                return;
            }

            long[] keys = readVerificationKeys();
            boolean valid = RSASign.verify(Path.of(args[1]), Path.of(args[2]),
                    keys[0], keys[1], keys[2]);
            log.info("Signature is {}", valid ? "valid" : "invalid");
        }

        private void verifyAttachedFile(String[] args) throws IOException {
            if (args.length != 3) {
                log.error("Usage: verify-attached <input> manual");
                return;
            }

            if (!"manual".equals(args[2])) {
                log.error("Verification mode must be manual");
                return;
            }

            long[] keys = readVerificationKeys();
            boolean valid = RSASign.verifyAttached(Path.of(args[1]), keys[0], keys[1], keys[2]);
            log.info("Attached signature is {}", valid ? "valid" : "invalid");
        }

        private long[] readSigningKeys(String mode) {
            if ("random".equals(mode)) {
                long[] keys = RSA.generateKeys();
                return new long[] {keys[0], keys[1], keys[3]};
            }

            if ("manual".equals(mode)) {
                long p = readLong("p");
                long q = readLong("q");
                long cb = readLong("Cb");
                return new long[] {p, q, cb};
            }

            log.error("Signing mode must be manual or random");
            return null;
        }

        private long[] readVerificationKeys() {
            long p = readLong("p");
            long q = readLong("q");
            long db = readLong("Db");
            return new long[] {p, q, db};
        }

        private long readLong(String name) {
            log.info("Enter {}:", name);
            return SCANNER.nextLong();
        }
    }
}
