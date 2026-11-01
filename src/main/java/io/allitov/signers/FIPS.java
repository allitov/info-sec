package io.allitov.signers;

import io.allitov.common.CryptoUtils;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;

/**
 * Implements file signing and signature verification with the FIPS 186 (DSA) digital signature algorithm.
 *
 * <p>The SHA-256 hash of a file is treated as a byte array. Every hash byte is signed
 * separately with the same DSA parameters. A signature can be stored either in a separate
 * file or in the signed file itself (signature bytes are written before the file content).</p>
 *
 * <p>DSA parameters are a prime modulus p, a prime divisor q of p - 1 and a generator
 * g = h^((p - 1) / q) mod p greater than 1. The secret key Cb lies in [1, q - 1] and the
 * public key Db = g^Cb mod p. Every hash byte h is signed as a pair (r, s), where
 * r = g^k mod p mod q and s = k^-1 (Cb * r + h) mod q for a random session key k
 * in [1, q - 1]; a zero r or s forces a new k. Verification computes
 * v = g^(h * w mod q) * Db^(r * w mod q) mod p mod q with w = s^(q - 2) mod q
 * and accepts the signature when v equals r.</p>
 */
@Slf4j
@UtilityClass
public class FIPS {

    private final String HASH_ALGORITHM = "SHA-256";
    private final int HASH_LENGTH = 32;
    private final int BUFFER_SIZE = 8192;
    private final long MIN_PRIME = 257L;
    private final long MAX_MODULUS = 3_037_000_000L;
    private final long MIN_SUBGROUP = 257L;

    private final Random RANDOM = new Random();

    /**
     * Generates parameters required by the FIPS 186 (DSA) signature.
     *
     * @return keys in the order p, q, g, Cb, Db
     */
    public long[] generateKeys() {
        long[] parameters = generateParameters();
        long p = parameters[0];
        long q = parameters[1];
        long g = parameters[2];
        long cb = RANDOM.nextLong(1, q);
        long db = CryptoUtils.pow(g, cb, p);

        log.info("Generated FIPS 186 (DSA) parameters: p = {}, q = {}, g = {}, Cb = {}, Db = {}",
                p, q, g, cb, db);

        return new long[] {p, q, g, cb, db};
    }

    /**
     * Validates parameters of the FIPS 186 (DSA) signature and calculates the public key Db
     * for prime modulus p, prime divisor q of p - 1, generator g and secret key Cb.
     *
     * @param p prime modulus
     * @param q prime divisor of p - 1
     * @param g generator with g^q mod p = 1
     * @param cb secret key
     * @return keys in the order p, q, g, Cb, Db
     */
    public long[] createKeys(long p, long q, long g, long cb) {
        validateParameters(p, q, g);
        validateSecretKey(cb, q);

        long db = CryptoUtils.pow(g, cb, p);
        log.info("Calculated FIPS 186 (DSA) parameters: p = {}, q = {}, g = {}, Cb = {}, Db = {}",
                p, q, g, cb, db);

        return new long[] {p, q, g, cb, db};
    }

    /**
     * Signs the SHA-256 hash of a file with the DSA secret key Cb and stores
     * the signature in a separate file.
     *
     * @param input path to the source file
     * @param output path to the signature file
     * @param p prime modulus
     * @param q prime divisor of p - 1
     * @param g generator with g^q mod p = 1
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void sign(Path input, Path output, long p, long q, long g, long cb) throws IOException {
        validateParameters(p, q, g);
        validateSecretKey(cb, q);
        byte[] digest = digest(input);

        log.info("Signing file {} with a separate signature file {}", input, output);

        try (OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, p, q, g, cb);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Signs the SHA-256 hash of a file with the DSA secret key Cb and stores
     * the signature in the signed file itself before the file content.
     *
     * @param input path to the source file
     * @param output path to the signed file
     * @param p prime modulus
     * @param q prime divisor of p - 1
     * @param g generator with g^q mod p = 1
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void signAttached(Path input, Path output, long p, long q, long g, long cb)
            throws IOException {
        validateParameters(p, q, g);
        validateSecretKey(cb, q);
        byte[] digest = digest(input);

        log.info("Signing file {} with an attached signature", input);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, p, q, g, cb);
            reader.transferTo(writer);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Verifies a detached FIPS 186 (DSA) signature of a file with the DSA public key Db.
     *
     * @param input path to the signed file
     * @param signature path to the signature file
     * @param p prime modulus
     * @param q prime divisor of p - 1
     * @param g generator with g^q mod p = 1
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if a file cannot be read
     */
    public boolean verify(Path input, Path signature, long p, long q, long g, long db)
            throws IOException {
        validateParameters(p, q, g);
        validatePublicKey(db, p);
        byte[] digest = digest(input);

        log.info("Verifying detached signature {} for file {}", signature, input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(signature)) {
            valid = matchesDetached(reader, digest, p, q, g, db);
        }

        log.info("Detached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    /**
     * Verifies an attached FIPS 186 (DSA) signature stored in the first bytes of the signed file.
     *
     * @param input path to the signed file
     * @param p prime modulus
     * @param q prime divisor of p - 1
     * @param g generator with g^q mod p = 1
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if the file cannot be read
     */
    public boolean verifyAttached(Path input, long p, long q, long g, long db) throws IOException {
        validateParameters(p, q, g);
        validatePublicKey(db, p);

        log.info("Verifying attached signature in file {}", input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(input)) {
            long[] signature = readSignature(reader, q);
            if (signature == null) {
                valid = false;
            } else {
                byte[] digest = digestRemaining(reader);
                valid = matches(signature, digest, p, q, g, db);
            }
        }

        log.info("Attached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    private long[] generateParameters() {
        while (true) {
            long q = CryptoUtils.randomLargePrime();
            long maxMultiplier = (MAX_MODULUS - 1) / q;
            if (maxMultiplier < 2) {
                continue;
            }

            long multiplier = 2 * RANDOM.nextLong(1, maxMultiplier / 2 + 1);
            long p = multiplier * q + 1;
            if (p > MAX_MODULUS || !CryptoUtils.ferma(p)) {
                continue;
            }

            return new long[] {p, q, generator(p, q)};
        }
    }

    private long generator(long p, long q) {
        while (true) {
            long base = RANDOM.nextLong(2, p - 1);
            long candidate = CryptoUtils.pow(base, (p - 1) / q, p);
            if (candidate > 1) {
                return candidate;
            }
        }
    }

    private void writeSignature(OutputStream output, byte[] digest, long p, long q, long g, long cb)
            throws IOException {
        for (byte hashByte : digest) {
            long[] pair = signaturePair(hashByte & 0xFF, p, q, g, cb);
            writeLong(output, pair[0]);
            writeLong(output, pair[1]);
        }
    }

    private long[] signaturePair(long h, long p, long q, long g, long cb) {
        long k = RANDOM.nextLong(1, q);
        long r = CryptoUtils.pow(g, k, p) % q;
        long s = CryptoUtils.pow(k, q - 2, q) * ((cb * r % q + h) % q) % q;
        while (r == 0 || s == 0) {
            k = RANDOM.nextLong(1, q);
            r = CryptoUtils.pow(g, k, p) % q;
            s = CryptoUtils.pow(k, q - 2, q) * ((cb * r % q + h) % q) % q;
        }

        return new long[] {r, s};
    }

    private boolean matchesDetached(InputStream input, byte[] digest, long p, long q, long g, long db)
            throws IOException {
        long[] signature = readSignature(input, q);
        if (signature == null || input.read() != -1) {
            return false;
        }

        return matches(signature, digest, p, q, g, db);
    }

    private long[] readSignature(InputStream input, long q) throws IOException {
        byte[] block = new byte[2 * Long.BYTES];
        long[] signature = new long[2 * HASH_LENGTH];
        for (int index = 0; index < HASH_LENGTH; index++) {
            int read = readFully(input, block);
            if (read != block.length) {
                return null;
            }

            long r = readLong(block, 0);
            long s = readLong(block, Long.BYTES);
            if (r < 1 || r > q - 1 || s < 1 || s > q - 1) {
                return null;
            }

            signature[2 * index] = r;
            signature[2 * index + 1] = s;
        }

        return signature;
    }

    private boolean matches(long[] signature, byte[] digest, long p, long q, long g, long db) {
        for (int index = 0; index < HASH_LENGTH; index++) {
            long r = signature[2 * index];
            long s = signature[2 * index + 1];
            long h = digest[index] & 0xFF;
            long w = CryptoUtils.pow(s, q - 2, q);
            long u1 = h * w % q;
            long u2 = r * w % q;
            long v = CryptoUtils.pow(g, u1, p) * CryptoUtils.pow(db, u2, p) % p % q;
            if (v != r) {
                return false;
            }
        }

        return true;
    }

    private void validateParameters(long p, long q, long g) {
        validatePrime(p);
        validateSubgroup(q, p);
        validateGenerator(g, p, q);
    }

    private void validatePrime(long p) {
        if (p < MIN_PRIME || p > MAX_MODULUS || !CryptoUtils.ferma(p)) {
            throw new IllegalArgumentException("p must be a prime number greater than 256 and suitable for long modular arithmetic");
        }
    }

    private void validateSubgroup(long q, long p) {
        if (q < MIN_SUBGROUP || q > MAX_MODULUS || !CryptoUtils.ferma(q) || (p - 1) % q != 0) {
            throw new IllegalArgumentException("q must be a prime divisor of p - 1 greater than 256");
        }
    }

    private void validateGenerator(long g, long p, long q) {
        if (g < 2 || g > p - 1 || CryptoUtils.pow(g, q, p) != 1) {
            throw new IllegalArgumentException("g must be in the range [2, p - 1] and satisfy g^q mod p = 1");
        }
    }

    private void validateSecretKey(long cb, long q) {
        if (cb < 1 || cb > q - 1) {
            throw new IllegalArgumentException("Cb must be in the range [1, q - 1]");
        }
    }

    private void validatePublicKey(long db, long p) {
        if (db < 1 || db > p - 1) {
            throw new IllegalArgumentException("Db must be in the range [1, p - 1]");
        }
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
                FIPS.sign(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2], keys[3]);
            }
        }

        private void signAttachedFile(String[] args) throws IOException {
            if (args.length != 4) {
                log.error("Usage: sign-attached <input> <output> manual|random");
                return;
            }

            long[] keys = readSigningKeys(args[3]);
            if (keys != null) {
                FIPS.signAttached(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2], keys[3]);
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
            boolean valid = FIPS.verify(Path.of(args[1]), Path.of(args[2]),
                    keys[0], keys[1], keys[2], keys[3]);
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
            boolean valid = FIPS.verifyAttached(Path.of(args[1]), keys[0], keys[1], keys[2], keys[3]);
            log.info("Attached signature is {}", valid ? "valid" : "invalid");
        }

        private long[] readSigningKeys(String mode) {
            if ("random".equals(mode)) {
                long[] keys = FIPS.generateKeys();
                return new long[] {keys[0], keys[1], keys[2], keys[3]};
            }

            if ("manual".equals(mode)) {
                long p = readLong("p");
                long q = readLong("q");
                long g = readLong("g");
                long cb = readLong("Cb");
                return new long[] {p, q, g, cb};
            }

            log.error("Signing mode must be manual or random");
            return null;
        }

        private long[] readVerificationKeys() {
            long p = readLong("p");
            long q = readLong("q");
            long g = readLong("g");
            long db = readLong("Db");
            return new long[] {p, q, g, db};
        }

        private long readLong(String name) {
            log.info("Enter {}:", name);
            return SCANNER.nextLong();
        }
    }
}
