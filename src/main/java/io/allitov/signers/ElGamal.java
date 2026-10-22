package io.allitov.signers;

import io.allitov.common.CryptoUtils;
import io.allitov.encoders.IlGamal;
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
import java.util.Random;
import java.util.Scanner;

/**
 * Implements file signing and signature verification with the ElGamal digital signature algorithm.
 *
 * <p>The SHA-256 hash of a file is treated as a byte array. Every hash byte is signed
 * separately with the same ElGamal parameters. A signature can be stored either in a separate
 * file or in the signed file itself (signature bytes are written before the file content).</p>
 */
@Slf4j
@UtilityClass
public class ElGamal {

    private final String HASH_ALGORITHM = "SHA-256";
    private final int HASH_LENGTH = 32;
    private final int BUFFER_SIZE = 8192;
    private final long MIN_PRIME = 257L;
    private final long MAX_MODULUS = 3_037_000_000L;

    private final Random RANDOM = new Random();

    /**
     * Generates parameters required by the ElGamal signature.
     *
     * @return keys in the order p, g, Cb, Db
     * @throws IOException if parameters cannot be generated
     */
    public long[] generateKeys() throws IOException {
        return IlGamal.generateKeys();
    }

    /**
     * Validates parameters of the ElGamal signature and calculates the public key Db
     * for prime modulus p, generator g and secret key Cb.
     *
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param cb secret key
     * @return keys in the order p, g, Cb, Db
     * @throws IOException if parameters cannot be calculated
     */
    public long[] createKeys(long p, long g, long cb) throws IOException {
        return IlGamal.createKeys(p, g, cb);
    }

    /**
     * Signs the SHA-256 hash of a file with the ElGamal secret key Cb and stores
     * the signature in a separate file.
     *
     * @param input path to the source file
     * @param output path to the signature file
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void sign(Path input, Path output, long p, long g, long cb) throws IOException {
        validateSigningKeys(p, g, cb);
        byte[] digest = digest(input);

        log.info("Signing file {} with a separate signature file {}", input, output);

        try (OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, p, g, cb);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Signs the SHA-256 hash of a file with the ElGamal secret key Cb and stores
     * the signature in the signed file itself before the file content.
     *
     * @param input path to the source file
     * @param output path to the signed file
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param cb secret key
     * @throws IOException if a file cannot be read or written
     */
    public void signAttached(Path input, Path output, long p, long g, long cb) throws IOException {
        validateSigningKeys(p, g, cb);
        byte[] digest = digest(input);

        log.info("Signing file {} with an attached signature", input);

        try (InputStream reader = Files.newInputStream(input);
                OutputStream writer = Files.newOutputStream(output)) {
            writeSignature(writer, digest, p, g, cb);
            reader.transferTo(writer);
        }

        log.info("File signed successfully: {}", output);
    }

    /**
     * Verifies a detached ElGamal signature of a file with the ElGamal public key Db.
     *
     * @param input path to the signed file
     * @param signature path to the signature file
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if a file cannot be read
     */
    public boolean verify(Path input, Path signature, long p, long g, long db) throws IOException {
        validatePrime(p);
        validateGenerator(g, p);
        validatePublicKey(db, p);
        byte[] digest = digest(input);

        log.info("Verifying detached signature {} for file {}", signature, input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(signature)) {
            valid = matchesDetached(reader, digest, p, g, db);
        }

        log.info("Detached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    /**
     * Verifies an attached ElGamal signature stored in the first bytes of the signed file.
     *
     * @param input path to the signed file
     * @param p prime modulus
     * @param g primitive root modulo p
     * @param db public key
     * @return true if the signature is valid, false otherwise
     * @throws IOException if the file cannot be read
     */
    public boolean verifyAttached(Path input, long p, long g, long db) throws IOException {
        validatePrime(p);
        validateGenerator(g, p);
        validatePublicKey(db, p);

        log.info("Verifying attached signature in file {}", input);

        boolean valid;
        try (InputStream reader = Files.newInputStream(input)) {
            long[] signature = readSignature(reader, p);
            if (signature == null) {
                valid = false;
            } else {
                byte[] digest = digestRemaining(reader);
                valid = matches(signature, digest, p, g, db);
            }
        }

        log.info("Attached signature verification result for file {}: {}", input, valid);
        return valid;
    }

    private void validateSigningKeys(long p, long g, long cb) {
        validatePrime(p);
        validateGenerator(g, p);
        validateSecretKey(cb, p);
    }

    private void writeSignature(OutputStream output, byte[] digest, long p, long g, long cb)
            throws IOException {
        for (byte hashByte : digest) {
            long[] pair = signaturePair(hashByte & 0xFF, p, g, cb);
            writeLong(output, pair[0]);
            writeLong(output, pair[1]);
        }
    }

    private long[] signaturePair(long h, long p, long g, long cb) {
        long k = randomSessionKey(p);
        long a = CryptoUtils.pow(g, k, p);
        long b = coefficient(h, k, a, cb, p);
        while (b == 0) {
            k = randomSessionKey(p);
            a = CryptoUtils.pow(g, k, p);
            b = coefficient(h, k, a, cb, p);
        }

        return new long[] {a, b};
    }

    private long coefficient(long h, long k, long a, long cb, long p) {
        return BigInteger.valueOf(k)
                .modInverse(BigInteger.valueOf(p - 1))
                .multiply(BigInteger.valueOf(h)
                        .subtract(BigInteger.valueOf(cb).multiply(BigInteger.valueOf(a))))
                .mod(BigInteger.valueOf(p - 1))
                .longValueExact();
    }

    private long randomSessionKey(long p) {
        long candidate = RANDOM.nextLong(1, p - 1);
        while (CryptoUtils.gcdSimple(candidate, p - 1) != 1) {
            candidate = RANDOM.nextLong(1, p - 1);
        }

        return candidate;
    }

    private boolean matchesDetached(InputStream input, byte[] digest, long p, long g, long db)
            throws IOException {
        long[] signature = readSignature(input, p);
        if (signature == null || input.read() != -1) {
            return false;
        }

        return matches(signature, digest, p, g, db);
    }

    private long[] readSignature(InputStream input, long p) throws IOException {
        byte[] block = new byte[2 * Long.BYTES];
        long[] signature = new long[2 * HASH_LENGTH];
        for (int index = 0; index < HASH_LENGTH; index++) {
            int read = readFully(input, block);
            if (read != block.length) {
                return null;
            }

            long a = readLong(block, 0);
            long b = readLong(block, Long.BYTES);
            if (a < 1 || a > p - 1 || b < 0 || b > p - 2) {
                return null;
            }

            signature[2 * index] = a;
            signature[2 * index + 1] = b;
        }

        return signature;
    }

    private boolean matches(long[] signature, byte[] digest, long p, long g, long db) {
        for (int index = 0; index < HASH_LENGTH; index++) {
            long a = signature[2 * index];
            long b = signature[2 * index + 1];
            long h = digest[index] & 0xFF;
            if (CryptoUtils.pow(g, h, p)
                    != (CryptoUtils.pow(db, a, p) * CryptoUtils.pow(a, b, p)) % p) {
                return false;
            }
        }

        return true;
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
                ElGamal.sign(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2]);
            }
        }

        private void signAttachedFile(String[] args) throws IOException {
            if (args.length != 4) {
                log.error("Usage: sign-attached <input> <output> manual|random");
                return;
            }

            long[] keys = readSigningKeys(args[3]);
            if (keys != null) {
                ElGamal.signAttached(Path.of(args[1]), Path.of(args[2]), keys[0], keys[1], keys[2]);
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
            boolean valid = ElGamal.verify(Path.of(args[1]), Path.of(args[2]),
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
            boolean valid = ElGamal.verifyAttached(Path.of(args[1]), keys[0], keys[1], keys[2]);
            log.info("Attached signature is {}", valid ? "valid" : "invalid");
        }

        private long[] readSigningKeys(String mode) {
            if ("random".equals(mode)) {
                long[] keys = IlGamal.generateKeys();
                return new long[] {keys[0], keys[1], keys[2]};
            }

            if ("manual".equals(mode)) {
                long p = readLong("p");
                long g = readLong("g");
                long cb = readLong("Cb");
                return new long[] {p, g, cb};
            }

            log.error("Signing mode must be manual or random");
            return null;
        }

        private long[] readVerificationKeys() {
            long p = readLong("p");
            long g = readLong("g");
            long db = readLong("Db");
            return new long[] {p, g, db};
        }

        private long readLong(String name) {
            log.info("Enter {}:", name);
            return SCANNER.nextLong();
        }
    }
}
