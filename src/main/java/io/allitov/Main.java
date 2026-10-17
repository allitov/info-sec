package io.allitov;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Scanner;

@Slf4j
@UtilityClass
public class Main {

    private final Scanner SCANNER = new Scanner(System.in);
    private final String USAGE = """
            Usage: sign <input> <signature> manual|random,
            sign-attached <input> <output> manual|random,
            verify <input> <signature> manual or verify-attached <input> manual
            """;

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
