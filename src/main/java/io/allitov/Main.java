package io.allitov;

import java.io.IOException;
import java.nio.file.Path;
import java.util.NoSuchElementException;
import java.util.Scanner;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@UtilityClass
public class Main {

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
            keys = IlGamal.generateKeys();
        } else if ("manual".equals(mode)) {
            long p = readLong("p");
            long g = readLong("g");
            long cb = readLong("Cb");
            keys = IlGamal.createKeys(p, g, cb);
        } else {
            log.error("Encryption mode must be manual or random");
            return;
        }

        IlGamal.encrypt(input, output, keys[0], keys[1], keys[3]);
    }

    private void decryptFile(Path input, Path output, String mode) throws IOException {
        if (!"manual".equals(mode)) {
            log.error("Decryption mode must be manual");
            return;
        }

        long p = readLong("p");
        long cb = readLong("Cb");
        IlGamal.decrypt(input, output, p, cb);
    }

    private long readLong(String name) {
        log.info("Enter {}:", name);
        return SCANNER.nextLong();
    }
}
