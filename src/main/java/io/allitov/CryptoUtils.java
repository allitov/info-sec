package io.allitov;

import java.util.List;
import java.util.Random;
import java.util.Scanner;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * Криптографическая библиотека.
 */
@Slf4j
@UtilityClass
public class CryptoUtils {

    private static final Random RANDOM = new Random();

    /**
     * Быстрое возведение числа в степень по модулю.
     * Вычисляет:
     *     y = a^x mod p
     * Используется алгоритм бинарного возведения в степень.
     *
     * @param a основание
     * @param x показатель степени
     * @param p модуль
     * @return a^x mod p
     */
    public long pow(long a, long x, long p) {
        if (p <= 0) {
            throw new IllegalArgumentException("Модуль p должен быть положительным");
        }

        if (x < 0) {
            throw new IllegalArgumentException("Степень x не может быть отрицательной");
        }

        if (p == 1) {
            return 0;
        }

        a = a % p;
        long result = 1;
        while (x > 0) {
            if ((x & 1) == 1) {
                result = (result * a) % p;
            }

            a = (a * a) % p;

            x >>= 1;
        }

        return result;
    }

    public long gcdSimple(long a, long b) {
        if (a < 0 || b < 0) {
            throw new IllegalArgumentException("Параметры должны быть положительными");
        }

        if (a < b) {
            long temp = a;
            a = b;
            b = temp;
        }

        while (b != 0) {
            long r = a % b;
            a = b;
            b = r;
        }

        return a;
    }

    public List<Long> gcd(long a, long b) {
        if (a < 0 || b < 0) {
            throw new IllegalArgumentException("Параметры должны положительные");
        }

        if (a < b) {
            long temp = a;
            a = b;
            b = temp;
        }
        List<Long> U = List.of(a, 1L, 0L);
        List<Long> V = List.of(b, 0L, 1L);
        while (V.getFirst() != 0) {
            Long u1 = U.getFirst();
            Long v1 = V.getFirst();
            Long q = u1 / v1;
            List<Long> T = List.of(u1 % v1, U.get(1) - q * V.get(1), U.getLast() - q * V.getLast());
            U = V;
            V = T;
        }
        return U;
    }

    /**
     * Вычисляет НОД и коэффициенты Безу для чисел a и b, введённых с клавиатуры.
     *
     * @return список [gcd, x, y]
     */
    public List<Long> gcdKeyboard() {
        Scanner scanner = new Scanner(System.in);
        log.info("Enter numbers a and b:");
        long a = scanner.nextLong();
        long b = scanner.nextLong();
        return gcd(a, b);
    }

    /**
     * Вычисляет НОД и коэффициенты Безу для случайно сгенерированных чисел a и b.
     *
     * @return список [gcd, x, y]
     */
    public List<Long> gcdRandom() {
        long a = RANDOM.nextLong(1, 1000);
        long b = RANDOM.nextLong(1, 1000);
        log.info("Generated numbers: a = {}, b = {}", a, b);
        return gcd(a, b);
    }

    /**
     * Вычисляет НОД и коэффициенты Безу для случайно сгенерированных простых чисел a и b.
     * Простота чисел проверяется тестом Ферма (метод ferma).
     *
     * @return список [gcd, x, y]
     */
    public List<Long> gcdRandomPrime() {
        long a = randomPrime();
        long b = randomPrime();
        log.info("Generated prime numbers: a = {}, b = {}", a, b);
        return gcd(a, b);
    }

    private long randomPrime() {
        long candidate = RANDOM.nextLong(2, 1000);
        while (!ferma(candidate)) {
            candidate = RANDOM.nextLong(2, 1000);
        }
        return candidate;
    }

    public boolean ferma(long p) {
        if (p == 2) {
            return true;
        }

        for (int i = 0; i < 100; i++) {
            long a = (RANDOM.nextInt(0, 32767) % (p - 2)) + 2;
            if (gcd(a, p).getFirst() != 1) {
                return false;
            }
            if (pow(a, p - 1, p) != 1) {
                return false;
            }
        }
        return true;
    }

    void main() {
        long a = 3;
        long x = 100;
        long p = 7;

        long y = pow(a, x, p);

        log.info("y = {}", y);

        log.info("GCD (simple): {}", gcdSimple(28, 8));

        log.info("GCD with Bezout coefficients: {}", gcd(28, 19));

        log.info("Primality test for 1105: {}", ferma(1105));

        log.info("GCD (keyboard input): {}", gcdKeyboard());
        log.info("GCD (random numbers): {}", gcdRandom());
        log.info("GCD (random primes): {}", gcdRandomPrime());
    }
}
