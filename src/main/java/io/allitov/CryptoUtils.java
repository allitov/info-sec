package io.allitov;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    /**
     * Решает задачу нахождения дискретного логарифма:
     *     y = a^x mod p
     * при известных a, y, p. Используется алгоритм «Шаг младенца, шаг великана».
     * Ищет x в диапазоне [1, m^2], где m = ceil(sqrt(p - 1)).
     *
     * @param a основание (взаимно простое с p)
     * @param y результат
     * @param p модуль (простое число)
     * @return x такое, что a^x mod p = y, или -1, если решения не существует
     */
    public long discreteLog(long a, long y, long p) {
        if (p <= 1) {
            throw new IllegalArgumentException("Модуль p должен быть больше 1");
        }

        a = Math.floorMod(a, p);
        y = Math.floorMod(y, p);

        if (gcd(a, p).getFirst() != 1) {
            throw new IllegalArgumentException("a и p должны быть взаимно простыми");
        }

        long m = (long) Math.ceil(Math.sqrt(p - 1));

        Map<Long, Long> babySteps = new HashMap<>();
        long current = y;
        for (long j = 0; j < m; j++) {
            babySteps.put(current, j);
            current = (current * a) % p;
        }

        long factor = pow(a, m, p);
        long gamma = 1;
        for (long i = 1; i <= m; i++) {
            gamma = (gamma * factor) % p;
            if (babySteps.containsKey(gamma)) {
                return i * m - babySteps.get(gamma);
            }
        }

        log.info("Discrete logarithm not found for a = {}, y = {}, p = {}", a, y, p);

        return -1;
    }

    /**
     * Решает задачу нахождения дискретного логарифма для чисел a, y, p, введённых с клавиатуры.
     *
     * @return x такое, что a^x mod p = y, или -1, если решения не существует
     */
    public long discreteLogKeyboard() {
        Scanner scanner = new Scanner(System.in);
        log.info("Enter numbers a, y and p:");
        long a = scanner.nextLong();
        long y = scanner.nextLong();
        long p = scanner.nextLong();
        return discreteLog(a, y, p);
    }

    /**
     * Решает задачу нахождения дискретного логарифма для случайно сгенерированных параметров:
     * простого p, основания a и результата y = a^x mod p.
     *
     * @return найденное x такое, что a^x mod p = y, или -1, если решения не существует
     */
    public long discreteLogRandom() {
        long p = randomPrime();
        long a = RANDOM.nextLong(1, p);
        long x = RANDOM.nextLong(0, p - 1);
        long y = pow(a, x, p);
        log.info("Generated parameters: a = {}, y = {}, p = {}", a, y, p);
        return discreteLog(a, y, p);
    }

    /**
     * Вычисляет общий секретный ключ двух абонентов по схеме Диффи-Хеллмана:
     *     Ya = g^Xa mod p, Yb = g^Xb mod p
     *     K = Yb^Xa mod p = Ya^Xb mod p = g^(Xa * Xb) mod p
     *
     * @param p большое простое число
     * @param g первообразный корень по модулю p
     * @param xa секретный показатель абонента A из диапазона [2, p - 1]
     * @param xb секретный показатель абонента B из диапазона [2, p - 1]
     * @return общий секретный ключ K
     */
    public long diffieHellman(long p, long g, long xa, long xb) {
        if (p < 3 || !ferma(p)) {
            throw new IllegalArgumentException("p должно быть простым числом больше 2");
        }

        if (g < 2 || g > p - 1) {
            throw new IllegalArgumentException("g должно быть в диапазоне [2, p - 1]");
        }

        if (xa < 2 || xa > p - 1 || xb < 2 || xb > p - 1) {
            throw new IllegalArgumentException("Секретные показатели Xa и Xb должны быть в диапазоне [2, p - 1]");
        }

        long ya = pow(g, xa, p);
        long yb = pow(g, xb, p);

        log.info("Public keys: Ya = {}, Yb = {}", ya, yb);

        return pow(yb, xa, p);
    }

    /**
     * Вычисляет общий секретный ключ по схеме Диффи-Хеллмана для параметров p, g, Xa, Xb,
     * введённых с клавиатуры.
     *
     * @return общий секретный ключ K
     */
    public long diffieHellmanKeyboard() {
        Scanner scanner = new Scanner(System.in);
        log.info("Enter numbers p, g, Xa and Xb:");
        long p = scanner.nextLong();
        long g = scanner.nextLong();
        long xa = scanner.nextLong();
        long xb = scanner.nextLong();
        return diffieHellman(p, g, xa, xb);
    }

    /**
     * Вычисляет общий секретный ключ по схеме Диффи-Хеллмана для случайно сгенерированных параметров:
     * большого простого p, первообразного корня g по модулю p и случайных показателей Xa, Xb из [2, p - 1].
     *
     * @return общий секретный ключ K
     */
    public long diffieHellmanRandom() {
        long p = randomLargePrime();
        long g = primitiveRoot(p);
        long xa = RANDOM.nextLong(2, p);
        long xb = RANDOM.nextLong(2, p);
        log.info("Generated parameters: p = {}, g = {}, Xa = {}, Xb = {}", p, g, xa, xb);
        return diffieHellman(p, g, xa, xb);
    }

    private long randomPrime() {
        long candidate = RANDOM.nextLong(2, 1000);
        while (!ferma(candidate)) {
            candidate = RANDOM.nextLong(2, 1000);
        }
        return candidate;
    }

    private long randomLargePrime() {
        long candidate = RANDOM.nextLong(1_000_000_000, 2_000_000_000);
        while (!ferma(candidate)) {
            candidate = RANDOM.nextLong(1_000_000_000, 2_000_000_000);
        }
        return candidate;
    }

    /**
     * Находит наименьший первообразный корень по модулю простого числа p.
     *
     * @param p простое число
     * @return наименьший первообразный корень по модулю p
     */
    private long primitiveRoot(long p) {
        List<Long> factors = primeFactors(p - 1);
        for (long g = 2; g <= p - 1; g++) {
            boolean isRoot = true;
            for (long factor : factors) {
                if (pow(g, (p - 1) / factor, p) == 1) {
                    isRoot = false;
                    break;
                }
            }

            if (isRoot) {
                return g;
            }
        }

        throw new IllegalArgumentException("Первообразный корень по модулю p не найден");
    }

    /**
     * Возвращает список простых делителей числа n (с повторениями).
     *
     * @param n число больше 1
     * @return список простых делителей
     */
    private List<Long> primeFactors(long n) {
        List<Long> factors = new ArrayList<>();
        long remaining = n;
        for (long d = 2; d * d <= remaining; d++) {
            while (remaining % d == 0) {
                factors.add(d);
                remaining /= d;
            }
        }

        if (remaining > 1) {
            factors.add(remaining);
        }

        return factors;
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

        log.info("Discrete log of 6 base 3 mod 7: {}", discreteLog(3, 6, 7));
        log.info("Discrete log (keyboard input): {}", discreteLogKeyboard());
        log.info("Discrete log (random parameters): {}", discreteLogRandom());

        log.info("Diffie-Hellman shared key for p = 23, g = 5, Xa = 6, Xb = 15: {}",
                diffieHellman(23, 5, 6, 15));
        log.info("Diffie-Hellman shared key (keyboard input): {}", diffieHellmanKeyboard());
        log.info("Diffie-Hellman shared key (random parameters): {}", diffieHellmanRandom());
    }
}
