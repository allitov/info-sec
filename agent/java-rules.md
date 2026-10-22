# Java Development Rules

This file contains mandatory rules that the AI agent must follow when creating, modifying, and reviewing the production source code of the project.

---

## Project Structure

- The project uses **Gradle** as the build system.
- All dependencies required for the project are already connected.
- Do not search for additional dependencies in external sources without an explicit need.
- Do not add new dependencies to `build.gradle` or `../build.gradle.kts` unless the task explicitly requires it.
- Do not modify existing dependencies without an explicit requirement.

---

## Production Code

### Classes

- Every production class must use the Lombok `@UtilityClass` annotation.
- When creating a new class, verify that `@UtilityClass` is present.
- When modifying an existing class, do not remove `@UtilityClass` unless the task explicitly requires it.
- Do not create plain classes without `@UtilityClass`.
- Exception messages must be written in English.

Example:

```java
import lombok.experimental.UtilityClass;

@UtilityClass
public class Calculator {

    public int add(int a, int b) {
        return a + b;
    }
}
```

### Logging

- Use the Lombok `@Slf4j` annotation for logging in production code.
- Use the `info` level for informational messages.
- Do not use `System.out.println()` for printing information in production code.
- Use `log.info(...)` whenever informational logging is required.
- All log messages must be written **in English**.
- Do not use the Russian language in log messages.
- Log messages must be clear and briefly describe what is happening in the program.
- Do not duplicate the same information in several log entries without necessity.

Example:

```java
import lombok.extern.slf4j.Slf4j;
import lombok.experimental.UtilityClass;

@Slf4j
@UtilityClass
public class Calculator {

    public int add(int a, int b) {
        log.info("Calculating sum for values: {} and {}", a, b);

        int result = a + b;

        log.info("Calculation completed with result: {}", result);

        return result;
    }
}
```

Correct:

```java
log.info("Starting calculation for order {}", orderId);
log.info("Order {} processed successfully", orderId);
```

Incorrect:

```java
log.info("Начало обработки заказа {}", orderId);
System.out.println("Order processed");
```
