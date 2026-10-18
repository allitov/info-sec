# Test Development Rules

This file contains mandatory rules that the AI agent must follow when creating, modifying, and reviewing the test code of the project.

---

## Test Structure

- Use a separate nested class annotated with `@Nested` for each individual production method.
- The name of the nested class must unambiguously reflect the method under test.
- Do not combine tests of different production methods in a single `@Nested` class.
- All tests of a specific method must be located inside its corresponding `@Nested` class.

Example:

```java
class CalculatorTest {

    @Nested
    class Add {

        // tests for the add() method
    }

    @Nested
    class Multiply {

        // tests for the multiply() method
    }
}
```

---

## Parameterized Tests

- Use parameterized tests wherever possible.
- If several test scenarios differ only in input data and the expected result, use a parameterized test.
- Prefer parameterized tests over duplicating identical test logic.
- Use `@CsvSource` for simple data sets.
- Use an appropriate argument-provision mechanism, such as `@MethodSource`, for complex objects or large data sets.

Example:

```java
@ParameterizedTest
@CsvSource({
        "1, 2, 3",
        "5, 10, 15",
        "-1, 1, 0"
})
@DisplayName("Сложение двух чисел")
void shouldAddNumbers(int a, int b, int expected) {
    assertThat(Calculator.add(a, b))
            .isEqualTo(expected);
}
```

---

## Placement of Test Data Methods

- Methods that provide test data must be located **after the test method that uses them**.
- Do not place `@MethodSource` methods before the tests that consume this data.
- The test method comes first, followed by the data source it uses.

Correct:

```java
@ParameterizedTest
@MethodSource("provideTestData")
@DisplayName("Проверка обработки входных данных")
void shouldProcessData(int input, int expected) {
    assertThat(Calculator.process(input))
            .isEqualTo(expected);
}

static Stream<Arguments> provideTestData() {
    return Stream.of(
            Arguments.of(1, 2),
            Arguments.of(2, 4),
            Arguments.of(3, 6)
    );
}
```

Incorrect:

```java
static Stream<Arguments> provideTestData() {
    // ...
}

@ParameterizedTest
@MethodSource("provideTestData")
void shouldProcessData(int input, int expected) {
    // ...
}
```

---

## `@DisplayName`

- Every test method must have the `@DisplayName` annotation.
- `@DisplayName` must briefly describe the behavior being verified.
- Do not leave test methods without `@DisplayName`.
- The `@DisplayName` text must be understandable without reading the test implementation.
- Use Russian in `@DisplayName` when it matches the language of the existing tests.

Example:

```java
@Test
@DisplayName("Возвращает 0 для пустого списка")
void shouldReturnZeroForEmptyList() {
    // ...
}
```
