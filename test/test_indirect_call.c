/*
 * Test indirect function calls (BLR instructions) in the emulator
 * This tests whether QEMU properly handles function pointers and BLR
 */
#include <stdio.h>
#include <stdint.h>

// Simple function that will be called via function pointer
static int add_numbers(int a, int b) {
    return a + b;
}

// Function that will be called indirectly
static int multiply_numbers(int a, int b) {
    return a * b;
}

// Function that uses a function pointer (will generate BLR instruction)
static int call_via_pointer(int (*func)(int, int), int x, int y) {
    // This should generate: BLR (indirect call through register)
    return func(x, y);
}

// Nested indirect call test
typedef int (*binary_op_t)(int, int);

static int apply_twice(binary_op_t op, int a, int b, int c) {
    int result = op(a, b);
    return op(result, c);
}

// Test structure with function pointer
struct calculator {
    int (*operation)(int, int);
    int operand1;
    int operand2;
};

static int execute_calculator(struct calculator *calc) {
    // Indirect call through structure member
    return calc->operation(calc->operand1, calc->operand2);
}

int main() {
    printf("Test 1: Simple indirect call via function pointer\n");
    int result1 = call_via_pointer(add_numbers, 5, 3);
    printf("  call_via_pointer(add_numbers, 5, 3) = %d (expected 8)\n", result1);
    if (result1 != 8) {
        printf("  FAILED!\n");
        return 1;
    }

    printf("\nTest 2: Different function via same pointer mechanism\n");
    int result2 = call_via_pointer(multiply_numbers, 4, 7);
    printf("  call_via_pointer(multiply_numbers, 4, 7) = %d (expected 28)\n", result2);
    if (result2 != 28) {
        printf("  FAILED!\n");
        return 1;
    }

    printf("\nTest 3: Nested indirect calls\n");
    int result3 = apply_twice(add_numbers, 10, 20, 30);
    printf("  apply_twice(add_numbers, 10, 20, 30) = %d (expected 60)\n", result3);
    if (result3 != 60) {
        printf("  FAILED!\n");
        return 1;
    }

    printf("\nTest 4: Indirect call through structure\n");
    struct calculator calc = {
        .operation = multiply_numbers,
        .operand1 = 6,
        .operand2 = 9
    };
    int result4 = execute_calculator(&calc);
    printf("  execute_calculator(6 * 9) = %d (expected 54)\n", result4);
    if (result4 != 54) {
        printf("  FAILED!\n");
        return 1;
    }

    printf("\nTest 5: Array of function pointers\n");
    binary_op_t operations[] = {add_numbers, multiply_numbers};
    int result5a = operations[0](100, 50);
    int result5b = operations[1](10, 5);
    printf("  operations[0](100, 50) = %d (expected 150)\n", result5a);
    printf("  operations[1](10, 5) = %d (expected 50)\n", result5b);
    if (result5a != 150 || result5b != 50) {
        printf("  FAILED!\n");
        return 1;
    }

    printf("\nAll indirect call tests PASSED!\n");
    return 0;
}
