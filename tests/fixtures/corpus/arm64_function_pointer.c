#include <stdint.h>

typedef int (*handler_t)(int);

__attribute__((noinline)) int handler_a(int value) {
    return value + 7;
}

__attribute__((noinline)) int handler_b(int value) {
    return value - 3;
}

static volatile handler_t selected_handler = handler_a;

__attribute__((noinline)) int dispatch(int value) {
    return selected_handler(value);
}

int main(void) {
    return dispatch(5) == 12 ? 0 : 1;
}
