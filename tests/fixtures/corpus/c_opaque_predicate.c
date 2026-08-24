static volatile int seed = 7;
int opaque(int value) { if ((seed * seed) % 2 == 1) return value + 1; return value - 1; }
int main(void) { return opaque(1) == 2 ? 0 : 1; }
