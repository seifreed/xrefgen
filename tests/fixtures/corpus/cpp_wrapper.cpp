static int target(int value) { return value * 2; }
static int (*resolve(void))(int) { return target; }
static int wrapper(int value) { return resolve()(value); }
int main() { return wrapper(3) == 6 ? 0 : 1; }
