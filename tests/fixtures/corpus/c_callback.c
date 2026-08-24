typedef int (*callback_t)(int);
static int add_one(int value) { return value + 1; }
static int apply(callback_t callback, int value) { return callback(value); }
int main(void) { return apply(add_one, 4) == 5 ? 0 : 1; }
