typedef int (*handler_t)(int);
static int handler(int value) { return value + 1; }
int dispatch(handler_t callback, int value) { return callback(value); }
int main(void) { return dispatch(handler, 1); }
