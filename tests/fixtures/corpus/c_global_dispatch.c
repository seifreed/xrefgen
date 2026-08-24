typedef int (*handler_t)(int);
static int left(int value) { return value - 1; }
static int right(int value) { return value + 1; }
static handler_t handler = left;
int dispatch(int value) { return handler(value); }
int main(void) { handler = right; return dispatch(1) == 2 ? 0 : 1; }
