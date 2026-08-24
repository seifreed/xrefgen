static int first(int value) { return value + 1; }
static int second(int value) { return value + 2; }
int flattened(int state, int value) { switch (state & 1) { case 0: return first(value); default: return second(value); } }
int main(void) { return flattened(1, 1) == 3 ? 0 : 1; }
