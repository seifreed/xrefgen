typedef int (*case_t)(int);
static int case_zero(int value) { return value; }
static int case_one(int value) { return value + 1; }
static int case_two(int value) { return value + 2; }
static case_t cases[] = {case_zero, case_one, case_two};
int dispatch_case(unsigned index, int value) { return index < 3 ? cases[index](value) : -1; }
int main(void) { return dispatch_case(2, 1) == 3 ? 0 : 1; }
