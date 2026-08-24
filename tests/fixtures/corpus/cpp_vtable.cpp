class Handler { public: virtual int run(int value) { return value + 1; } virtual ~Handler() {} };
class Special : public Handler { public: int run(int value) override { return value + 2; } };
int main() { Handler *handler = new Special(); int result = handler->run(1); delete handler; return result == 3 ? 0 : 1; }
