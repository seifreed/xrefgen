#include <typeinfo>
class Base { public: virtual ~Base() {} };
class Derived : public Base {};
int main() { Base *value = new Derived(); bool ok = typeid(*value) == typeid(Derived); delete value; return ok ? 0 : 1; }
