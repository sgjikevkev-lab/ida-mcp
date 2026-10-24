extern "C" __declspec(dllexport) int mcp_fixture_add(int a, int b) {
    return a + b;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_branch(int value) {
    if (value > 4) return value + 1;
    return value - 1;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_overwrite(int input) {
    volatile int value = input;
    value = 0;
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_accumulate(int input) {
    volatile int value = input;
    value += 1;
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_xor_accumulate(int input) {
    volatile int value = input;
    value ^= 0x55;
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_loop(int limit, int seed) {
    int value = seed;
    for (int i = 0; i < limit; ++i) value += (i ^ seed);
    return value;
}
extern "C" __declspec(dllexport) int mcp_fixture_global = 7;
extern "C" __declspec(dllexport) int* mcp_fixture_global_ptr = &mcp_fixture_global;
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_set_global(int value) {
    mcp_fixture_global = value;
    return value;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_read_global() {
    return mcp_fixture_global;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_read_pointer() {
    return *mcp_fixture_global_ptr;
}
struct MCPFixtureNode {
    int value;
    MCPFixtureNode* next;
};
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_update(MCPFixtureNode* node, int delta) {
    if (!node) return -1;
    node->value += delta;
    if (node->next) node->next->value = node->value;
    return node->value;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_call(int value) {
    MCPFixtureNode node = {value, nullptr};
    volatile int result = mcp_fixture_update(&node, 1);
    return result + 1;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_outer(int value) {
    volatile int result = mcp_fixture_call(value);
    return result + 1;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_mutate_buffer(unsigned char* bytes, int delta) {
    if (!bytes) return -1;
    bytes[0] = static_cast<unsigned char>(bytes[0] + delta);
    return bytes[0];
}
extern "C" __declspec(dllexport) __declspec(noinline) double mcp_fixture_double(double value) {
    return value * 2.0;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_stub_target(int value) {
    return value * 2;
}
extern "C" __declspec(dllexport) __declspec(noinline) int mcp_fixture_stub_caller(int value) {
    return mcp_fixture_stub_target(value) + 1;
}
class MCPFixtureBase {
public:
    virtual int value(int input) { return input + 1; }
    virtual ~MCPFixtureBase() = default;
};
class MCPFixtureDerived : public MCPFixtureBase {
public:
    int value(int input) override { return input + 2; }
};
extern "C" __declspec(dllexport) MCPFixtureBase* mcp_fixture_object() {
    static MCPFixtureDerived object;
    return &object;
}
extern "C" __declspec(dllexport) int mcp_fixture_virtual_call(MCPFixtureBase* object, int input) {
    return object->value(input);
}
int main() { return mcp_fixture_add(1, 2); }
