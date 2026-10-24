extern "C" __declspec(dllexport) int mcp_fixture_add(int a, int b) {
    return a + b;
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
    return mcp_fixture_update(&node, 1);
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
