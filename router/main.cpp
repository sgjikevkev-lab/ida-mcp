#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <iostream>

#include "router/ida_router.h"

int main() {
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) {
        return 1;
    }
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    try {
        router::IdaRouter router;
        router.Run();
    } catch (const std::exception& error) {
        std::cerr << "IDA MCP router: " << error.what() << '\n';
        return 1;
    }

    return 0;
}
