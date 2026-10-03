#include "server/pipe_server.h"
#include "discovery/registration.h"
#include <string>
#include <memory>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

namespace {
    class McpPluginSession : public plugmod_t {
    public:
        McpPluginSession() {
            discovery::InstanceRegistration::CleanupLegacyInstances();
            server_.Start();
        }

        virtual ~McpPluginSession() {
            server_.Stop();
        }

        virtual bool idaapi run(size_t) override {
            info("[IDA MCP] Native Named Pipe server is active on \\\\.\\pipe\\ida_mcp_%lu\n", GetCurrentProcessId());
            return true;
        }

    private:
        server::PipeServer server_;
    };

    plugmod_t* idaapi init() {
        return new McpPluginSession();
    }
}

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_MULTI | PLUGIN_HIDE,
    init,
    nullptr,
    nullptr,
    "IDA Pro MCP Server",
    "",
    "ida_mcp",
    ""
};