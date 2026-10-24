#include "server/pipe_server.h"
#include <string>
#include <memory>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

namespace {
    ssize_t idaapi DatabaseChanged(void*, int event, va_list) {
        switch (event) {
            case idb_event::byte_patched:
            case idb_event::renamed:
            case idb_event::ti_changed:
            case idb_event::op_ti_changed:
            case idb_event::func_added:
            case idb_event::func_updated:
            case idb_event::func_deleted:
            case idb_event::make_code:
            case idb_event::make_data:
            case idb_event::destroyed_items:
            case idb_event::local_types_changed:
            case idb_event::segm_added:
            case idb_event::segm_deleted:
            case idb_event::segm_moved:
            case idb_event::allsegs_moved:
                // Never clear a vector while an SDK callback may be using it.
                // Apply invalidation at the next tool boundary on the main thread.
                cache::MarkDatabaseChanged();
                break;
        }
        return 0;
    }
    class McpPluginSession : public plugmod_t {
    public:
        McpPluginSession() {
            hook_to_notification_point(HT_IDB, DatabaseChanged, this);
            if (!server_.Start()) {
                unhook_from_notification_point(HT_IDB, DatabaseChanged, this);
                throw std::runtime_error("Cannot start MCP pipe server");
            }
        }

        virtual ~McpPluginSession() {
            server_.Stop();
            unhook_from_notification_point(HT_IDB, DatabaseChanged, this);
        }

        virtual bool idaapi run(size_t) override {
            msg("[IDA MCP] Native Named Pipe server is active on \\\\.\\pipe\\ida_mcp_%lu\n", GetCurrentProcessId());
            return true;
        }

    private:
        server::PipeServer server_;
    };

    plugmod_t* idaapi init() {
        try { return new McpPluginSession(); }
        catch (const std::exception& error) {
            msg("[IDA MCP] Startup failed: %s\n", error.what());
            return nullptr;
        }
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
