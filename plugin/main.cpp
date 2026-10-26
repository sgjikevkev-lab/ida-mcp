#include "server/pipe_server.h"
#include <string>
#include <memory>
#include "ui/settings_window.h"

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <netnode.hpp>

namespace {
    constexpr char kMcpSettingsNode[] = "$ ida_mcp";
    constexpr nodeidx_t kMcpEnabledIndex = 0;

    bool LoadMcpEnabled() {
        netnode settings(kMcpSettingsNode);
        return settings == BADNODE || settings.altval(kMcpEnabledIndex) != 2;
    }

    bool SaveMcpEnabled(bool enabled) {
        netnode settings(kMcpSettingsNode, 0, true);
        return settings != BADNODE && settings.altset(kMcpEnabledIndex, enabled ? 1 : 2);
    }

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
        McpPluginSession() : enabled_(LoadMcpEnabled()) {
            hook_to_notification_point(HT_IDB, DatabaseChanged, this);
            server_.SetEnabled(enabled_);
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
            char version[64]{};
            get_kernel_version(version, sizeof(version));
            version[sizeof(version) - 1] = '\0';
            if (!ui::ShowMcpSettings(enabled_, version, [this](bool requested) {
                const bool saved = SaveMcpEnabled(requested);
                enabled_ = requested;
                server_.SetEnabled(enabled_);
                msg("[IDA MCP] MCP for this database is now %s\n", enabled_ ? "enabled" : "disabled");
                if (!saved)
                    msg("[IDA MCP] Setting applies for this session but could not be saved with the database.\n");
                return saved;
            }))
                warning("IDA MCP: could not open the settings window.");
            return true;
        }

    private:
        bool enabled_ = true;
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
    PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Control MCP for this database",
    "Toggle MCP availability for the current database",
    "IDA MCP",
    ""
};
