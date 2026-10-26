#pragma once

#include <functional>
#include <string_view>

namespace ui {
    // on_change applies immediately and returns whether the setting was persisted.
    bool ShowMcpSettings(bool enabled, std::string_view ida_version,
                         const std::function<bool(bool)>& on_change);
}
