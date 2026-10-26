#include "settings_window.h"

#include <algorithm>
#include <cmath>
#include <string>
#include <windows.h>
#include <windowsx.h>
#include <objidl.h>
#include <gdiplus.h>

namespace ui {
namespace {
    constexpr wchar_t kWindowClass[] = L"IdaMcpSettingsWindow";
    constexpr int kWidth = 360;
    constexpr int kHeight = 184;
    constexpr UINT_PTR kAnimationTimer = 1;
    constexpr float kAnimationMs = 180.0f;
    constexpr RECT kSwitchRect{ 266, 108, 336, 146 };
    constexpr RECT kCloseRect{ 308, 12, 348, 52 };

    struct WindowState {
        bool enabled = true;
        bool saved = true;
        bool animate = true;
        bool switch_hovered = false;
        bool close_hovered = false;
        bool keyboard_focus = false;
        bool close_focused = false;
        UINT dpi = 96;
        float scale = 1.0f;
        float position = 1.0f;
        float animation_from = 1.0f;
        ULONGLONG animation_started = 0;
        std::wstring version;
        std::function<bool(bool)> on_change;
    };

    bool Contains(const RECT& rect, POINT point) {
        return PtInRect(&rect, point) != FALSE;
    }

    POINT LogicalPoint(LPARAM lparam, const WindowState& state) {
        return { static_cast<LONG>(GET_X_LPARAM(lparam) / state.scale),
                 static_cast<LONG>(GET_Y_LPARAM(lparam) / state.scale) };
    }

    Gdiplus::Color Blend(Gdiplus::Color from, Gdiplus::Color to, float t) {
        auto channel = [t](BYTE a, BYTE b) {
            return static_cast<BYTE>(std::lround(a + (b - a) * t));
        };
        return Gdiplus::Color(255, channel(from.GetR(), to.GetR()),
                            channel(from.GetG(), to.GetG()), channel(from.GetB(), to.GetB()));
    }

    void Capsule(Gdiplus::Graphics& graphics, float x, float y, float width,
                 float height, const Gdiplus::Color& color) {
        Gdiplus::GraphicsPath path;
        path.AddArc(x, y, height, height, 90, 180);
        path.AddArc(x + width - height, y, height, height, 270, 180);
        path.CloseFigure();
        Gdiplus::SolidBrush brush(color);
        graphics.FillPath(&brush, &path);
    }

    void Text(HDC dc, const wchar_t* text, int x, int y, int size,
              int weight, COLORREF color, const WindowState& state) {
        HFONT font = CreateFontW(-MulDiv(size, state.dpi, 96), 0, 0, 0, weight,
                                 FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                 CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ previous = SelectObject(dc, font);
        SetTextColor(dc, color);
        SetBkMode(dc, TRANSPARENT);
        TextOutW(dc, MulDiv(x, state.dpi, 96), MulDiv(y, state.dpi, 96),
                 text, static_cast<int>(wcslen(text)));
        SelectObject(dc, previous);
        DeleteObject(font);
    }

    void Render(HDC dc, const WindowState& state) {
        {
            Gdiplus::Graphics graphics(dc);
            graphics.Clear(Gdiplus::Color(255, 0, 0, 0));
            graphics.SetSmoothingMode(Gdiplus::SmoothingModeAntiAlias);
            graphics.ScaleTransform(state.scale, state.scale);

            Gdiplus::Pen border(Gdiplus::Color(255, 49, 49, 49), 1.0f);
            graphics.DrawRectangle(&border, 0.5f, 0.5f, kWidth - 1.0f, kHeight - 1.0f);
            Gdiplus::Pen divider(Gdiplus::Color(255, 31, 31, 31), 1.0f);
            graphics.DrawLine(&divider, 24.0f, 81.5f, 336.0f, 81.5f);

            if (state.close_hovered || (state.keyboard_focus && state.close_focused)) {
                Gdiplus::SolidBrush hover(Gdiplus::Color(255, 31, 31, 31));
                graphics.FillEllipse(&hover, 314.0f, 18.0f, 28.0f, 28.0f);
            }
            // Draw the cross as geometry so it never depends on source encoding or a font glyph.
            Gdiplus::Pen cross(state.close_hovered ? Gdiplus::Color(255, 245, 245, 245)
                                                 : Gdiplus::Color(255, 150, 150, 150), 1.5f);
            cross.SetStartCap(Gdiplus::LineCapRound);
            cross.SetEndCap(Gdiplus::LineCapRound);
            graphics.DrawLine(&cross, 324.0f, 28.0f, 332.0f, 36.0f);
            graphics.DrawLine(&cross, 332.0f, 28.0f, 324.0f, 36.0f);

            Gdiplus::Color track = Blend(Gdiplus::Color(255, 255, 239, 213),
                                        Gdiplus::Color(255, 48, 209, 88), state.position);
            if (state.switch_hovered)
                track = Blend(track, Gdiplus::Color(255, 255, 255, 255), 0.04f);
            Capsule(graphics, 266.0f, 108.0f, 70.0f, 38.0f, track);

            float knob_x = 269.0f + 32.0f * state.position;
            Gdiplus::SolidBrush shadow(Gdiplus::Color(24, 0, 0, 0));
            graphics.FillEllipse(&shadow, knob_x, 112.0f, 32.0f, 32.0f);
            Gdiplus::SolidBrush knob(Gdiplus::Color(255, 255, 255, 255));
            graphics.FillEllipse(&knob, knob_x, 111.0f, 32.0f, 32.0f);

            if (state.keyboard_focus && !state.close_focused) {
                Gdiplus::Pen focus(Gdiplus::Color(255, 158, 158, 158), 1.0f);
                Gdiplus::GraphicsPath outline;
                outline.AddArc(262.0f, 104.0f, 46.0f, 46.0f, 90, 180);
                outline.AddArc(294.0f, 104.0f, 46.0f, 46.0f, 270, 180);
                outline.CloseFigure();
                graphics.DrawPath(&focus, &outline);
            }
        }

        Text(dc, L"IDA MCP", 24, 19, 18, FW_SEMIBOLD, RGB(241, 241, 241), state);
        Text(dc, state.version.c_str(), 24, 47, 12, FW_NORMAL, RGB(144, 144, 144), state);
        Text(dc, L"Enable MCP", 24, 105, 16, FW_MEDIUM, RGB(235, 235, 235), state);
        Text(dc, !state.saved ? L"Session only (not saved)"
                             : state.enabled ? L"Active for this database" : L"Listed as inactive",
             24, 132, 12, FW_NORMAL,
             state.saved ? RGB(144, 144, 144) : RGB(232, 186, 112), state);
    }

    bool AdvanceAnimation(WindowState& state) {
        float elapsed = static_cast<float>(GetTickCount64() - state.animation_started);
        float t = std::clamp(elapsed / kAnimationMs, 0.0f, 1.0f);
        float eased = t * t * (3.0f - 2.0f * t);
        float target = state.enabled ? 1.0f : 0.0f;
        state.position = state.animation_from + (target - state.animation_from) * eased;
        return t < 1.0f;
    }

    void Toggle(HWND window, WindowState& state) {
        if (state.animation_started != 0)
            AdvanceAnimation(state);
        state.enabled = !state.enabled;
        state.animation_from = state.position;
        state.animation_started = GetTickCount64();
        state.saved = state.on_change(state.enabled);
        if (!state.animate || SetTimer(window, kAnimationTimer, 15, nullptr) == 0) {
            KillTimer(window, kAnimationTimer);
            state.position = state.enabled ? 1.0f : 0.0f;
            state.animation_started = 0;
        }
        InvalidateRect(window, nullptr, FALSE);
    }

    LRESULT CALLBACK WindowProc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
        auto* state = reinterpret_cast<WindowState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
        if (message == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
            SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
            return TRUE;
        }
        if (state == nullptr)
            return DefWindowProcW(window, message, wparam, lparam);

        switch (message) {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT paint{};
            HDC dc = BeginPaint(window, &paint);
            RECT client{};
            GetClientRect(window, &client);
            HDC buffer = CreateCompatibleDC(dc);
            HBITMAP bitmap = CreateCompatibleBitmap(dc, client.right, client.bottom);
            if (buffer != nullptr && bitmap != nullptr) {
                HGDIOBJ previous = SelectObject(buffer, bitmap);
                Render(buffer, *state);
                BitBlt(dc, 0, 0, client.right, client.bottom, buffer, 0, 0, SRCCOPY);
                SelectObject(buffer, previous);
            } else {
                Render(dc, *state);
            }
            if (bitmap != nullptr)
                DeleteObject(bitmap);
            if (buffer != nullptr)
                DeleteDC(buffer);
            EndPaint(window, &paint);
            return 0;
        }
        case WM_MOUSEMOVE: {
            POINT point = LogicalPoint(lparam, *state);
            bool switch_hovered = Contains(kSwitchRect, point);
            bool close_hovered = Contains(kCloseRect, point);
            if (state->switch_hovered != switch_hovered || state->close_hovered != close_hovered) {
                state->switch_hovered = switch_hovered;
                state->close_hovered = close_hovered;
                InvalidateRect(window, nullptr, FALSE);
            }
            TRACKMOUSEEVENT tracking{ sizeof(tracking), TME_LEAVE, window, 0 };
            TrackMouseEvent(&tracking);
            return 0;
        }
        case WM_MOUSELEAVE:
            state->switch_hovered = false;
            state->close_hovered = false;
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        case WM_SETCURSOR:
            if (LOWORD(lparam) == HTCLIENT) {
                POINT point{};
                GetCursorPos(&point);
                ScreenToClient(window, &point);
                point.x = static_cast<LONG>(point.x / state->scale);
                point.y = static_cast<LONG>(point.y / state->scale);
                SetCursor(LoadCursorW(nullptr, Contains(kSwitchRect, point) || Contains(kCloseRect, point)
                                              ? IDC_HAND : IDC_ARROW));
                return TRUE;
            }
            break;
        case WM_LBUTTONDOWN: {
            state->keyboard_focus = false;
            POINT point = LogicalPoint(lparam, *state);
            if (Contains(kCloseRect, point)) {
                DestroyWindow(window);
            } else if (Contains(kSwitchRect, point)) {
                state->close_focused = false;
                Toggle(window, *state);
            } else if (point.y < 81) {
                ReleaseCapture();
                SendMessageW(window, WM_NCLBUTTONDOWN, HTCAPTION, 0);
            }
            return 0;
        }
        case WM_KEYDOWN:
            if (wparam == VK_ESCAPE) {
                DestroyWindow(window);
                return 0;
            }
            if (wparam == VK_TAB) {
                if (state->keyboard_focus)
                    state->close_focused = !state->close_focused;
                else
                    state->close_focused = false;
                state->keyboard_focus = true;
                InvalidateRect(window, nullptr, FALSE);
                return 0;
            }
            if ((wparam == VK_SPACE || wparam == VK_RETURN) && (lparam & (1LL << 30)) == 0) {
                state->keyboard_focus = true;
                if (state->close_focused)
                    DestroyWindow(window);
                else
                    Toggle(window, *state);
                return 0;
            }
            break;
        case WM_TIMER:
            if (wparam == kAnimationTimer) {
                if (!AdvanceAnimation(*state)) {
                    KillTimer(window, kAnimationTimer);
                    state->animation_started = 0;
                }
                InvalidateRect(window, nullptr, FALSE);
                return 0;
            }
            break;
        case WM_DPICHANGED: {
            state->dpi = HIWORD(wparam);
            state->scale = state->dpi / 96.0f;
            auto* rect = reinterpret_cast<RECT*>(lparam);
            SetWindowPos(window, nullptr, rect->left, rect->top,
                         MulDiv(kWidth, state->dpi, 96), MulDiv(kHeight, state->dpi, 96),
                         SWP_NOZORDER | SWP_NOACTIVATE);
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            KillTimer(window, kAnimationTimer);
            return 0;
        }
        return DefWindowProcW(window, message, wparam, lparam);
    }
}

bool ShowMcpSettings(bool enabled, std::string_view ida_version,
                     const std::function<bool(bool)>& on_change) {
    ULONG_PTR graphics_token = 0;
    Gdiplus::GdiplusStartupInput graphics_input;
    if (Gdiplus::GdiplusStartup(&graphics_token, &graphics_input, nullptr) != Gdiplus::Ok)
        return false;

    HINSTANCE instance = nullptr;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(&WindowProc), &instance);
    WNDCLASSEXW window_class{};
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_DROPSHADOW;
    window_class.lpfnWndProc = WindowProc;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    window_class.lpszClassName = kWindowClass;
    bool registered_here = RegisterClassExW(&window_class) != 0;
    if (!registered_here && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        Gdiplus::GdiplusShutdown(graphics_token);
        return false;
    }

    HWND owner = GetActiveWindow();
    if (owner == nullptr)
        owner = GetForegroundWindow();
    DWORD owner_process = 0;
    GetWindowThreadProcessId(owner, &owner_process);
    if (owner_process != GetCurrentProcessId())
        owner = nullptr;

    WindowState state;
    state.enabled = enabled;
    state.position = enabled ? 1.0f : 0.0f;
    state.on_change = on_change;
    state.version = L"IDA ";
    if (ida_version.empty()) {
        state.version += L"version unavailable";
    } else {
        for (unsigned char character : ida_version)
            state.version += static_cast<wchar_t>(character);
    }
    state.dpi = owner != nullptr ? GetDpiForWindow(owner) : GetDpiForSystem();
    if (state.dpi == 0)
        state.dpi = 96;
    state.scale = state.dpi / 96.0f;
    BOOL animate = TRUE;
    if (SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &animate, 0))
        state.animate = animate != FALSE;

    MONITORINFO monitor{ sizeof(monitor) };
    GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &monitor);
    RECT bounds = monitor.rcWork;
    if (owner != nullptr)
        GetWindowRect(owner, &bounds);
    int width = MulDiv(kWidth, state.dpi, 96);
    int height = MulDiv(kHeight, state.dpi, 96);
    int x = bounds.left + (bounds.right - bounds.left - width) / 2;
    int y = bounds.top + (bounds.bottom - bounds.top - height) / 2;
    x = std::max(monitor.rcWork.left, std::min(static_cast<LONG>(x), monitor.rcWork.right - width));
    y = std::max(monitor.rcWork.top, std::min(static_cast<LONG>(y), monitor.rcWork.bottom - height));

    // A frameless owned popup has no system minimize/maximize controls or light dialog frame.
    HWND window = CreateWindowExW(WS_EX_TOOLWINDOW, kWindowClass, L"IDA MCP",
                                  WS_POPUP, x, y, width, height,
                                  owner, nullptr, instance, &state);
    if (window == nullptr) {
        if (registered_here)
            UnregisterClassW(kWindowClass, instance);
        Gdiplus::GdiplusShutdown(graphics_token);
        return false;
    }

    bool owner_was_enabled = owner != nullptr && IsWindowEnabled(owner);
    if (owner_was_enabled)
        EnableWindow(owner, FALSE);
    ShowWindow(window, SW_SHOW);
    UpdateWindow(window);
    SetForegroundWindow(window);
    SetFocus(window);

    MSG message{};
    bool quitting = false;
    while (IsWindow(window)) {
        BOOL result = GetMessageW(&message, nullptr, 0, 0);
        if (result <= 0) {
            quitting = result == 0;
            DestroyWindow(window);
            break;
        }
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    if (owner_was_enabled && IsWindow(owner)) {
        EnableWindow(owner, TRUE);
        SetForegroundWindow(owner);
    }
    if (registered_here)
        UnregisterClassW(kWindowClass, instance);
    Gdiplus::GdiplusShutdown(graphics_token);
    if (quitting)
        PostQuitMessage(static_cast<int>(message.wParam));
    return true;
}
}
