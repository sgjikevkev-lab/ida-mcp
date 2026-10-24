#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <string>
#include "runtime_limits.h"

namespace ipc {
    // OVERLAPPED, its event and its buffer remain alive until cancelled I/O
    // has completed. CancelIoEx alone does not establish that lifetime.
    inline bool Transfer(HANDLE pipe, bool writing, void* data, DWORD size,
                         DWORD& transferred, ULONGLONG deadline, HANDLE stop = nullptr) {
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) return false;
        transferred = 0;
        BOOL ok = writing ? WriteFile(pipe, data, size, &transferred, &ov)
                          : ReadFile(pipe, data, size, &transferred, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            const auto now = GetTickCount64();
            const DWORD remaining = now >= deadline ? 0 : static_cast<DWORD>(deadline - now);
            HANDLE events[] = {ov.hEvent, stop};
            const DWORD wr = WaitForMultipleObjects(stop ? 2 : 1, events, FALSE, remaining);
            if (wr != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &ov);
                const BOOL completed = GetOverlappedResult(pipe, &ov, &transferred, TRUE);
                ok = completed && wr == WAIT_TIMEOUT;
                if (!ok) SetLastError(wr == WAIT_TIMEOUT ? ERROR_TIMEOUT : ERROR_OPERATION_ABORTED);
            } else {
                ok = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
            }
        }
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(ov.hEvent);
        SetLastError(error);
        return ok != FALSE;
    }

    inline bool WriteFrame(HANDLE pipe, const std::string& frame, ULONGLONG deadline,
                           HANDLE stop = nullptr) {
        size_t offset = 0;
        while (offset < frame.size()) {
            DWORD written = 0;
            const DWORD size = static_cast<DWORD>(std::min<size_t>(65536, frame.size() - offset));
            if (!Transfer(pipe, true, const_cast<char*>(frame.data() + offset), size,
                          written, deadline, stop) || written == 0) return false;
            offset += written;
        }
        return true;
    }
}
