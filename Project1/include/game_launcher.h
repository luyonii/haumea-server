#pragma once
// Target process lifecycle helper: stop by name, start from path.

namespace game_launcher {

enum class stop_result {
    not_running,
    stopped,
    access_denied,
    enum_failed,
    terminate_failed
};

enum class start_result {
    ok,
    create_failed,
    invalid_path
};

struct process {
    void*         hProcess;
    void*         hThread;
    unsigned long pid;
    unsigned long tid;
};

// Case-insensitive basename match against the system process list.
// Terminates the first matching process and waits up to 5s for exit.
stop_result stop_by_name(const wchar_t* exe_name);

// Launch a new instance from `exe_path`. When `suspended` is true the
// primary thread is created in CREATE_SUSPENDED state.
// Caller owns hProcess / hThread on success and must CloseHandle them.
start_result start(const wchar_t* exe_path, bool suspended, process* out);

// Last GetLastError() captured on a failed start(). 0 when start() succeeded
// or has not been called. Single thread of control assumed (smoke tests).
unsigned long last_create_error();

// Poll the target process for a loaded module whose basename matches
// `module_name` (case-insensitive, ASCII). Returns true as soon as the match
// shows up, false on timeout or a hard enumeration error. Interval is 500 ms;
// the final iteration sleeps the remainder of the budget.
// Uses `K32EnumProcessModulesEx` + `K32GetModuleBaseNameW` (kernel32 forwarders
// since Win7), resolved through dynapi so the loader keeps a zero IAT.
bool wait_for_module(void* hProc, const wchar_t* module_name, unsigned long timeout_ms);

} // namespace game_launcher
