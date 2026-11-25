// Minimal Win32 Service reporting SERVICE_RUNNING for "nfextlag" inside Wine.
// ExitLag.exe opens SCM -> OpenServiceA("nfextlag") -> QueryServiceStatus()
// and checks dwCurrentState == SERVICE_RUNNING (4).
#include <windows.h>

namespace {

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;

void report_status(DWORD state, DWORD exit_code, DWORD wait_hint) {
    static DWORD checkpoint = 1;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exit_code;
    g_status.dwServiceSpecificExitCode = 0;
    g_status.dwWaitHint = wait_hint;
    if (state == SERVICE_START_PENDING) {
        g_status.dwControlsAccepted = 0;
    } else {
        g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED) {
        g_status.dwCheckPoint = 0;
    } else {
        g_status.dwCheckPoint = checkpoint++;
    }
    if (g_status_handle) {
        SetServiceStatus(g_status_handle, &g_status);
    }
}

void WINAPI ctrl_handler(DWORD ctrl) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            report_status(SERVICE_STOP_PENDING, NO_ERROR, 1000);
            if (g_stop_event) {
                SetEvent(g_stop_event);
            }
            break;
        case SERVICE_CONTROL_INTERROGATE:
            if (g_status_handle) {
                SetServiceStatus(g_status_handle, &g_status);
            }
            break;
        default:
            break;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerW(L"nfextlag", ctrl_handler);
    if (!g_status_handle) return;

    report_status(SERVICE_START_PENDING, NO_ERROR, 3000);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        report_status(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    report_status(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(g_stop_event, INFINITE);
    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    report_status(SERVICE_STOPPED, NO_ERROR, 0);
}

}  // namespace

int wmain() {
    wchar_t svc_name[] = L"nfextlag";
    SERVICE_TABLE_ENTRYW table[] = {
        {svc_name, service_main},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}
