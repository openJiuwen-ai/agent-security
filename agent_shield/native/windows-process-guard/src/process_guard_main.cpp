#include "operation_mapping.h"
#include "pipe_io.h"
#include "record_json.h"
#include "process_guard_startup.h"

#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <detours.h>

#include <stdio.h>
#include <string.h>

#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

static std::wstring g_decide_name;
static std::wstring g_hook_x64;
static std::wstring g_hook_x86;
static uint32_t g_delete_mode = SANDBOX_DELETE_TRASH;
static uint32_t g_timeout_ms = 300000;
static char g_tool_call_id[SANDBOX_TOOL_CALL_ID_CAP];
static char g_tool_name[SANDBOX_TOOL_NAME_CAP];
static int g_saw_tool_id = 0;
static int g_saw_tool_name = 0;
static HANDLE g_stop = nullptr;
static CRITICAL_SECTION g_threads_lock;
static std::vector<HANDLE> g_threads;
static std::vector<HANDLE> g_mappings;
static SECURITY_ATTRIBUTES g_security = {};
static PSECURITY_DESCRIPTOR g_sd = nullptr;

struct BrokerStart {
    HANDLE server;
};

static int fail(const wchar_t* reason) {
    fwprintf(stderr, L"agent-security-process-guard: failed: %s\n", reason);
    return SANDBOX_FAIL_EXIT;
}

static const wchar_t* take_arg(int argc, wchar_t** argv, int* index) {
    if (*index + 1 >= argc) {
        return nullptr;
    }
    *index += 1;
    return argv[*index];
}

static int parent_of(DWORD pid, DWORD* parent) {
    int attempt;
    for (attempt = 0; attempt < 5; ++attempt) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (snapshot != INVALID_HANDLE_VALUE && Process32FirstW(snapshot, &entry)) {
            do {
                if (entry.th32ProcessID == pid) {
                    *parent = entry.th32ParentProcessID;
                    CloseHandle(snapshot);
                    return 1;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        if (snapshot != INVALID_HANDLE_VALUE) {
            CloseHandle(snapshot);
        }
        Sleep(10);
    }
    return 0;
}

static int read_sid(HANDLE token, TOKEN_INFORMATION_CLASS kind, char* dest, size_t cap) {
    DWORD length = 0;
    std::vector<unsigned char> buffer;
    PSID sid = nullptr;
    LPWSTR text = nullptr;
    GetTokenInformation(token, kind, nullptr, 0, &length);
    if (length == 0) {
        return 0;
    }
    buffer.resize(length);
    if (!GetTokenInformation(token, kind, buffer.data(), length, &length)) {
        return 0;
    }
    if (kind == TokenUser) {
        sid = ((PTOKEN_USER)buffer.data())->User.Sid;
    } else {
        sid = ((PTOKEN_MANDATORY_LABEL)buffer.data())->Label.Sid;
    }
    if (!ConvertSidToStringSidW(sid, &text)) {
        return 0;
    }
    if (!wide_to_utf8(text, dest, cap)) {
        LocalFree(text);
        return 0;
    }
    LocalFree(text);
    return 1;
}

static int read_integrity(HANDLE token, char* dest, size_t cap) {
    DWORD length = 0;
    std::vector<unsigned char> buffer;
    PSID sid;
    DWORD rid;
    const char* name;
    GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &length);
    if (length == 0) {
        return 0;
    }
    buffer.resize(length);
    if (!GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), length, &length)) {
        return 0;
    }
    sid = ((PTOKEN_MANDATORY_LABEL)buffer.data())->Label.Sid;
    rid = *GetSidSubAuthority(sid, *GetSidSubAuthorityCount(sid) - 1);
    if (rid >= SECURITY_MANDATORY_SYSTEM_RID) {
        name = "system";
    } else if (rid >= SECURITY_MANDATORY_HIGH_RID) {
        name = "high";
    } else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) {
        name = "medium";
    } else {
        name = "low";
    }
    return strcpy_s(dest, cap, name) == 0;
}

static int fill_identity(HANDLE process, DWORD pid, SandboxIdentity* identity) {
    wchar_t image[1024];
    DWORD size = 1024;
    FILETIME created;
    FILETIME exited;
    FILETIME kernel;
    FILETIME user_time;
    ULARGE_INTEGER stamp;
    HANDLE token = nullptr;
    DWORD parent = 0;
    memset(identity, 0, sizeof(*identity));
    identity->pid = pid;
    if (!parent_of(pid, &parent) || !GetProcessTimes(process, &created, &exited, &kernel, &user_time)) {
        return 0;
    }
    identity->parent_pid = parent;
    stamp.LowPart = created.dwLowDateTime;
    stamp.HighPart = created.dwHighDateTime;
    snprintf(identity->instance_id, sizeof(identity->instance_id), "%lu:%llu", (unsigned long)pid, (unsigned long long)stamp.QuadPart);
    if (!QueryFullProcessImageNameW(process, 0, image, &size) || !wide_to_utf8(image, identity->image_utf8, sizeof(identity->image_utf8))) {
        return 0;
    }
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        return 0;
    }
    if (!read_sid(token, TokenUser, identity->user_sid, sizeof(identity->user_sid)) ||
        !read_integrity(token, identity->integrity, sizeof(identity->integrity))) {
        CloseHandle(token);
        return 0;
    }
    CloseHandle(token);
    return identity->user_sid[0] != '\0' && identity->image_utf8[0] != '\0';
}

static int target_arch(HANDLE process, char* dest, size_t cap) {
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (cap < 4 || !IsWow64Process2(process, &process_machine, &native_machine)) {
        return 0;
    }
    if (native_machine == IMAGE_FILE_MACHINE_ARM64 || process_machine == IMAGE_FILE_MACHINE_ARM64) {
        return 0;
    }
    if (process_machine == IMAGE_FILE_MACHINE_I386) {
        return strcpy_s(dest, cap, "x86") == 0;
    }
    if (process_machine == IMAGE_FILE_MACHINE_UNKNOWN && native_machine == IMAGE_FILE_MACHINE_AMD64) {
        return strcpy_s(dest, cap, "x64") == 0;
    }
    return 0;
}

static int init_security() {
    HANDLE token = nullptr;
    DWORD length = 0;
    std::vector<unsigned char> buffer;
    LPWSTR sid = nullptr;
    wchar_t sddl[512];
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return 0;
    }
    GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    buffer.resize(length);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), length, &length) ||
        !ConvertSidToStringSidW(((PTOKEN_USER)buffer.data())->User.Sid, &sid)) {
        CloseHandle(token);
        return 0;
    }
    CloseHandle(token);
    if (swprintf(sddl, 512, L"D:P(A;;GA;;;%s)", sid) < 0) {
        LocalFree(sid);
        return 0;
    }
    LocalFree(sid);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &g_sd, nullptr)) {
        return 0;
    }
    g_security.nLength = sizeof(g_security);
    g_security.lpSecurityDescriptor = g_sd;
    g_security.bInheritHandle = FALSE;
    return 1;
}

static int create_broker_pair(HANDLE* server, HANDLE* client) {
    static volatile LONG serial = 0;
    wchar_t name[160];
    HANDLE server_handle;
    HANDLE client_handle;
    OVERLAPPED overlapped = {};
    BOOL connected;
    LONG id = InterlockedIncrement(&serial);
    swprintf(name, 160, L"\\\\.\\pipe\\agent-security-broker-%lu-%ld", (unsigned long)GetCurrentProcessId(), id);
    server_handle = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                     PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, &g_security);
    if (server_handle == INVALID_HANDLE_VALUE) {
        return 0;
    }
    client_handle = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (client_handle == INVALID_HANDLE_VALUE) {
        CloseHandle(server_handle);
        return 0;
    }
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    connected = ConnectNamedPipe(server_handle, &overlapped);
    if (!connected) {
        DWORD error = GetLastError();
        if (error == ERROR_IO_PENDING && WaitForSingleObject(overlapped.hEvent, 5000) != WAIT_OBJECT_0) {
            CloseHandle(overlapped.hEvent);
            CloseHandle(client_handle);
            CloseHandle(server_handle);
            return 0;
        }
        if (error != ERROR_IO_PENDING && error != ERROR_PIPE_CONNECTED) {
            CloseHandle(overlapped.hEvent);
            CloseHandle(client_handle);
            CloseHandle(server_handle);
            return 0;
        }
    }
    CloseHandle(overlapped.hEvent);
    SetHandleInformation(client_handle, HANDLE_FLAG_INHERIT, 0);
    *server = server_handle;
    *client = client_handle;
    return 1;
}

static DWORD WINAPI broker_proc(LPVOID param);

static int provision_child(const char* request);

static int store_tool(char* dest, size_t cap, const char* src) {
    size_t length = src == nullptr ? 0 : strlen(src);
    if (length + 1 > cap) {
        return 0;
    }
    if (length > 0) {
        memcpy(dest, src, length);
    }
    dest[length] = '\0';
    return 1;
}

static int copy_tool_argument(const wchar_t* src, char* dest, size_t cap) {
    size_t index;
    if (src == nullptr || src[0] == L'\0' || !wide_to_utf8(src, dest, cap)) {
        return 0;
    }
    for (index = 0; dest[index] != '\0'; ++index) {
        if ((unsigned char)dest[index] < 0x20u) {
            dest[0] = '\0';
            return 0;
        }
    }
    return 1;
}

static int attach_process(HANDLE process, DWORD pid, HANDLE decide, const char* tool_call_id, const char* tool_name) {
    SandboxIdentity identity = {};
    ProcessGuardStartup startup = {};
    char bind[8192];
    HANDLE server = nullptr;
    HANDLE client = nullptr;
    HANDLE remote_decide = nullptr;
    HANDLE remote_broker = nullptr;
    char architecture[8];
    int is_x86;
    const wchar_t* dll;
    HANDLE thread;
    BrokerStart* start;
    if (!fill_identity(process, pid, &identity) || bind_to_json(&identity, bind, sizeof(bind)) < 0 ||
        !pipe_write_message(decide, bind, nullptr, 5000)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: bind\n");
        CloseHandle(decide);
        return 0;
    }
    if (!create_broker_pair(&server, &client)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: broker\n");
        CloseHandle(decide);
        return 0;
    }
    if (!DuplicateHandle(GetCurrentProcess(), decide, process, &remote_decide, 0, FALSE, DUPLICATE_SAME_ACCESS) ||
        !DuplicateHandle(GetCurrentProcess(), client, process, &remote_broker, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: duplicate\n");
        CloseHandle(decide);
        CloseHandle(client);
        CloseHandle(server);
        return 0;
    }
    startup.decide_handle = (uint64_t)(uintptr_t)remote_decide;
    startup.broker_handle = (uint64_t)(uintptr_t)remote_broker;
    startup.decision_timeout_ms = g_timeout_ms;
    startup.delete_mode = g_delete_mode;
    startup.pid = identity.pid;
    startup.parent_pid = identity.parent_pid;
    snprintf(startup.instance_id, sizeof(startup.instance_id), "%s", identity.instance_id);
    snprintf(startup.user_sid, sizeof(startup.user_sid), "%s", identity.user_sid);
    snprintf(startup.integrity, sizeof(startup.integrity), "%s", identity.integrity);
    snprintf(startup.image_utf8, sizeof(startup.image_utf8), "%s", identity.image_utf8);
    if (!store_tool(startup.tool_call_id, sizeof(startup.tool_call_id), tool_call_id) ||
        !store_tool(startup.tool_name, sizeof(startup.tool_name), tool_name)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: tool_cause\n");
        CloseHandle(decide);
        CloseHandle(client);
        CloseHandle(server);
        return 0;
    }
    CloseHandle(decide);
    CloseHandle(client);
    if (!target_arch(process, architecture, sizeof(architecture)) || !process_guard_target_supported(architecture)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: architecture\n");
        CloseHandle(server);
        TerminateProcess(process, 1);
        return 0;
    }
    is_x86 = strcmp(architecture, "x86") == 0;
    dll = is_x86 ? g_hook_x86.c_str() : g_hook_x64.c_str();
    wchar_t mapping_name[96];
    char dll_ansi[1024];
    HANDLE mapping;
    void* view;
    swprintf(mapping_name, 96, L"Local\\agent-security-%lu", (unsigned long)pid);
    if (WideCharToMultiByte(CP_ACP, 0, dll, -1, dll_ansi, sizeof(dll_ansi), nullptr, nullptr) <= 0) {
        fwprintf(stderr, L"agent-security-process-guard: failed: dll_path\n");
        CloseHandle(server);
        TerminateProcess(process, 1);
        return 0;
    }
    mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, &g_security, PAGE_READWRITE, 0, sizeof(startup), mapping_name);
    view = mapping == nullptr ? nullptr : MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(startup));
    if (view == nullptr) {
        fwprintf(stderr, L"agent-security-process-guard: failed: mapping %lu\n", GetLastError());
        if (mapping != nullptr) {
            CloseHandle(mapping);
        }
        CloseHandle(server);
        TerminateProcess(process, 1);
        return 0;
    }
    memcpy(view, &startup, sizeof(startup));
    UnmapViewOfFile(view);
    LPCSTR dlls[] = {dll_ansi};
    if (!DetourUpdateProcessWithDll(process, dlls, 1)) {
        fwprintf(stderr, L"agent-security-process-guard: failed: update_process %lu\n", GetLastError());
        CloseHandle(mapping);
        CloseHandle(server);
        TerminateProcess(process, 1);
        return 0;
    }
    EnterCriticalSection(&g_threads_lock);
    g_mappings.push_back(mapping);
    LeaveCriticalSection(&g_threads_lock);
    start = new BrokerStart();
    start->server = server;
    thread = CreateThread(nullptr, 0, broker_proc, start, 0, nullptr);
    if (thread == nullptr) {
        delete start;
        CloseHandle(server);
        TerminateProcess(process, 1);
        return 0;
    }
    EnterCriticalSection(&g_threads_lock);
    g_threads.push_back(thread);
    LeaveCriticalSection(&g_threads_lock);
    return 1;
}

static int provision_child(const char* request) {
    char spec[64];
    char architecture[16];
    char actual[8];
    char tool_call_id[SANDBOX_TOOL_CALL_ID_CAP];
    char tool_name[SANDBOX_TOOL_NAME_CAP];
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint32_t flags = 0;
    HANDLE process;
    HANDLE decide;
    (void)tid;
    (void)flags;
    if (!json_copy_string(request, "spec", spec, sizeof(spec)) || strcmp(spec, "process-guard-broker/v1") != 0) {
        return 0;
    }
    if (!json_copy_uint(request, "pid", &pid) || pid == 0 || !json_copy_uint(request, "tid", &tid) ||
        !json_copy_uint(request, "creation_flags", &flags) || !json_copy_string(request, "architecture", architecture, sizeof(architecture)) ||
        !process_guard_target_supported(architecture) || !json_copy_string(request, "tool_call_id", tool_call_id, sizeof(tool_call_id)) ||
        !json_copy_string(request, "tool_name", tool_name, sizeof(tool_name)) ||
        (tool_call_id[0] == '\0') != (tool_name[0] == '\0')) {
        return 0;
    }
    process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                              PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME,
                          FALSE, pid);
    if (process == nullptr || !target_arch(process, actual, sizeof(actual)) || strcmp(actual, architecture) != 0) {
        if (process != nullptr) {
            CloseHandle(process);
        }
        return 0;
    }
    if (!WaitNamedPipeW(g_decide_name.c_str(), 5000)) {
        TerminateProcess(process, 1);
        CloseHandle(process);
        return 0;
    }
    decide = CreateFileW(g_decide_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (decide == INVALID_HANDLE_VALUE || !attach_process(process, pid, decide, tool_call_id, tool_name)) {
        TerminateProcess(process, 1);
        CloseHandle(process);
        return 0;
    }
    CloseHandle(process);
    return 1;
}

static DWORD WINAPI broker_proc(LPVOID param) {
    BrokerStart* start = (BrokerStart*)param;
    char request[2048];
    char response[128];
    while (pipe_read_message(start->server, request, sizeof(request), g_stop, INFINITE)) {
        int ok = provision_child(request);
        snprintf(response, sizeof(response), "{\"spec\":\"process-guard-broker/v1\",\"action\":\"provision_child\",\"ok\":%s}", ok ? "true" : "false");
        if (!pipe_write_message(start->server, response, g_stop, 5000)) {
            break;
        }
    }
    CloseHandle(start->server);
    delete start;
    return 0;
}

static std::wstring quote_arg(const std::wstring& arg) {
    std::wstring out;
    size_t index;
    if (arg.find_first_of(L" \t\"") == std::wstring::npos) {
        return arg;
    }
    out.push_back(L'"');
    for (index = 0; index < arg.size(); ++index) {
        if (arg[index] == L'"') {
            out += L"\\\"";
        } else {
            out.push_back(arg[index]);
        }
    }
    out.push_back(L'"');
    return out;
}

static void join_brokers() {
    std::vector<HANDLE> threads;
    SetEvent(g_stop);
    EnterCriticalSection(&g_threads_lock);
    threads.swap(g_threads);
    LeaveCriticalSection(&g_threads_lock);
    for (HANDLE thread : threads) {
        WaitForSingleObject(thread, 5000);
        CloseHandle(thread);
    }
    for (HANDLE mapping : g_mappings) {
        CloseHandle(mapping);
    }
    g_mappings.clear();
}

int main() {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int index;
    int separator = -1;
    std::wstring command;
    std::vector<wchar_t> buffer;
    HANDLE decide = INVALID_HANDLE_VALUE;
    STARTUPINFOW startup = {};
    PROCESS_INFORMATION information = {};
    DWORD exit_code = SANDBOX_FAIL_EXIT;
    if (argv == nullptr) {
        return fail(L"argument");
    }
    for (index = 1; index < argc; ++index) {
        if (wcscmp(argv[index], L"--") == 0) {
            separator = index;
            break;
        }
        if (wcscmp(argv[index], L"--decide-pipe") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr) {
                return fail(L"argument");
            }
            g_decide_name = value;
        } else if (wcscmp(argv[index], L"--hook-dll") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr) {
                return fail(L"argument");
            }
            g_hook_x64 = value;
        } else if (wcscmp(argv[index], L"--hook-dll-x86") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr) {
                return fail(L"argument");
            }
            g_hook_x86 = value;
        } else if (wcscmp(argv[index], L"--delete-mode") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr) {
                return fail(L"argument");
            }
            if (wcscmp(value, L"trash") == 0) {
                g_delete_mode = SANDBOX_DELETE_TRASH;
            } else if (wcscmp(value, L"permanent") == 0) {
                g_delete_mode = SANDBOX_DELETE_PERMANENT;
            } else {
                return fail(L"delete_mode");
            }
        } else if (wcscmp(argv[index], L"--tool-call-id") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr || !copy_tool_argument(value, g_tool_call_id, sizeof(g_tool_call_id))) {
                return fail(L"tool_cause");
            }
            g_saw_tool_id = 1;
        } else if (wcscmp(argv[index], L"--tool-name") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr || !copy_tool_argument(value, g_tool_name, sizeof(g_tool_name))) {
                return fail(L"tool_cause");
            }
            g_saw_tool_name = 1;
        } else if (wcscmp(argv[index], L"--decision-timeout-ms") == 0) {
            const wchar_t* value = take_arg(argc, argv, &index);
            if (value == nullptr) {
                return fail(L"argument");
            }
            g_timeout_ms = (uint32_t)wcstoul(value, nullptr, 10);
        } else {
            return fail(L"argument");
        }
    }
    if (g_saw_tool_id != g_saw_tool_name) {
        LocalFree(argv);
        return fail(L"tool_cause");
    }
    if (separator < 0 || separator + 1 >= argc || g_decide_name.empty() || g_hook_x64.empty() || g_hook_x86.empty() ||
        g_timeout_ms == 0) {
        LocalFree(argv);
        return fail(L"argument");
    }
    for (index = separator + 1; index < argc; ++index) {
        if (!command.empty()) {
            command.push_back(L' ');
        }
        command += quote_arg(argv[index]);
    }
    LocalFree(argv);
    if (!init_security()) {
        return fail(L"security");
    }
    g_stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    InitializeCriticalSection(&g_threads_lock);
    if (!WaitNamedPipeW(g_decide_name.c_str(), 5000)) {
        return fail(L"decide_pipe");
    }
    decide = CreateFileW(g_decide_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (decide == INVALID_HANDLE_VALUE) {
        return fail(L"decide_pipe");
    }
    SetHandleInformation(decide, HANDLE_FLAG_INHERIT, 0);
    buffer.assign(command.begin(), command.end());
    buffer.push_back(L'\0');
    startup.cb = sizeof(startup);
    if (!CreateProcessW(nullptr, buffer.data(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &startup, &information)) {
        CloseHandle(decide);
        return fail(L"create_process");
    }
    if (!attach_process(information.hProcess, information.dwProcessId, decide, g_tool_call_id, g_tool_name)) {
        TerminateProcess(information.hProcess, 1);
        CloseHandle(information.hThread);
        CloseHandle(information.hProcess);
        join_brokers();
        return fail(L"inject");
    }
    ResumeThread(information.hThread);
    WaitForSingleObject(information.hProcess, INFINITE);
    GetExitCodeProcess(information.hProcess, &exit_code);
    CloseHandle(information.hThread);
    CloseHandle(information.hProcess);
    join_brokers();
    if (g_sd != nullptr) {
        LocalFree(g_sd);
    }
    DeleteCriticalSection(&g_threads_lock);
    CloseHandle(g_stop);
    return (int)exit_code;
}
