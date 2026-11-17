#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <shellapi.h>
#include <winternl.h>

#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif

static int denied_or_other() {
    return GetLastError() == ERROR_ACCESS_DENIED ? 5 : 3;
}

static int open_file(LPCWSTR path, DWORD access, DWORD disposition) {
    HANDLE file = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return denied_or_other();
    }
    CloseHandle(file);
    return 0;
}

static int connect_ip(const wchar_t* ip, int port) {
    char text[128];
    WSADATA wsa;
    SOCKET sock;
    int family;
    sockaddr_storage address = {};
    int length;
    int result;
    u_long mode = 1;
    if (WideCharToMultiByte(CP_UTF8, 0, ip, -1, text, sizeof(text), nullptr, nullptr) <= 0) {
        return 6;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 6;
    }
    family = strchr(text, ':') != nullptr ? AF_INET6 : AF_INET;
    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        int failure = WSAGetLastError();
        WSACleanup();
        return failure == WSAEACCES ? 5 : 6;
    }
    if (family == AF_INET6) {
        sockaddr_in6* ipv6 = (sockaddr_in6*)&address;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
        length = sizeof(sockaddr_in6);
        if (inet_pton(AF_INET6, text, &ipv6->sin6_addr) != 1) {
            closesocket(sock);
            WSACleanup();
            return 6;
        }
    } else {
        sockaddr_in* ipv4 = (sockaddr_in*)&address;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
        length = sizeof(sockaddr_in);
        if (inet_pton(AF_INET, text, &ipv4->sin_addr) != 1) {
            closesocket(sock);
            WSACleanup();
            return 6;
        }
    }
    ioctlsocket(sock, FIONBIO, &mode);
    result = connect(sock, (sockaddr*)&address, length);
    if (result != 0 && WSAGetLastError() == WSAEWOULDBLOCK) {
        fd_set waiting;
        timeval budget = {};
        int ready;
        FD_ZERO(&waiting);
        FD_SET(sock, &waiting);
        budget.tv_sec = 1;
        ready = select(0, nullptr, &waiting, nullptr, &budget);
        if (ready > 0) {
            int failure = 0;
            int failure_size = sizeof(failure);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&failure, &failure_size);
            result = failure == 0 ? 0 : SOCKET_ERROR;
            WSASetLastError(failure);
        } else {
            result = SOCKET_ERROR;
            WSASetLastError(WSAETIMEDOUT);
        }
    }
    if (result == 0) {
        closesocket(sock);
        WSACleanup();
        return 4;
    }
    result = WSAGetLastError() == WSAEACCES ? 5 : 6;
    closesocket(sock);
    WSACleanup();
    return result;
}

static int connect_host(const wchar_t* host, int port) {
    HINTERNET session = InternetOpenW(L"process-guard-probe", INTERNET_OPEN_TYPE_DIRECT, nullptr, nullptr, 0);
    HINTERNET connection;
    if (session == nullptr) {
        return denied_or_other();
    }
    connection = InternetConnectW(session, host, (INTERNET_PORT)port, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == nullptr) {
        int code = denied_or_other();
        InternetCloseHandle(session);
        return code;
    }
    InternetCloseHandle(connection);
    InternetCloseHandle(session);
    return 0;
}

static int execute(const wchar_t* application, wchar_t* command) {
    STARTUPINFOW startup = {};
    PROCESS_INFORMATION information = {};
    BOOL ok;
    startup.cb = sizeof(startup);
    ok = CreateProcessW(application, command, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
    if (!ok) {
        return denied_or_other();
    }
    WaitForSingleObject(information.hProcess, 8000);
    TerminateProcess(information.hProcess, 0);
    CloseHandle(information.hThread);
    CloseHandle(information.hProcess);
    return 0;
}

static int run(int argc, wchar_t** argv) {
    wchar_t command[32768];
    if (argc < 3) {
        return 2;
    }
    if (_wcsicmp(argv[1], L"check-file-policy") == 0 && argc == 4) {
        FILETIME created, exited, kernel, user;
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) return 2;
        ULARGE_INTEGER stamp;
        stamp.LowPart = created.dwLowDateTime;
        stamp.HighPart = created.dwHighDateTime;
        printf("%u %lu %llu\n", (unsigned)(8 * sizeof(void*)), GetCurrentProcessId(), stamp.QuadPart);
        if (open_file(argv[2], GENERIC_WRITE, CREATE_NEW) != 0) {
            return 3;
        }
        return open_file(argv[3], GENERIC_WRITE, CREATE_NEW) == ERROR_ACCESS_DENIED ? 0 : 4;
    }
    if (_wcsicmp(argv[1], L"attributes") == 0) {
        return GetFileAttributesW(argv[2]) != INVALID_FILE_ATTRIBUTES ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"enumerate") == 0) {
        WIN32_FIND_DATAW data;
        HANDLE search=FindFirstFileW(argv[2],&data);
        if(search==INVALID_HANDLE_VALUE)return denied_or_other();
        FindClose(search);
        return 0;
    }
    if (_wcsicmp(argv[1], L"set-attributes") == 0) {
        return SetFileAttributesW(argv[2],FILE_ATTRIBUTE_HIDDEN) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"shell") == 0 && argc >= 4) {
        SHELLEXECUTEINFOW info={};
        info.cbSize=sizeof(info); info.fMask=SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb=argc>=5?argv[4]:L"open";
        info.lpFile=argv[2]; info.lpParameters=argv[3];
        if(!ShellExecuteExW(&info))return denied_or_other();
        WaitForSingleObject(info.hProcess,10000);
        DWORD exit_code=3;
        GetExitCodeProcess(info.hProcess,&exit_code);
        CloseHandle(info.hProcess);
        return (int)exit_code;
    }
    if ((_wcsicmp(argv[1], L"token-exec") == 0 || _wcsicmp(argv[1], L"as-user") == 0) && argc >= 4) {
        HANDLE token=NULL, primary=NULL;
        if(!OpenProcessToken(GetCurrentProcess(),TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY,&token)) {
            fprintf(stderr,"stage=OpenProcessToken error=%lu\n",GetLastError());
            return 3;
        }
        BOOL copied=DuplicateTokenEx(token,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenPrimary,&primary);
        DWORD token_error=GetLastError();
        CloseHandle(token);
        if(!copied) {
            fprintf(stderr,"stage=DuplicateTokenEx error=%lu\n",token_error);
            return 3;
        }
        STARTUPINFOW startup={}; startup.cb=sizeof(startup);
        PROCESS_INFORMATION child={};
        BOOL ok=_wcsicmp(argv[1],L"as-user")==0
            ? CreateProcessAsUserW(primary,argv[2],argv[3],NULL,NULL,FALSE,CREATE_NO_WINDOW,NULL,NULL,&startup,&child)
            : CreateProcessWithTokenW(primary,0,argv[2],argv[3],CREATE_NO_WINDOW,NULL,NULL,&startup,&child);
        DWORD error=GetLastError(); CloseHandle(primary);
        if(!ok) {
            fprintf(stderr,"stage=%s error=%lu\n",
                _wcsicmp(argv[1],L"as-user")==0 ? "CreateProcessAsUserW" : "CreateProcessWithTokenW",error);
            return error==ERROR_PRIVILEGE_NOT_HELD ? 77 : error==ERROR_ACCESS_DENIED ? 5 : 3;
        }
        WaitForSingleObject(child.hProcess,10000);
        DWORD code=3; GetExitCodeProcess(child.hProcess,&code);
        CloseHandle(child.hProcess); CloseHandle(child.hThread);
        return (int)code;
    }
    if (_wcsicmp(argv[1], L"read") == 0) {
        return open_file(argv[2], GENERIC_READ, OPEN_EXISTING);
    }
    if (_wcsicmp(argv[1], L"write") == 0) {
        return open_file(argv[2], GENERIC_WRITE, CREATE_NEW);
    }
    if (_wcsicmp(argv[1], L"mkdir") == 0) {
        return CreateDirectoryW(argv[2], nullptr) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"delete") == 0) {
        return DeleteFileW(argv[2]) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"close-delete") == 0 || _wcsicmp(argv[1], L"close-overwrite") == 0 ||
        _wcsicmp(argv[1], L"close-create") == 0 || _wcsicmp(argv[1], L"disposition") == 0 ||
        _wcsicmp(argv[1], L"close-protected") == 0) {
        bool on_close = _wcsicmp(argv[1], L"disposition") != 0;
        DWORD creation = _wcsicmp(argv[1], L"close-overwrite") == 0 ? CREATE_ALWAYS :
                         _wcsicmp(argv[1], L"close-create") == 0 ? CREATE_NEW : OPEN_EXISTING;
        if (creation != OPEN_EXISTING && argc > 3 && !DeleteFileW(argv[3])) return denied_or_other();
        HANDLE file = CreateFileW(argv[2], DELETE | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, creation,
            on_close ? FILE_FLAG_DELETE_ON_CLOSE : FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return denied_or_other();
        if (!on_close) {
            FILE_DISPOSITION_INFO disposition = {TRUE};
            if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition))) {
                DWORD error = GetLastError(); CloseHandle(file); SetLastError(error); return denied_or_other();
            }
        }
        if (_wcsicmp(argv[1], L"close-protected") == 0) {
            if (!SetHandleInformation(file,HANDLE_FLAG_PROTECT_FROM_CLOSE,HANDLE_FLAG_PROTECT_FROM_CLOSE)) return 3;
            if (CloseHandle(file)) return 3;
            if (!SetHandleInformation(file,HANDLE_FLAG_PROTECT_FROM_CLOSE,0)) return 3;
        }
        return CloseHandle(file) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"rename-replace") == 0)
        return MoveFileExW(argv[2], argv[3], MOVEFILE_REPLACE_EXISTING) ? 0 : denied_or_other();
    if (_wcsicmp(argv[1], L"rename-invalid") == 0) {
        HANDLE file = CreateFileW(argv[2], DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return denied_or_other();
        BYTE bytes[4096] = {};
        FILE_RENAME_INFO* info = reinterpret_cast<FILE_RENAME_INFO*>(bytes);
        info->Flags = 0x80000001; // Invalid kernel flag after the recoverable target has been handled.
        info->FileNameLength = static_cast<DWORD>(wcslen(argv[3]) * sizeof(wchar_t));
        memcpy(info->FileName, argv[3], info->FileNameLength);
        typedef NTSTATUS (NTAPI *SetInfo)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
        SetInfo set = reinterpret_cast<SetInfo>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
        IO_STATUS_BLOCK io = {};
        NTSTATUS status = set(file, &io, info, FIELD_OFFSET(FILE_RENAME_INFO,FileName)+info->FileNameLength,
                              static_cast<FILE_INFORMATION_CLASS>(65));
        CloseHandle(file);
        return status >= 0 ? 0 : 5;
    }
    if (_wcsicmp(argv[1], L"copy") == 0 && argc >= 4) {
        return CopyFileW(argv[2], argv[3], FALSE) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"move") == 0 && argc >= 4) {
        return MoveFileW(argv[2], argv[3]) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"replace") == 0 && argc >= 4) {
        const wchar_t* backup = argc >= 5 ? argv[4] : nullptr;
        return ReplaceFileW(argv[3], argv[2], backup, 0, nullptr, nullptr) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"symlink") == 0 && argc >= 4) {
        return CreateSymbolicLinkW(argv[3], argv[2], SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"hardlink") == 0 && argc >= 4) {
        return CreateHardLinkW(argv[3], argv[2], nullptr) ? 0 : denied_or_other();
    }
    if (_wcsicmp(argv[1], L"open") == 0 && argc >= 4) {
        DWORD access = _wcsicmp(argv[2], L"write") == 0 ? GENERIC_WRITE : GENERIC_READ;
        return open_file(argv[3], access, OPEN_EXISTING);
    }
    if (_wcsicmp(argv[1], L"connect") == 0) {
        int port;
        if (argc == 3 && _wcsicmp(argv[2], L"metadata") == 0) {
            return connect_ip(L"169.254.169.254", 80);
        }
        if (argc < 5) {
            return 2;
        }
        port = _wtoi(argv[4]);
        if (_wcsicmp(argv[2], L"-") != 0) {
            return connect_host(argv[2], port);
        }
        return connect_ip(argv[3], port);
    }
    if (_wcsicmp(argv[1], L"exec") == 0 && argc >= 4) {
        const wchar_t* application = _wcsicmp(argv[2], L"-") == 0 ? nullptr : argv[2];
        if (wcscpy_s(command, 32768, argv[3]) != 0) {
            return 2;
        }
        return execute(application, command);
    }
    return 2;
}

int main() {
    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int code;
    if (argv == nullptr) {
        return 2;
    }
    code = run(argc, argv);
    LocalFree(argv);
    return code;
}
