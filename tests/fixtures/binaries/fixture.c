// Freestanding fixture for Hexlora's static analysis tests.
//
// The binaries built from this file are inspected, never executed. They only
// need to link and to contain a known set of functions, calls, imports,
// strings, and debug information. Rebuild them with ./build.sh.

static const char message[] = "hexlora fixture\n";

#if defined(HEXLORA_DRIVER)

typedef long NTSTATUS;
typedef struct { unsigned short Length, MaximumLength; const unsigned short *Buffer; } UNICODE_STRING;
__declspec(dllimport) NTSTATUS IoCreateDevice(void *driver, unsigned long extension, UNICODE_STRING *name,
                                              unsigned long type, unsigned long characteristics,
                                              unsigned char exclusive, void **device);
__declspec(dllimport) NTSTATUS IoCreateSymbolicLink(UNICODE_STRING *link, UNICODE_STRING *device);
__declspec(dllimport) void *MmMapIoSpace(long long address, unsigned long long size, int cache);
__declspec(dllimport) NTSTATUS ZwOpenProcess(void **handle, unsigned long access, void *attributes, void *client);

static const unsigned short device_name[] = L"\\Device\\HexloraFixture";
static const unsigned short link_name[] = L"\\DosDevices\\HexloraFixture";

__declspec(noinline) void *map_region(long long address) {
    return MmMapIoSpace(address, 0x1000, 0);
}

NTSTATUS DriverEntry(void *driver, void *registry) {
    UNICODE_STRING device = {sizeof(device_name) - 2, sizeof(device_name), device_name};
    UNICODE_STRING link = {sizeof(link_name) - 2, sizeof(link_name), link_name};
    void *object = 0;
    void *process = 0;
    (void)registry;
    (void)message;
    IoCreateDevice(driver, 0, &device, 0x22, 0, 0, &object);
    ZwOpenProcess(&process, 0x1fffff, 0, 0);
    map_region(0x1000);
    return IoCreateSymbolicLink(&link, &device);
}

#elif defined(_WIN32)

typedef void *HANDLE;
typedef unsigned long DWORD;
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD id);
__declspec(dllimport) int __stdcall WriteFile(HANDLE file, const void *data, DWORD size, DWORD *written,
                                              void *overlapped);
__declspec(dllimport) void __stdcall ExitProcess(unsigned code);
__declspec(dllimport) HANDLE __stdcall OpenProcess(DWORD access, int inherit, DWORD process);
__declspec(dllimport) void *__stdcall VirtualAllocEx(HANDLE process, void *address, unsigned long long size,
                                                     DWORD type, DWORD protect);
__declspec(dllimport) int __stdcall WriteProcessMemory(HANDLE process, void *address, const void *data,
                                                       unsigned long long size, unsigned long long *written);
__declspec(dllimport) HANDLE __stdcall CreateRemoteThread(HANDLE process, void *attributes,
                                                          unsigned long long stack, void *start, void *parameter,
                                                          DWORD flags, DWORD *thread);

__declspec(noinline) int add_numbers(int left, int right) {
    return left + right;
}

__declspec(noinline) void write_message(void) {
    DWORD written = 0;
    WriteFile(GetStdHandle((DWORD)-11), message, sizeof(message) - 1, &written, 0);
}

__declspec(noinline) void inject(DWORD process) {
    HANDLE handle = OpenProcess(0x1fffff, 0, process);
    void *remote = VirtualAllocEx(handle, 0, 0x1000, 0x3000, 0x40);
    WriteProcessMemory(handle, remote, message, sizeof(message), 0);
    CreateRemoteThread(handle, 0, 0, remote, 0, 0, 0);
}

__declspec(dllexport) int exported_entry(int value) {
    return add_numbers(value, 2);
}

void fixture_start(void) {
    write_message();
    inject(4);
    ExitProcess((unsigned)exported_entry(40));
}

#elif defined(__APPLE__)

extern int puts(const char *text);
extern void *malloc(unsigned long size);

__attribute__((noinline)) int add_numbers(int left, int right) {
    return left + right;
}

__attribute__((noinline)) void write_message(void) {
    puts(message);
    malloc(16);
}

__attribute__((visibility("default"))) int exported_entry(int value) {
    write_message();
    return add_numbers(value, 2);
}

#else

__attribute__((noinline)) int add_numbers(int left, int right) {
    return left + right;
}

__attribute__((noinline)) const char *message_text(void) {
    return message;
}

__attribute__((visibility("default"))) int exported_entry(int value) {
    return add_numbers(value, 2);
}

void _start(void) {
    message_text();
    exported_entry(40);
    for (;;) {
    }
}

#endif
