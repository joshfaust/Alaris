#pragma once
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <stdio.h>
#include <bcrypt.h>
using namespace std;
#define ENCRYPT_ALGORITHM CALG_AES_256
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

class crypto
{

public:

	std::pair<DWORD, PBYTE> decrypt(BYTE pIV[], int iv_size, BYTE pKEY[], int key_size, DWORD cipherTextLen, PBYTE cipherTextPointer);
	std::pair<DWORD, PBYTE> encrypt(unsigned char pShellcode[], int shell_size, BYTE pIV[], int iv_size, BYTE pKEY[], int key_size);

};

