#include "crypto.h"
#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <stdio.h>
#include <bcrypt.h>

#define ENCRYPT_ALGORITHM CALG_AES_256
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
using namespace std;


std::pair<DWORD, PBYTE> crypto::encrypt(unsigned char pShellcode[],int shell_size, BYTE pIV[], int iv_size, BYTE pKEY[], int key_size)
{
    
    BYTE IV[16] = {};
    BYTE KEY[32] = {};
    unsigned char shellcode[500] = {};
    
    int i;

    for (i = 0; i <= iv_size; i++)
    {
        IV[i] = pIV[i];
    }
    for (i = 0; i <= key_size; i++)
    {
        KEY[i] = pKEY[i];
    }
    for (i = 0; i <= shell_size; i++)
    {
        shellcode[i] = pShellcode[i];
    }

    

    printf("KEY: %x\n", KEY);
    printf("IV: %x\n", IV);
    printf("SHELLCODE: %x\n", shellcode);

    BCRYPT_ALG_HANDLE       hAesAlg = NULL;
    BCRYPT_KEY_HANDLE       hKey = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbCipherText = 0,
                            cbPlainText = 0,
                            cbData = 0,
                            cbKeyObject = 0,
                            cbBlockLen = 0,
                            cbBlob = 0;
    PBYTE                   pbCipherText = NULL,
                            pbPlainText = NULL,
                            pbKeyObject = NULL,
                            pbIV = NULL,
                            pbBlob = NULL;


    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;

    }

    //calculate the size of the buffer to hold the KeyObject
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the key object on the heap
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the block length for the IV
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // See if the cbBlockLen is not longer than the IV length
    if (cbBlockLen > sizeof(IV))
    {
        wprintf(L"**** block length is longer than the provided IV length\n");
        printf("Block Length: %d\n", cbBlockLen);
        printf("IV Length: %d", sizeof(IV));
        goto Cleanup;
    }

    //allocate a buffer for the IV. it is consumed during the 
    //encrypt/decrypt process
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (NULL == pbIV)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIV, IV, cbBlockLen);

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }



    // generate the key from supplied input key bytes
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)KEY,
        sizeof(KEY),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }


    //save another copy of the key for later
    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        0,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }


    // allocate the buffer to hold the blob
    pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
    if (NULL == pbBlob)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        pbBlob,
        cbBlob,
        &cbBlob,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptExportKey\n", status);
        goto Cleanup;
    }

    cbPlainText = sizeof(shellcode);
    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbPlainText, shellcode, sizeof(shellcode));

    //
    //get the output buffer size
    //
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // use the key to encrypt the plaintext buffer.
    //for block sized messages, block padding will add an extra block
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        pbCipherText,
        cbCipherText,
        &cbData,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        goto Cleanup;
    }


    //destroy the key and reimport from saved blob
    if (!NT_SUCCESS(status = BCryptDestroyKey(hKey)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDestroyKey\n", status);
        goto Cleanup;
    }
    hKey = 0;


    return std::make_pair(cbCipherText, pbCipherText);

    Cleanup:

        if (hAesAlg)
        {
            BCryptCloseAlgorithmProvider(hAesAlg, 0);
        }

        if (hKey)
        {
            BCryptDestroyKey(hKey);
        }

        if (pbCipherText)
        {
            HeapFree(GetProcessHeap(), 0, pbCipherText);
        }

        if (pbPlainText)
        {
            HeapFree(GetProcessHeap(), 0, pbPlainText);
        }

        if (pbKeyObject)
        {
            HeapFree(GetProcessHeap(), 0, pbKeyObject);
        }

        if (pbIV)
        {
            HeapFree(GetProcessHeap(), 0, pbIV);
        }
}

std::pair<DWORD, PBYTE> crypto::decrypt(BYTE pIV[], int iv_size, BYTE pKEY[], int key_size, DWORD cipherTextLen, PBYTE cipherTextPointer)
{

    BYTE IV[16] = {};
    BYTE KEY[32] = {};
    unsigned char shellcode[500] = {};

    int i;

    for (i = 0; i <= iv_size; i++)
    {
        IV[i] = pIV[i];
    }
    for (i = 0; i <= key_size; i++)
    {
        KEY[i] = pKEY[i];
    }



    BCRYPT_ALG_HANDLE       hAesAlg = NULL;
    BCRYPT_KEY_HANDLE       hKey = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbCipherText = cipherTextLen,
                            cbPlainText = 0,
                            cbData = 0,
                            cbKeyObject = 0,
                            cbBlockLen = 0,
                            cbBlob = 0;
    PBYTE                   pbCipherText = cipherTextPointer,
                            pbPlainText = NULL,
                            pbKeyObject = NULL,
                            pbIV = NULL,
                            pbBlob = NULL;


    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;

    }

    //calculate the size of the buffer to hold the KeyObject
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    //allocate the key object on the heap
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    //calculate the block length for the IV
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_BLOCK_LENGTH,
        (PBYTE)&cbBlockLen,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // See if the cbBlockLen is not longer than the IV length
    if (cbBlockLen > sizeof(IV))
    {
        wprintf(L"**** block length is longer than the provided IV length\n");
        goto Cleanup;
    }

    //allocate a buffer for the IV. it is consumed during the 
    //encrypt/decrypt process
    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (NULL == pbIV)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    memcpy(pbIV, IV, cbBlockLen);

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        goto Cleanup;
    }



    // generate the key from supplied input key bytes
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)KEY,
        sizeof(KEY),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        goto Cleanup;
    }


    //
    //get the output buffer size
    //
    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        pbPlainText,
        cbPlainText,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        goto Cleanup;
    }


    return std::make_pair(cbPlainText, pbPlainText);


Cleanup:

    if (hAesAlg)
    {
        BCryptCloseAlgorithmProvider(hAesAlg, 0);
    }

    if (hKey)
    {
        BCryptDestroyKey(hKey);
    }

    if (pbCipherText)
    {
        HeapFree(GetProcessHeap(), 0, pbCipherText);
    }

    if (pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, pbPlainText);
    }

    if (pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, pbKeyObject);
    }

    if (pbIV)
    {
        HeapFree(GetProcessHeap(), 0, pbIV);
    }
}



