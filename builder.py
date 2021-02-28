import re
import os
import base64
import binascii
import argparse
import mimetypes
from Crypto.Cipher import AES
import pbkdf2


def aes_pad(data: bytes) -> bytes:
    """
    Pad the data to make sure we are %16 == 0
    """
    bs = AES.block_size
    while len(data) % bs != 0:
        data += b"\x90"

    return data


def get_crypto_data(password: str) -> tuple:
    """
    Uses pbkdf2 to build a KEY and IV pair.
    """
    salt = "\x00" * 16
    key = pbkdf2.PBKDF2(password, salt).read(32)
    iv = pbkdf2.PBKDF2(password, salt).read(48)[32:]
    return (key, iv, salt)


def build_c_vars(data: bytes) -> str:
    """
    Takes in any string, separates for each 2 chars, assumes they're
    bytes and puts it into proper C syntax for byte array.
    """
    data = binascii.hexlify(data).decode("utf-8")
    split_data = re.findall("..", data)
    c_data = ""
    for i, b in enumerate(split_data):
        if i == (len(split_data) - 1):
            c_data += f"0x{b}"
        else:
            c_data += f"0x{b},"
    return c_data


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> str:
    """
    Takes in data to encrypt, a key, and an iv. Encrypts the
    data with AES256, encodes the encrypted bytes with base64.
    """
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode("utf-8")


def parse_shellcode(shellcode_file: str) -> bytes:
    """
    Takes in a filepath as a parameter, verifies it's a binary file (raw)
    and parses the shellcode from within
    """
    if not os.path.exists(shellcode_file):
        print(f"[!] ERROR: {shellcode_file} does not exist")
        exit(1)
    # Check if the file is a binary (RAW) file
    file_type = mimetypes.guess_type(shellcode_file)[0]
    if "octet-stream" not in file_type:
        print(f"[!] Error: {shellcode_file} does not look to be a RAW Binary file")
        exit(1)

    with open(shellcode_file, "rb") as f:
        data = f.read()
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--shellcode_file",
        metavar="",
        dest="sc_file",
        required=True,
        help="Path to RAW shellcode file",
    )
    parser.add_argument(
        "-p",
        "--password",
        metavar="",
        dest="enc_pass",
        required=True,
        help="Encryption Passphrase",
    )
    args = parser.parse_args()

    key, iv, salt = get_crypto_data("test")
    c_key = "uint8_t key[32] = {%s};" % build_c_vars(key)
    c_iv = "uint8_t iv[16] = {%s};" % build_c_vars(iv)

    raw_shellcode = parse_shellcode(args.sc_file)
    raw_padded_shellcode = aes_pad(raw_shellcode)
    encrypted_encoded_shellcode = aes_encrypt(raw_padded_shellcode, key, iv)

    print(f'shellcode = "{encrypted_encoded_shellcode}";')
