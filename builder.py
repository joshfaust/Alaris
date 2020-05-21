import os
import argparse
import binascii
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util import Padding


KEY = bytes(bytearray.fromhex("707620f23f4c4c1045fb5093d8d1c9fb6c304588ddb2f4af9c1c2213266724bd"))
IV = bytes(bytearray.fromhex("89547f64c0ce3a44f0eeafa1a8dc6b65"))

def parse_shellcode(shellcodeFile):
        parsedShellcode = []
        try:
            print(f"[+] Parsing RAW shellcode")
            with open(shellcodeFile, "rb") as tmp_file:
                data = tmp_file.read()
            tmp_file.close()
            parsedShellcode = bytearray(data)
            return parsedShellcode

        except Exception as e:
            print(f"ERROR: {e}")
            exit(1)
 

def pad(shellcode):
    s = Padding.pad(shellcode, 16, style="pkcs7")
    return s

def encrypt(shellcode):
    padded_shellcode = pad(shellcode)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    return b64encode(cipher.encrypt(bytes(padded_shellcode)))

def decrypt(shellcode):
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    data = b64decode(shellcode)
    print(cipher.decrypt(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", metavar='', dest="shell", required=True, help="Path to raw (bin) shellcode")
    args = parser.parse_args()

    if (not os.path.isfile(args.shell)):
        print(f"[!] ERROR: {args.shell} does not exist.")
        exit(1)

    shellcode = parse_shellcode(args.shell)
    enc_shellcode = encrypt(shellcode)
    print(enc_shellcode.decode("utf-8"))


