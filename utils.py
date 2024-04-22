from enum import Enum
import os, platform, shutil
from pathlib import Path
from rich import print
from typer import Exit
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

# enum of supported key algorithms
class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",


# locate a vault directory
# create one if one doesn't exist
def get_vault_path(dir: str):
    try:
        # get the right path based on the host OS
        hostOS = platform.system()
        vault_path = ""
        if hostOS == "Darwin":
            vault_path = Path('/Users/').joinpath(os.getlogin(), '.vault', dir)
        elif hostOS == "Linux":
            vault_path = Path('/usr/').joinpath('share', 'vault', dir)
        elif hostOS == "Windows":
            vault_path = Path('C:/').joinpath('Program Files', 'Vault', dir)
        # check if the path was reachable
        if(not vault_path):
            raise Exception("Insufficient file system privileges or unsupported OS. You can specify a custom path using the --path option.")
        # create directories at the path if none exist
        vault_path.mkdir(parents=True, exist_ok=True)
        return vault_path
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not find or create a vault.\n{e}")
        raise Exit("Exited with status code 1.")


# encrypt a file using aes and save to output path
def encrypt_file_aes(file: Path, key: bytes, output: Path):
    try:
        # prepare key and cipher
        cipher = AES.new(key, AES.MODE_CBC)
        # read plaintext file
        with file.open("rb") as f:
            data = f.read()
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            ct = b64encode(ct_bytes).decode('utf-8')
            iv = b64encode(cipher.iv).decode('utf-8')
            # get file name from path
            out_name = file.stem + file.suffix
            # write iv + ciphertext to output file
            with open (Path(output).joinpath(f"{out_name}.enc"), 'w') as o:
                o.write(iv + ct)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt file.\n{e}")
        raise Exit("Exited with status code 1.")


# decrypt a file using aes and save to output path
def decrypt_file_aes(file: Path, key: bytes, output: Path):
    try:
        # prepare key and cipher
        cipher = AES.new(key, AES.MODE_CBC)
        # read ciphertext file
        with open(file, 'r') as f:
            data = f.read()
            # extract iv and ciphertext
            iv = b64decode(data[:24])
            ciphertext = b64decode(data[24:])
            # decrypt ciphertext
            pt_bytes = cipher.decrypt(ciphertext)
            # remove padding
            pt = unpad(pt_bytes, AES.block_size)
            # write plaintext to output file
            with open(output, 'wb') as o:
                o.write(pt)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not decrypt file.\n{e}")
        raise Exit("Exited with status code 1.")


# encrypt a key using RSA and save to output path
def encrypt_message_rsa(message: bytes, key_path: Path, output: Path):
    try:
        # encrypt AES key with RSA public key
        public_key = RSA.import_key(open(key_path).read())
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        # save to key file in project path
        with open(Path(output).joinpath("aes.key"), "wb") as f:
            f.write(ciphertext)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt AES key.\n{e}")
        raise Exit("Exited with status code 1.")

# decrypt a key using RSA and save to output path
def decrypt_message_rsa(ciphertext: bytes, key_path: Path, output: Path):
    try:
        # decrypt AES key with RSA private key
        private_key = RSA.import_key(open(key_path).read())
        cipher = PKCS1_OAEP.new(private_key)
        pt_bytes = cipher.decrypt(ciphertext)
        with open(output, 'wb') as f:
            f.write(pt_bytes)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not decrypt RSA message.\n{e}")
        raise Exit("Exited with status code 1.")


# compress a folder and save to output path
def compress_folder(alias: str, folder_path: Path):
    try:
        # create ZIP archive
        archived = shutil.make_archive(Path(os.getcwd()).joinpath(alias), "zip", folder_path)
        if(Path(archived).exists()): return
        else: raise Exception("Error saving ZIP archive!")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not compress folder.\n{e}")
        raise Exit("Exited with status code 1.")

# generate a key based on algo, RSA default
def generate_private_key(algo: str):
    try:
        key = None
        match(algo):
            case Algo.RSA: key = RSA.generate(2048)
            case Algo.ECC: key = ECC.generate(curve='P-256')
            # default case - RSA
            case _: key = RSA.generate(2048)
        if (key is None): raise Exception("Error generating private key!")
        else: return key
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not generate private key.\n{e}")
        raise Exit("Exited with status code 1.")
