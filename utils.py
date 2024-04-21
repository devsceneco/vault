import os, platform, shutil
from pathlib import Path
from rich import print  # printing rich text
from typer import Exit
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad
from base64 import b64encode

# locate a managed keys directory or create one if it doesn't exist
def get_vault_path(dir: str):
    try:
        # get the right path based on the host OS
        # TODO - add support for other OS
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
            # write iv + ciphertext to output file
            out_name = f.name.split("/")[-1]
            with open (Path(output).joinpath(f"{out_name}.enc"), 'w') as o:
                o.write(iv + ct)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt file.\n{e}")
        raise Exit("Exited with status code 1.")

# encrypt a key using RSA and save to output path
def encrypt_message_rsa(message: bytes, key_path: Path, output: Path):
    try:
        # encrypt AES key with RSA key
        key = RSA.import_key(open(key_path).read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(message)
        ciphertext = b64encode(ciphertext).decode("utf-8")
        # save to key file in project path
        with open (Path(output).joinpath("aes.key"), "w") as f:
            f.write(ciphertext)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt AES key.\n{e}")
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
