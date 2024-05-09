from enum import Enum
from posixpath import ismount
import os, platform, shutil, json, time
from pathlib import Path
from rich import print
from typer import Exit
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA, ECC
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import BLAKE2b
from base64 import b64encode, b64decode

# enum of supported key algorithms
class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",
    AES = "AES"


# locate a vault directory
# create one if one doesn't exist
def get_vault_path(dir: str | Path) -> Path:
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
        raise Exit(1)


# encrypt a file using aes and save to output path
def encrypt_file_aes(file: Path, key: bytes, out_path: Path, alias: str) -> None:
    try:
        # prepare key and cipher
        cipher = AES.new(key, AES.MODE_CBC)
        # read plaintext file
        data = file.read_bytes()
        # encrypt file to get ciphertext and iv
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        iv = bytes(cipher.iv)
        # write iv + ciphertext to output file
        with open (Path(out_path).joinpath(f"ENC_{alias}.enc"), 'wb') as f:
            f.write(iv)
            f.write(ciphertext)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] AES encryption error.\n{e}")
        raise Exit(1)

# decrypt a file using aes and save to output path
def decrypt_file_aes(file: Path, key: bytes, out_path: Path):
    try:
        # prepare ciphertext and iv from file
        data = file.read_bytes()
        iv = data[:16]
        ciphertext = data[16:]
        # prepare cipher
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # decrypt ciphertext
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        # write plaintext to output file
        with open(out_path, 'wb') as o:
            o.write(plaintext)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] AES decryption error.\n{e}")
        raise Exit(1)


# encrypt a key using RSA and save to output path
def encrypt_message_rsa(message: bytes, key: str, out_path: Path) -> None:
    try:
        # get key path
        key_path = Path(get_vault_path("keys")).joinpath(key).joinpath(f"PUBKEY_{key}.pub")

        # load public key
        public_key = RSA.import_key(open(key_path).read())
        # encrypt message
        cipher = PKCS1_OAEP.new(public_key)
        ciphertext = cipher.encrypt(message)
        # save to output to file
        with open(out_path, "wb") as f:
            f.write(ciphertext)

        # open metadata file and update last used timestamp
        metadata_path = Path(key_path).parent.joinpath(f"METADATA_{key}.json")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
            metadata["public_key_last_used"] = time.ctime()
        with open(metadata_path, "w") as f:
            f.write(json.dumps(metadata))


    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] RSA encryption error.\n{e}")
        raise Exit(1)

# decrypt a key using RSA and save to output path
def decrypt_message_rsa(ciphertext: bytes, key: str, password: str) -> bytes:
    try:
        # get key path
        key_path = Path(get_vault_path("keys")).joinpath(key).joinpath(f"PRIVKEY_{key}.pem")

        # load RSA private key
        private_key = RSA.import_key(open(key_path).read(), password)
        # decrypt message
        cipher = PKCS1_OAEP.new(private_key)
        plaintext = cipher.decrypt(ciphertext)

        # open metadata file and update last used timestamp
        metadata_path = Path(key_path).parent.joinpath(f"METADATA_{key}.json")
        with open(metadata_path, "r") as f:
            metadata = json.load(f)
            metadata["private_key_last_used"] = time.ctime()
        with open(metadata_path, "w") as f:
            f.write(json.dumps(metadata))

        return plaintext
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] RSA decryption error.\n{e}")
        raise Exit(1)


# compress a folder and save to output path
def compress_folder(folder_path: Path, out_path: Path) -> None:
    try:
        # create ZIP archive
        archived = shutil.make_archive(out_path, "zip", folder_path)
        if(Path(archived).exists()): return
        else: raise Exception("Error saving ZIP archive!")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not compress folder.\n{e}")
        raise Exit(1)

# decompress folder
def decompress_folder(archive_path: Path, out_path: Path) -> None:
    try:
        # extract ZIP archive
        shutil.unpack_archive(archive_path, out_path)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not extract archive.\n{e}")
        raise Exit(1)

# generate hash of hash
def generate_hash_of_hash(message: str) -> str:
    try:
        # generate hash of password
        hasherOne = BLAKE2b.new()
        hasherOne.update(message.encode())
        digest = hasherOne.digest()

        # generate hash of hash
        hasherTwo = BLAKE2b.new()
        hasherTwo.update(digest)
        return hasherTwo.hexdigest()

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not generate hash of hash.\n{e}")
        raise Exit(1)
