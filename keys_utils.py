from functools import wraps
import json
from typer import Exit
from pathlib import Path
from os import urandom
from rich import print
from rich.console import Console
from rich.table import Table
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

RSA_KEY_SIZE = 3072

# save aes key to file
def save_aes_key(path: Path, alias: str, password: str) -> None:
    try:
        # generate encrypted AES key
        key_len = 32
        salt = get_random_bytes(16)
        key = PBKDF2(password, salt, dkLen=key_len, count=21000)
        # save key to file
        with open(path.joinpath(f"KEY_{alias}.key"), "xb") as f:
            f.write(key)

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise Exit(1)

# save ECC keys to file with password if any
def save_ecc_keypair(out_path: Path, alias: str, password: str) -> None:
    try:
        # generate encrypted private key
        private_key = ECC.generate(curve='P-256')
        data = private_key.export_key(
            format='PEM', passphrase=password,
            protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
            prot_params={"iteration_count": 21000}
        )
        # save private key to file
        with open (out_path.joinpath(f"PRIVKEY_{alias}.pem"), "xb") as f:
            f.write(data.encode())

        # generate public key
        public_key = private_key.public_key()
        data = public_key.export_key(format='PEM')
        # save public key to file
        with open(Path(out_path).joinpath(f"PUBKEY_{alias}.pub"), "xb") as f:
            f.write(data.encode())

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise Exit(1)

# save RSA keys to file with password if any
def save_rsa_keypair(out_path: Path, alias: str, password: str) -> None:
    try:
        # generate encrypted private key
        private_key = RSA.generate(RSA_KEY_SIZE)
        data = private_key.export_key(
            format='PEM', passphrase=password, pkcs=8,
            protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
            prot_params={"iteration_count": 21000}
        )
        # save private key to file
        with open (out_path.joinpath(f"PRIVKEY_{alias}.pem"), "xb") as f:
            f.write(data)

        # generate public key
        public_key = private_key.public_key()
        data = public_key.export_key(format='PEM')
        # save public key to file
        with open(Path(out_path).joinpath(f"PUBKEY_{alias}.pub"), "xb") as f:
            f.write(data)

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise Exit(1)

# print key metadata in tables
def print_key_metadata(metadata_path: Path) -> None:
    try:
        # read metadata file
        with open(metadata_path, "r") as f:
            data = f.read()
            data = json.loads(data)
        # print data in a pretty table
        console = Console()
        table = Table("Property", "Value", show_header=True, header_style="bold magenta")
        for key, value in data.items():
            value = str(value)
            if(len(value) > 30): value = value[:10] + "..." + value[-10:]
            table.add_row(key, value)
        console.print(table)

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not read metadata file.\n{e}")
        raise Exit(1)
