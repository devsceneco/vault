from typer import Exit
from pathlib import Path
from os import urandom
from Crypto.PublicKey import RSA, ECC
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# save aes key to file
def save_aes_key(path: Path, alias: str, password: str) -> None:
    try:
        key = urandom(32)

        with open(path.joinpath(f"KEY_{alias}.key"), "xb") as f:
            f.write(key)
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise Exit(1)

# save ECC keys to file with password if any
def save_ecc_keypair(out_path: Path, alias: str, password: str) -> None:
    try:
        private_key = ECC.generate(curve='P-256')
        if password == "":
            data = private_key.export_key(format='PEM')
        else:
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
        # generate private key
        private_key = RSA.generate(2048)
        if password == "":
            data = private_key.export_key(format='PEM')
        else:
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
