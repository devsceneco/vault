import typer, os, time, json
import utils
from shutil import copyfile
from pathlib import Path
from typing_extensions import Annotated, Any, List
from Crypto.PublicKey import RSA, ECC
from enum import Enum
from rich import print

# enum of supported algorithms
class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",

# typer sub app for 'vault keys' commands
app = typer.Typer()

@app.command()
def generate(
    alias: Annotated[str, typer.Argument(help="name the key, default is a random ID")] = None,
    algo: Annotated[Algo, typer.Option(help="currently supports RSA [default] and ECC", case_sensitive=False)] = Algo.RSA,
    passwd: Annotated[str, typer.Option(help="to encrypt the private key file, default is none")] = None,
    path: Annotated[str, typer.Option(help="CUSTOM PATH for keys, PREVENTS vault from managing keys")] = None,
):
    """
    generates key(pairs) to store in vault or custom path
    """
    try:
        # generate private key
        key = utils.generate_private_key(algo)

        # prepare private key output path
        if alias is None: alias = os.urandom(4).hex()
        if (path is None): out_path = Path(utils.get_vault_path("keys"))
        else: out_path = Path(path)
        if not out_path.exists(): raise Exception(f"Path not found: {out_path}")

        # make a new folder for the new keypair
        out_path = out_path.joinpath(alias)
        out_path.mkdir(parents=True, exist_ok=True)

        # save private key to file with password
        if(algo == Algo.RSA):
            save_private_key_rsa(key, passwd, Path(out_path).joinpath(f"PRIVKEY_{alias}.pem"))
        elif(algo == Algo.ECC):
            save_private_key_ecc(key, passwd, Path(out_path).joinpath(f"PRIVKEY_{alias}.pem"))

        # generate and store public key
        with open(Path(out_path).joinpath(f"PUBKEY_{alias}.pub"), "xb") as f:
            data = key.public_key().export_key(format="PEM")
            if (algo == Algo.RSA): f.write(data)
            elif (algo == Algo.ECC): f.write(data.encode())

        # create metadata file for the keypair in the same folder
        metadata = {
            "alias": alias,
            "algorithm": algo,
            "created_at": time.ctime(),
        }
        if algo == Algo.RSA or algo == Algo.ECC:
            metadata["private_key"] = f"PRIVKEY_{alias}.pem"
            metadata["private_key_last_used"] = ""
            metadata["public_key"] = f"PUBKEY_{alias}.pub"
            metadata["public_key_last_used"] = ""
        elif algo == Algo.AES:
            metadata["key"] = Path(out_path).joinpath(f"KEY_{alias}.key")
            metadata["last_used"] = ""

        with open (out_path.joinpath(f"METADATA_{alias}.json"), "w") as f:
            f.write(json.dumps(metadata))

        print(f":tada: [bold green]Success:[/bold green] Keypair [green]{alias}[/green] generated and stored in vault.")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not generate and store keypair.\n{e}")
        raise typer.Exit()

@app.command()
def list(
    path: Annotated[str, typer.Option(help="ONLY if you store your keys at a CUSTOM PATH")] = None,
):
    """
    lists the keys stored in your vault
    """
    try:
        # get vault path
        if path is None: path = utils.get_vault_path("keys")
        else: path = Path(path)
        if not path.exists(): raise Exception(f"Path not found: {path}")

        # get all the key folders in vault
        vault = Path(path).glob("*")

        # list keys and their count
        valid_key_suffixes = [".pem", ".pub", ".key"]
        key_count = 0
        for folder in vault:
            if folder.is_dir():
                for file in folder.glob("*"):
                    if file.is_file() and file.suffix in valid_key_suffixes:
                        print(f":key: [cyan]{file.name}[/cyan]")
                        key_count += 1

        print(f":sparkles: Found [bold green]{key_count}[/bold green] keys in [green]{path}[/green]")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not list keys in vault.\n{e}")
        raise typer.Exit()

@app.command()
def delete(
    alias: Annotated[str, typer.Argument(help="alias of the key(pair) to delete")],
    path: Annotated[str, typer.Option(help="ONLY if you store your keys at a CUSTOM PATH")] = None,
):
    """
    deletes a key(pair) from your vault
    """
    try:
        # get vault path
        if path is None: path = utils.get_vault_path("keys")
        else: path = Path(path)
        if not path.exists(): raise Exception(f"Path not found: {path}")

        # get keypair metadata
        with open(Path(path).joinpath(f"{alias}/METADATA_{alias}.json"), "r") as f:
            metadata = json.loads(f.read())
            symmetric = metadata["algorithm"] == "AES"
        
        # delete symmetric key if present
        if(symmetric):
            if Path(path).joinpath(f"{alias}").joinpath(f"KEY_{alias}.key").exists():
                Path(path).joinpath(f"KEY_{alias}.key").unlink()
                print(f":wastebasket: [bold green] Success:[/bold green] KEY [green]{alias}[/green] deleted.")
            else:
                print(f":warning: [bold red]Error:[/bold red] KEY [red]{alias}[/red] not found in vault.")

        # delete asymmetric keypair if present
        else:
            # delete keypair folder
            keypair_path = Path(path).joinpath(f"{alias}")
            if keypair_path.exists():
                for file in keypair_path.glob("*"):
                    file.unlink()
                keypair_path.rmdir()
                print(f":wastebasket: [bold green] Success:[/bold green] Keypair [green]{alias}[/green] deleted.")
            else:
                print(f":warning: [bold red]Error:[/bold red] Keypair [red]{alias}[/red] not found in vault.")

    except Exception as e:
        print(f":no_entry: [bold red] Error:[/bold red] Could not delete keypair from vault.\n{e}")
        raise typer.Exit()

@app.command()
def save(
    path: Annotated[str, typer.Argument(help="path to the key to be saved")],
    alias: Annotated[str, typer.Argument(help="name the key to be saved")] = None,
    symmetric: Annotated[bool, typer.Option(help="asymmetric [default] | symmetric key")] = False,
    private: Annotated[bool, typer.Option(help="public [default] | private if asymmetric key")] = False,
):
    """
    imports external key file and stores it in managed vault
    """
    try:
        # get vault path
        vault_path = utils.get_vault_path("keys")

        # check if file exists
        if not Path(path).is_file():
            raise Exception(f"Invalid path: [red]{path}[/red]")

        # prepare output path
        if alias is None: alias = os.urandom(4).hex()
        if(not symmetric):
            if(private): out_path = Path(vault_path).joinpath(f"PRIVKEY_{alias}.pem")
            else: out_path = Path(vault_path).joinpath(f"PUBKEY_{alias}.pub")
        else:
            out_path = Path(vault_path).joinpath(f"KEY_{alias}.key")

        # copy file to vault
        copyfile(path, out_path)

        print(f":tada: [bold green]Success:[/bold green] Key stored in {out_path}")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not store key in vault.\n{e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()

# KEY UTILS
# save private key with password to file
def save_private_key_rsa(key: Any, passwd: str, path: Path):
    try:
        if passwd is None:
            data = key.export_key(format='PEM')
        else:
            data = key.export_key(
                format='PEM', passphrase=passwd, pkcs=8,
                protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                prot_params={"iteration_count": 21000}
            )
        f = open(path, "xb")
        f.write(data)
        f.close()
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise typer.Exit("Exited with status code 1.")

# save private key with password to file
def save_private_key_ecc(key: Any, passwd: str, path: Path):
    try:
        if passwd is None:
            data = key.export_key(format='PEM')
        else:
            data = key.export_key(
                format='PEM', passphrase=passwd,
                protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                prot_params={"iteration_count": 21000}
            )
        f = open(path, "xb")
        f.write(data.encode())
        f.close()
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save key to file.\n{e}")
        raise typer.Exit("Exited with status code 1.")
