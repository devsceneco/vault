import typer, os, time, json
import utils
from shutil import copyfile
from pathlib import Path
from typing_extensions import Annotated, Any, List
from Crypto.PublicKey import RSA, ECC
from enum import Enum
from rich import print
import keys_utils

# enum of supported algorithms
class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",
    AES = "AES"

# typer sub app for 'vault keys' commands
app = typer.Typer()

@app.command()
def generate(
    passwd: Annotated[str, typer.Option(help="to protect the key")],
    alias: Annotated[str, typer.Argument(help="name the key, default is a random ID")] = "",
    algo: Annotated[Algo, typer.Option(help="algorithm for key generation & usage", case_sensitive=False)] = Algo.RSA
):
    """
    generates key(pairs) to store in vault or custom path
    """
    try:
        # prepare private key output path
        if alias == "": alias = os.urandom(4).hex()

        out_path = Path(utils.get_vault_path("keys"))
        if not out_path.exists(): raise Exception(f"Path not found: {out_path}")

        # make a new folder for the new key(pair)
        out_path = out_path.joinpath(alias)
        out_path.mkdir(parents=True, exist_ok=True)

        # create metadata file for the key(pair) in the same folder
        digest = utils.generate_hash_of_hash(passwd)
        metadata = {
            "alias": alias,
            "algorithm": algo,
            "created_at": time.ctime(),
            "last_used": "",
            "times_used": 0,
            "passwd_digest": digest
        }

        # save AES key to file
        if (algo == Algo.AES): # symmetric key
            keys_utils.save_aes_key(out_path, alias, passwd)
            # update metadata
            metadata["key"] = f"KEY_{alias}.key"

        else: # asymmetric keypair
            if(algo == Algo.RSA):
                keys_utils.save_rsa_keypair(out_path, alias, passwd)
            elif(algo == Algo.ECC):
                keys_utils.save_ecc_keypair(out_path, alias, passwd)
            # update metadata
            metadata["private_key"] = f"PRIVKEY_{alias}.pem"
            metadata["private_key_last_used"] = ""
            metadata["public_key"] = f"PUBKEY_{alias}.pub"
            metadata["public_key_last_used"] = ""

        # save metadata to file
        with open(out_path.joinpath(f"METADATA_{alias}.json"), "w") as f:
            f.write(json.dumps(metadata))

        print(f":tada: [bold green]Success:[/bold green] Keypair [green]{alias}[/green] generated and stored in vault.")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not generate and store key(pair).\n{e}")
        raise typer.Exit()


@app.command()
def list():
    """
    lists the keys stored in your vault
    """
    try:
        # get vault path
        path = utils.get_vault_path("keys")
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
):
    """
    deletes a key(pair) from your vault
    """
    try:
        # get vault path
        path = utils.get_vault_path("keys")
        if not path.exists(): raise Exception(f"Path not found: {path}")

        # get keypair metadata
        with open(Path(path).joinpath(f"{alias}/METADATA_{alias}.json"), "r") as f:
            metadata = json.loads(f.read())
            symmetric = metadata["algorithm"] == "AES"

        # delete symmetric key if present
        key_path = Path(path).joinpath(alias)
        if key_path.exists():
            for file in key_path.glob("*"):
                file.unlink()
            key_path.rmdir()
            print(f":wastebasket: [bold green] Success:[/bold green] key(pair) folder [green]{alias}[/green] deleted.")
        else:
            print(f":warning: [bold red]Error:[/bold red] key(pair) folder [red]{alias}[/red] not found in vault.")

    except Exception as e:
        print(f":no_entry: [bold red] Error:[/bold red] Could not delete keypair from vault.\n{e}")
        raise typer.Exit()

@app.command()
def save(
    path: Annotated[str, typer.Argument(help="path to the key to be saved")],
    alias: Annotated[str, typer.Argument(help="name the key to be saved")] = "",
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
        if alias == "": alias = os.urandom(4).hex()
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
