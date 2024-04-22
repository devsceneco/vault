import typer, os
from shutil import copyfile
from pathlib import Path
from typing_extensions import Annotated, List
from Crypto.PublicKey import RSA, ECC
from enum import Enum
from utils import get_vault_path
from rich import print

# enum of supported algorithms
class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",

# typer sub app for keypair command
app = typer.Typer()

@app.command()
def generate(
    alias: Annotated[str, typer.Argument(help="to name the key, default is random 6 digit id")] = None,
    algo: Annotated[List[Algo], typer.Option(help="currently supports RSA [default] and ECC")] = [Algo.RSA],
    passwd: Annotated[str, typer.Option(help="to encrypt the private key file, default is none")] = None,
    path: Annotated[str, typer.Option(help="CUSTOM PATH for keys, PREVENTS vault from managing your keys")] = None,
):
    """
    generates an asymmetric keypair and stores it in your vault
    """
    try:
        # generate private key
        match(type):
            case "RSA": key = RSA.generate(2048)
            case "ECC": key = ECC.generate(curve='P-256')
            # default case
            case _: key = RSA.generate(2048)

        # prepare private key output path
        vault_path = get_vault_path("keys")
        if alias is None: alias = str(uuid.uuid4())[0:6]
        out_path = Path(vault_path).joinpath(f"PRIVKEY_{alias}.pem")
        # store private key
        with open(out_path, "wb") as f:
            if passwd is None: data = key.export_key(format='PEM')
            else:
                data = key.export_key(
                    format='PEM', passphrase=passwd, pkcs=8,
                    protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                    prot_params={"iteration_count": 21000}
                )
            f.write(data)

        # prepare public key output path
        out_path = vault_path.joinpath(f"PUBKEY_{alias}.pub")
        # generate and store public key
        with open(out_path, "xb") as f:
            data = key.public_key().export_key(format="PEM")
            f.write(data)

        print(f":tada: [bold green]Success:[/bold green] Keypair generated and stored in vault.")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not store keypair in vault.\n{e}")
        raise typer.Exit()

@app.command()
def list(
    path: Annotated[str, typer.Option(help="ONLY if you store your keys at a CUSTOM PATH")] = None,
    # TODO - add a flag to list only public keys, private keys or symmetric keys
):
    """
    lists the keys stored in your vault
    """
    try:
        # get vault path
        if path is None: path = get_vault_path("keys")
        else: path = Path(path)
        # get files in vault
        vault = path.iterdir()

        # list keys and their count
        valid_key_suffixes = [".pem", ".pub", ".key"]
        key_count = 0
        for file in vault:
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
    symmetric: Annotated[bool, typer.Option(help="delete symmetric key, default is asymmetric keypair")] = False,
):
    """
    deletes a key(pair) from your vault
    """
    try:
        # get vault path
        path = get_vault_path("keys")

        # delete symmetric key if present
        if(symmetric):
            if Path(path).joinpath(f"KEY_{alias}.key").exists():
                Path(path).joinpath(f"KEY_{alias}.key").unlink()
                print(f":wastebasket: [bold green] Success:[/bold green] KEY [green]{alias}[/green] deleted.")
            else:
                print(f":warning: [bold red]Error:[/bold red] KEY [red]{alias}[/red] not found in vault.")

        # delete asymmetric keypair if present
        else:
            # delete private key if present
            if Path(path).joinpath(f"PRIVKEY_{alias}.pem").exists():
                Path(path).joinpath(f"PRIVKEY_{alias}.pem").unlink()
                print(f":wastebasket: [bold green] Success:[/bold green] PRIVKEY [green]{alias}[/green] deleted.")
            else:
                print(f":warning: [bold red]Error:[/bold red] PRIVKEY [red]{alias}[/red] not found in vault.")
            # delete public key if present
            if Path(path).joinpath(f"PUBKEY_{alias}.pub").exists():
                Path(path).joinpath(f"PUBKEY_{alias}.pub").unlink()
                print(f":wastebasket: [bold green] Success:[/bold green] PUBKEY [green]{alias}[/green] deleted.")
            else:
                print(f":warning: [bold red]Error:[/bold red] PUBKEY [red]{alias}[/red] not found in vault.")

    except Exception as e:
        print(f":no_entry: [bold red] Error:[/bold red] Could not delete keypair from vault.\n{e}")
        raise typer.Exit()

@app.command()
def show(alias: Annotated[str, typer.Argument(help="alias of the keypair to show")]):
    """
    displays the path of the keypair
    """
    try:
        # get vault path
        path = get_vault_path("keys")

        # show private key path if present
        if Path(path).joinpath(f"PRIVKEY_{alias}.pem").exists():
            print(f":key: [cyan]{Path(path).joinpath(f'PRIVKEY_{alias}.pem')}[/cyan]")
        else:
            print(f":warning: [bold red]Error:[/bold red] PRIVKEY [red]{alias}[/red] not found in vault.")
        # show public key path if present
        if Path(path).joinpath(f"PUBKEY_{alias}.pub").exists():
            print(f":key: [cyan]{Path(path).joinpath(f'PUBKEY_{alias}.pub')}[/cyan]")
        else:
            print(f":warning: [bold red]Error:[/bold red] PUBKEY [red]{alias}[/red] not found in vault.")
    except Exception as e:
        print(f":no_entry: [bold red] Error:[/bold red] Could not show keypair from vault.\n{e}")
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
        vault_path = get_vault_path("keys")

        # check if file exists
        if not Path(path).is_file():
            raise Exception(f"Invalid path: [red]{path}[/red]")

        # prepare output path
        if alias is None: alias = os.urandom(5).hex()
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
