import typer, uuid
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
        # generate keypair
        match(type):
            case "RSA": key = RSA.generate(2048)
            case "ECC": key = ECC.generate(curve='P-256')
            # default case
            case _: key = RSA.generate(2048)

        # generate file name
        if alias is None: alias = "PRIVKEY_" + str(uuid.uuid4())[0:6]
        else: alias = "PRIVKEY_" + alias
        # generate file path
        if path is None: path = get_vault_path("keys")
        else: path = Path(path)

        # store keypair
        with open(Path(path).joinpath(f"{alias}.pem"), "wb") as f:
            if passwd is None: data = key.export_key(format='PEM')
            else:
                data = key.export_key(
                    format='PEM', passphrase=passwd, pkcs=8,
                    protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC',
                    prot_params={"iteration_count": 21000}
                )
            f.write(data)
        with open(Path(path).joinpath(f"{alias.replace('PRIVKEY', 'PUBKEY')}.pub"), "xb") as f:
            data = key.public_key().export_key(format="PEM")
            f.write(data)
        print(f":tada: [bold green]Success:[/bold green] Keypair generated and stored in [green]{path}[/green]")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not store keypair in vault.\n{e}")
        raise typer.Exit()

@app.command()
def list(path: Annotated[str, typer.Option(help="specify ONLY IF you passed a CUSTOM PATH while generating keys")] = None):
    """
    lists the keypairs stored in your vault
    """
    try:
        # get vault path
        if path is None: path = get_vault_path("keys")
        else: path = Path(path)
        # get files in vault
        vault = path.iterdir()

        # list private keys and their count
        key_count = 0
        for file in vault:
            if file.is_file() and file.suffix == ".pem":
                print(f":key: [cyan]{file.name.replace('PRIVKEY_', '').replace('.pem', ' keypair')}[/cyan]")
                key_count += 1
        print(f":sparkles: Found [bold green]{key_count}[/bold green] keypairs in [green]{path}[/green]")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not list keypairs in vault.\n{e}")
        raise typer.Exit()

@app.command()
def delete(alias: Annotated[str, typer.Argument(help="alias of the keypair to delete")]):
    """
    deletes a keypair from your vault
    """
    try:
        # get vault path
        path = get_vault_path("keys")

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

# TODO - add an import command to save an externally generated key to vault

if __name__ == "__main__":
    app()
