import typer, os
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
    alias: Annotated[str, typer.Argument(help="name the key, default is random 8 digit id")] = None,
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
        if(path is None): out_path = utils.get_vault_path("keys")
        else: out_path = Path(path)
        if not out_path.exists(): raise Exception(f"Path not found: {out_path}")

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

        print(f":tada: [bold green]Success:[/bold green] Keypair generated and stored in vault.")
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
        path = utils.get_vault_path("keys")

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
        path = utils.get_vault_path("keys")

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
