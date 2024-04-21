import typer, uuid, os, platform
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
    passwd: Annotated[str, typer.Option()] = None,
    algo: Annotated[List[Algo], typer.Option()] = [Algo.RSA],
    path: Annotated[str, typer.Option()] = None,
    alias: Annotated[str, typer.Option()] = None,
):
    """
    generates an asymmetric keypair and stores it in your vault
    """
    try:
        # generate keypair
        match(type):
            case "RSA":
                key = RSA.generate(2048)
            case "ECC":
                key = ECC.generate(curve='P-256')
            # default case
            case _:
                key = RSA.generate(2048)

        # generate file name
        if alias is None:
            alias = "PRIVKEY_" + str(uuid.uuid4())[0:6]
        else:
            alias = "PRIVKEY_" + alias
        # generate file path
        if path is None:
            path = get_vault_path()
        else:
            path = Path(path)
            path.mkdir(parents=True, exist_ok=True)
        # store keypair
        with open(Path(path).joinpath(f"{alias}.pem"), "wb") as f:
            if passwd is None:
                data = key.export_key(format='PEM')
            else:
                data = key.export_key(format='PEM', passphrase=passwd, pkcs=8, protection='PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC', prot_params={"iteration_count": 21000})
            f.write(data)
        with open(Path(path).joinpath(f"{alias.replace("PRIVKEY", "PUBKEY")}.pub"), "xb") as f:
            data = key.public_key().export_key(format="PEM")
            f.write(data)

        print(f":tada: [bold green]Success:[/bold green] Keypair generated and stored in [green]{path}[/green]")
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not store keypair in vault.\n{e}")
        exit(1)

if __name__ == "__main__":
    app()
