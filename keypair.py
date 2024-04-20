import typer, uuid, os
from typing_extensions import Annotated, List
from Crypto.PublicKey import RSA, ECC
from enum import Enum

class Algo(str, Enum):
    RSA = "RSA",
    ECC = "ECC",

app = typer.Typer()

@app.command()
def generate(
    passwd: Annotated[str, typer.Argument()],
    algo: Annotated[List[Algo], typer.Option()] = [Algo.RSA],
    path: Annotated[str, typer.Option()] = "~/Downloads/.vault/keys",
    alias: Annotated[str, typer.Option()] = "random uuid",
):
    """
    generates, store, retrieve an asymmetric keypair
    """
    if alias == "random uuid":
        alias = "PRIVKEY_" + str(uuid.uuid4())[0:6]
    match(type):
        case "RSA":
            key = RSA.generate(2048)
        case "ECC":
            key = ECC.generate(curve='P-256')
        # default case
        case _:
            key = RSA.generate(2048)

    with open(f"{alias}.pem", "wb") as f:
        data = key.export_key(format="PEM", passphrase=passwd)
        f.write(data)
    with open(f"{alias.replace("PRIVKEY", "PUBKEY")}.pub", "wb") as f:
        data = key.public_key().export_key(format="PEM")
        f.write(data)

if __name__ == "__main__":
    app()
