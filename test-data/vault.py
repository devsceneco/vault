import typer, uuid, os
from typing_extensions import Annotated
from rich import print
import keypair, encrypt, decrypt

app = typer.Typer()
# key management app
app.add_typer(keypair.app, name="keypair", help="generate, store and manage asymmetric keypairs")
# file encryption app
app.add_typer(encrypt.app, name="encrypt", help="encrypt a file using a key")
# app.add_typer(decrypt.app, name="decrypt", help="decrypt a file using a key")

if __name__ == "__main__":
    app()
