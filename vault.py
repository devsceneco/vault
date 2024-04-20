import typer, uuid, os
from typing import Optional
from typing_extensions import Annotated
from Crypto.PublicKey import RSA
import keypair

app = typer.Typer()
app.add_typer(keypair.app, name="keypair")

@app.command()
def bye():
    """
    just says byee
    """
    print('byee')

@app.command()
def add(x: int, y: int):
    """
    returns sum of two integers
    """
    print(x + y)

if __name__ == "__main__":
    app()
