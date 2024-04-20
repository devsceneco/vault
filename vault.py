import typer
from typing import Optional

app = typer.Typer()

@app.command()
def hello(name: Optional[str] = None):
    """
    greets you by name, if name is passed
    """
    if (name):
        print(f"hello {name}")
    else:
        print('hiee')

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
