import os, platform
from pathlib import Path
from rich import print
from typer import Exit
import typer

def get_vault_path():
    try:
        hostOS = platform.system()
        vault_path = ""
        if hostOS == "Darwin":
            vault_path = Path('/Users/').joinpath(os.getlogin(), '.vault', 'keys')
        elif hostOS == "Linux":
            vault_path = Path('/usr/').joinpath('share', 'vault', 'keys')
        elif hostOS == "Windows":
            vault_path = Path('C:/').joinpath('Program Files', 'Vault', 'keys')
        if(not vault_path):
            raise Exception("Insufficient file system privileges or unsupported OS. You can specify a custom path using the --path option.")
        vault_path.mkdir(parents=True, exist_ok=True)
        return vault_path
    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not find or create a vault.\n{e}")
        raise Exit("Exited with status code 1.")
