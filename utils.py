import os, platform
from pathlib import Path
from rich import print

def get_vault_path():
    try:
        hostOS = platform.system()
        vault_path = ""
        if hostOS == "Darwin":
            vault_path = Path('/Users/').joinpath(os.getlogin(), '.vault', 'keys')
            vault_path.mkdir(parents=True, exist_ok=True)
        elif hostOS == "Linux":
            vault_path = Path('/usr/').joinpath('share', 'vault', 'keys')
            vault_path.mkdir(parents=True, exist_ok=True)
        elif hostOS == "Windows":
            vault_path = Path('C:/').joinpath('Program Files', 'Vault', 'keys')
            vault_path.mkdir(parents=True, exist_ok=True)
        return vault_path
    except Exception as e:
        print(f"[bold red]Error:[/bold red] Could not find or create a vault.\n{e}")
        exit(1)
