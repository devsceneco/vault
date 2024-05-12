import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils
from getpass import getpass

app = typer.Typer()

@app.command()
def aws() -> None:
    """
    saves AWS credentials to local file
    """
    # get config path
    vault_path = Path(utils.get_vault_path(".config").joinpath("awsconfig.json"))
    id = getpass(f"Your AWS accessKey ID: ")
    secret = getpass(f"Your AWS secret accessKey: ")

    # create config json
    config = {
        "accessKey": {
            "access_key_id": id,
            "secret_access_key": secret
        }
    }

    # write to file
    with open(vault_path, "w") as f:
        json.dump(config, f, indent=4)

    print(f":tada: AWS credentials saved to {vault_path}")
