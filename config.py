import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils, aws_utils
from getpass import getpass

app = typer.Typer()

@app.command()
def aws() -> None:
    """
    saves AWS credentials to local file and creates vault bucket
    """
    try:
        # get config path
        vault_path = Path(utils.get_vault_path(".config"))
        id = getpass(f"Your AWS accessKey ID: ")
        secret = getpass(f"Your AWS secret accessKey: ")

        # create config file
        bucket_name = f"vault-{os.urandom(4).hex()}"
        config = {
            "accessKey": {
                "access_key_id": id,
                "secret_access_key": secret,
                "bucket_name": bucket_name
            }
        }
        # write to file
        with open(vault_path.joinpath("awsconfig.json"), "w") as f:
            json.dump(config, f, indent=4)
        print(f":white_check_mark: [bold green]Success:[/bold green] AWS credentials saved.")

        # create bucket
        aws_utils.create_bucket(bucket_name)
        print(f":white_check_mark: [bold green]Success:[/bold green] Created S3 bucket [green]{bucket_name}[/green]")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not save AWS credentials.\n{e}")
        raise typer.Exit(1)
