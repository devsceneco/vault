from click.types import BoolParamType
import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils, aws_utils
import boto3
from pyperclip import copy

app = typer.Typer()

@app.command()
def share(
    alias: Annotated[str, typer.Argument(help="alias of the project")],
) -> None:
    """
    exports project to s3 bucket
    """
    try:
        # get export path
        project_path = Path(utils.get_vault_path("exports")).joinpath(alias)
        if not project_path.exists():
            raise Exception(f"Project not found: {project_path}")

        # get archive path
        archive_path = project_path.joinpath(f"{alias}.zip")
        if not archive_path.exists():
            print('creating archive', project_path)
            utils.compress_folder(project_path, project_path.joinpath(alias))

        # upload archive to s3
        aws_utils.upload_file(archive_path)
        print(f":white_check_mark: [bold green]Success:[/bold green] Archive uploaded to S3.")

        # get presigned URL
        url = aws_utils.get_presigned_url(f'{alias}.zip')
        copy(url)
        print(f":link: [bold green]Success:[/bold green] Presigned URL copied to clipboard.")
        print(f":warning: [bold yellow]Warning:[/bold yellow] URL expires in 10 minutes.")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not export project.\n{e}")
        raise typer.Exit(1)
