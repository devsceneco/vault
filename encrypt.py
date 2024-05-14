import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils, aws_utils
from pyperclip import copy

app = typer.Typer()

@app.command()
def rsa(
    file: Annotated[Path, typer.Argument(..., help="path to input file")],
    key: Annotated[Path, typer.Argument(..., help="alias of the public key")],
    out: Annotated[Path, typer.Argument(..., help="path to store export file")],
    share: Annotated[bool, typer.Option(..., "--share", help="share the encrypted file")] = False,
    alias: Annotated[str, typer.Option(..., help="name the export, default is random ID")] = os.urandom(5).hex(),
):
    """
    hybrid encryption on file, AES + RSA
    """
    try:
        # get key path
        key_path = Path(utils.get_vault_path("keys")).joinpath(key).joinpath(f"PUBKEY_{key}.pub")
        if(not key_path.exists()): raise typer.BadParameter(f"Key file {key} not found.")

        # get output path
        project_path = Path(utils.get_vault_path(Path("exports").joinpath(alias)))

        # generate 32 byte key for AES
        aes_key = os.urandom(32)
        # encrypt the file with AES
        utils.encrypt_file_aes(file, aes_key, project_path, alias)
        print(f":white_check_mark: 1/3 saved encrypted file to {project_path}/ENC_{alias}.enc")

        # encrypt AES key with RSA
        utils.encrypt_message_rsa(aes_key, key, project_path.joinpath(f"AESKEY_{alias}.key"))
        print(f":white_check_mark: 2/3 saved encrypted AES key to {project_path}/AESKEY_{alias}.key")

        # create metadata file
        metadata = {
            "alias": alias,
            "suffix": file.suffix,
            "stem": file.stem,
            "timestamp": time.time()
        }
        with open(project_path.joinpath(f"METADATA_{alias}.json"), "w") as f:
            f.write(json.dumps(metadata))

        # package the files for transfer
        if out.exists(): out_path = Path(out).joinpath(alias)
        else: out_path = project_path.joinpath(alias)
        utils.compress_folder(project_path, out_path)        
        print(f":white_check_mark: 3/3 saved compressed archive to {out_path}.zip")

        if (share):
            out_path = out_path.with_suffix(".zip")
            # upload archive to s3
            aws_utils.upload_file(out_path)
            print(f":white_check_mark: [bold green]Success:[/bold green] Archive uploaded to S3.")

            # get presigned URL
            url = aws_utils.get_presigned_url(f'{alias}.zip')
            copy(url)
            # print the URL
            print(f":link: [bold green]Success:[/bold green] URL: {url}")
            print(f":link: [bold green]Success:[/bold green] URL copied to clipboard.")
            print(f":warning:  [bold yellow]Warning:[/bold yellow] URL expires in 10 minutes.")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt file.\n{e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
