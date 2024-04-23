import typer, os, time, json
from rich import print
from typing_extensions import Annotated
from pathlib import Path
import utils

app = typer.Typer()

@app.command()
def rsa(
    file: Annotated[Path, typer.Argument(..., help="path to input file")],
    key: Annotated[Path, typer.Argument(..., help="PATH or ALIAS of RSA public key file")],
    out: Annotated[Path, typer.Argument(..., help="path to store export file")] = None,
    alias: Annotated[str, typer.Option(..., help="name the export, default is random ID")] = os.urandom(5).hex(),
):
    """
    hybrid encryption on file, AES + RSA
    """
    try:
        # get key path
        key_path = Path(utils.get_vault_path("keys")).joinpath(f"PUBKEY_{key}.pub")
        if(not key_path.exists()): key_path = Path(key)
        if(not key_path.exists()): raise typer.BadParameter(f"Key file {key} not found.")

        # get output path
        project_path = Path(utils.get_vault_path(Path("exports").joinpath(alias)))

        # generate 32 byte key for AES
        aes_key = os.urandom(32)
        # encrypt the file with AES
        utils.encrypt_file_aes(file, aes_key, project_path, alias)
        print(f":white_check_mark: 1/3 saved encrypted file to {project_path}/ENC_{alias}.enc")

        # encrypt AES key with RSA
        utils.encrypt_message_rsa(aes_key, key_path, project_path.joinpath(f"AESKEY_{alias}.key"))
        print(f":white_check_mark: 2/3 saved encrypted AES key to {project_path}/AESKEY_{alias}.key")

        # create metadata file
        metadata = {
            "alias": alias,
            "suffix": file.suffix,
            "stem": file.stem,
            "timestamp": time.time()
        }
        with open (project_path.joinpath(f"METADATA_{alias}.json"), "w") as f:
            f.write(json.dumps(metadata))

        # package the files for transfer
        if(out is None): out = project_path
        else: out = Path(out)
        utils.compress_folder(project_path, out, alias)
        print(f":white_check_mark: 3/3 saved compressed archive to {out}/{alias}.zip")

    except Exception as e:
        print(f":no_entry: [bold red]Error:[/bold red] Could not encrypt file.\n{e}")
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
